from __future__ import annotations

from typing import Any

import pytest

from app.models.schemas import AlertIn
from app.playbooks.conditions import evaluate
from app.playbooks.loader import load_playbooks
from app.playbooks.models import Condition, Playbook
from app.services.playbook_engine import PlaybookEngine
from tests.conftest import PLAYBOOK_DIR, ssh_alert


def ctx(**kw: Any) -> dict[str, Any]:
    return AlertIn.model_validate(ssh_alert(**kw)).to_context()


def ssh_playbook() -> Playbook:
    return next(p for p in load_playbooks(PLAYBOOK_DIR) if p.id == "ssh-bruteforce-containment")


def test_sample_playbooks_load() -> None:
    ids = {p.id for p in load_playbooks(PLAYBOOK_DIR)}
    assert ids == {"ssh-bruteforce-containment", "container-isolation", "web-attack-block"}


@pytest.mark.parametrize(
    ("rule_id", "level", "description", "expected"),
    [
        (5712, 10, "sshd: brute force trying to get access to the system.", True),
        (5716, 10, "sshd: Authentication failed for root", True),
        (5716, 9, "sshd: Authentication failed for root", False),
        (5710, 5, "sshd: Attempt to login using a non-existent user", False),
        (1002, 12, "Unknown problem somewhere", False),
    ],
)
def test_ssh_trigger_condition(rule_id: int, level: int, description: str,
                               expected: bool) -> None:
    trigger = ssh_playbook().trigger
    assert evaluate(trigger, ctx(rule_id=rule_id, level=level,
                                 description=description)) is expected


def test_condition_operators() -> None:
    c = {"rule_id": "5712", "groups": ["a", "b"], "raw": {"data": {"srcuser": "root"}}}
    assert evaluate(Condition(field="rule_id", op="eq", value=5712), c)
    assert evaluate(Condition(field="groups", op="contains", value="b"), c)
    assert evaluate(Condition(field="raw.data.srcuser", op="regex", value="^ro"), c)
    assert evaluate(Condition(field="missing", op="ne", value=1), c)
    assert not evaluate(Condition(field="missing", op="exists"), c)
    assert evaluate(Condition.model_validate({"not": {"field": "rule_id", "op": "lt",
                                                      "value": 100}}), c)


def test_condition_requires_single_form() -> None:
    with pytest.raises(ValueError, match="exactly one"):
        Condition.model_validate({"field": "x", "op": "eq", "value": 1, "any": []})


async def test_threshold_requires_more_than_five_in_window() -> None:
    engine = PlaybookEngine(PLAYBOOK_DIR)
    engine.set_playbooks([ssh_playbook()])
    # 4 plain failures + trigger = 5 events -> not > 5
    for i in range(4):
        assert await engine.evaluate(ctx(), now=float(i)) == []
    assert await engine.evaluate(ctx(rule_id=5712, level=10), now=4.0) == []
    # 6th event within the window fires
    matches = await engine.evaluate(ctx(rule_id=5712, level=10), now=5.0)
    assert len(matches) == 1
    assert matches[0].correlated_events == 6
    assert matches[0].variables == {"attacker_ip": "203.0.113.50", "agent_id": "001",
                                    "target_host": "target-victim"}


async def test_threshold_window_expires() -> None:
    engine = PlaybookEngine(PLAYBOOK_DIR)
    engine.set_playbooks([ssh_playbook()])
    for i in range(5):
        await engine.evaluate(ctx(), now=float(i))
    # 70s later the old events have aged out of the 60s window
    assert await engine.evaluate(ctx(rule_id=5712, level=10), now=75.0) == []


async def test_threshold_is_per_source_ip() -> None:
    engine = PlaybookEngine(PLAYBOOK_DIR)
    engine.set_playbooks([ssh_playbook()])
    for i in range(5):
        await engine.evaluate(ctx(ip=f"198.51.100.{i}"), now=float(i))
    assert await engine.evaluate(ctx(rule_id=5712, level=10, ip="198.51.100.9"), now=6) == []


def test_wazuh_native_alert_is_flattened() -> None:
    native = {
        "timestamp": "2026-10-11T04:00:00.123+0000",
        "rule": {"level": 10, "description": "sshd: brute force trying to get access to the "
                 "system. Non existent user.", "id": "5712", "groups": ["syslog", "sshd"]},
        "agent": {"id": "001", "name": "target-victim", "ip": "172.28.0.30"},
        "data": {"srcip": "172.28.0.66", "srcport": "40000"},
        "full_log": "Oct 11 04:00:00 target-victim sshd[1]: Invalid user x from 172.28.0.66",
    }
    alert = AlertIn.model_validate(native)
    assert alert.rule_id == 5712
    assert str(alert.source_ip) == "172.28.0.66"
    assert alert.agent_id == "001"
    assert alert.raw == native
