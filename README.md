# Lightweight SOAR platform for Wazuh

An async FastAPI SOAR engine wired to a Wazuh Manager. It takes in alerts in real time, checks them against YAML playbooks (with sliding-window correlation), asks a human to approve high-impact containment (Slack / e-mail, with signed links and a timeout), runs the containment (Wazuh Active Response, SSH iptables, or Docker network isolation), and writes every step to a hash-chained, append-only audit log.

```
attacker-sim ──hydra──▶ target-victim (sshd, nginx, wazuh-agent)
                              │ auth.log
                              ▼
                        wazuh-manager ──custom-soar integration (X-SOAR-Token)──▶ soar-engine
                              ▲                                                     │  playbooks + threshold
                              │ PUT /active-response (JWT)                          │  HITL ─▶ Slack / SMTP (mailpit)
                              └──────────────────── approve link ◀── admin ◀─────────┘
                                   firewall-drop on agent  |  ssh iptables  |  docker network disconnect
```

## Quick start

```bash
cp .env.example .env            # then replace every change-me value
docker compose up -d --build    # wazuh-manager, soar-engine, target-victim, attacker-sim, postgres, mailpit, docker-proxy
python3 scripts/e2e_test.py     # live attack -> HITL -> block, 16 checks (generates .env if missing)
```

| URL | What |
|---|---|
| http://localhost:8000/dashboard | SOAR Console: live incidents, timeline, approve/deny, audit chain, playbooks (sign in with `SOAR_ADMIN_TOKEN`) |
| http://localhost:8000/docs | SOAR OpenAPI UI |
| http://localhost:8025 | Mailpit, where HITL approval e-mails land |

Admin APIs need the `X-Admin-Token` header. `GET /api/v1/incidents`, `/incidents/{id}/timeline`, `/audit/verify`, `/playbooks`, and `/system/dependencies` are the most useful ones.

## Layout

```
soar_engine/app/
  routers/    alerts (ingest), actions (approve/deny), incidents, audit, system
  services/   incident_service (lifecycle), playbook_engine, notifier (Slack/SMTP), audit (hash chain),
              executor + retry, responders/{wazuh, ssh_iptables, docker_isolation}, security (HMAC links)
  playbooks/  playbook schema, condition evaluator, YAML loader
  models/     SQLAlchemy ORM (alerts, incidents, action_executions, audit_log) + Pydantic schemas
soar_engine/playbooks/   ssh_bruteforce.yaml, container_isolation.yaml, web_attack_block.yaml
lab/                     wazuh (ossec.conf, rules, custom-soar integration), victim, attacker
scripts/e2e_test.py      live end-to-end test
```

## Pipeline

1. **Ingest:** `POST /api/v1/alerts/ingest`, authenticated by `X-SOAR-Token` (constant-time compare). It accepts the flat schema (`rule_id, rule_level, source_ip, agent_id, agent_name, timestamp, raw_log, description`) or a raw Wazuh alert.
2. **Playbooks:** `all`/`any`/`not` trees with operators `eq, ne, gt, gte, lt, lte, in, contains, icontains, regex, exists`. A per-key sliding-window threshold is available, for example `> 5 events per source_ip in 60s`. Hot-reload with `POST /api/v1/playbooks/reload`.
3. **HITL:** the incident ID, threat type, target host, attacker IP, and HMAC-signed, expiring approve/deny links go to Slack and/or SMTP. The first decision wins (conditional UPDATE). After `timeout_seconds` (300 by default) the incident is **denied** (safe posture), unless the severity is above `auto_execute_above_level` (12), in which case it is auto-executed.
4. **Containment:** responders are tried in order with retries (3 retries, exponential backoff), falling back to the next responder. Examples: the Wazuh API returns 401, or the agent is disconnected, so the SSH iptables responder runs instead. IPs in `SOAR_PROTECTED_CIDRS` are never blocked.
5. **Audit:** every lifecycle step is appended to `audit_log` with `hash = sha256(prev_hash ‖ canonical event)`. DB triggers reject UPDATE/DELETE. `GET /api/v1/audit/verify` recomputes the chain. Incidents store the raw payload, the parsed variables, the actions, the responder response, and the HTTP status code, plus timestamps for received → triggered → HITL sent → decision → completed.

## Development

```bash
cd soar_engine && python3 -m venv .venv && .venv/bin/pip install -e '.[dev]'
.venv/bin/ruff check . && .venv/bin/mypy app && .venv/bin/pytest -q
```

## Production notes

- Set `SOAR_PUBLIC_BASE_URL` to an HTTPS URL that approvers can reach, and put a TLS reverse proxy in front.
- Set `SOAR_WAZUH_VERIFY_SSL=true` once the manager has a trusted certificate.
- Run one uvicorn worker. The correlation windows and the HITL sweeper live in that process.
- The lab victim has an intentionally weak `admin` password. Never expose it.
