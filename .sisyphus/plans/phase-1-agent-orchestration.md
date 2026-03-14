# Phase 1 Agent Orchestration Plan

## Goal
Implement a safe, additive manager-agent pull model in the existing Flask app to support:
- multi-node batch deployment task dispatch
- per-instance start/stop task dispatch
- runtime state visibility for FRPS/FRPC instances reported by nodes

## Scope
In scope (Phase 1):
- JSON-backed persistence for nodes/jobs/runtimes in `utils/config_manager.py`
- Admin APIs for node/job/runtime management
- Agent APIs for register/pull/start/complete/runtime-report
- Auth boundary updates to allow only token-authenticated `/api/agent/v1/*` without admin session
- API-only delivery (no frontend UI changes in this phase)

Out of scope:
- scheduler/cron
- streaming logs
- multi-manager clustering
- SQLite migration

## Design Constraints
- Keep existing FRPS/FRPC routes and payloads unchanged
- Keep `frp_manager/config.json` backward compatible
- Single-process correctness with existing lock/atomic-write model
- Idempotent completion semantics with lease + execution_id

## Data Model (Additive)
- `agent.nodes[]`: node identity, token hash, heartbeat metadata
- `agent.jobs[]`: queued/leased/running/succeeded/failed jobs with lease fields
- `agent.runtimes[]`: last reported runtime status snapshots per instance

## API Plan
### Admin (session-auth required)
- `GET /api/agent/nodes`
- `POST /api/agent/node`
- `GET /api/agent/node/<node_id>`
- `PUT /api/agent/node/<node_id>`
- `DELETE /api/agent/node/<node_id>`
- `POST /api/agent/node/<node_id>/rotate-token`
- `GET /api/agent/jobs`
- `POST /api/agent/job`
- `POST /api/agent/jobs/batch`
- `GET /api/agent/runtimes`
- `POST /api/agent/runtime/<runtime_id>/ensure-running`
- `POST /api/agent/runtime/<runtime_id>/ensure-stopped`

### Agent (token-auth, no session)
- `POST /api/agent/v1/register`
- `POST /api/agent/v1/pull`
- `POST /api/agent/v1/jobs/<job_id>/start`
- `POST /api/agent/v1/jobs/<job_id>/complete`
- `POST /api/agent/v1/runtime/report`

`register` in Phase 1 is handshake/heartbeat only (no node creation). Nodes are always created by admin through `POST /api/agent/node` and receive one-time plaintext token.

## Auth Boundary Plan
Update `enforce_auth_flow()`:
- Keep existing exemptions unchanged
- Add narrow exemption: `path.startswith('/api/agent/v1/')`
- Do not exempt any other orchestration path
- Pre-setup (`setup_done == False`) keeps old behavior: `/api/agent/v1/*` still blocked with 403 until admin setup is completed

Each `/api/agent/v1/*` endpoint must:
- require `Authorization: Bearer <token>`
- require `node_id` in body
- validate token hash against node

## Idempotency and Leasing
- Pull leases max one job per poll for node
- `start` requires matching `(job_id, node_id, lease_id)`
- `complete` requires matching `(job_id, node_id, lease_id)`
- repeated completion on terminal jobs (`succeeded/failed`) returns success without mutating terminal state

## Files To Change
- `utils/config_manager.py` (already updated)
- `app.py` (imports, auth gate, new helpers and routes)
- `README.md` (phase-1 API and workflow notes)

## Verification
- `python -m compileall app.py utils`
- `python -c "import sys; sys.path.insert(0,'.'); import app; print('ok')"`
- confirm existing routes still import and app starts
