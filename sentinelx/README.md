# SentinelX

**Autonomous Identity, Credential & Secret Governance for Databricks**

Discover. Assess. Govern. Rotate. Remediate.

A runnable hackathon MVP with metadata-only discovery, deterministic scoring,
SQLite history, authenticated FastAPI, nine Streamlit views, grounded compliance
Q&A, a centralized remediation action center, and approval-gated reversible
remediation. Demo mode works without a Databricks workspace or AWS account.

## Start the Demo

Python 3.11+ is required. From the repository root:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.lock.txt
.\.venv\Scripts\python.exe -m scripts.dev
```

On Linux/macOS, use `.venv/bin/python` instead. The launcher prints the dashboard
URL, chooses available ports, and creates random, process-only API keys. Both
servers bind to loopback. Ctrl+C stops both. Default demo execution changes only
local metadata; `--audit-only` disables it. No cloud credentials are needed.

For this machine, the isolated interpreter is available at
`../sentinelx-runtime/python.exe`; use it instead of `python`.

## What Works

- 64 realistic demo assets across all seven requested inventory types.
- Live workspace SCIM service principals, admin PAT metadata, scope/key metadata,
  account-level SP OAuth secrets, and paginated boto3 Secrets Manager metadata.
- 30-day age/rotation/activity policies; expired and 7/15/30-day expiry findings;
  unowned, inactive, unused, privilege, and evidence-gap findings.
- Weighted 0-100 governance scores; green/yellow/orange/red risk levels.
- Scheduled scans, historical snapshots, CSV/JSON reports, and hash-chained audits.
- Dry-run, independent approval, 24-hour approval expiry, atomic execution claims,
  inventory-fingerprint checks, replay protection, and separately approved rollback.
- Stable finding IDs, filtered/paginated finding and action APIs, and idempotent
  action requests tied to current findings.
- SentinelX Compliance Copilot answers supported questions from current structured
  reports and action status, with finding/report references. It never receives
  credential values and cannot invoke remediation.
- Remediation & Action Center with finding evidence, policy context, supported
  remediation guidance, approval workflow, status, and execution history.
- Live SP OAuth renewal into AWS AWSPENDING, OAuth validation, Databricks scope
  update, AWSCURRENT promotion, durable checkpoints, and version-based rollback.
- Encrypted provider configuration and separate reader/operator/approver API keys.

## Important Boundaries

Demo rotation is **simulated**, not a cloud operation. The demo dashboard holds
role keys to simulate multiple actors and must never be publicly exposed.
The live dashboard is read-only; separate authenticated API clients perform
approval and execution. The Docker dashboard has only a reader key.

Live renewal requires account API access, a configured executor SP, an existing
AWS OAuth JSON secret and Databricks key, and an owner-attested rollback mapping.
New secret material exists only in executor memory and provider writes, never
in API responses, metadata, audit events, configuration exports, or SQLite.
Discovery and dry runs never call `GetSecretValue`.

The Copilot currently uses grounded structured queries, not a configured LLM or
Databricks Model Serving endpoint. An allowlisted intent-provider interface is
available for future approved integration. API keys are role-based rather than
per-user identities, so team-scoped results are not available. The optional
Databricks App hosts only the Streamlit dashboard; FastAPI and its persistent
SQLite database must be hosted separately.

Generic OAuth/application credentials require an authoritative metadata registry.
Missing owner is an **orphan candidate**, not proof the identity is unused.
PAT ownership/activity and least privilege may be unknown depending on API access
and version. Secret last-modified timestamps are **not** rotation evidence.
Metadata alignment does **not** prove value synchronization.

Old SP secrets are retained for rollback. Revocation, deletion, arbitrary PAT
rotation, standalone live AWS rotation, and automatic privilege removal are
intentionally unavailable because the MVP cannot guarantee their rollback.
OAuth validation verifies credential issuance, not all dependent workloads.
Real Databricks/AWS acceptance testing still requires your provisioned accounts.

## Verification

```powershell
python -m pytest -q
python -m ruff check .
python -m scripts.brand_asset
python -m scripts.sample_outputs
```

Tests include scoring boundaries, approval/rollback, encrypted config, FastAPI
workflows, boto3 Stubber contracts, Databricks mocks, all nine Streamlit views,
grounded Copilot queries, and the Action Center approval/execution flow.
No unit/integration test needs cloud credentials. The lockfile records the
dependency versions used for local verification; CI builds the Docker image.

## Documentation

- [Architecture and five diagrams](docs/architecture.md)
- [Workspace onboarding, permissions, and live validation](docs/onboarding.md)
- [API capability and workaround matrix](docs/capabilities.md)
- [Local, Docker, AWS, Databricks, and CI/CD deployment](docs/deployment.md)
- [Authenticated API reference](docs/api.md)
- [Security model and recovery procedures](docs/security.md)
- [Demo walkthrough and presentation narrative](docs/demo.md)
- [Generated sample output](docs/sample_output.json)
- [Generated sample inventory](configs/sample_assets.json)

## Repository Layout

```text
sentinelx/
  backend/{api,services,models,governance,remediation}/
  databricks/{service_principals,credentials,secrets,clients}/
  aws/{secrets_manager,integrations}/
  dashboard/  audit/  scoring/  configs/  scripts/  tests/
  deployment/  docs/  .github/workflows/
```

Provider implementations are centralized in `backend/services/providers.py` and
`backend/remediation/live.py`. The Databricks folders contain integration contracts,
not a local `databricks` Python package, avoiding collision with the official SDK.
SQLite is intentionally single-instance. PostgreSQL, distributed workers, SSO for
API actors, immutable external audit anchors, and workload validators are future
production hardening, not implemented enterprise features.