# Deployment Guide

## Local

Use Python 3.11+ and the README virtual-environment commands. Install the lockfile,
not unbounded dependencies. Run from the repository root using `python -m scripts.dev`.
The launcher avoids occupied ports and keeps demo keys in process memory only.
For audit-only demo use `--audit-only`. For live audit use `--live`; explicit
`--execute` enables the approved API workflow, never the live dashboard controls.

For separately managed services, inject the role keys and settings through your
process supervisor, then use:

```text
python -m uvicorn backend.api.app:create_app --factory --host 127.0.0.1 --port 8000 --no-access-log
python -m streamlit run dashboard/app.py --server.address 127.0.0.1 --server.port 8501
```

Set `SENTINELX_API_URL` and give the dashboard only `SENTINELX_READER_KEY` in live
deployments. Never run multiple Uvicorn workers with this SQLite scheduler.
Python scripts do not automatically load `.env`; the template is for supervisors
or Docker Compose. Metadata reports still require authenticated API access.

## Docker

Docker Desktop/Engine and Compose v2 are prerequisites. Copy the placeholder
environment template to `.env` **locally**, replace all role keys using your
approved secret-management process, and keep it untracked. Commands from the root:

```text
docker compose --env-file .env -f deployment/compose.yaml up --build -d
docker compose --env-file .env -f deployment/compose.yaml logs api dashboard
docker compose --env-file .env -f deployment/compose.yaml down
```

Dashboard: `http://127.0.0.1:8501`. API: authenticated `http://127.0.0.1:8000`.
The API uses a named data volume; `down` without `-v` retains it. The dashboard is
read-only in this Compose configuration, including demo mode; use the local launcher
for the interactive actor simulation or separate API clients for decisions.
Both containers run as UID/GID 10001 with dropped capabilities. Startup data-volume
ownership must match this UID when using bind mounts.

For live mode, mount encrypted provider config read-only in the API only and inject
its key from the secret store. Do not bake secrets or encrypted blobs into the image.
Use an environment-specific Compose override for this mount and IAM credential
delivery. The checked-in Compose file is a safe local demo/audit baseline, not a
complete production secrets-delivery system. Docker could not be locally exercised
on the initial Windows host; CI includes an image build gate.

## AWS Option

MVP deployment: one private EC2 instance with an encrypted EBS filesystem and Docker
Compose; mount SQLite on local EBS, not EFS/S3/DBFS. Use IAM instance roles, a private
Secrets Manager/KMS endpoint when required, TLS via an internal ALB/reverse proxy,
restricted outbound Databricks connectivity, and an identity-aware dashboard proxy.
Inject configuration/role keys at boot via the organization's secret agent; do not
place them in user-data logs. Restrict ingress to the approved security team.

Use the discovery and remediation IAM templates and Databricks roles in onboarding.
Archive encrypted EBS snapshots and metadata reports to a restricted S3 bucket;
publish audit-chain digests to an external append-only store for tamper anchoring.
Configure CloudTrail for provider actions and operational alerts for failed scans,
stale inventory, low score, expiring secrets, and recovery-required actions.
No alert transport is implemented in the MVP; consume authenticated reports/audits
through your existing monitoring system. One API replica only; PostgreSQL and a
durable distributed job queue are required before horizontally scaling.

## Databricks Option

**Git folder:** In the target workspace, connect the GitHub account under User
Settings if needed, then create a Git folder for
`https://github.com/elakkiya-devlab/databricks-project` on the approved branch.
The SentinelX project is in the repository's `sentinelx` subdirectory; preserve
that tree and use that subdirectory as the app source. Git-provider authorization
and workspace permissions are controlled by the workspace administrator.

**Databricks App dashboard:** The root `app.yaml` starts the existing Streamlit
dashboard and reads `requirements.txt` from the SentinelX root. The matching
`deployment/app.yaml` is retained as a deployment reference. Replace the example
`SENTINELX_API_URL` with the HTTPS URL of the separately hosted FastAPI service.
Create a Databricks App resource named `sentinelx-reader-key` and grant the App
access to it; `valueFrom` injects the resource as `SENTINELX_READER_KEY`. Do not
put role keys or provider credentials in `app.yaml`, Git, notebooks, or the Git
folder. Keep the App reader-only. App authentication does not replace API role
authorization, and the App does not host FastAPI or SQLite.

After connecting and creating the App in the workspace UI, an authorized operator
can deploy from the workspace source folder with the Databricks CLI:

```text
databricks auth login --host https://<workspace-host>
databricks apps create sentinelx
databricks apps deploy sentinelx --source-code-path /Workspace/Users/<you>/databricks-project/sentinelx
```

Verify the App's dependency build and health in the Databricks Apps UI. If the
backend URL cannot be reached, check private DNS/egress, TLS, firewall policy, and
the App's reader secret resource. The FastAPI service must run separately on
persistent storage, use one SQLite-owning process, and receive distinct
reader/operator/approver keys through its secret manager. The live dashboard must
not receive operator, approver, executor, or AWS credentials. Use the existing
authenticated API workflow for live decisions and execution.

**Scheduled audit:** Package this source/requirements as a workspace job artifact.
On the driver, install the lockfile, inject the encrypted config path and decryption
key securely, and run `python -m scripts.scan --output-dir /Volumes/CATALOG/SCHEMA/VOLUME/sentinelx`.
Set `SENTINELX_DB_PATH` to a local driver path, not a Volume/DBFS SQLite path.
Grant the job SP USE CATALOG, USE SCHEMA, and WRITE VOLUME for reports; use OAuth
M2M/SP authentication for provider discovery. Store only encrypted configuration
on the Volume; inject its key separately. Schedule every 5-15 minutes as approved.

An ephemeral driver SQLite file loses action/history continuity between runs.
Timestamped report artifacts persist on the Volume but are not automatically
imported into the dashboard database. Use the persistent API scheduler as the
primary history/remediation owner. This batch option is audit-only, never a rotation
worker, and requires organizational secret injection and networking validation.

**Copilot and Action Center:** The Copilot uses structured current report data and
deterministic query templates; no Model Serving endpoint is configured by default.
An optional provider-independent intent-router interface can be supplied to the API
factory, but it may select only from allowlisted query intents and cannot execute
remediation. The chat UI retains conversation history in the Streamlit session;
the API does not persist prompts. Team-scoped access is unavailable until an
authenticated user-to-team mapping is integrated. The Action Center uses the same
authenticated finding and remediation APIs as the existing workflow.

## Configuration and CI/CD

The environment template defines policy thresholds, scan interval, audit/remediation
mode, API keys, API URL, and optional encrypted config/key. The provider template
defines explicit discovery/executor SPs, region/profiles, bindings, and owner registry.
Treat decrypted config as sensitive; Fernet key rotation requires resealing.

GitHub Actions installs Python 3.11 and the lockfile, runs lint, tests, bytecode
compilation, and builds the image without cloud secrets. Unit/contract tests use
mocks, not live credentials. For deployment, extend the workflow with an approved
environment gate, GitHub OIDC -> IAM short-lived credentials, registry push, and
the organization's deploy mechanism. No auto-deploy or repository cloud secrets
are configured. Pin action/image digests and run dependency/image scans before
promoting to a real production environment.