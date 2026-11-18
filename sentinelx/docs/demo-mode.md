# Demo Mode, Copilot, Action Center and AWS Connection

This guide covers the self-contained Databricks Apps experience. For the separately hosted
API-backed (Live) dashboard see [deployment.md](deployment.md).

## Why the dashboard showed "Governance API unavailable"

`app.yaml` pointed `SENTINELX_API_URL` at a placeholder host
(`https://your-private-governance-api.example.com`). A Databricks App runs only the Streamlit process;
it does not host the FastAPI backend or its SQLite store. Every dashboard call therefore failed, and
each failed call raised its own error banner.

Fixes:

- The dashboard has an explicit mode. `DEMO_MODE=true` (default) serves a built-in synthetic dataset and
  needs no backend. Nothing is hidden: the sidebar shows the mode, backend and AWS state.
- `api()` no longer renders a banner per call. Connectivity failures are logged
  (`sentinelx.dashboard`), probed with a 2-second cached health check, and shown once in Live Mode with a
  specific cause (placeholder URL, missing reader key, or unreachable host).
- `app.yaml` no longer ships the placeholder URL or an unresolved `valueFrom` secret resource.

## Modes

| Variables | Result |
| --- | --- |
| unset, or `DEMO_MODE=true` `LIVE_MODE=false` | Demo Mode: synthetic data, simulated approvals and execution, no cloud writes |
| `LIVE_MODE=true` or `DEMO_MODE=false` | Live Mode: dashboard reads the authenticated governance API |
| both `true` | Conflict; the dashboard falls back to Demo Mode and says so |

Demo Mode never imports provider clients for writes. The only optional cloud calls are the read-only AWS
connection check (`sts:GetCallerIdentity`, `secretsmanager:ListSecrets` with `MaxResults=1`), the optional
Model Serving intent classification, and the opt-in SentinelPilot AWS agent described below.

## Synthetic dataset

`backend/demo/seed.py` is the single source: 10 service principals, 8 service principal secrets, 8 PATs,
5 application credentials, 10 AWS secret records, 20 findings (`SX-1001`..`SX-1020`), 10 remediation actions
(`ACT-2001`..`ACT-2010`) and 5 audit records. Dates are day offsets from "today", so "expires in 5 days"
stays true. All identities, ARNs (account `111122223333`) and names are fictional; no secret values exist.

Findings store only an asset, a rule code and a severity. Owner, expiry, rotation date, evidence, text and
statuses are joined from the inventory, and `DemoWorkspace.integrity_issues()` (tested) proves every rule
still holds. Governance score = mean per-asset score (100 minus 45/30/15/5 per open
critical/high/medium/low finding). Compliance = assets with no open finding. Simulated completions update
in-memory inventory so every page, chart and Copilot answer stays consistent.

Scenarios: SP secret expiring in 5 days (SX-1004), expired SP secret (SX-1001), PAT lifetime above policy
(SX-1005, SX-1011), orphaned SP (SX-1003), credential without owner (SX-1007), AWS secret near rotation
(SX-1014), Databricks/AWS mismatch (SX-1006), missing rotation evidence (SX-1012, SX-1013), critical
credential without owner (SX-1002) and a compliant credential (SPC-004).

## SentinelX AI Copilot

Demo Mode uses `backend/demo/copilot.py`, a deterministic engine that classifies the question and
computes the answer from the dataset (counts, filters, ranking). It keeps conversation context in the
Streamlit session (the last finding) for follow-ups such as "Who owns it?". Answers cite finding IDs with
buttons that open the finding, remediation steps or approval screen. Imperative requests ("rotate...",
"approve...") and requests for secret values are refused; the engine has no mutation methods.

If `SENTINELX_MODEL_SERVING_ENDPOINT` is set, `ModelServingIntentProvider` may classify questions the
keyword router cannot. It receives only the question text and may return only an allowlisted intent name;
answers are still computed from data. It never generates facts or calls remediation. The same provider is
used by the API Copilot in Live Mode.

## Remediation and Action Center

Routing is session-state based (`ac_screen`, `ac_finding`), passed by button callbacks: list, finding
detail, evidence, remediation steps, approval/execution and audit history. Ask AI opens the Copilot with
the finding as context. Demo workflow: request approval, approve (separate simulated actor), confirm, then
execute. Every step is audited in memory and remains simulated. Before execution the approval screen shows
**SIMULATED REMEDIATION — NO CLOUD CHANGES PERFORMED**; after a completed execution it shows a green
**DEMO MODE** success card (**REMEDIATION COMPLETED SUCCESSFULLY**) whose indicators come from
`DemoWorkspace.execution_result`, i.e. the recorded action and audit trail. No cloud changes are made and
the live-success message is never shown.
Use "Reset demo data" on Audit & Governance to restore the seed state.

Live Mode keeps the existing controls: explicit live mode, owner-attested binding, preflight/dry run,
separate approver API, 24-hour approval expiry, inventory fingerprint, replay and idempotency protection,
version-based rollback, post-execution verification and a hash-chained audit. The LLM has no path to
those APIs.

## AWS Secrets Manager connection page

Set these non-secret App environment values (never access keys):

| Variable | Purpose |
| --- | --- |
| `SENTINELX_AWS_ACCOUNT_ID`, `SENTINELX_AWS_REGION` | Expected account and region |
| `SENTINELX_AWS_ROLE_ARN` (`SENTINELX_AWS_EXTERNAL_ID` optional) | IAM Role / STS AssumeRole using the runtime's federated identity |
| `SENTINELX_AWS_AUTH_METHOD=identity_center`, `SENTINELX_AWS_SSO_START_URL`, `SENTINELX_AWS_SSO_REGION`, `SENTINELX_AWS_SSO_ROLE_NAME` | IAM Identity Center device-authorization sign-in |

Status shows **Connected** only after the identity's account matches and `ListSecrets` succeeds.
Otherwise the page shows "AWS connection is not configured..." or the AWS error code. Test Connection never
fabricates success. Temporary Identity Center credentials live only in server session memory and are cleared
by Disconnect. Use the discovery policy in `deployment/iam-discovery.json`; remediation roles remain separate.

## SentinelPilot AWS agent (real Secrets Manager rotation, opt-in)

After you press **Approve (simulated)** or **Execute Remediation (simulated)** in the Action Center, a SentinelPilot dialog
pops up. It restates that nothing in the cloud changed, names the AWS secret the finding maps to, offers **Open AWS Console**
(opens a new tab; browsers do not allow a page to open tabs by itself, so it is a button) and **Continue with SentinelPilot**,
which jumps to the agent with `Fix <finding>` already asked. The console link defaults to
`https://signin.aws.amazon.com/signup?request_type=register`; set `SENTINELX_AWS_CONSOLE_URL` to your account's sign-in
or Secrets Manager console URL to land somewhere more useful.

On **SentinelX AI Copilot**, switch to **SentinelPilot (AWS agent)**. It is a chat agent whose only actions are
validated backend tools (`backend/agent/remediation_agent.py`, `backend/services/aws_remediation.py`):

1. Ask in plain language, e.g. `Is AWS configured?`, `List my AWS secrets`, `Rotate sentinelx/prod/app/key`, `Fix SX-1019`.
   If AWS is not configured the agent answers **"AWS is not configured"** and makes no AWS call.
2. For a rotation the agent reads secret metadata and proposes a plan: native `RotateSecret` when the secret has
   rotation enabled, otherwise a newly generated random value written with `PutSecretValue`. Nothing changes yet.
3. A human ticks the confirmation and presses **Approve and execute**. The agent cannot approve (chat requests to
   approve are refused). The backend then re-validates the approval, allowed prefix, AWS account and that the secret
   is unchanged since planning, executes exactly that plan, and verifies the version stages (no values are read).
4. Results are reported as verified, not-yet-confirmed or failed. Generated-value rotations can be rolled back to
   `AWSPREVIOUS`. Every step is written to the agent audit log without secret material.

Execution is off by default. To enable it set (non-secret) App variables:

| Variable | Purpose |
| --- | --- |
| `SENTINELX_AWS_EXECUTION_ENABLED=true` | Allow approved plans to execute |
| `SENTINELX_AWS_ALLOWED_SECRET_PREFIXES=sentinelx/` | Comma-separated name prefixes the agent may change (required) |
| `SENTINELX_AWS_REMEDIATION_ROLE_ARN` | Separate write role assumed only for approved execution (IAM Role method) |

The remediation role needs `secretsmanager:DescribeSecret`, `RotateSecret`, `PutSecretValue`,
`UpdateSecretVersionStage` on the allowed secrets (plus KMS use of their key). Generated-value rotation replaces the
whole secret value, so use it for test or simple secrets; structured credentials should use native rotation.
Scope: the agent now works across AWS Secrets Manager **and Databricks** (see below). The dataset and Action Center
workflow remain simulated. Plans live in the session; the audit trail is session-only unless the Delta table is configured.

### Databricks credential sync (cross-platform rotation)

Declare which Databricks credentials mirror which AWS secrets in `SENTINELX_SYNC_BINDINGS` (JSON list; the agent can
only touch declared bindings). When a plan targets a bound AWS secret, it becomes a **cross-platform sync**: create the
new Databricks credential, stage it in AWS (pending), validate it, write the Databricks secret scope key, promote the AWS
version, then verify. Failures stop before promotion and offer **Roll back**, which restores the previous credential on
both platforms and revokes the unused new one.

```json
[{"name": "etl-oauth", "kind": "service_principal_secret", "aws_secret": "sentinelx/prod/etl/oauth",
  "scope": "etl", "key": "client_secret", "service_principal_id": "<id>", "client_id": "<application id>",
  "scopes": ["all-apis"], "lifetime_days": 90, "rollback_contract_verified_by_owner": true},
 {"name": "ci-pat", "kind": "pat", "aws_secret": "sentinelx/dev/ci/pat", "scope": "ci", "key": "token",
  "application_id": "<service principal application id>", "lifetime_days": 30, "rollback_contract_verified_by_owner": true}]
```

- `service_principal_secret`: AWS payload must be JSON `{client_id, client_secret, secret_id}`; needs `DATABRICKS_HOST`,
  `SENTINELX_DATABRICKS_ACCOUNT_ID` and an App identity allowed to manage that service principal's secrets (account level).
- `pat`: creates an on-behalf-of token for the service principal (App identity must be a workspace admin); the AWS payload
  is the token string. The previous PAT is not revoked automatically and stays valid until it expires.
- The owner attestation `rollback_contract_verified_by_owner` is mandatory: AWS's current version is the rollback source.
- The App identity also needs `WRITE`/`MANAGE` on the Databricks secret scope used by each binding.

### Language model (optional)

Set `SENTINELX_MODEL_SERVING_ENDPOINT` to let a Databricks Model Serving chat endpoint (1) map free-form requests to an
allowlisted tool (`aws_status`, `list_secrets`, `plan_rotation`, `explain_finding`, `ask_governance`, `help`) and (2) add a
short "Pilot's note" to plans and results. The model only sees your message and non-sensitive facts. It cannot approve,
execute or call arbitrary tools, its notes are discarded if they look like credentials or claim success that the backend
did not verify, and without the endpoint the agent uses deterministic routing.

### Persistent audit trail (Delta)

Set `SENTINELX_AUDIT_TABLE=<catalog>.<schema>.<table>` and `SENTINELX_SQL_WAREHOUSE_ID`. The table is created on first
write (`event_id, at, session_id, actor, event, target, detail`). Approval and execution start are **fail-closed**: if the
durable log cannot be written, the agent refuses to approve or change anything. Grant the App identity only `SELECT` and
`INSERT` on the table (no UPDATE/DELETE) and use Delta history for tamper evidence. The page can load recent persisted events.

## Deploy to Databricks Apps

1. In the workspace, create or open the `sentinelx` App and point it at this `sentinelx` directory
   (Git folder or `databricks apps deploy sentinelx --source-code-path /Workspace/Users/<you>/databricks-project/sentinelx`).
2. Keep the provided `app.yaml` (`DEMO_MODE=true`). No App resources or secrets are required for Demo Mode.
3. Deploy and open the App URL. Expected: no API error banner; sidebar shows
   "Demo Mode — Synthetic Data", Backend "Not configured", AWS "Not Connected".
4. Optional: add the AWS variables above and the App's runtime identity to enable a real connection test.
5. Live Mode: host the FastAPI service separately, then set `DEMO_MODE=false`, `LIVE_MODE=true`,
   `SENTINELX_API_URL` and `SENTINELX_READER_KEY` (App secret resource). Keep the App reader-only.

Check App logs for `sentinelx.dashboard` warnings if a configured backend is unreachable.

## Verification status

| Area | Verified by |
| --- | --- |
| Dataset volume, referential integrity, rules, metrics | `tests/test_demo_workflow.py` |
| Demo workflow, simulation labels, audit, reset | `tests/test_demo_workflow.py`, `tests/test_demo_dashboard.py` |
| Copilot answers, follow-ups, refusals, model-serving allowlist | `tests/test_demo_workflow.py` |
| All nine pages, navigation, AWS page, single live banner | `tests/test_demo_dashboard.py` |
| AWS connection logic (botocore Stubber) | `tests/test_aws_connection.py` |
| SentinelPilot agent: not-configured, plan/approve/execute/verify, rollback, guardrails (fake Secrets Manager) | `tests/test_aws_agent.py` |
| Databricks sync (SP secret + PAT), rollback, Delta audit (fail-closed), language-model guardrails | `tests/test_databricks_sync.py` |
| Live gating (no executor / disabled execution / unsupported action) | `tests/test_demo_workflow.py`, `tests/test_workflow.py` |

Requires your accounts (not testable here): the Databricks Apps deployment itself, a real AWS role or
Identity Center sign-in, a Model Serving endpoint, and the hosted API for Live Mode.
