# API Capabilities, Assumptions, and Workarounds

| Feature | MVP support | Evidence or limitation |
|---|---|---|
| Workspace service principals | Live SDK SCIM list | Visible/assigned identities only; workspace admin generally needed for exhaustive inventory |
| Account service principals | Live SDK list for SP secrets | Account access is separate from workspace administration |
| SP OAuth secret list/create | Live account `service_principal_secrets.list/create` | List returns metadata; create returns one-time secret in executor memory |
| SP secret expiry | Live `create_time` and `expire_time` | 7/15/30-day buckets and expired detection; scopes/lifetime availability depend on SDK/API |
| SP renewal | Live staged create-and-cutover | Does not extend an existing secret; old credential remains active |
| SP rotation history | Registry plus audit checkpoints | Secret `update_time` is not automatically treated as rotation evidence |
| PAT inventory | Live `workspace.token_management.list` | Admin token-management access; list returns metadata, not token values |
| PAT expiry | API `expiry_time` | Zero/-1 or missing maps to unknown; non-expiring tokens remain attention findings |
| PAT usage/owner | Registry workaround | Creator is not automatically the accountable owner; `last_used_day` is not parsed without an established version-specific contract |
| PAT renewal/revocation | Recommendations only | New PATs cannot update unknown consumers; revocation is irreversible |
| OAuth/application/API/integration credentials | Metadata registry | No universal Databricks API enumerates arbitrary external application credentials; registry assets represent OAuth/application types |
| Databricks secret inventory | Live list scopes and list keys | READ access to scope required; only key/update metadata visible |
| Databricks secret age/rotation | Owner registry workaround | Last update is not creation time or proof of rotation; values are never read by discovery |
| AWS inventory | Live paginated list and describe | IAM/region visibility; single configured region per instance; tags provide owner/application |
| AWS rotation evidence | `LastRotatedDate`, `RotationEnabled` | Manual version writes may not advance `LastRotatedDate`; audit remains evidence of MVP renewal |
| Synchronization | Explicit bindings, metadata comparison | Compares normalized rotation dates and known rotation modes; no value equality assertion |
| Failed synchronization | Failed/recovery actions and audit | Not an external-provider log aggregator |
| Cross-provider synchronization | Inside approved SP renewal | Standalone live sync disabled without a verified rollback and workload contract |
| Standalone AWS rotation | Demo only; recommendations live | Arbitrary Lambda rotation can mutate external databases; version rollback alone is insufficient |
| Orphan identities | Candidate detection from missing owner | Confirm through owner/HR registry and workload audit; no automatic claim of proven orphanhood |
| Inactive/unused credentials | API active flag plus registry usage | Unknown activity receives an attention finding, not an inferred inactive status |
| Excessive privileges | Account-admin role and registry evidence | Not a comprehensive Unity Catalog/IAM grant graph; unknown privilege penalized |
| Approval and dry run | Functional API state machine | Three API roles; demo simulates actors; live approvals use separate clients |
| Rollback | Local metadata or prior AWS/DB secret material | New/old SP secrets retained; no delete/revoke actions implemented |
| Compliance Copilot | Grounded structured Q&A | Deterministic queries over current report/findings/actions; no Model Serving endpoint configured; no provider values or prompt persistence |
| Copilot model integration | Intent-provider protocol | Optional injected classifier is allowlisted; no LLM facts or remediation tools |
| Remediation Action Center | Filterable finding queue and evidence details | Stable finding IDs; API pagination/filters; UI filters, approval status, action history, and supported-action validation |
| Per-user/team findings | Not implemented | API keys identify roles, not people; owner filtering is available but does not establish team membership |
| Databricks App | Optional Streamlit deployment | Root `app.yaml` starts the dashboard only; FastAPI and persistent SQLite must be hosted separately |
| Continuous monitoring | API lifespan scheduler | Defaults to 300 seconds; one worker/replica; batch entrypoint for cloud schedulers |
| Historical reporting | SQLite snapshots plus CSV/JSON | Single-instance MVP; no cross-workspace fleet aggregation |

## Score Definition

Start at 100, subtract findings, clamp at zero. Penalties: missing owner 20;
inactive 15; unknown activity 5; known excessive privilege 20; unknown privilege 5;
unused beyond activity policy 15; stale age 15; unknown age 5; expired 65;
expiry within 7/15/30 days 25/15/10; unknown expiry 5; unknown rotation 10;
overdue rotation 20; disabled secret rotation 10; mapped sync uncertainty/drift 15.
Identity age itself is not treated as a stale credential.

Risk: critical/red below 40; high/orange below 70; attention/yellow for any remaining
finding; compliant/green only with no findings. Compliance means no findings,
including evidence gaps. Overall score is the arithmetic mean of discovered assets,
not a proof of whole-account compliance. High-risk count is an asset count, while
finding count counts individual violations. Empty inventory scores are null.

Default age, rotation, and inactivity thresholds are 30 days and configurable via
environment. Expiry uses exact remaining seconds, including boundary tests.
Static example registry timestamps are placeholders, not live telemetry.