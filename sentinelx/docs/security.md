# Security and Recovery

## Enforced MVP Controls

- Metadata-only Asset schema rejects unknown value fields. No credential hashes,
  generated secrets, request bodies, authentication headers, or provider exception
  text are persisted by audit/API handlers.
- All API endpoints, including health and schema, require role keys. Reader cannot
  request actions; operator cannot approve; approver cannot execute. Requester and
  approver must differ. Keys are distinct, minimum 32 characters, constant-time compared.
- Provider config encrypted using Fernet; key external to the encrypted file.
  SDK authentication explicitly OAuth M2M, AWS signed via IAM role/profile.
- Audit mode blocks execution. Execute requests default to dry run. Approval requires
  a reviewed dry run and expires after 24 hours. Metadata changes invalidate requests.
- Atomic queue claims prevent replay and related concurrent execution. Recovery-required
  and provider-failed related actions block new rotations until reconciled.
- SP renewal checkpoints record IDs and phases only. Old SP secrets and AWS versions
  remain available. Rollback is a new independently approved action, not an unguarded button.
- CSV export neutralizes spreadsheet formula prefixes. Invalid requests do not echo
  submitted inputs. Provider SDK debug logging must remain disabled.
- Copilot Q&A uses structured inventory/findings/actions and deterministic response
  templates. It has no provider-write tools, no configured LLM, and does not persist
  chat prompts. References contain finding/report/action identifiers and metadata.

## Recovery Playbook

1. Stop new related rotations and preserve the database/audit files. Failed actions
   include a receipt when provider mutation began. Restart converts `running` to
   `recovery_required`; no automatic retry creates duplicate credentials.
2. Inspect receipt phases: `intent`, `credential_created`, `aws_staged`,
   `databricks_updated`, `promoted`, `validated`. Correlate IDs with CloudTrail and
   Databricks account audit events. Never retrieve/display values for troubleshooting.
3. Verify the old AWS version still exists and no later rotation has superseded
   either the recorded old or new AWSCURRENT. A newer version causes rollback refusal.
4. POST a rollback action with `asset_id`, `action="rollback"`, and `original_id`.
   Run dry-run review, obtain a different actor's approval, then explicitly execute.
   The executor reads old material into memory, restores the bound Databricks key,
   promotes the old AWS version if necessary, removes its unfinished pending stage,
   and verifies AWS staging metadata. Both SP secrets remain valid if unexpired.
5. Run dependent workload checks. Expired/disabled old credentials cannot restore
   authentication even when metadata/state rollback succeeds; perform approved forward
   recovery with the retained new credential. Retire surplus secrets manually later.

A crash after provider mutation but before its checkpoint is not atomically
recoverable across systems. `intent` includes a UUID AWS version token, but Databricks
secret creation has no transaction shared with SQLite. If the process dies between
SP creation and recording its ID, identify that SP secret using account metadata and
audit events before any retry. This is a documented manual reconciliation case.
Do not claim distributed exactly-once execution or automatic recovery for it.

## Boundaries and Production Hardening

Hash chaining detects edits/reordering when verified, but a database writer can
rewrite the whole chain or truncate its tail. It is **not immutable audit storage**;
external digest anchoring/object-lock archival is required for production evidence.
SQLite and reports contain sensitive metadata and require encrypted disk, ACLs,
backups, and retention policy. SQLite itself is not encrypted by this MVP.

Static role keys represent three actors, not per-person SSO identities. Add an
organization identity gateway/JWT actor binding before production remediation.
The demo dashboard deliberately holds all three keys for simulation and is
loopback-only; it is unsuitable for public deployment. The live UI is read-only.
Put deployed dashboards behind Databricks Apps authentication or a trusted SSO proxy;
Streamlit user authentication is not implemented by the standalone demo.
Owner filters do not enforce team membership; team-scoped queries must remain
unavailable until authenticated identities are mapped to approved teams.

The executor and discovery SDK clients have separate Databricks SP credentials,
but live in one API process. AWS profiles can distinguish identities locally;
default IAM role credentials otherwise share that role. Process/worker IAM isolation
is future hardening. API authorization does not itself establish provider least privilege.

Owner/application strings are governed metadata: operators must never put sensitive
material into names or metadata fields. The schema blocks value-shaped fields, not
secret text maliciously disguised as a name. Python cannot guarantee zeroization of
all transient string buffers. No claim of universal secret redaction is made.

Generic secret rotation, PAT deletion, SP deactivation, and privilege changes are
recommendations only where rollback/workload validation is unproven. The MVP does
not call DeleteSecret, revoke PATs, or delete existing/new OAuth secrets automatically.