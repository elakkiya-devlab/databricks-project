# Databricks Workspace and AWS Onboarding

## 1. Platform Handoff

Ask the platform team for workspace HTTPS URL, cloud/region, numeric workspace ID,
Databricks account ID/host, identity-federation status, assigned SPs, secret scope
names/backend types, networking restrictions, and AWS account/region. Do not ask
for users' PAT values. Obtain an approved inventory scope and identify data owners.
Workspace admin and account admin are distinct roles. Workspace access alone
does not unlock account-level OAuth-secret administration.

## 2. Separate Service Principals

Create `sentinelx-discovery` and `sentinelx-executor` in the account console.
Record each SCIM numeric ID and application/client UUID; these are not interchangeable.
Assign the discovery SP to the shared workspace. Mint OAuth M2M client secrets
through the account console/admin workflow and distribute through an approved secret
store, not chat, tickets, repository, or terminal output. Prefer OAuth/federation
over user PATs. Keep the executor secret out of the dashboard.

| Operation | Required Databricks access |
|---|---|
| Workspace SCIM enumeration | Workspace admin or API-supported read privileges for complete listing |
| Account SP and secret metadata | Account-level SP visibility and permission to manage/view target SPs; verify current account API policy |
| PAT admin metadata | Workspace admin token-management permissions; token configuration must permit the endpoint |
| Secret key inventory | READ on every in-scope Databricks secret scope |
| OAuth secret creation | Account-admin/SP-manager permissions accepted by account SP-secret API |
| Scope key update/rollback | WRITE or MANAGE on the explicitly bound Databricks-backed scope |
| New workload credential OAuth validation | Workload SP assigned to the workspace and allowed OAuth scope |

An initial sandbox admin role may be necessary to establish exhaustive visibility.
Do not call that least privilege: document the API requirement, then reduce to
supported target-SP management/read permissions where available. If the platform
cannot delegate secret creation without account admin, leave remediation disabled.
Azure Key Vault-backed scopes are not eligible for this AWS/Databricks write flow.

## 3. SDK Configuration

Use `configs/provider.example.json` as a schema reference, not as a credentials file.
Fill discovery/executor OAuth client IDs/secrets, workspace host, account ID and AWS
region in an encrypted configuration. The implementation forces `auth_type="oauth-m2m"`
and does not fall back to PAT-based SDK configuration. Use standard AWS IAM role
credentials or explicit separately authorized AWS profiles, never hard-code AWS keys.

Set a Fernet key using your approved secret manager and inject it as
`SENTINELX_CONFIG_KEY`. Run `python -m scripts.seal_config` locally and type the
JSON and key into its hidden prompts. Neither is echoed. The output is encrypted
`configs/provider.enc`; restrict its filesystem ACL and keep the key elsewhere.
Set `SENTINELX_CONFIG_FILE` to that file. The app fails closed on decryption failure.
Templates contain placeholders only. No `.env` loader is implicit in Python;
set process environment explicitly or use your deployment secret injection.

## 4. Establish Metadata Evidence

List all scope keys with READ grants. Do not use `get_secret`, `dbutils.secrets.get`,
or `GetSecretValue` for inventory. Supply accountable owner, application, original
creation/expiry, confirmed last rotation, activity, and privilege review through
`metadata_overrides`. Never infer rotation from a key update timestamp.

Register external OAuth/application credentials using `registry_assets`, with unique
IDs and timezone-qualified ISO timestamps. Do not put values, hashes of values,
comments containing secrets, or connection strings in the registry.
Registry evidence requires owner validation; it is not auto-discovered API truth.
The sample ownership labels do not represent a real organization.

## 5. AWS Integration

Provision a discovery IAM role using `deployment/iam-discovery.json`, substituting
region/account/resource prefix. ListSecrets requires `Resource: "*"`; DescribeSecret
is restricted to approved secret ARNs. The collector lists all visible secrets,
so denied descriptions make coverage partial instead of silently hiding them.
Use a dedicated AWS account/prefix/visibility boundary or authorize DescribeSecret
for the entire inventory scope. The MVP covers one AWS region per instance.

Tag secrets `Owner` and `Application`. Prepare a separate executor IAM role/profile
using `deployment/iam-remediation.json`; narrow to exact bound ARNs and KMS key.
For customer-managed KMS keys, grant key-policy and IAM access plus Secrets Manager
ViaService restrictions. CloudTrail should record provider writes independently.
With EC2/ECS IAM credentials, both boto3 clients use the attached role unless separate
profiles are configured: true role isolation requires separate credentials/processes.

## 6. Prepare the Mandatory Renewal Contract

Choose a sandbox workload SP. Its **numeric ID** is the `bindings` map key. Set
`client_id` to the workload application UUID, AWS secret ARN, existing Databricks
scope/key, lifetime days (1-730), and owner-approved OAuth scopes. The example
`all-apis` scope is broad; review whether the target APIs support narrower scopes.

The current AWS SecretString must be provider-side JSON of this shape:

```json
{"client_id":"workload-application-uuid","client_secret":"PROVIDER_VALUE_ONLY","secret_id":"existing-databricks-oauth-secret-id"}
```

Do not put actual JSON material in logs or this repository. The bound Databricks
key must currently contain that same client secret, not the JSON document.
An owner must validate this mapping out of band and set
`rollback_contract_verified_by_owner=true`. Workspace metadata cannot prove value
equality, so this attestation is an explicit prerequisite, not API-verified truth.
Ensure exactly one AWS AWSCURRENT and no unfinished AWSPENDING version.
Reserve SP-secret quota for the newly created credential; old secrets are retained.

## 7. Audit-Only Acceptance

Set three distinct random API keys (at least 32 characters), `SENTINELX_MODE=live`,
and leave `SENTINELX_REMEDIATION_ENABLED=false`. Run `python -m scripts.dev --live`.
Confirm inventory counts against the Databricks/account consoles and AWS list.
Check `/summary` coverage: failed modules contain only error-class names, not
sensitive provider exception text. Missing access is not treated as empty inventory.
If a later scan is partial/failed, the existing snapshot is retained and becomes
visibly stale. Inspect audit history and repair permissions before execution.

Validate PAT creation/expiry fields using an admin-approved sandbox token. Verify
that expired and ownerless findings exist. Confirm no value fields in `/assets`,
`/report`, SQLite rows, or audits. Compare missing activity/rotation evidence to the
owner registry. Run an approved dry run and check CloudTrail for **zero writes**.

## 8. Approved Live Renewal Acceptance

Only after contract validation, launch `python -m scripts.dev --live --execute`.
Use an operator API client to POST `/actions`, then `/actions/{id}/dry-run`.
A separate approver client POSTs `/actions/{id}/decision` with `{"approve":true}`.
The operator executes with explicit `{"dry_run":false}`. Use `X-API-Key` from each
actor's approved secret store, never paste it in chat or command history.

Check OAuth issuance, AWS staging, Databricks key-update acknowledgement, checkpoint
receipts, audit chain, and new inventory. Run actual dependent workload smoke tests
with the platform team. OAuth issuance alone does not prove workload health.
Request rollback as a new action with the original action ID, repeat dry run and
independent approval, execute, and verify prior AWS stage plus workload recovery.
If the prior credential was expired, rollback restores state but cannot restore
valid authentication; use forward recovery and the retained new credential.

Retire old credentials only through a separately approved manual process after a
grace period. The MVP deliberately does not implement irreversible deletion.