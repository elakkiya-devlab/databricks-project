# SentinelX API

The FastAPI service is the source of truth for inventory, findings, reports, and
remediation actions. All routes, including health and OpenAPI, require an
`X-API-Key`. Configure separate reader, operator, and approver keys. The live
dashboard receives only a reader key; API clients perform live approval and
execution. Serve the API behind TLS and restrict network access.

The OpenAPI schema is available at `/openapi.json` to an authenticated reader.
Interactive Swagger/ReDoc routes are disabled.

## Compliance and reports

| Method and route | Access | Purpose |
|---|---|---|
| `GET /compliance/summary` | reader | Current governance summary, finding counts and latest report |
| `GET /compliance/findings` | reader | Filtered, paginated current findings |
| `GET /compliance/findings/{finding_id}` | reader | Current finding details and evidence |
| `GET /assets` | reader | Current assessed inventory |
| `GET /history` | reader | Report history |
| `GET /report?format=json\|csv` | reader | Download current report |
| `POST /discover` | operator | Trigger a discovery scan |
| `GET /audit` | reader | Hash-chain status and recent audit events |

`GET /compliance/findings` supports `risk`, `kind`, `expired`, `expiring`,
`unassigned`, `owner`, `pending_approval`, `remediation_status`, and text `query`
filters. Comma-separated risk, kind, and status values are accepted. Pagination
uses `page` (1-based) and `page_size` (1-200; default 50). Finding IDs are stable
hashes of the asset ID and finding code. The current inventory does not include a
workspace name or user/team membership, so `workspace` is reported as unavailable
and team-scoped authorization is not implemented.

Finding responses include risk, recommendation, current evidence, report
timestamp, applicable policy, supported action types, and related action status.
Credential values are never included. Inventory identifiers may contain provider
object IDs, as they do in the existing `/assets` response; they are not credential
values.

## Copilot

| Method and route | Access | Purpose |
|---|---|---|
| `GET /copilot/suggestions` | reader | Suggested questions |
| `POST /copilot/chat` | reader | Grounded answer against current report data |

Example request:

```json
{
  "question": "Which service-principal secrets are expired?",
  "context_finding_id": null
}
```

The response contains a concise answer, `answer_source`, support status, report
timestamp, and references to finding IDs or action IDs. Unsupported or team-scoped
questions receive an explicit limitation response. The default Copilot uses
deterministic structured queries; it does not call an LLM or execute actions.
`backend.copilot.service.IntentProvider` is an optional dependency-injection seam
for an approved future classifier. It can select only an allowlisted intent;
all facts and answer text remain generated from SentinelX data.

## Remediation

| Method and route | Access | Purpose |
|---|---|---|
| `GET /remediation/actions` | reader | Filtered, paginated action list |
| `GET /remediation/actions/{action_id}` | reader | Action details |
| `GET /remediation/actions/{action_id}/history` | reader | Related audit events |
| `POST /remediation/actions` | operator | Request an action |
| `POST /remediation/actions/{action_id}/dry-run` | operator | Validate the plan without provider writes |
| `POST /remediation/actions/{action_id}/approval` | approver | Approve or reject a reviewed request |
| `POST /remediation/actions/{action_id}/execute` | operator | Execute only after independent approval |

Example request:

```json
{
  "asset_id": "db:sp-secret:example",
  "action": "renew_sp",
  "finding_id": "finding-<stable-id>",
  "idempotency_key": "<unique-random-request-key>"
}
```

`owner` is required for `assign_owner`; `original_id` is required for `rollback`.
When a finding ID is supplied, the API verifies it still matches the current
inventory and that the requested action is supported for that finding and mode.
Repeating an identical request with the same idempotency key returns its original
action; reusing the key for a different request returns `409`.

The established `/actions` routes remain available for compatibility. Live
execution still requires explicit remediation enablement, a dry run, a separate
approver, an unexpired approval, an unchanged inventory fingerprint, and the
existing live executor preflight. Demo writes are simulated; no endpoint lets the
Copilot perform or approve an action.

Invalid input returns `422`; insufficient role returns `403`; missing records
return `404`; workflow conflicts return `409`. API audit records include route,
actor role, target, and outcome, not request bodies, chat prompts, or credential
values.
