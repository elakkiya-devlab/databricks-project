# Service Principal Integration

Workspace SCIM and account SP/OAuth-secret collectors are owned by
`backend/services/providers.py::LiveCollector`. Creation/expiry come from account
secret metadata. Safe renewal and retained-credential rollback live in
`backend/remediation/live.py`. See `docs/onboarding.md` for distinct numeric/client IDs.