"""Synthetic SentinelX dataset. All identities, ARNs, and dates are fictional; no secret values exist here.

Dates are stored as day offsets from "today" so scenarios such as "expires in 5 days" stay true.
"""

AWS_ACCOUNT_ID = "111122223333"
AWS_REGION = "us-east-1"

# Policy thresholds used by the demo rules and shown in finding evidence.
POLICY = {
    "pat_max_lifetime_days": 90,
    "sp_secret_max_age_days": 90,
    "expiry_warning_days": 30,
    "aws_rotation_warning_days": 7,
    "inactivity_days": 45,
}

SERVICE_PRINCIPALS = [
    dict(id="SP-001", name="sp-etl-sales-prod", owner="Priya Nair", team="Data Platform", environment="Production",
         active=True, privileged=False, last_used=-1, created=-410),
    dict(id="SP-002", name="sp-ml-feature-store", owner="Marcus Chen", team="ML Engineering", environment="Production",
         active=True, privileged=False, last_used=-2, created=-380),
    dict(id="SP-003", name="sp-finance-reporting", owner="Aisha Rahman", team="Finance Operations",
         environment="Production", active=True, privileged=False, last_used=-1, created=-300),
    dict(id="SP-004", name="sp-legacy-migration", owner=None, team=None, environment="Development",
         active=False, privileged=False, last_used=-140, created=-720),
    dict(id="SP-005", name="sp-bi-dashboard-refresh", owner="Daniel Okafor", team="Business Intelligence",
         environment="Production", active=True, privileged=False, last_used=0, created=-200),
    dict(id="SP-006", name="sp-data-quality-monitor", owner="Priya Nair", team="Data Platform", environment="Staging",
         active=True, privileged=False, last_used=-52, created=-250),
    dict(id="SP-007", name="sp-platform-admin-automation", owner=None, team=None, environment="Production",
         active=True, privileged=True, last_used=-1, created=-540),
    dict(id="SP-008", name="sp-customer-360-pipeline", owner="Elena Petrova", team="Customer Analytics",
         environment="Production", active=True, privileged=False, last_used=0, created=-330),
    dict(id="SP-009", name="sp-ci-deployment", owner="Marcus Chen", team="ML Engineering", environment="Development",
         active=True, privileged=False, last_used=-3, created=-150),
    dict(id="SP-010", name="sp-audit-export", owner="Aisha Rahman", team="Finance Operations",
         environment="Production", active=True, privileged=False, last_used=-1, created=-260),
]

# Service principal OAuth secrets (credential_type "sp_secret").
SP_CREDENTIALS = [
    dict(id="SPC-001", name="sp-etl-sales-prod / oauth-secret", sp_id="SP-001", expires=5, last_rotation=-85, created=-85),
    dict(id="SPC-002", name="sp-ml-feature-store / oauth-secret", sp_id="SP-002", expires=-9, last_rotation=-190, created=-190),
    dict(id="SPC-003", name="sp-finance-reporting / oauth-secret", sp_id="SP-003", expires=60, last_rotation=-6, created=-6),
    dict(id="SPC-004", name="sp-bi-dashboard-refresh / oauth-secret", sp_id="SP-005", expires=75, last_rotation=-15, created=-15),
    dict(id="SPC-005", name="sp-platform-admin-automation / oauth-secret", sp_id="SP-007", expires=20, last_rotation=-70, created=-70),
    dict(id="SPC-006", name="sp-customer-360-pipeline / oauth-secret", sp_id="SP-008", expires=40, last_rotation=None, created=-50),
    dict(id="SPC-007", name="sp-ci-deployment / oauth-secret", sp_id="SP-009", expires=12, last_rotation=-78, created=-78),
    dict(id="SPC-008", name="sp-audit-export / oauth-secret", sp_id="SP-010", expires=88, last_rotation=-2, created=-2),
]

# expires=None means the token never expires.
PATS = [
    dict(id="PAT-001", name="pat-priya-notebook-dev", owner="Priya Nair", environment="Development", created=-30, expires=60, last_used=-1),
    dict(id="PAT-002", name="pat-marcus-model-registry", owner="Marcus Chen", environment="Production", created=-120, expires=245, last_used=-2),
    dict(id="PAT-003", name="pat-daniel-bi-gateway", owner="Daniel Okafor", environment="Production", created=-10, expires=80, last_used=0),
    dict(id="PAT-004", name="pat-elena-segmentation-job", owner="Elena Petrova", environment="Production", created=-85, expires=3, last_used=-1),
    dict(id="PAT-005", name="pat-aisha-finance-export", owner="Aisha Rahman", environment="Production", created=-400, expires=None, last_used=-6),
    dict(id="PAT-006", name="pat-priya-sandbox", owner="Priya Nair", environment="Development", created=-60, expires=30, last_used=-75),
    dict(id="PAT-007", name="pat-marcus-ci-readonly", owner="Marcus Chen", environment="Development", created=-45, expires=45, last_used=-1),
    dict(id="PAT-008", name="pat-daniel-reporting-legacy", owner="Daniel Okafor", environment="Production", created=-95, expires=-5, last_used=-6),
]

APP_CREDENTIALS = [
    dict(id="APP-001", name="tableau-connector-secret", owner="Daniel Okafor", environment="Production", expires=120, last_rotation=-30),
    dict(id="APP-002", name="airflow-orchestrator-token", owner="Priya Nair", environment="Production", expires=18, last_rotation=-72),
    dict(id="APP-003", name="partner-sftp-integration-key", owner=None, environment="Production", expires=95, last_rotation=-40),
    dict(id="APP-004", name="fivetran-ingest-credential", owner="Elena Petrova", environment="Production", expires=200, last_rotation=-20),
    dict(id="APP-005", name="legacy-reporting-api-key", owner="Aisha Rahman", environment="Production", expires=-30, last_rotation=-400),
]

# sync: in_sync | mismatch | unverified. bound_to links an AWS secret to the Databricks credential it mirrors.
AWS_SECRETS = [
    dict(id="AWS-001", name="sentinelx/prod/etl-sales/oauth", bound_to="SPC-001", owner="Priya Nair", environment="Production",
         rotation_enabled=True, last_rotation=-85, next_rotation=25, sync="in_sync", kms="alias/sentinelx-prod"),
    dict(id="AWS-002", name="sentinelx/prod/ml-feature-store/oauth", bound_to="SPC-002", owner="Marcus Chen", environment="Production",
         rotation_enabled=False, last_rotation=-190, next_rotation=None, sync="in_sync", kms="alias/sentinelx-prod"),
    dict(id="AWS-003", name="sentinelx/prod/finance-reporting/oauth", bound_to="SPC-003", owner="Aisha Rahman", environment="Production",
         rotation_enabled=True, last_rotation=-62, next_rotation=28, sync="mismatch", kms="alias/sentinelx-prod"),
    dict(id="AWS-004", name="sentinelx/prod/bi-refresh/oauth", bound_to="SPC-004", owner="Daniel Okafor", environment="Production",
         rotation_enabled=True, last_rotation=-15, next_rotation=45, sync="in_sync", kms="alias/sentinelx-prod"),
    dict(id="AWS-005", name="sentinelx/prod/platform-admin/oauth", bound_to="SPC-005", owner="Platform Security", environment="Production",
         rotation_enabled=True, last_rotation=-70, next_rotation=20, sync="in_sync", kms="alias/sentinelx-prod"),
    dict(id="AWS-006", name="sentinelx/prod/customer-360/oauth", bound_to="SPC-006", owner="Elena Petrova", environment="Production",
         rotation_enabled=True, last_rotation=None, next_rotation=30, sync="unverified", kms="alias/sentinelx-prod"),
    dict(id="AWS-007", name="sentinelx/dev/ci-deployment/oauth", bound_to="SPC-007", owner="Marcus Chen", environment="Development",
         rotation_enabled=True, last_rotation=-78, next_rotation=4, sync="in_sync", kms="alias/sentinelx-dev"),
    dict(id="AWS-008", name="sentinelx/prod/audit-export/oauth", bound_to="SPC-008", owner="Aisha Rahman", environment="Production",
         rotation_enabled=True, last_rotation=-2, next_rotation=80, sync="in_sync", kms="alias/sentinelx-prod"),
    dict(id="AWS-009", name="sentinelx/prod/fivetran/credential", bound_to="APP-004", owner="Elena Petrova", environment="Production",
         rotation_enabled=True, last_rotation=-20, next_rotation=70, sync="in_sync", kms="alias/sentinelx-prod"),
    dict(id="AWS-010", name="sentinelx/prod/legacy-reporting/api-key", bound_to="APP-005", owner="Aisha Rahman", environment="Production",
         rotation_enabled=False, last_rotation=-400, next_rotation=None, sync="in_sync", kms="alias/sentinelx-prod"),
]

# Findings reference an asset and a rule code; all other facts are joined from the inventory.
FINDINGS = [
    ("SX-1001", "critical", "sp_secret_expired", "SPC-002"),
    ("SX-1002", "critical", "critical_no_owner", "SPC-005"),
    ("SX-1003", "high", "sp_orphaned", "SP-004"),
    ("SX-1004", "high", "sp_secret_expiring", "SPC-001"),
    ("SX-1005", "high", "pat_lifetime_exceeded", "PAT-002"),
    ("SX-1006", "high", "sync_mismatch", "AWS-003"),
    ("SX-1007", "high", "credential_no_owner", "APP-003"),
    ("SX-1008", "high", "pat_expired", "PAT-008"),
    ("SX-1009", "high", "app_credential_expired", "APP-005"),
    ("SX-1010", "high", "pat_expiring", "PAT-004"),
    ("SX-1011", "high", "pat_lifetime_exceeded", "PAT-005"),
    ("SX-1012", "medium", "rotation_evidence_missing", "SPC-006"),
    ("SX-1013", "medium", "rotation_evidence_missing", "AWS-006"),
    ("SX-1014", "medium", "aws_rotation_due", "AWS-007"),
    ("SX-1015", "medium", "sp_secret_expiring", "SPC-007"),
    ("SX-1016", "medium", "app_credential_expiring", "APP-002"),
    ("SX-1017", "medium", "aws_rotation_disabled", "AWS-002"),
    ("SX-1018", "low", "pat_unused", "PAT-006"),
    ("SX-1019", "medium", "aws_rotation_disabled", "AWS-010"),
    ("SX-1020", "low", "sp_inactive", "SP-006"),
]

# approval: pending | approved | rejected. status: awaiting_approval | ready | completed | rejected.
ACTIONS = [
    dict(id="ACT-2001", finding_id="SX-1001", action_type="renew_sp_secret", approval="pending", status="awaiting_approval",
         requested_by="sec.analyst@sentinelx.example", requested=-2, approver=None, decided=None, executed=None),
    dict(id="ACT-2002", finding_id="SX-1004", action_type="renew_sp_secret", approval="approved", status="ready",
         requested_by="sec.analyst@sentinelx.example", requested=-3, approver="governance.lead@sentinelx.example",
         decided=-1, executed=None),
    dict(id="ACT-2003", finding_id="SX-1006", action_type="sync_secret", approval="pending", status="awaiting_approval",
         requested_by="cloud.engineer@sentinelx.example", requested=-1, approver=None, decided=None, executed=None),
    dict(id="ACT-2004", finding_id="SX-1007", action_type="assign_owner", approval="pending", status="awaiting_approval",
         requested_by="sec.analyst@sentinelx.example", requested=-1, approver=None, decided=None, executed=None,
         proposed_owner="Platform Integrations Team"),
    dict(id="ACT-2005", finding_id="SX-1008", action_type="rotate_pat", approval="approved", status="completed",
         requested_by="sec.analyst@sentinelx.example", requested=-8, approver="governance.lead@sentinelx.example",
         decided=-7, executed=-6),
    dict(id="ACT-2006", finding_id="SX-1009", action_type="rotate_app_credential", approval="rejected", status="rejected",
         requested_by="cloud.engineer@sentinelx.example", requested=-5, approver="governance.lead@sentinelx.example",
         decided=-4, executed=None, note="Legacy reporting API is scheduled for decommission; retire instead of rotating."),
    dict(id="ACT-2007", finding_id="SX-1010", action_type="rotate_pat", approval="approved", status="ready",
         requested_by="sec.analyst@sentinelx.example", requested=-1, approver="governance.lead@sentinelx.example",
         decided=0, executed=None),
    dict(id="ACT-2008", finding_id="SX-1019", action_type="rotate_aws_secret", approval="approved", status="completed",
         requested_by="cloud.engineer@sentinelx.example", requested=-4, approver="governance.lead@sentinelx.example",
         decided=-3, executed=-2),
    dict(id="ACT-2009", finding_id="SX-1012", action_type="record_rotation_evidence", approval="pending",
         status="awaiting_approval", requested_by="sec.analyst@sentinelx.example", requested=0, approver=None,
         decided=None, executed=None),
    dict(id="ACT-2010", finding_id="SX-1003", action_type="disable_orphaned_sp", approval="pending",
         status="awaiting_approval", requested_by="sec.analyst@sentinelx.example", requested=0, approver=None,
         decided=None, executed=None),
]

# (event_id, offset_days, actor, event, target, detail)
AUDIT = [
    ("AUD-3001", -8, "sec.analyst@sentinelx.example", "approval_requested", "ACT-2005", "Requested simulated PAT rotation for SX-1008."),
    ("AUD-3002", -6, "governance.lead@sentinelx.example", "execution_simulated", "ACT-2005", "Simulated PAT rotation; no cloud changes performed."),
    ("AUD-3003", -4, "governance.lead@sentinelx.example", "approval_rejected", "ACT-2006", "Rejected: asset is scheduled for decommission."),
    ("AUD-3004", -2, "governance.lead@sentinelx.example", "execution_simulated", "ACT-2008", "Simulated AWS secret rotation; no cloud changes performed."),
    ("AUD-3005", -1, "sec.analyst@sentinelx.example", "approval_requested", "ACT-2002", "Requested simulated SP secret renewal for SX-1004."),
]
