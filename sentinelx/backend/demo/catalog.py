"""Rule catalog: finding titles, narrative, policy references, and remediation guidance for the demo dataset."""

SEVERITY_DEFINITIONS = {
    "critical": "An active policy violation on a production or privileged asset that can cause an outage or "
                "unaccountable access now. Target: remediate within 24 hours.",
    "high": "A policy violation or imminent expiry that needs action this week. Target: remediate within 7 days.",
    "medium": "An asset approaching a policy limit or lacking required evidence. Target: remediate within 30 days.",
    "low": "A hygiene issue with no near-term operational or security impact. Address in routine review.",
}
SEVERITY_ORDER = ["critical", "high", "medium", "low"]

TYPE_LABELS = {
    "service_principal": "Service Principal",
    "sp_secret": "SP Secret",
    "pat": "PAT Token",
    "application_credential": "Application Credential",
    "aws_secret": "AWS Secret",
}

ACTION_TYPES = {
    "renew_sp_secret": "Renew service principal secret",
    "rotate_pat": "Rotate PAT token",
    "rotate_app_credential": "Rotate application credential",
    "rotate_aws_secret": "Rotate AWS secret",
    "sync_secret": "Synchronize Databricks and AWS secret",
    "assign_owner": "Assign accountable owner",
    "record_rotation_evidence": "Record rotation evidence",
    "disable_orphaned_sp": "Disable orphaned service principal",
}

SP_RENEWAL_STEPS = [
    "Identify the Service Principal.",
    "Confirm the resource owner.",
    "Review dependent workloads.",
    "Validate live-mode eligibility.",
    "Verify Databricks and AWS permissions.",
    "Establish explicit resource binding.",
    "Validate rollback configuration.",
    "Request approval.",
    "Execute the supported renewal through the separate execution API.",
    "Update the applicable AWS secret.",
    "Verify the resulting credential state.",
    "Record the audit event.",
]
SP_PERMISSIONS = [
    "Databricks account: create OAuth secret for the bound service principal",
    "Databricks workspace: write access to the bound secret scope key",
    "AWS Secrets Manager: PutSecretValue and UpdateSecretVersionStage on the bound secret",
    "AWS KMS: kms:GenerateDataKey and kms:Decrypt via Secrets Manager",
]
SP_ROLLBACK = ("Retain the previous OAuth secret until the new one is verified; restore the prior AWS secret version "
               "(AWSPREVIOUS) and Databricks secret value if verification fails.")

PAT_STEPS = [
    "Identify the token owner and the jobs or tools that use the token.",
    "Confirm the owner is still accountable for the token.",
    "Review dependent workloads and external integrations.",
    "Prefer a service principal OAuth credential over a user PAT where possible.",
    "Request approval for the replacement token with a lifetime within policy.",
    "Create the replacement token with an expiry within the policy maximum.",
    "Update consumers to the replacement token.",
    "Revoke the original token after consumers are verified.",
    "Verify the resulting token inventory state.",
    "Record the audit event.",
]
APP_STEPS = [
    "Identify the application and its integration owner.",
    "Review dependent integrations and scheduled jobs.",
    "Request approval for rotation.",
    "Issue the replacement application credential.",
    "Update the application configuration or secret store entry.",
    "Verify the integration authenticates with the replacement credential.",
    "Retire the old credential.",
    "Record the audit event.",
]
AWS_ROTATION_STEPS = [
    "Identify the AWS Secrets Manager secret and its bound Databricks credential.",
    "Confirm the resource owner.",
    "Review consumers of the secret.",
    "Verify AWS and Databricks permissions for the rotation role.",
    "Validate rollback: confirm the AWSPREVIOUS version is retained.",
    "Request approval.",
    "Execute the rotation through the separate execution API.",
    "Verify the new AWSCURRENT version and that consumers authenticate.",
    "Record the audit event.",
]
SYNC_STEPS = [
    "Identify the Databricks credential and the AWS secret bound to it.",
    "Confirm the resource owner and the intended source of truth.",
    "Compare rotation timestamps and secret version stages (metadata only; values are never displayed).",
    "Verify Databricks and AWS permissions.",
    "Validate rollback: confirm the previous AWS version is retained.",
    "Request approval.",
    "Execute the supported synchronization through the separate execution API.",
    "Verify both systems now report the same rotation version.",
    "Record the audit event.",
]
OWNER_STEPS = [
    "Identify the asset and its consumers from workspace usage records.",
    "Ask the platform and security leads to nominate an accountable owner.",
    "Confirm the nominee accepts ownership.",
    "Request approval to record the owner in SentinelX metadata.",
    "Record the owner overlay (metadata only; the provider record is unchanged).",
    "Verify the asset now shows the accountable owner.",
    "Record the audit event.",
]
EVIDENCE_STEPS = [
    "Identify the credential and the system of record for rotation events.",
    "Confirm the resource owner.",
    "Collect rotation evidence (ticket, pipeline run, or provider audit log entry).",
    "Request approval to attach the evidence.",
    "Attach the evidence reference to the credential record.",
    "Re-evaluate the policy status.",
    "Record the audit event.",
]
ORPHAN_STEPS = [
    "Identify the service principal and confirm it is unowned and inactive.",
    "Search for dependent jobs, clusters, and grants.",
    "Notify the platform lead and attempt to locate an owner.",
    "Validate rollback: confirm the principal can be re-activated.",
    "Request approval to disable the principal.",
    "Disable the principal (never delete) through the separate execution API.",
    "Monitor for authentication failures during the observation window.",
    "Record the audit event.",
]
REVIEW_STEPS = [
    "Review the evidence with the resource owner.",
    "Decide whether the asset is still required.",
    "Request approval for the chosen action.",
    "Apply the change through the separate execution API.",
    "Verify the resulting state.",
    "Record the audit event.",
]


def _d(value):
    return "never" if value is None else str(value)


# Each rule: title, severity-neutral narrative, policy, guidance, and a predicate used to keep seed data honest.
RULES = {
    "sp_secret_expired": dict(
        title="Service Principal secret is expired", action_type="renew_sp_secret", steps=SP_RENEWAL_STEPS,
        policy="Service principal OAuth secrets must be renewed before expiry (max age 90 days).",
        summary=lambda a, t: f"The OAuth secret for {a['name']} expired {abs((a['expiry_date'] - t).days)} day(s) ago.",
        why=lambda a, t: "Production workloads authenticating with this secret are failing or about to fail, "
                         "so this is an active outage-class violation.",
        impact="Dependent pipelines and jobs cannot authenticate; downstream reports and models may be stale.",
        permissions=SP_PERMISSIONS, operational="Creates a replacement secret and updates the bound AWS and Databricks "
        "locations; dependent workloads must be validated.", rollback=SP_ROLLBACK,
        predicate=lambda a, t, p: a["expiry_date"] is not None and a["expiry_date"] < t,
    ),
    "sp_secret_expiring": dict(
        title="Service Principal secret expiring soon", action_type="renew_sp_secret", steps=SP_RENEWAL_STEPS,
        policy="Service principal OAuth secrets must be renewed before expiry (max age 90 days).",
        summary=lambda a, t: f"The OAuth secret for {a['name']} expires in {(a['expiry_date'] - t).days} day(s) "
                             f"on {a['expiry_date']}.",
        why=lambda a, t: "Expiry is within the policy warning window; failure to renew will interrupt dependent workloads.",
        impact="If the secret expires, jobs running as this service principal will fail authentication.",
        permissions=SP_PERMISSIONS, operational="Creates a replacement secret and updates the bound AWS and Databricks "
        "locations; dependent workloads must be validated.", rollback=SP_ROLLBACK,
        predicate=lambda a, t, p: a["expiry_date"] is not None and 0 <= (a["expiry_date"] - t).days <= p["expiry_warning_days"],
    ),
    "pat_lifetime_exceeded": dict(
        title="PAT lifetime exceeds policy", action_type="rotate_pat", steps=PAT_STEPS,
        policy="Personal access tokens must not have a lifetime beyond 90 days.",
        summary=lambda a, t: ("This PAT never expires" if a["expiry_date"] is None else
                              f"This PAT was issued with a {(a['expiry_date'] - a['created']).days}-day lifetime")
                             + " while policy allows at most 90 days.",
        why=lambda a, t: "A long-lived personal token is a standing credential that, if leaked, remains usable for months.",
        impact="A leaked or forgotten long-lived token gives prolonged workspace access under the owner's identity.",
        permissions=["Token owner or workspace admin: create and revoke tokens", "Consumers: ability to update token configuration"],
        operational="Consumers using the old token must be updated before it is revoked.",
        rollback="Keep the old token disabled-but-restorable only if your platform supports it; otherwise re-issue a token.",
        predicate=lambda a, t, p: a["expiry_date"] is None or (a["expiry_date"] - a["created"]).days > p["pat_max_lifetime_days"],
    ),
    "pat_expired": dict(
        title="PAT is expired", action_type="rotate_pat", steps=PAT_STEPS,
        policy="Expired tokens must be removed or replaced promptly.",
        summary=lambda a, t: f"{a['name']} expired {abs((a['expiry_date'] - t).days)} day(s) ago but is still in the inventory.",
        why=lambda a, t: "The token is in production use patterns (recently used), so consumers may be failing or using a workaround.",
        impact="Integrations using this token fail; stale tokens clutter the inventory and hide real exposure.",
        permissions=["Token owner or workspace admin: create and revoke tokens"],
        operational="Replacement token must be distributed to consumers.", rollback="Re-issue a replacement token.",
        predicate=lambda a, t, p: a["expiry_date"] is not None and a["expiry_date"] < t,
    ),
    "pat_expiring": dict(
        title="PAT expiring soon", action_type="rotate_pat", steps=PAT_STEPS,
        policy="Tokens must be rotated before expiry.",
        summary=lambda a, t: f"{a['name']} expires in {(a['expiry_date'] - t).days} day(s) on {a['expiry_date']}.",
        why=lambda a, t: "Expiry is imminent (7 days or fewer) on a production credential that is actively used.",
        impact="Scheduled jobs using this token will fail when it expires.",
        permissions=["Token owner or workspace admin: create and revoke tokens"],
        operational="Consumers must switch to the replacement token before expiry.", rollback="Re-issue a replacement token.",
        predicate=lambda a, t, p: a["expiry_date"] is not None and 0 <= (a["expiry_date"] - t).days <= p["expiry_warning_days"],
    ),
    "pat_unused": dict(
        title="PAT unused beyond policy window", action_type="rotate_pat", steps=REVIEW_STEPS,
        policy="Credentials unused for more than 45 days should be reviewed and revoked.",
        summary=lambda a, t: f"{a['name']} was last used {abs((a['last_used'] - t).days)} day(s) ago.",
        why=lambda a, t: "Unused credentials add exposure without business value, but pose no immediate operational risk.",
        impact="Unused tokens enlarge the attack surface.", permissions=["Token owner or workspace admin"],
        operational="Low; no known consumers.", rollback="Re-issue a token if it is later needed.",
        predicate=lambda a, t, p: a["last_used"] is not None and (t - a["last_used"]).days > p["inactivity_days"],
    ),
    "sp_orphaned": dict(
        title="Orphaned Service Principal", action_type="disable_orphaned_sp", steps=ORPHAN_STEPS,
        policy="Every service principal must have an accountable owner and recent activity.",
        summary=lambda a, t: f"{a['name']} has no owner and has been inactive for {abs((a['last_used'] - t).days)} days.",
        why=lambda a, t: "No one is accountable for the identity, and it still holds grants that nobody reviews.",
        impact="An unowned, dormant identity can be abused without detection and blocks ownership reviews.",
        permissions=["Databricks account admin: deactivate service principal"],
        operational="Disabling may break an undocumented dependency; disable (not delete) first.",
        rollback="Re-activate the service principal; its grants are retained while disabled.",
        predicate=lambda a, t, p: not a["owner"] and not a["extra"].get("active", True),
    ),
    "credential_no_owner": dict(
        title="Application credential has no assigned owner", action_type="assign_owner", steps=OWNER_STEPS,
        policy="Every credential must have an accountable owner.",
        summary=lambda a, t: f"{a['name']} has no assigned owner.",
        why=lambda a, t: "A production credential with no owner delays rotation and incident response.",
        impact="Nobody is accountable for rotation, review, or incident response.",
        permissions=["SentinelX operator role to record an owner overlay"],
        operational="Updates SentinelX metadata only; the provider record is unchanged.",
        rollback="Restore the previous owner metadata.",
        predicate=lambda a, t, p: not a["owner"],
    ),
    "critical_no_owner": dict(
        title="Critical credential with no accountable owner", action_type="assign_owner", steps=OWNER_STEPS,
        policy="Privileged credentials must have an accountable owner and rotate within 60 days.",
        summary=lambda a, t: f"{a['name']} belongs to a privileged service principal with no accountable owner.",
        why=lambda a, t: "The credential is administrative, used in production, and nobody is accountable for it.",
        impact="A privileged identity without an owner can change workspace configuration with no accountable reviewer.",
        permissions=["SentinelX operator role to record an owner overlay"],
        operational="Updates SentinelX metadata only; the provider record is unchanged.",
        rollback="Restore the previous owner metadata.",
        predicate=lambda a, t, p: not a["owner"] and bool(a["extra"].get("privileged")),
    ),
    "app_credential_expired": dict(
        title="Application credential is expired", action_type="rotate_app_credential", steps=APP_STEPS,
        policy="Application credentials must be rotated before expiry.",
        summary=lambda a, t: f"{a['name']} expired {abs((a['expiry_date'] - t).days)} day(s) ago.",
        why=lambda a, t: "The credential is expired in production; the integration is failing or relies on a fallback.",
        impact="The integration cannot authenticate; an expired key left in place also signals missing rotation hygiene.",
        permissions=["Application admin: issue credential", "Secret store write access"],
        operational="Integration must be reconfigured with the replacement credential.",
        rollback="Re-enable the previous credential if the provider supports it, otherwise re-issue.",
        predicate=lambda a, t, p: a["expiry_date"] is not None and a["expiry_date"] < t,
    ),
    "app_credential_expiring": dict(
        title="Application credential expiring soon", action_type="rotate_app_credential", steps=APP_STEPS,
        policy="Application credentials must be rotated before expiry.",
        summary=lambda a, t: f"{a['name']} expires in {(a['expiry_date'] - t).days} day(s).",
        why=lambda a, t: "Expiry falls within the 30-day warning window, so action is needed but nothing is failing yet.",
        impact="Orchestrated jobs will fail when the credential expires.",
        permissions=["Application admin: issue credential", "Secret store write access"],
        operational="Integration must be reconfigured with the replacement credential.",
        rollback="Re-enable the previous credential if the provider supports it, otherwise re-issue.",
        predicate=lambda a, t, p: a["expiry_date"] is not None and 0 <= (a["expiry_date"] - t).days <= p["expiry_warning_days"],
    ),
    "sync_mismatch": dict(
        title="Databricks and AWS secret out of sync", action_type="sync_secret", steps=SYNC_STEPS,
        policy="Secrets mirrored in Databricks and AWS must carry the same rotation version.",
        summary=lambda a, t: f"{a['name']} was last rotated {abs((a['last_rotation'] - t).days)} day(s) ago in AWS, "
                             "but the bound Databricks credential was rotated more recently.",
        why=lambda a, t: "Consumers reading from AWS will present a stale credential that Databricks no longer accepts.",
        impact="Workloads reading the AWS copy will fail authentication once the old credential is revoked.",
        permissions=SP_PERMISSIONS, operational="Writes the current credential to the AWS secret; consumers pick it up on next read.",
        rollback="Restore the previous AWS version (AWSPREVIOUS).",
        predicate=lambda a, t, p: a["extra"].get("sync") == "mismatch",
    ),
    "rotation_evidence_missing": dict(
        title="Credential rotation evidence is missing", action_type="record_rotation_evidence", steps=EVIDENCE_STEPS,
        policy="Every credential must have verifiable rotation evidence.",
        summary=lambda a, t: f"No rotation record exists for {a['name']}, so its rotation compliance cannot be demonstrated.",
        why=lambda a, t: "An evidence gap is a compliance risk rather than an active exposure, so it is rated medium.",
        impact="Auditors cannot verify the rotation policy; the true credential age is unknown.",
        permissions=["SentinelX operator role to attach evidence references"],
        operational="Updates SentinelX metadata only.", rollback="Remove the evidence reference.",
        predicate=lambda a, t, p: a["last_rotation"] is None,
    ),
    "aws_rotation_due": dict(
        title="AWS secret approaching rotation date", action_type="rotate_aws_secret", steps=AWS_ROTATION_STEPS,
        policy="AWS Secrets Manager secrets must rotate on schedule.",
        summary=lambda a, t: f"{a['name']} is due for rotation in {(a['extra']['next_rotation'] - t).days} day(s).",
        why=lambda a, t: "The rotation date is within a week but the secret is in a non-production environment.",
        impact="Missing the scheduled rotation extends the credential lifetime beyond policy.",
        permissions=["AWS Secrets Manager: PutSecretValue, UpdateSecretVersionStage", "AWS KMS: GenerateDataKey, Decrypt"],
        operational="Short consumer refresh interval; consumers must retry on authentication failure.",
        rollback="Restore the previous version (AWSPREVIOUS).",
        predicate=lambda a, t, p: a["extra"].get("next_rotation") is not None
        and 0 <= (a["extra"]["next_rotation"] - t).days <= p["aws_rotation_warning_days"],
    ),
    "aws_rotation_disabled": dict(
        title="AWS secret automatic rotation is disabled", action_type="rotate_aws_secret", steps=AWS_ROTATION_STEPS,
        policy="AWS Secrets Manager secrets must have automatic rotation enabled.",
        summary=lambda a, t: f"{a['name']} has automatic rotation disabled and was last rotated {_d(a['last_rotation'])[:10]}.",
        why=lambda a, t: "Rotation is disabled, so the secret ages indefinitely; no active outage, hence medium.",
        impact="The secret will never rotate on its own and keeps ageing beyond policy.",
        permissions=["AWS Secrets Manager: RotateSecret, PutSecretValue", "AWS KMS: GenerateDataKey, Decrypt"],
        operational="Enabling rotation requires a rotation function and owner sign-off.",
        rollback="Disable the rotation schedule and restore AWSPREVIOUS.",
        predicate=lambda a, t, p: a["extra"].get("rotation_enabled") is False,
    ),
    "sp_inactive": dict(
        title="Service Principal inactive beyond policy window", action_type="disable_orphaned_sp", steps=REVIEW_STEPS,
        policy="Service principals unused for more than 45 days should be reviewed.",
        summary=lambda a, t: f"{a['name']} has not been used for {abs((a['last_used'] - t).days)} days.",
        why=lambda a, t: "The principal has an owner and is in staging, so this is a routine review item.",
        impact="Dormant identities enlarge the attack surface.", permissions=["Databricks account admin: deactivate service principal"],
        operational="Low; confirm with the owner before disabling.", rollback="Re-activate the service principal.",
        predicate=lambda a, t, p: a["last_used"] is not None and (t - a["last_used"]).days > p["inactivity_days"],
    ),
}
