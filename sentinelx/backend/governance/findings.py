import hashlib


_SEVERITY = {"critical": "critical", "high": "high", "attention": "medium", "compliant": "low"}
_TITLES = {
    "missing_owner": "No accountable owner",
    "inactive": "Identity is inactive",
    "activity_unknown": "Activity evidence is missing",
    "excessive_privilege": "Privileged identity requires review",
    "privilege_unknown": "Privilege evidence is missing",
    "unused": "Credential has not been used within policy",
    "age_unknown": "Credential age is unknown",
    "stale": "Credential exceeds the age policy",
    "expired": "Credential is expired",
    "expires_7d": "Credential expires within 7 days",
    "expires_15d": "Credential expires within 15 days",
    "expires_30d": "Credential expires within 30 days",
    "expiry_unknown": "Credential expiry is unknown",
    "rotation_unknown": "Rotation evidence is missing",
    "rotation_overdue": "Credential rotation is overdue",
    "rotation_disabled": "Automatic secret rotation is disabled",
    "sync_missing_counterpart": "Mapped provider counterpart is missing",
    "sync_unverified": "Mapped provider synchronization is unverified",
    "sync_drift": "Mapped provider metadata is out of sync",
}
_DESCRIPTIONS = {
    "missing_owner": "No accountable owner is recorded for this identity or credential.",
    "inactive": "The provider reports this identity as inactive; dependent workloads should be reviewed before deactivation.",
    "activity_unknown": "The inventory does not include enough activity evidence to determine whether this identity is active.",
    "excessive_privilege": "Available metadata indicates an administrative role that requires owner review.",
    "privilege_unknown": "Available inventory does not establish whether the assigned privileges are least-privilege.",
    "unused": "Recorded usage is older than the configured inactivity threshold.",
    "age_unknown": "Creation metadata is missing, so credential age cannot be evaluated.",
    "stale": "The credential age exceeds the configured maximum age policy.",
    "expired": "The recorded credential expiry time has passed.",
    "expires_7d": "The credential is scheduled to expire within seven days.",
    "expires_15d": "The credential is scheduled to expire within fifteen days.",
    "expires_30d": "The credential is scheduled to expire within thirty days.",
    "expiry_unknown": "The inventory does not contain a verifiable expiry time.",
    "rotation_unknown": "The inventory has no verifiable credential rotation timestamp.",
    "rotation_overdue": "The time since the recorded rotation exceeds the configured rotation policy.",
    "rotation_disabled": "The provider reports that automatic secret rotation is disabled.",
    "sync_missing_counterpart": "The configured binding has no discovered asset from the other provider.",
    "sync_unverified": "A provider counterpart exists, but metadata is insufficient to verify alignment.",
    "sync_drift": "Mapped provider rotation metadata or rotation modes are inconsistent.",
}
_ROTATION_CODES = {"stale", "expired", "expires_7d", "expires_15d", "expires_30d", "rotation_overdue"}


def finding_id(asset_id, code):
    digest = hashlib.sha256(f"{asset_id}\0{code}".encode("utf-8")).hexdigest()[:20]
    return "finding-" + digest


def _supported_actions(asset, code, mode):
    kind = asset["kind"]
    if code == "missing_owner":
        return ["assign_owner"]
    if mode == "demo":
        if kind == "sp_secret" and code in _ROTATION_CODES:
            return ["renew_sp"]
        if kind in {"aws_secret", "databricks_secret"} and code.startswith("sync_"):
            return ["sync_secret", "rotate_secret"]
        if kind in {"aws_secret", "databricks_secret"} and code in _ROTATION_CODES:
            return ["rotate_secret"]
        return []
    if kind == "sp_secret" and asset.get("rotation_supported") and code in _ROTATION_CODES:
        return ["renew_sp"]
    return []


def _guidance(code, supported_actions):
    if code == "missing_owner":
        return {
            "business_impact": "Without an accountable owner, review and incident escalation may be delayed.",
            "required_permissions": ["SentinelX operator role to record an owner metadata overlay"],
            "expected_operational_impact": "Updates SentinelX metadata only; it does not change the provider's ownership record.",
            "rollback": "A separately approved rollback restores the previous SentinelX owner metadata.",
        }
    if "renew_sp" in supported_actions:
        return {
            "business_impact": "An expired or aging service-principal credential may interrupt dependent workloads.",
            "required_permissions": [
                "Databricks account access to create the bound service-principal credential",
                "Write access to the configured Databricks secret key",
                "AWS Secrets Manager access to stage and promote the explicitly bound secret",
            ],
            "expected_operational_impact": "Creates a replacement credential and updates the configured Databricks and AWS locations; dependent workloads still require validation.",
            "rollback": "A separately approved rollback restores the recorded prior Databricks value and AWS version when the receipt and prior version remain valid.",
        }
    if code.startswith("sync_"):
        return {
            "business_impact": "Mapped provider metadata is incomplete or inconsistent; metadata comparison does not prove secret-value equality.",
            "required_permissions": ["Owner review of the binding and provider metadata"],
            "expected_operational_impact": "No live synchronization is available for this finding type.",
            "rollback": "No provider mutation is performed by the recommendation.",
        }
    return {
        "business_impact": "The finding indicates a policy or evidence gap that may increase credential or identity risk.",
        "required_permissions": ["Owner review and the provider-specific permissions required by any approved change"],
        "expected_operational_impact": "Follow the recommendation only after validating the owner, dependencies, and supported workflow.",
        "rollback": "No automatic provider change is supported for this finding type.",
    }


def build_findings(inventory, actions, report_at, policy, mode, remediation_enabled):
    actions_by_asset = {}
    actions_by_id = {action["id"]: action for action in actions}
    for action in actions:
        actions_by_asset.setdefault(action["asset_id"], []).append(action)

    def matches_action(action, asset, code, identity):
        if action.get("finding_id"):
            return action["finding_id"] == identity
        operation = action.get("action")
        if operation == "rollback":
            original = actions_by_id.get(action.get("original_id"))
            return bool(original and matches_action(original, asset, code, identity))
        if code == "missing_owner":
            return operation == "assign_owner"
        if code.startswith("sync_"):
            return operation == "sync_secret"
        if code in _ROTATION_CODES:
            if asset["kind"] == "sp_secret":
                return operation == "renew_sp"
            if mode == "demo" and asset["kind"] in {"aws_secret", "databricks_secret"}:
                return operation == "rotate_secret"
        return False

    def newest(records):
        return max(records, key=lambda record: record.get("updated_at") or record.get("created_at") or "")

    result = []
    for record in inventory:
        asset = record["asset"]
        assessment = record["assessment"]
        for finding in assessment["findings"]:
            code = finding["code"]
            identity = finding_id(asset["id"], code)
            related = [action for action in actions_by_asset.get(asset["id"], [])
                       if matches_action(action, asset, code, identity)]
            action = newest(related) if related else None
            actions_supported = _supported_actions(asset, code, mode)
            status = action.get("status", "not_requested") if action else "not_requested"
            approval_status = "not_requested"
            if action:
                approval_status = {
                    "pending": "awaiting_approval" if action.get("reviewed") else "pending_review",
                    "approved": "approved",
                    "rejected": "rejected",
                    "running": "executing",
                    "succeeded": "executed",
                    "failed": "failed",
                    "recovery_required": "recovery_required",
                    "rolled_back": "rolled_back",
                }.get(status, status)
            result.append({
                "finding_id": identity,
                "asset_id": asset["id"],
                "asset_name": asset["name"],
                "credential_type": asset["kind"],
                "workspace": "not recorded in the current inventory",
                "environment": asset.get("source") or "unknown",
                "owner": asset.get("owner"),
                "severity": _SEVERITY[assessment["risk"]],
                "risk": assessment["risk"],
                "code": code,
                "title": _TITLES.get(code, code.replace("_", " ").capitalize()),
                "description": _DESCRIPTIONS.get(code, "A governance policy finding requires review."),
                "recommendation": finding["recommendation"],
                "penalty": finding["penalty"],
                "expiry_date": asset.get("expires_at"),
                "remediation_status": status,
                "approval_status": approval_status,
                "action_id": action.get("id") if action else None,
                "last_updated": (action.get("updated_at") or action.get("created_at")) if action else report_at,
                "report_reference": report_at,
                "evidence": {
                    "created_at": asset.get("created_at"),
                    "expires_at": asset.get("expires_at"),
                    "last_used_at": asset.get("last_used_at"),
                    "last_rotated_at": asset.get("last_rotated_at"),
                    "age_days": assessment.get("age_days"),
                    "rotation_age_days": assessment.get("rotation_age_days"),
                    "days_remaining": assessment.get("days_remaining"),
                    "owner": asset.get("owner"),
                    "active": asset.get("active"),
                    "privileged": asset.get("privileged"),
                    "sync_state": asset.get("sync_state"),
                    "rotation_enabled": asset.get("rotation_enabled"),
                },
                "policy": dict(policy),
                "supported_actions": actions_supported,
                "execution_enabled": bool(remediation_enabled and actions_supported),
                **_guidance(code, actions_supported),
            })
    return sorted(result, key=lambda row: (
        {"critical": 0, "high": 1, "medium": 2, "low": 3}[row["severity"]],
        -row["penalty"],
        row["asset_name"].casefold(),
        row["code"],
    ))
