from dataclasses import dataclass
from datetime import datetime

from backend.models.asset import Asset, parse_time, utcnow


@dataclass(frozen=True)
class Policy:
    max_age_days: int = 30
    rotation_days: int = 30
    inactivity_days: int = 30

    def __post_init__(self):
        if min(self.max_age_days, self.rotation_days, self.inactivity_days) < 1:
            raise ValueError("Policy thresholds must be positive")


def assess(asset: Asset, policy: Policy | None = None, now: datetime | None = None):
    policy = policy or Policy()
    now = now or utcnow()
    findings = []

    def add(code, penalty, recommendation):
        findings.append({"code": code, "penalty": penalty, "recommendation": recommendation})

    def age(value):
        return max(0, (now - parse_time(value)).days) if value else None

    age_days = age(asset.created_at)
    rotation_age = age(asset.last_rotated_at)
    expiry = parse_time(asset.expires_at)
    days_remaining = (expiry - now).total_seconds() / 86400 if expiry else None
    if not asset.owner:
        add("missing_owner", 20, "Assign a verified accountable owner")
    if asset.active is False:
        add("inactive", 15, "Review workload dependencies before deactivation")
    elif asset.active is None:
        add("activity_unknown", 5, "Collect workload or audit activity evidence")
    if asset.privileged is True:
        add("excessive_privilege", 20, "Review grants and reduce privileges with owner approval")
    elif asset.privileged is None:
        add("privilege_unknown", 5, "Review entitlements; inventory alone does not establish least privilege")
    if asset.last_used_at and age(asset.last_used_at) > policy.inactivity_days:
        add("unused", 15, "Validate dependencies and retire unused credentials")
    if asset.kind != "service_principal":
        if age_days is None:
            add("age_unknown", 5, "Supply creation metadata from an authoritative registry")
        elif age_days > policy.max_age_days:
            add("stale", 15, "Renew or rotate credentials beyond the age policy")
        if days_remaining is not None:
            if days_remaining <= 0:
                add("expired", 65, "Renew immediately and validate dependent workloads")
            elif days_remaining <= 7:
                add("expires_7d", 25, "Schedule immediate approved renewal")
            elif days_remaining <= 15:
                add("expires_15d", 15, "Schedule renewal within this week")
            elif days_remaining <= 30:
                add("expires_30d", 10, "Plan renewal before expiry")
        elif asset.kind in {"sp_secret", "pat", "oauth", "application_credential"}:
            add("expiry_unknown", 5, "Verify expiry with the issuing authority")
        if rotation_age is None:
            add("rotation_unknown", 10, "Record verifiable renewal or rotation history")
        elif rotation_age > policy.rotation_days:
            add("rotation_overdue", 20, "Rotate and validate the dependent application")
        if asset.kind in {"aws_secret", "databricks_secret"} and asset.rotation_enabled is False:
            add("rotation_disabled", 10, "Enable a supported rotation workflow")
    if asset.binding and asset.sync_state != "metadata_aligned":
        add("sync_" + asset.sync_state, 15, "Validate mapped metadata and provider version state")
    score = max(0, 100 - sum(item["penalty"] for item in findings))
    risk = "critical" if score < 40 else "high" if score < 70 else "attention" if findings else "compliant"
    return {"asset_id": asset.id, "score": score, "risk": risk, "compliant": not findings,
            "age_days": age_days, "rotation_age_days": rotation_age,
            "days_remaining": round(days_remaining, 1) if days_remaining is not None else None,
            "findings": findings}