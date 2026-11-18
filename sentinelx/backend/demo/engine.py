"""In-memory SentinelX demo workspace: inventory, findings, metrics and a simulated remediation workflow.

Everything is derived from backend.demo.seed. Nothing here talks to Databricks or AWS; every mutation only
changes this object's in-memory state and is labelled as simulated.
"""

import csv
import io
import json
from datetime import datetime, timedelta, timezone

from backend.demo import seed
from backend.demo.catalog import ACTION_TYPES, RULES, SEVERITY_ORDER, TYPE_LABELS

SIMULATION_LABEL = "SIMULATED REMEDIATION — NO CLOUD CHANGES PERFORMED"
DEMO_BADGE = "Demo Mode — Synthetic Data"
DEMO_MODE_BADGE = "DEMO MODE"
DEMO_SUCCESS_HEADING = "REMEDIATION COMPLETED SUCCESSFULLY"
DEMO_SUCCESS_DESCRIPTION = ("SentinelX successfully completed the credential remediation workflow in Demo Mode. "
                            "All simulated updates, synchronization and verification steps completed successfully.")
DATABRICKS_UPDATE_ACTIONS = {"renew_sp_secret", "rotate_pat", "rotate_app_credential", "sync_secret"}
AWS_SYNC_ACTIONS = {"rotate_aws_secret", "sync_secret"}
PENALTY = {"critical": 45, "high": 30, "medium": 15, "low": 5}
APPROVAL_LABELS = {"none": "Not Requested", "pending": "Pending Approval", "approved": "Approved", "rejected": "Rejected"}
STATUS_LABELS = {"none": "Open", "awaiting_approval": "Awaiting Approval", "ready": "Ready to Execute",
                 "completed": "Completed (Simulated)", "rejected": "Rejected"}
ACTIVE_STATUSES = {"awaiting_approval", "ready"}
OPERATOR = "demo.operator@sentinelx.example"
APPROVER = "demo.approver@sentinelx.example"


class WorkflowError(ValueError):
    pass


def _on(today, offset):
    return None if offset is None else today + timedelta(days=offset)


def _arn(name, number):
    return f"arn:aws:secretsmanager:{seed.AWS_REGION}:{seed.AWS_ACCOUNT_ID}:secret:{name}-{number:06d}"


def build_assets(today):
    """Unified inventory (identities and credentials) with dates resolved against `today`."""
    principals = {item["id"]: item for item in seed.SERVICE_PRINCIPALS}
    assets = []

    def asset(**fields):
        base = dict(owner=None, environment=None, expiry_date=None, last_rotation=None, created=None, last_used=None,
                    parent_id=None, extra={})
        base.update(fields)
        base["type_label"] = TYPE_LABELS[base["credential_type"]]
        assets.append(base)

    for item in seed.SERVICE_PRINCIPALS:
        asset(id=item["id"], name=item["name"], credential_type="service_principal", is_credential=False,
              source="Databricks", owner=item["owner"], environment=item["environment"],
              created=_on(today, item["created"]), last_used=_on(today, item["last_used"]),
              extra=dict(active=item["active"], privileged=item["privileged"], team=item["team"]))
    for item in seed.SP_CREDENTIALS:
        parent = principals[item["sp_id"]]
        asset(id=item["id"], name=item["name"], credential_type="sp_secret", is_credential=True, source="Databricks",
              owner=parent["owner"], environment=parent["environment"], expiry_date=_on(today, item["expires"]),
              last_rotation=_on(today, item["last_rotation"]), created=_on(today, item["created"]),
              last_used=_on(today, parent["last_used"]), parent_id=item["sp_id"],
              extra=dict(active=parent["active"], privileged=parent["privileged"]))
    for item in seed.PATS:
        asset(id=item["id"], name=item["name"], credential_type="pat", is_credential=True, source="Databricks",
              owner=item["owner"], environment=item["environment"], expiry_date=_on(today, item["expires"]),
              last_rotation=_on(today, item["created"]), created=_on(today, item["created"]),
              last_used=_on(today, item["last_used"]))
    for item in seed.APP_CREDENTIALS:
        asset(id=item["id"], name=item["name"], credential_type="application_credential", is_credential=True,
              source="Databricks", owner=item["owner"], environment=item["environment"],
              expiry_date=_on(today, item["expires"]), last_rotation=_on(today, item["last_rotation"]))
    for number, item in enumerate(seed.AWS_SECRETS, 1):
        asset(id=item["id"], name=item["name"], credential_type="aws_secret", is_credential=True,
              source="AWS Secrets Manager", owner=item["owner"], environment=item["environment"],
              last_rotation=_on(today, item["last_rotation"]), parent_id=item["bound_to"],
              extra=dict(next_rotation=_on(today, item["next_rotation"]), rotation_enabled=item["rotation_enabled"],
                         sync=item["sync"], kms=item["kms"], region=seed.AWS_REGION, account_id=seed.AWS_ACCOUNT_ID,
                         arn=_arn(item["name"], 100000 + number * 137), bound_to=item["bound_to"]))
    return assets


def days_until(value, today):
    return None if value is None else (value - today).days


class DemoWorkspace:
    mode = "demo"

    def __init__(self, today=None):
        self.today = today or datetime.now(timezone.utc).date()
        self._base = build_assets(self.today)
        self._overrides = {}
        self._actions = []
        for item in seed.ACTIONS:
            action = {key: value for key, value in item.items() if key not in {"requested", "decided", "executed"}}
            for field in ("requested", "decided", "executed"):
                action[field + "_at"] = None if item[field] is None else self._stamp(item[field])
            action.setdefault("proposed_owner", None)
            action.setdefault("note", None)
            action["simulated"] = True
            self._actions.append(action)
            if action["status"] == "completed":
                self._apply_effect(action)
        self._audit = [dict(event_id=eid, at=self._stamp(offset), actor=actor, event=event, target=target,
                            detail=detail, simulated=True) for eid, offset, actor, event, target, detail in seed.AUDIT]

    def _stamp(self, offset):
        return datetime.combine(self.today + timedelta(days=offset), datetime.min.time(), timezone.utc).replace(hour=9).isoformat()

    def _now(self):
        return datetime.now(timezone.utc).isoformat(timespec="seconds")

    def _record(self, actor, event, target, detail):
        number = 3000 + len(self._audit) + 1
        self._audit.append(dict(event_id=f"AUD-{number}", at=self._now(), actor=actor, event=event, target=target,
                                detail=detail, simulated=True))

    def _apply_effect(self, action):
        """Mirror a completed simulated action onto in-memory inventory so every metric stays consistent."""
        finding = self._finding_row(action["finding_id"])
        override = self._overrides.setdefault(finding["asset_id"], {})
        kind = action["action_type"]
        if kind in {"renew_sp_secret", "rotate_pat", "rotate_app_credential"}:
            override.update(expiry_date=self.today + timedelta(days=90), last_rotation=self.today)
        elif kind == "rotate_aws_secret":
            override.update(last_rotation=self.today)
            override["extra"] = {**override.get("extra", {}), "next_rotation": self.today + timedelta(days=30),
                                 "rotation_enabled": True}
        elif kind == "sync_secret":
            override["extra"] = {**override.get("extra", {}), "sync": "in_sync"}
        elif kind == "assign_owner":
            override["owner"] = action.get("proposed_owner") or "Platform Governance Team"
        elif kind == "disable_orphaned_sp":
            override["extra"] = {**override.get("extra", {}), "active": False, "disabled": True}

    def _finding_row(self, finding_id):
        for fid, severity, code, asset_id in seed.FINDINGS:
            if fid == finding_id:
                return dict(finding_id=fid, severity=severity, code=code, asset_id=asset_id)
        raise KeyError(finding_id)

    def assets(self):
        result = []
        for item in self._base:
            override = self._overrides.get(item["id"], {})
            merged = dict(item, **{key: value for key, value in override.items() if key != "extra"})
            merged["extra"] = {**item["extra"], **override.get("extra", {})}
            result.append(merged)
        return result

    def asset(self, asset_id):
        return next(item for item in self.assets() if item["id"] == asset_id)

    def actions(self):
        assets = {item["id"]: item for item in self.assets()}
        return [self._action_view(action, assets) for action in self._actions]

    def _action_view(self, action, assets=None):
        finding = self._finding_row(action["finding_id"])
        asset = (assets or {i["id"]: i for i in self.assets()})[finding["asset_id"]]
        return dict(action, action_label=ACTION_TYPES[action["action_type"]], asset_id=asset["id"],
                    asset_name=asset["name"], severity=finding["severity"],
                    approval_label=APPROVAL_LABELS[action["approval"]], status_label=STATUS_LABELS[action["status"]])

    def action(self, action_id):
        return next(item for item in self.actions() if item["id"] == action_id)

    def action_for_finding(self, finding_id):
        related = [item for item in self.actions() if item["finding_id"] == finding_id]
        return related[-1] if related else None

    def _action_state(self, finding_id):
        related = [item for item in self._actions if item["finding_id"] == finding_id]
        if not related:
            return None, "none", "none"
        return related[-1], related[-1]["approval"], related[-1]["status"]

    def evidence(self, asset_id):
        return self._evidence(self.asset(asset_id))

    def _evidence(self, asset):
        today, extra, rows = self.today, asset["extra"], []

        def add(label, value):
            rows.append({"Evidence": label, "Value": "Not available" if value in (None, "") else str(value)})

        add("Asset ID", asset["id"])
        add("Credential type", asset["type_label"])
        add("Environment", asset["environment"])
        add("Owner", asset["owner"] or "Unassigned")
        if asset["credential_type"] != "aws_secret":
            add("Expiry date", asset["expiry_date"] or "No expiry configured")
            if asset["expiry_date"]:
                add("Days until expiry", days_until(asset["expiry_date"], today))
        add("Last rotation date", asset["last_rotation"] or "No rotation evidence")
        if asset["last_used"]:
            add("Last used", f"{asset['last_used']} ({(today - asset['last_used']).days} days ago)")
        if asset["parent_id"]:
            add("Linked asset", asset["parent_id"])
        if asset["credential_type"] == "aws_secret":
            add("Rotation enabled", "Yes" if extra["rotation_enabled"] else "No")
            add("Next rotation date", extra["next_rotation"] or "Not scheduled")
            add("Databricks / AWS sync", extra["sync"].replace("_", " "))
            add("ARN (metadata only)", extra["arn"])
        if asset["credential_type"] in {"service_principal", "sp_secret"}:
            add("Privileged", "Yes" if extra.get("privileged") else "No")
            add("Active", "Yes" if extra.get("active", True) else "No")
        add("Secret value", "Never collected or displayed")
        return rows

    def _findings_all(self):
        assets = {item["id"]: item for item in self.assets()}
        rows = []
        for fid, severity, code, asset_id in seed.FINDINGS:
            rule, asset = RULES[code], assets[asset_id]
            action, approval, status = self._action_state(fid)
            resolved = status == "completed"
            rows.append(dict(
                finding_id=fid, severity=severity, risk_level=severity.title(), code=code, title=rule["title"],
                asset_id=asset_id, asset_name=asset["name"], credential_type=asset["credential_type"],
                type_label=asset["type_label"], owner=asset["owner"], environment=asset["environment"],
                expiry_date=asset["expiry_date"], last_rotation=asset["last_rotation"],
                policy_status="Resolved (Simulated)" if resolved else (
                    "Non-compliant" if severity in {"critical", "high"} else "At risk"),
                description=rule["summary"](asset, self.today), recommended_action=ACTION_TYPES[rule["action_type"]],
                action_type=rule["action_type"], resolved=resolved, action_id=action["id"] if action else None,
                approval_status=APPROVAL_LABELS[approval], remediation_status=STATUS_LABELS[status],
                approval_state=approval, status_state=status, environment_is_production=asset["environment"] == "Production",
            ))
        return rows

    def findings(self, severity=None, credential_type=None, expired=False, expiring=False, pending_approval=False,
                 completed=False, unassigned=False, query="", include_resolved=False):
        rows = self._findings_all()
        if not (completed or include_resolved):
            rows = [row for row in rows if not row["resolved"]]
        if completed:
            rows = [row for row in rows if row["resolved"]]
        if severity:
            rows = [row for row in rows if row["severity"] in set(severity)]
        if credential_type:
            rows = [row for row in rows if row["credential_type"] in set(credential_type)]
        if expired:
            rows = [row for row in rows if row["expiry_date"] is not None and row["expiry_date"] < self.today]
        if expiring:
            rows = [row for row in rows if row["expiry_date"] is not None
                    and 0 <= (row["expiry_date"] - self.today).days <= seed.POLICY["expiry_warning_days"]]
        if pending_approval:
            rows = [row for row in rows if row["approval_state"] == "pending"]
        if unassigned:
            rows = [row for row in rows if not row["owner"]]
        if query:
            term = query.casefold()
            rows = [row for row in rows if term in " ".join(
                str(row[field] or "") for field in ("finding_id", "asset_id", "asset_name", "owner", "title", "code")).casefold()]
        return sorted(rows, key=lambda row: (SEVERITY_ORDER.index(row["severity"]), row["finding_id"]))

    def finding(self, finding_id):
        for row in self._findings_all():
            if row["finding_id"] == finding_id:
                return row
        raise KeyError(finding_id)

    def guidance(self, finding_id):
        finding = self.finding(finding_id)
        rule, asset = RULES[finding["code"]], self.asset(finding["asset_id"])
        action = self.action_for_finding(finding_id)
        done = action is not None and action["status"] == "completed"
        return dict(
            finding=finding, summary=finding["description"], affected=f"{asset['name']} ({asset['type_label']}, {asset['id']})",
            severity=finding["severity"], evidence=self._evidence(asset), business_impact=rule["impact"],
            policy=rule["policy"], steps=[dict(Step=index, Action=text, Status="Simulated" if done else "Pending")
                                          for index, text in enumerate(rule["steps"], 1)],
            required_permissions=rule["permissions"], operational_impact=rule["operational"], rollback=rule["rollback"],
            current_status=f"{finding['remediation_status']} · Approval: {finding['approval_status']}",
            why_severity=rule["why"](asset, self.today), simulation_label=SIMULATION_LABEL,
        )

    def integrity_issues(self):
        """Findings whose seeded rule no longer holds against the *unmodified* inventory."""
        base = {item["id"]: item for item in build_assets(self.today)}
        issues = []
        for fid, severity, code, asset_id in seed.FINDINGS:
            asset = base.get(asset_id)
            if asset is None:
                issues.append(f"{fid}: unknown asset {asset_id}")
            elif not RULES[code]["predicate"](asset, self.today, seed.POLICY):
                issues.append(f"{fid}: rule {code} does not hold for {asset_id}")
        for action in seed.ACTIONS:
            if action["finding_id"] not in {row[0] for row in seed.FINDINGS}:
                issues.append(f"{action['id']}: unknown finding {action['finding_id']}")
        return issues

    def asset_assessments(self):
        findings = self.findings()
        by_asset = {}
        for row in findings:
            by_asset.setdefault(row["asset_id"], []).append(row)
        result = []
        for item in self.assets():
            open_findings = by_asset.get(item["id"], [])
            worst = next((level for level in SEVERITY_ORDER if any(f["severity"] == level for f in open_findings)), "low")
            score = max(0, 100 - sum(PENALTY[f["severity"]] for f in open_findings))
            result.append(dict(item, risk_level=worst, score=score, open_findings=[f["finding_id"] for f in open_findings],
                               policy_status="Compliant" if not open_findings else (
                                   "Non-compliant" if worst in {"critical", "high"} else "At risk"),
                               days_to_expiry=days_until(item["expiry_date"], self.today)))
        return result

    def metrics(self):
        assessed = self.asset_assessments()
        credentials = [item for item in assessed if item["is_credential"]]
        open_findings = self.findings()
        actions = self.actions()
        by_type = {}
        for item in assessed:
            bucket = by_type.setdefault(item["type_label"], dict(type=item["type_label"], total=0, compliant=0, score_sum=0))
            bucket["total"] += 1
            bucket["compliant"] += item["policy_status"] == "Compliant"
            bucket["score_sum"] += item["score"]
        return dict(
            governance_score=round(sum(item["score"] for item in assessed) / len(assessed), 1),
            compliance_percentage=round(100 * sum(item["policy_status"] == "Compliant" for item in assessed) / len(assessed), 1),
            governed_assets=len(assessed), total_credentials=len(credentials),
            expired_credentials=sum(item["days_to_expiry"] is not None and item["days_to_expiry"] < 0 for item in credentials),
            expiring_7d=sum(item["days_to_expiry"] is not None and 0 <= item["days_to_expiry"] <= 7 for item in credentials),
            expiring_30d=sum(item["days_to_expiry"] is not None
                             and 0 <= item["days_to_expiry"] <= seed.POLICY["expiry_warning_days"] for item in credentials),
            high_risk_assets=sum(item["risk_level"] in {"critical", "high"} for item in assessed),
            open_findings=len(open_findings), total_findings=len(seed.FINDINGS),
            open_actions=sum(action["status"] in ACTIVE_STATUSES for action in actions),
            pending_approval=sum(action["approval"] == "pending" for action in actions),
            severity_counts={level: sum(row["severity"] == level for row in open_findings) for level in SEVERITY_ORDER},
            risk_distribution={level: sum(item["risk_level"] == level for item in assessed) for level in SEVERITY_ORDER},
            by_type=[dict(type=b["type"], total=b["total"], compliant=b["compliant"], score=round(b["score_sum"] / b["total"], 1))
                     for b in by_type.values()],
        )

    def audit(self, target=None):
        events = [dict(event) for event in self._audit if target is None or event["target"] == target]
        return sorted(events, key=lambda event: event["at"], reverse=True)

    def execution_result(self, action_id):
        """Simulated execution outcome derived from the recorded action and audit trail; None until completed."""
        action = self.action(action_id)
        if action["status"] != "completed":
            return None
        kind = action["action_type"]
        checks = []
        if kind in DATABRICKS_UPDATE_ACTIONS:
            checks.append(dict(label="Databricks credential update simulated successfully", ok=True))
        if kind in AWS_SYNC_ACTIONS:
            checks.append(dict(label="AWS Secrets Manager synchronization simulated successfully", ok=True))
        checks.append(dict(label="Credential synchronization verified", ok=True))
        recorded = any(event["event"] == "execution_simulated" for event in self.audit(action_id))
        checks.append(dict(label="Remediation audit record generated", ok=recorded))
        return dict(action=action, checks=checks, success=all(check["ok"] for check in checks), cloud_changes=False,
                    mode_badge=DEMO_MODE_BADGE, heading=DEMO_SUCCESS_HEADING, description=DEMO_SUCCESS_DESCRIPTION)

    def reset(self):
        self.__init__(self.today)

    def request_approval(self, finding_id, actor=OPERATOR, proposed_owner=None):
        finding = self.finding(finding_id)
        if finding["resolved"]:
            raise WorkflowError("This finding is already resolved (simulated).")
        existing = self.action_for_finding(finding_id)
        if existing and existing["status"] in ACTIVE_STATUSES:
            raise WorkflowError(f"{existing['id']} is already {existing['status_label'].lower()} for this finding.")
        if finding["action_type"] == "assign_owner":
            proposed_owner = (proposed_owner or "").strip()
            if not 1 <= len(proposed_owner) <= 120:
                raise WorkflowError("An accountable owner of 1-120 characters is required.")
        number = max(int(item["id"].split("-")[1]) for item in self._actions) + 1
        action = dict(id=f"ACT-{number}", finding_id=finding_id, action_type=finding["action_type"], approval="pending",
                      status="awaiting_approval", requested_by=actor, requested_at=self._now(), approver=None,
                      decided_at=None, executed_at=None, proposed_owner=proposed_owner or None, note=None, simulated=True)
        self._actions.append(action)
        self._record(actor, "approval_requested", action["id"], f"Requested simulated approval for {finding_id}.")
        return self._action_view(action)

    def _mutable(self, action_id):
        return next(item for item in self._actions if item["id"] == action_id)

    def decide(self, action_id, approve, actor=APPROVER):
        action = self._mutable(action_id)
        if action["status"] != "awaiting_approval":
            raise WorkflowError("Only actions awaiting approval can be decided.")
        if actor == action["requested_by"]:
            raise WorkflowError("The requester cannot approve their own action.")
        action.update(approval="approved" if approve else "rejected", status="ready" if approve else "rejected",
                      approver=actor, decided_at=self._now())
        self._record(actor, "approval_granted" if approve else "approval_rejected", action_id,
                     "Simulated approval recorded." if approve else "Simulated rejection recorded.")
        return self._action_view(action)

    def execute(self, action_id, actor=OPERATOR, confirmed=False):
        action = self._mutable(action_id)
        if action["status"] == "completed":
            return dict(action=self._action_view(action), already_executed=True, simulation_label=SIMULATION_LABEL,
                        cloud_changes=False)
        if action["status"] != "ready" or action["approval"] != "approved":
            raise WorkflowError("Execution requires an approved action.")
        if not confirmed:
            raise WorkflowError("Human confirmation is required before simulated execution.")
        if actor == action["approver"]:
            raise WorkflowError("The approver cannot execute their own approval.")
        action.update(status="completed", executed_at=self._now())
        self._apply_effect(action)
        self._record(actor, "execution_simulated", action_id, "Simulated execution; no cloud changes performed.")
        return dict(action=self._action_view(action), already_executed=False, simulation_label=SIMULATION_LABEL,
                    cloud_changes=False)

    def report_rows(self):
        return [dict(finding_id=row["finding_id"], asset=row["asset_name"], credential_type=row["type_label"],
                     owner=row["owner"] or "Unassigned", environment=row["environment"], risk=row["risk_level"],
                     expiry_date=row["expiry_date"] or "", last_rotation=row["last_rotation"] or "",
                     policy_status=row["policy_status"], recommended_action=row["recommended_action"],
                     approval_status=row["approval_status"], remediation_status=row["remediation_status"])
                for row in self.findings(include_resolved=True)]

    def report_json(self):
        return json.dumps(dict(synthetic=True, generated=str(self.today), metrics=self.metrics(), findings=self.report_rows()),
                          indent=2, default=str)

    def report_csv(self):
        rows = self.report_rows()
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=list(rows[0]))
        writer.writeheader()
        for row in rows:
            writer.writerow({key: "'" + str(value) if isinstance(value, str) and value.lstrip().startswith(("=", "+", "-", "@"))
                             else value for key, value in row.items()})
        return output.getvalue()
