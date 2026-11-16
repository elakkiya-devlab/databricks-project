"""Deterministic SentinelX Copilot for Demo Mode.

Every answer is computed from the DemoWorkspace read APIs. The Copilot holds no mutation methods: it can only
describe findings and point the UI at the controlled approval workflow.
"""

import re

from backend.demo.catalog import RULES, SEVERITY_DEFINITIONS, SEVERITY_ORDER, TYPE_LABELS
from backend.demo.engine import DEMO_BADGE, SIMULATION_LABEL

SUGGESTED_QUESTIONS = [
    "What is our current governance score?",
    "How many credentials are expired?",
    "Show me all critical Service Principals.",
    "Which credentials are expiring in the next 7 days?",
    "Which Service Principals have no owner?",
    "Why is finding SX-1001 classified as critical?",
    "What are the top five remediation priorities?",
    "Which AWS secrets are not synchronized?",
    "What is the recommended remediation for an expired SP secret?",
    "Which remediation actions are awaiting approval?",
    "Show me all non-compliant PAT tokens.",
    "What is the difference between critical and high-risk findings?",
]

INTENTS = ("score", "expired", "expiring", "no_owner", "critical_sps", "explain", "priorities", "sync", "guidance",
           "pending_actions", "noncompliant", "severity_difference", "list_findings", "lookup", "help")

_TYPE_WORDS = [
    ("service_principal", r"service principals?|\bsps?\b(?! secret)"),
    ("sp_secret", r"sp secrets?|service principal secrets?|oauth secrets?"),
    ("pat", r"\bpats?\b|personal access tokens?|tokens?"),
    ("application_credential", r"application credentials?|app credentials?|api keys?"),
    ("aws_secret", r"aws secrets?|secrets manager|aws"),
]
_WORD_NUMBERS = {"one": 1, "two": 2, "three": 3, "four": 4, "five": 5, "six": 6, "seven": 7, "ten": 10}
_ACTION_VERB = re.compile(r"^(please\s+)?(can you\s+|could you\s+)?(go ahead and\s+)?(rotate|renew|revoke|delete|disable|execute|"
                          r"approve|apply|run|remediate|fix|reset)\b")


def _days(text):
    if "week" in text:
        return 7
    if "month" in text:
        return 30
    match = re.search(r"(\d+)\s*days?", text)
    return int(match.group(1)) if match else None


def _types(text):
    found = []
    for kind, pattern in _TYPE_WORDS:
        if re.search(pattern, text):
            found.append(kind)
    if "sp_secret" in found and "service_principal" in found and not re.search(r"service principals?\b(?! secret)", text):
        found.remove("service_principal")
    if "aws_secret" in found and len(found) > 1 and not re.search(r"aws secret|secrets manager", text):
        found.remove("aws_secret")
    return found


class DemoCopilot:
    def __init__(self, workspace, intent_provider=None):
        self.workspace = workspace
        self.intent_provider = intent_provider

    def answer(self, question, context=None):
        context = dict(context or {})
        text = " ".join(question.strip().split())
        lowered = text.casefold()
        result = self._route(text, lowered, context)
        context.update(result.pop("context", {}))
        result.setdefault("references", [])
        return dict(answer=f"*{DEMO_BADGE}: calculated from the synthetic dataset.*\n\n" + result["answer"],
                    references=result["references"], intent=result["intent"], synthetic=True, context=context,
                    engine="deterministic-structured-query")

    # -- routing ---------------------------------------------------------------------------------------------
    def _route(self, text, lowered, context):
        ids = [match.upper() for match in re.findall(r"\bsx-\d{4}\b", lowered, re.I)]
        if re.search(r"secret value|password|private key|show .*(token|secret) value|reveal", lowered):
            return self._reply("help", "SentinelX never collects or displays secret values, tokens, or keys, so I cannot "
                                       "show them. I can describe metadata such as owner, expiry, and rotation status.")
        if _ACTION_VERB.search(lowered):
            return self._refuse(ids, context, self._asset_finding(lowered))
        intent = self._intent(lowered, ids, context)
        if intent is None and self.intent_provider:
            candidate = self.intent_provider.classify(text, INTENTS)
            intent = candidate if candidate in INTENTS else None
        handler = getattr(self, "_" + (intent or "fallback"))
        return handler(text, lowered, ids, context)

    def _intent(self, text, ids, context):
        has_context = bool(ids or context.get("finding_id"))
        if re.search(r"difference between|differ", text) and "critical" in text and "high" in text:
            return "severity_difference"
        if re.search(r"governance score|compliance (score|percentage|rate)|how compliant|overall score|posture", text):
            return "score"
        if re.search(r"await|pending", text) and re.search(r"approv|action|remediation", text):
            return "pending_actions"
        if re.search(r"sync|mismatch|drift", text):
            return "sync"
        if re.search(r"no owner|without (an )?owner|unowned|unassigned|ownerless|no assigned owner|orphan", text):
            return "no_owner"
        if re.search(r"\btop\s+\w+|priorit|highest risk|most urgent", text):
            return "priorities"
        if re.search(r"\bwhy\b|reason|classified|justif|how serious|explain", text):
            return "explain" if has_context else None
        if re.search(r"non[- ]?compliant|violat|out of policy|failing policy", text) and (
                "pat" in _types(text) or re.search(r"\bpats?\b|token", text)):
            return "noncompliant"
        if re.search(r"remediat|recommend|how (do|can|should)|what should|steps|fix", text):
            return "guidance"
        if re.search(r"expir|\bdue\b|rotation", text):
            if re.search(r"how many|count|already|\bexpired\b", text) and not re.search(r"next|within|soon|upcoming|approach", text):
                return "expired"
            return "expiring" if re.search(r"next|within|soon|upcoming|approach|\d+\s*days?|week|month", text) else "expired"
        if re.search(r"critical|high[- ]risk|\bhigh\b|\bmedium\b|\blow\b|show (me )?all|list", text):
            return "critical_sps" if re.search(r"critical", text) and re.search(r"service principals?|\bsps?\b", text) else "list_findings"
        if ids or re.search(r"\b(sp|pat|app|aws|spc)-\d{3}\b", text):
            return "lookup"
        if re.search(r"help|what can you|capabilit|hello|^hi\b", text):
            return "help"
        if has_context and re.search(r"owner|who|status|approval|when|more|detail|what next|that|\bit\b|this", text):
            return "explain"
        return None

    # -- helpers ----------------------------------------------------------------------------------------------
    def _reply(self, intent, answer, references=None, context=None):
        return dict(intent=intent, answer=answer, references=references or [], context=context or {})

    def _ref(self, row):
        return dict(type="finding", finding_id=row["finding_id"], asset_name=row["asset_name"], severity=row["severity"],
                    action_id=row.get("action_id"))

    def _line(self, row):
        owner = row["owner"] or "no owner"
        expiry = ""
        if row["expiry_date"] is not None:
            delta = (row["expiry_date"] - self.workspace.today).days
            expiry = f", expired {-delta} day(s) ago" if delta < 0 else f", expires in {delta} day(s)"
        return (f"- **{row['finding_id']}** · {row['type_label']} `{row['asset_name']}` — **{row['risk_level']}** — "
                f"{row['title']} ({owner}{expiry}). Status: {row['remediation_status']}.")

    def _finding_list(self, rows, empty):
        if not rows:
            return empty, []
        return "\n".join(self._line(row) for row in rows), [self._ref(row) for row in rows]

    def _target(self, ids, context):
        for identity in ids:
            try:
                return self.workspace.finding(identity)
            except KeyError:
                continue
        if ids:
            return None
        if context.get("finding_id"):
            return self.workspace.finding(context["finding_id"])
        return None

    def _asset_finding(self, lowered):
        """Open finding for an asset ID or name mentioned in the text, if any."""
        for item in self.workspace.assets():
            if item["id"].casefold() in lowered or item["name"].casefold() in lowered:
                return next((r for r in self.workspace.findings() if r["asset_id"] == item["id"]), None)
        return None

    def _context_for(self, rows):
        return {"finding_id": rows[0]["finding_id"]} if len(rows) == 1 else {}

    # -- handlers ---------------------------------------------------------------------------------------------
    def _score(self, text, lowered, ids, context):
        m = self.workspace.metrics()
        sev = m["severity_counts"]
        answer = (f"The governance score is **{m['governance_score']} / 100** and **{m['compliance_percentage']}%** of the "
                  f"{m['governed_assets']} governed assets are fully compliant.\n\n"
                  f"- {m['open_findings']} open findings: {sev['critical']} critical, {sev['high']} high, "
                  f"{sev['medium']} medium, {sev['low']} low\n- {m['expired_credentials']} expired credentials, "
                  f"{m['expiring_30d']} expiring within 30 days\n- {m['open_actions']} remediation actions in progress\n\n"
                  "In plain terms: most assets are healthy, but a small number of production credentials need attention soon.")
        return self._reply("score", answer)

    def _expired(self, text, lowered, ids, context):
        rows = [row for row in self.workspace.findings() if row["expiry_date"] is not None
                and row["expiry_date"] < self.workspace.today]
        expired_all = [a for a in self.workspace.asset_assessments() if a["is_credential"]
                       and a["days_to_expiry"] is not None and a["days_to_expiry"] < 0]
        names = ", ".join(f"`{a['name']}`" for a in expired_all) or "none"
        body, refs = self._finding_list(rows, "No expired credentials have open findings.")
        answer = f"**{len(expired_all)}** credential(s) are expired: {names}.\n\n{body}"
        return self._reply("expired", answer, refs, self._context_for(rows))

    def _expiring(self, text, lowered, ids, context):
        window = _days(lowered) or 7
        today = self.workspace.today
        due = [a for a in self.workspace.asset_assessments() if a["is_credential"] and a["days_to_expiry"] is not None
               and 0 <= a["days_to_expiry"] <= window]
        rotations = [a for a in self.workspace.asset_assessments() if a["credential_type"] == "aws_secret"
                     and a["extra"]["next_rotation"] is not None and 0 <= (a["extra"]["next_rotation"] - today).days <= window]
        by_asset = {row["asset_id"]: row for row in self.workspace.findings()}
        lines, refs = [], []
        for item in sorted(due, key=lambda a: a["days_to_expiry"]):
            row = by_asset.get(item["id"])
            lines.append(f"- {'**' + row['finding_id'] + '** · ' if row else ''}{item['type_label']} `{item['name']}` — "
                         f"expires in {item['days_to_expiry']} day(s) ({item['expiry_date']}), owner: {item['owner'] or 'none'}.")
            refs.append(self._ref(row) if row else dict(type="asset", asset_name=item["name"], asset_id=item["id"]))
        for item in rotations:
            row = by_asset.get(item["id"])
            lines.append(f"- {'**' + row['finding_id'] + '** · ' if row else ''}AWS secret `{item['name']}` — rotation due in "
                         f"{(item['extra']['next_rotation'] - today).days} day(s).")
            refs.append(self._ref(row) if row else dict(type="asset", asset_name=item["name"], asset_id=item["id"]))
        if not lines:
            return self._reply("expiring", f"No credentials expire within the next {window} days.")
        return self._reply("expiring", f"**{len(due)}** credential(s) expire and **{len(rotations)}** AWS secret(s) are due "
                                       f"for rotation within the next {window} days:\n\n" + "\n".join(lines), refs)

    def _no_owner(self, text, lowered, ids, context):
        kinds = _types(lowered)
        assets = [a for a in self.workspace.asset_assessments() if not a["owner"] and (not kinds or a["credential_type"] in kinds)]
        if "service_principal" in kinds and len(kinds) == 1:
            assets = [a for a in assets if a["credential_type"] == "service_principal"]
        by_asset = {}
        for row in self.workspace.findings():
            by_asset.setdefault(row["asset_id"], row)
        lines, refs = [], []
        for item in assets:
            related = by_asset.get(item["id"])
            lines.append(f"- {item['type_label']} `{item['name']}` ({item['id']}, {item['environment']})"
                         + (f" — see **{related['finding_id']}** ({related['risk_level']})." if related else "."))
            refs.append(self._ref(related) if related else dict(type="asset", asset_name=item["name"], asset_id=item["id"]))
        if not assets:
            return self._reply("no_owner", "Every matching asset has an accountable owner.")
        scope = "Service Principals" if kinds == ["service_principal"] else "assets"
        return self._reply("no_owner", f"**{len(assets)}** {scope} have no accountable owner:\n\n" + "\n".join(lines)
                           + "\n\nIn plain terms: nobody is responsible for rotating or retiring these, so issues can go unnoticed.",
                           refs)

    def _critical_sps(self, text, lowered, ids, context):
        assessed = self.workspace.asset_assessments()
        principals = {a["id"]: a for a in assessed if a["credential_type"] == "service_principal"}
        lines, refs = [], []
        by_asset = {row["asset_id"]: row for row in self.workspace.findings()}
        for identity, principal in principals.items():
            group = [principal] + [a for a in assessed if a["parent_id"] == identity and a["credential_type"] == "sp_secret"]
            critical = [a for a in group if a["risk_level"] == "critical"]
            if critical:
                row = by_asset.get(critical[0]["id"])
                lines.append(f"- `{principal['name']}` ({identity}) — critical via `{critical[0]['name']}`"
                             + (f" (**{row['finding_id']}**: {row['title']})." if row else "."))
                if row:
                    refs.append(self._ref(row))
        if not lines:
            return self._reply("critical_sps", "No Service Principals currently have critical findings.")
        return self._reply("critical_sps", f"**{len(lines)}** Service Principal(s) are critical:\n\n" + "\n".join(lines), refs)

    def _explain(self, text, lowered, ids, context):
        row = self._target(ids, context)
        if row is None:
            return self._fallback(text, lowered, ids, context)
        guide = self.workspace.guidance(row["finding_id"])
        action = self.workspace.action_for_finding(row["finding_id"])
        sentence = f"Action **{action['id']}**: {action['status_label']}." if action else "No remediation action has been requested yet."
        if re.search(r"owner|who owns|accountable", lowered):
            body = f"Owner: **{row['owner'] or 'Unassigned'}**."
        elif re.search(r"status|approval|progress", lowered):
            body = f"{sentence} Approval: {row['approval_status']}."
        elif re.search(r"expire|when|due", lowered):
            body = f"Expiry date: **{row['expiry_date'] or 'none configured'}**. Last rotation: {row['last_rotation'] or 'no evidence'}."
        else:
            body = (f"**{row['finding_id']}** is classified **{row['risk_level']}** because: {guide['why_severity']}\n\n"
                    f"- Finding: {guide['summary']}\n- Policy: {guide['policy']}\n- Business impact: {guide['business_impact']}\n"
                    f"- Definition of {row['risk_level']}: {SEVERITY_DEFINITIONS[row['severity']]}\n- {sentence}")
        return self._reply("explain", body, [self._ref(row)], {"finding_id": row["finding_id"]})

    def _priorities(self, text, lowered, ids, context):
        count = 5
        match = re.search(r"top\s+(\w+)", lowered)
        if match:
            value = match.group(1)
            count = int(value) if value.isdigit() else _WORD_NUMBERS.get(value, 5)
        today = self.workspace.today

        def urgency(row):
            return (SEVERITY_ORDER.index(row["severity"]), 0 if row["environment"] == "Production" else 1,
                    (row["expiry_date"] - today).days if row["expiry_date"] else 9999, row["finding_id"])

        rows = sorted(self.workspace.findings(), key=urgency)[:max(1, min(count, 20))]
        body, refs = self._finding_list(rows, "No open findings.")
        return self._reply("priorities", f"Top {len(rows)} remediation priorities (ranked by severity, production exposure, "
                                         f"then time to expiry):\n\n{body}", refs, self._context_for(rows))

    def _sync(self, text, lowered, ids, context):
        issues = [a for a in self.workspace.asset_assessments() if a["credential_type"] == "aws_secret"
                  and a["extra"]["sync"] != "in_sync"]
        by_asset = {row["asset_id"]: row for row in self.workspace.findings(include_resolved=True)}
        total = sum(a["credential_type"] == "aws_secret" for a in self.workspace.assets())
        lines, refs = [], []
        for item in issues:
            row = by_asset.get(item["id"])
            state = "out of sync with Databricks" if item["extra"]["sync"] == "mismatch" else "synchronization unverified"
            lines.append(f"- AWS secret `{item['name']}` ({item['id']}) bound to {item['parent_id']} — {state}."
                         + (f" See **{row['finding_id']}** ({row['remediation_status']})." if row else ""))
            refs.append(self._ref(row) if row else dict(type="asset", asset_name=item["name"], asset_id=item["id"]))
        if not issues:
            return self._reply("sync", f"All {total} AWS secrets are synchronized with their Databricks credentials.")
        return self._reply("sync", f"**{len(issues)}** of {total} AWS secrets are not synchronized:\n\n" + "\n".join(lines)
                           + "\n\nSync status compares rotation metadata only; secret values are never read or shown.", refs)

    def _guidance(self, text, lowered, ids, context):
        row = self._target(ids, context)
        code = None
        if row is None:
            if "expired" in lowered and re.search(r"sp secret|service principal|oauth", lowered):
                code = "sp_secret_expired"
            elif "expir" in lowered and re.search(r"sp secret|service principal|oauth", lowered):
                code = "sp_secret_expiring"
            elif "expired" in lowered and re.search(r"pat|token", lowered):
                code = "pat_expired"
            elif re.search(r"pat|token", lowered):
                code = "pat_lifetime_exceeded"
            elif re.search(r"owner", lowered):
                code = "credential_no_owner"
            elif re.search(r"sync", lowered):
                code = "sync_mismatch"
            elif "orphan" in lowered:
                code = "sp_orphaned"
            if code is None:
                return self._fallback(text, lowered, ids, context)
            rows = [item for item in self.workspace.findings() if item["code"] == code]
            rule = RULES[code]
            steps = "\n".join(f"{i}. {step}" for i, step in enumerate(rule["steps"], 1))
            refs = [self._ref(item) for item in rows]
            affected = ", ".join(f"**{item['finding_id']}**" for item in rows) or "none currently open"
            return self._reply("guidance", f"Recommended remediation for **{rule['title'].lower()}** (open findings: {affected}):\n\n"
                                           f"{steps}\n\nRollback: {rule['rollback']}\n\n"
                                           "I can explain these steps but cannot execute them; open the finding to request approval.",
                               refs, self._context_for(rows))
        guide = self.workspace.guidance(row["finding_id"])
        steps = "\n".join(f"{item['Step']}. {item['Action']}" for item in guide["steps"])
        return self._reply("guidance", f"Recommended remediation for **{row['finding_id']}** (`{row['asset_name']}`):\n\n{steps}\n\n"
                                       f"Rollback: {guide['rollback']}\n\nI can explain these steps but cannot execute them; "
                                       "execution stays in the separately controlled approval workflow.",
                           [self._ref(row)], {"finding_id": row["finding_id"]})

    def _pending_actions(self, text, lowered, ids, context):
        actions = [a for a in self.workspace.actions() if a["approval"] == "pending"]
        if not actions:
            return self._reply("pending_actions", "No remediation actions are awaiting approval.")
        refs, lines = [], []
        for action in actions:
            row = self.workspace.finding(action["finding_id"])
            refs.append(dict(self._ref(row), action_id=action["id"]))
            lines.append(f"- **{action['id']}** for **{action['finding_id']}** — {action['action_label']} on "
                         f"`{action['asset_name']}` ({action['severity'].title()}), requested by {action['requested_by']}.")
        return self._reply("pending_actions", f"**{len(actions)}** remediation action(s) await approval:\n\n" + "\n".join(lines)
                           + "\n\nApprovals are recorded in the Remediation & Action Center, never by the Copilot.", refs)

    def _noncompliant(self, text, lowered, ids, context):
        pats = [a for a in self.workspace.asset_assessments() if a["credential_type"] == "pat" and a["policy_status"] != "Compliant"]
        by_asset = {row["asset_id"]: row for row in self.workspace.findings()}
        lines, refs = [], []
        for item in pats:
            row = by_asset[item["id"]]
            lines.append(f"- **{row['finding_id']}** · `{item['name']}` ({item['owner'] or 'no owner'}) — {row['title']}: "
                         f"{row['description']}")
            refs.append(self._ref(row))
        total = sum(a["credential_type"] == "pat" for a in self.workspace.assets())
        if not pats:
            return self._reply("noncompliant", f"All {total} PAT tokens are compliant.")
        return self._reply("noncompliant", f"**{len(pats)}** of {total} PAT tokens are non-compliant:\n\n" + "\n".join(lines), refs)

    def _severity_difference(self, text, lowered, ids, context):
        counts = self.workspace.metrics()["severity_counts"]
        answer = (f"- **Critical** ({counts['critical']} open): {SEVERITY_DEFINITIONS['critical']}\n"
                  f"- **High** ({counts['high']} open): {SEVERITY_DEFINITIONS['high']}\n\n"
                  "In plain terms: critical means something is broken or unaccountable right now; high means it will "
                  "become a problem this week if left alone.")
        return self._reply("severity_difference", answer)

    def _list_findings(self, text, lowered, ids, context):
        severities = [level for level in SEVERITY_ORDER if re.search(rf"\b{level}\b", lowered)]
        kinds = _types(lowered)
        rows = self.workspace.findings(severity=severities or None, credential_type=kinds or None)
        label = " ".join(filter(None, [", ".join(severities), ", ".join(TYPE_LABELS[k] for k in kinds)])) or "open"
        body, refs = self._finding_list(rows, f"No {label} findings are open.")
        return self._reply("list_findings", f"**{len(rows)}** {label} finding(s):\n\n{body}", refs, self._context_for(rows))

    def _lookup(self, text, lowered, ids, context):
        row = self._target(ids, {})
        if row is None:
            for item in self.workspace.assets():
                if item["id"].casefold() in lowered or item["name"].casefold() in lowered:
                    related = [r for r in self.workspace.findings(include_resolved=True) if r["asset_id"] == item["id"]]
                    if related:
                        row = related[0]
                    else:
                        return self._reply("lookup", f"`{item['name']}` ({item['id']}) is **compliant** with no open findings.",
                                           [dict(type="asset", asset_name=item["name"], asset_id=item["id"])])
                    break
        if row is None:
            return self._fallback(text, lowered, ids, context)
        return self._explain(text, "", [row["finding_id"]], {})

    def _help(self, text, lowered, ids, context):
        return self._reply("help", "I answer questions about credential governance using the current dataset: scores, expiry, "
                                   "owners, findings, AWS synchronization, remediation guidance, and approval status. "
                                   "I explain and link to workflows, but I never change credentials.")

    def _fallback(self, text, lowered, ids, context):
        if ids:
            return self._reply("fallback", f"I could not find {', '.join(ids)} in the current dataset. "
                                           "Finding IDs look like SX-1001 to SX-1020.")
        return self._reply("fallback", "I could not map that question to the governance dataset. Try asking about the "
                                       "governance score, expired or expiring credentials, owners, a finding ID such as "
                                       "SX-1001, AWS synchronization, remediation priorities, or pending approvals.")

    def _refuse(self, ids, context, asset_row=None):
        row = self._target(ids, {}) if ids else (asset_row or self._target([], context))
        refs = [self._ref(row)] if row else []
        tail = (f" Open **{row['finding_id']}** to request approval; execution happens only after a separate approval, "
                f"and in Demo Mode it is simulated ({SIMULATION_LABEL}).") if row else (
            " Select a finding in the Remediation & Action Center to request approval.")
        return self._reply("refused", "I cannot change or rotate credentials, approve actions, or run remediation." + tail,
                           refs, {"finding_id": row["finding_id"]} if row else {})
