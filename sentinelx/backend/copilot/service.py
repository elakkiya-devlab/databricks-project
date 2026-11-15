from typing import Protocol


SUGGESTED_QUESTIONS = [
    "What is the current governance score?",
    "What are the critical compliance findings?",
    "Which service-principal secrets are expired?",
    "Which credentials are approaching expiry?",
    "Which credentials have no assigned owner?",
    "What are the top five remediation priorities?",
    "Which PATs violate the configured age policy?",
    "Are mapped AWS and Databricks secrets synchronized?",
    "Which remediation actions are pending approval?",
]

_INTENTS = {"score", "critical", "high", "expired", "expiring", "unowned", "priority",
            "pat_age", "synchronization", "pending_actions", "explain", "guidance"}


class IntentProvider(Protocol):
    def classify(self, question: str, allowed_intents: tuple[str, ...]) -> str | None:
        """Return one allowed intent; implementations must not generate compliance facts."""


def _intent(question):
    text = question.casefold()
    if "score" in text or "compliance percentage" in text or "compliant percentage" in text:
        return "score"
    if "pending" in text and ("approval" in text or "action" in text or "remediation" in text):
        return "pending_actions"
    if "synchron" in text or "sync" in text or "drift" in text:
        return "synchronization"
    if "pat" in text and any(word in text for word in ("age", "old", "stale", "policy", "violate")):
        return "pat_age"
    if any(word in text for word in (
            "ownerless", "unassigned owner", "without an owner", "no assigned owner",
            "don't have an assigned owner", "do not have an assigned owner", "unowned")):
        return "unowned"
    if any(word in text for word in ("top ", "priorit", "highest risk")):
        return "priority"
    if "expir" in text and any(word in text for word in ("approach", "upcoming", "soon", "within", "near")):
        return "expiring"
    if "expired" in text:
        return "expired"
    if any(word in text for word in ("why", "reason", "classified", "evidence")):
        return "explain"
    if any(word in text for word in ("recommend", "remediation step", "how do i remediate", "what should i do")):
        return "guidance"
    if "critical" in text:
        return "critical"
    if "high risk" in text or "high-risk" in text:
        return "high"
    return None


class ComplianceCopilot:
    def __init__(self, intent_provider=None):
        self.intent_provider = intent_provider

    def answer(self, question, findings, summary, actions, inventory, report_at, context_finding_id=None):
        text = question.strip()
        lowered = text.casefold()
        if "my team" in lowered or "my group" in lowered:
            return self._result(
                "Team-scoped results are unavailable: SentinelX has role-based API keys but no authenticated user-to-team mapping. Use the owner filter where owner metadata is available.",
                [], report_at, supported=False,
            )

        intent = _intent(text)
        if intent is None and self.intent_provider:
            candidate = self.intent_provider.classify(text, tuple(sorted(_INTENTS)))
            if candidate in _INTENTS:
                intent = candidate
        if intent is None and context_finding_id and any(
                word in lowered for word in ("why", "explain", "more", "details", "recommend", "what next", "steps")):
            intent = "explain"

        if intent == "score":
            latest = summary.get("latest")
            if not latest:
                return self._result("No successful compliance report is available yet.", [], report_at, supported=False)
            answer = (f"The current governance score is {latest['score']} / 100 and compliance is "
                      f"{latest['compliance_percentage']}% across {latest['total']} discovered assets. "
                      f"The report timestamp is {latest['at']}.")
            return self._result(answer, [self._report_reference(latest["at"])], latest["at"])

        if intent == "pending_actions":
            pending = [item for item in actions if item.get("status") == "pending"]
            approved = [item for item in actions if item.get("status") == "approved"]
            refs = [self._action_reference(item) for item in pending[:10] + approved[:10]]
            if not refs:
                answer = "There are no pending-approval or approved remediation actions in the current action store."
            else:
                answer = f"There are {len(pending)} actions pending review/approval and {len(approved)} approved actions awaiting execution."
            return self._result(answer, refs, report_at)

        if intent == "synchronization":
            mapped = [item for item in inventory if item["asset"].get("binding")]
            states = {}
            for item in mapped:
                state = item["asset"].get("sync_state", "unverified")
                states[state] = states.get(state, 0) + 1
            relevant = [row for row in findings if row["code"].startswith("sync_")]
            if not mapped:
                answer = "No explicitly bound AWS/Databricks assets are present in the latest inventory, so synchronization cannot be assessed."
            else:
                answer = "Mapped metadata states: " + ", ".join(f"{key}={value}" for key, value in sorted(states.items()))
                answer += ". Metadata alignment does not prove that secret values are equal."
            return self._result(answer, self._finding_references(relevant[:10], report_at) or
                                ([self._report_reference(report_at)] if report_at else []), report_at)

        if intent in {"critical", "high", "expired", "expiring", "unowned", "priority", "pat_age"}:
            rows = list(findings)
            if intent in {"critical", "high"}:
                rows = [row for row in rows if row["severity"] == intent]
            elif intent == "expired":
                rows = [row for row in rows if row["code"] == "expired"]
                rows = self._filter_requested_kind(rows, lowered)
            elif intent == "expiring":
                rows = [row for row in rows if row["code"] in {"expires_7d", "expires_15d", "expires_30d"}]
                rows = self._filter_requested_kind(rows, lowered)
            elif intent == "unowned":
                rows = [row for row in rows if row["code"] == "missing_owner"]
            elif intent == "priority":
                rows = rows[:5]
            elif intent == "pat_age":
                rows = [row for row in rows if row["credential_type"] == "pat" and row["code"] == "stale"]
            if not rows:
                return self._result("No matching findings are present in the latest successful compliance report.",
                                    [self._report_reference(report_at)] if report_at else [], report_at)
            label = {"critical": "critical findings", "high": "high-risk findings", "expired": "expired credentials",
                     "expiring": "credentials approaching expiry", "unowned": "findings without an assigned owner",
                     "priority": "top remediation priorities", "pat_age": "PATs exceeding the configured age policy"}[intent]
            return self._result(
                f"Found {len(rows)} {label}: " + "; ".join(
                    f"{row['asset_name']} ({row['finding_id']}, {row['severity']}, {row['code']})"
                    for row in rows[:10]
                ),
                self._finding_references(rows[:10], report_at),
                report_at,
            )

        if intent in {"explain", "guidance"}:
            row = self._find_context(text, findings, context_finding_id)
            if not row:
                return self._result("Select a finding or include its asset name to retrieve grounded evidence and remediation guidance.",
                                    [], report_at, supported=False)
            evidence = row["evidence"]
            facts = []
            if evidence.get("days_remaining") is not None:
                facts.append(f"{evidence['days_remaining']} days until expiry")
            if evidence.get("age_days") is not None:
                facts.append(f"credential age {evidence['age_days']} days")
            if evidence.get("rotation_age_days") is not None:
                facts.append(f"{evidence['rotation_age_days']} days since recorded rotation")
            if evidence.get("sync_state"):
                facts.append(f"mapped metadata state {evidence['sync_state']}")
            evidence_text = "; ".join(facts) if facts else "the report lacks the relevant lifecycle metadata"
            action_text = ", ".join(row["supported_actions"]) if row["supported_actions"] else "no automatic remediation action is supported"
            answer = (f"{row['asset_name']} is classified {row['severity']} because finding {row['code']} "
                      f"was assessed (penalty {row['penalty']}). Evidence: {evidence_text}. "
                      f"Recommendation: {row['recommendation']} Supported action(s): {action_text}. "
                      f"{row['expected_operational_impact']} Rollback: {row['rollback']}")
            return self._result(answer, self._finding_references([row], report_at), report_at)

        return self._result(
            "I can answer questions about the current score, critical/high findings, expiry, ownership, PAT age, synchronization, remediation actions, and a selected finding. I do not have a configured Model Serving endpoint; answers are computed from SentinelX report data.",
            [], report_at, supported=False,
        )

    @staticmethod
    def _find_context(question, findings, context_finding_id):
        if context_finding_id:
            row = next((item for item in findings if item["finding_id"] == context_finding_id), None)
            if row:
                return row
        lowered = question.casefold()
        return next((row for row in findings if row["asset_name"].casefold() in lowered), None)

    @staticmethod
    def _filter_requested_kind(rows, question):
        normalized = question.replace("-", " ")
        if "service principal" in normalized or "sp secret" in normalized:
            return [row for row in rows if row["credential_type"] == "sp_secret"]
        if "pat" in normalized:
            return [row for row in rows if row["credential_type"] == "pat"]
        if "aws" in normalized:
            return [row for row in rows if row["credential_type"] == "aws_secret"]
        return rows

    @staticmethod
    def _finding_references(rows, report_at):
        return [dict(type="finding", finding_id=row["finding_id"],
                     asset_name=row["asset_name"], risk=row["severity"], code=row["code"],
                     report_reference=report_at) for row in rows]

    @staticmethod
    def _report_reference(report_at):
        return dict(type="report", report_reference=report_at)

    @staticmethod
    def _action_reference(action):
        return dict(type="remediation_action", action_id=action["id"],
                    asset_name=action.get("before", {}).get("name", "Unknown asset"),
                    status=action["status"], action=action["action"])

    def _result(self, answer, references, report_at, supported=True):
        return dict(answer=answer, references=references, report_reference=report_at,
                    supported=supported, answer_source="structured_report")
