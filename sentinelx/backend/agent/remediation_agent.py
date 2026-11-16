"""SentinelPilot: a tool-using remediation agent whose only actions are validated backend calls.

The agent can inspect AWS Secrets Manager metadata, explain findings, prepare rotation plans (AWS only, or AWS plus
Databricks when a binding is declared) and run a plan that a human has approved. It cannot approve anything itself
(approval is a separate human-only method), never receives credentials or secret values, and reports only what the
backend verified. An optional language model interprets free-form requests into allowlisted tools and adds a short note
to backend facts; it never executes anything.
"""

import logging
import re
import uuid
from datetime import datetime, timezone

from backend.services.audit_sink import AuditUnavailable, MemoryAuditSink
from backend.services.aws_remediation import RemediationError

log = logging.getLogger("sentinelx.agent")

ARN = re.compile(r"arn:aws[\w-]*:secretsmanager:[\w-]+:\d{12}:secret:[\w/+=.@-]+")
NAME = re.compile(r"(?<![\w/])[\w.+=@-]+(?:/[\w.+=@-]+)+")
IDENT = re.compile(r"\b(?:SX-\d{4}|AWS-\d{3})\b", re.I)
ROTATE = re.compile(r"\b(rotate|rotation|renew|remediate|fix|refresh|update|sync|synchronize|synchronise)\b", re.I)
APPROVE = re.compile(r"\b(approve|approval|execute|run|go ahead|confirm|apply|commit)\b", re.I)
ROLLBACK = re.compile(r"\b(rollback|roll back|revert|undo)\b", re.I)
LIST = re.compile(r"\b(list|show|inventory|discover|which|what)\b.*\bsecrets?\b|\bsecrets?\b.*\b(list|inventory)\b", re.I)
STATUS = re.compile(r"\b(status|connect|connected|connection|login|log in|sign in|configured|aws)\b", re.I)

HELP = ("I can check the AWS connection, list Secrets Manager secrets, explain a finding, and prepare a rotation plan, for "
        "example **rotate sentinelx/prod/fivetran/credential** or **fix SX-1019**. Secrets bound to a Databricks credential are "
        "rotated on both platforms together. After you approve a plan, I carry it out through the controlled backend and "
        "verify the result. I can't approve plans, run commands, or see secret values.")
NEED_TARGET = "Which secret should I rotate? Give a secret name, ARN, or finding ID such as SX-1019."


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class RemediationAgent:
    def __init__(self, remediator, resolver=None, llm=None, knowledge=None, sink=None, session_id=None):
        self.remediator, self.resolver, self.llm, self.knowledge = remediator, resolver, llm, knowledge
        self.sink, self.session_id = sink or MemoryAuditSink(), session_id or uuid.uuid4().hex[:12]
        self.plans, self.audit, self.audit_errors = {}, [], []
        remediator.phase_listener = lambda plan, phase: self._record(
            "agent", "sync_phase", plan.secret_name, f"plan {plan.plan_id}: {phase}")

    # audit -----------------------------------------------------------------------------------------------------
    def _record(self, actor, event, target, detail, required=False):
        row = dict(event_id=uuid.uuid4().hex, at=_now(), session_id=self.session_id, actor=actor, event=event, target=target,
                   detail=str(detail)[:500])
        try:
            self.sink.append(row)
            row["persisted"] = self.sink.durable
        except AuditUnavailable as error:
            row["persisted"] = False
            self.audit_errors.append(str(error))
            log.warning("agent audit not persisted: %s", error)
            if required:
                raise RemediationError("The durable audit log is unavailable, so I will not make changes. " + str(error)) from error
        finally:
            self.audit.append({key: row.get(key) for key in ("at", "actor", "event", "target", "detail", "persisted")})

    # chat ------------------------------------------------------------------------------------------------------
    def handle(self, message, sso_credentials=None):
        """Return dict(answer, plan_id). Every path is a read or a plan; nothing here changes AWS or Databricks."""
        text = message.strip()
        if not text:
            return dict(answer=HELP, plan_id=None)
        reply = self._deterministic(text, sso_credentials)
        if reply is None and self.llm:
            reply = self._interpreted(text, sso_credentials)
        if reply is None:
            reply = dict(answer=NEED_TARGET if ROTATE.search(text) else HELP, plan_id=None)
        return reply

    def _deterministic(self, text, sso):
        unavailable = self.remediator.not_configured()
        if ROLLBACK.search(text):
            return self._refuse("Rollback changes credentials, so it needs a human decision. Use the **Roll back** button on the plan.", text)
        if ROTATE.search(text) and (ARN.search(text) or NAME.search(text) or IDENT.search(text)):
            return self._plan(text, unavailable, sso)
        if APPROVE.search(text) and not LIST.search(text):
            return self._approval_request(text)
        if unavailable and (LIST.search(text) or STATUS.search(text) or ROTATE.search(text)):
            return self._unavailable(unavailable)
        if LIST.search(text):
            return self._list(sso)
        if STATUS.search(text):
            return self._status(sso)
        return None

    def _interpreted(self, text, sso):
        decision = self.llm.interpret(text)
        if not decision:
            return None
        tool, target = decision["tool"], decision["target"]
        unavailable = self.remediator.not_configured()
        if tool == "ask_governance":
            return dict(answer=self.knowledge(text), plan_id=None) if self.knowledge else None
        if tool == "help":
            return dict(answer=HELP, plan_id=None)
        if tool == "explain_finding" and target and IDENT.search(target) and self.resolver:
            resolved = self.resolver(IDENT.search(target).group(0).upper())
            note = (resolved or {}).get("explanation") or (resolved or {}).get("unsupported")
            return dict(answer=note or "I couldn't find that finding in the governance dataset.", plan_id=None)
        if unavailable:
            return self._unavailable(unavailable)
        if tool == "aws_status":
            return self._status(sso)
        if tool == "list_secrets":
            return self._list(sso)
        if tool == "plan_rotation" and target:
            resolved = self._match_secret(target, sso)
            return resolved if isinstance(resolved, dict) else self._plan(resolved, unavailable, sso)
        return None

    def _match_secret(self, target, sso):
        if ARN.search(target) or NAME.search(target) or IDENT.search(target):
            return f"rotate {target}"
        try:
            names = [row["name"] for row in self.remediator.list_secrets(sso, limit=200) if target.lower() in row["name"].lower()]
        except RemediationError as error:
            return dict(answer=f"I could not look up secrets: {error}", plan_id=None)
        if len(names) == 1:
            return f"rotate {names[0]}"
        if not names:
            return dict(answer=f"I couldn't find a secret matching `{target}`.", plan_id=None)
        return dict(answer="Several secrets match; which one do you mean?\n" + "\n".join(f"- `{name}`" for name in names[:8]), plan_id=None)

    def _unavailable(self, reason):
        return dict(answer=f"**AWS is not configured.** {reason}", plan_id=None)

    def _refuse(self, answer, text):
        self._record("agent", "refused", "-", text[:80])
        return dict(answer=answer, plan_id=None)

    def _approval_request(self, text):
        pending = [plan for plan in self.plans.values() if plan.status in {"proposed", "approved"}]
        self._record("agent", "approval_not_self_service", "-", text[:80])
        if not pending:
            return dict(answer="There is no plan to run. Ask me to rotate a secret first.", plan_id=None)
        return dict(answer="I can't approve plans myself. Review the plan and use **Approve and execute**; once a human "
                           "approves, I run exactly that plan and verify it.", plan_id=pending[-1].plan_id)

    def _status(self, sso):
        try:
            self.remediator.list_secrets(sso, limit=1)
        except RemediationError as error:
            return dict(answer=f"AWS is configured but I could not connect: {error}", plan_id=None)
        blockers = self.remediator.blockers()
        suffix = "Execution is ready." if not blockers else "Planning is available, but execution is blocked: " + blockers[0]
        sync = self.remediator.sync
        bound = f" {len(sync.bindings)} Databricks binding(s) are declared." if sync and sync.bindings else ""
        return dict(answer=f"AWS is connected and Secrets Manager is readable. {suffix}{bound}", plan_id=None)

    def _list(self, sso):
        try:
            rows = self.remediator.list_secrets(sso)
        except RemediationError as error:
            return dict(answer=f"I could not list secrets: {error}", plan_id=None)
        if not rows:
            return dict(answer="AWS is connected, but the account has no secrets I can see.", plan_id=None)
        sync = self.remediator.sync

        def tag(row):
            return " · bound to Databricks" if sync and sync.binding_for(row["name"], row["arn"]) else ""

        lines = [f"- `{row['name']}` · rotation {'on' if row['rotation_enabled'] else 'off'} · {row['agent_scope']}{tag(row)}"
                 for row in rows[:15]]
        more = f"\n…and {len(rows) - 15} more." if len(rows) > 15 else ""
        return dict(answer=f"I found {len(rows)} secrets (names and metadata only):\n" + "\n".join(lines) + more, plan_id=None)

    def _plan(self, text, unavailable, sso):
        if unavailable:
            return dict(answer=f"**AWS is not configured.** {unavailable} I can't prepare a rotation plan until it is.", plan_id=None)
        finding_id, context = "", ""
        arn, name, ident = ARN.search(text), NAME.search(text), IDENT.search(text)
        if ident and self.resolver:
            resolved = self.resolver(ident.group(0).upper())
            if not resolved:
                return dict(answer=f"I couldn't find {ident.group(0).upper()} in the governance dataset.", plan_id=None)
            if resolved.get("unsupported"):
                return dict(answer=resolved["unsupported"], plan_id=None)
            target, finding_id, context = resolved["secret_name"], resolved.get("finding_id", ""), resolved.get("explanation", "")
        elif ident:
            return dict(answer="No governance dataset is attached, so give me the secret name or ARN.", plan_id=None)
        else:
            target = arn.group(0) if arn else name.group(0)
        try:
            plan = self.remediator.plan_rotation(target, sso, finding_id)
        except RemediationError as error:
            return dict(answer=f"I couldn't prepare a plan for `{target}`: {error}", plan_id=None)
        self.plans[plan.plan_id] = plan
        self._record("agent", "plan_created", plan.secret_name, f"{plan.strategy}; plan {plan.plan_id}")
        how = {"native_rotation": "It has rotation enabled, so I'll ask AWS to run its native rotation.",
               "cross_platform_sync": f"It is bound to a Databricks credential (`{plan.binding}`), so I would rotate the "
                                      "Databricks credential and keep AWS in step, validating before anything is promoted."
               }.get(plan.strategy, "Rotation isn't enabled, so I would write a newly generated random value as a new version.")
        ready = ("Review the plan below. Nothing changes until you approve it." if not plan.blockers
                 else "I can describe the plan, but execution is blocked: " + plan.blockers[0])
        answer = (f"{context}\n\n" if context else "") + f"I prepared plan `{plan.plan_id}` for `{plan.secret_name}`. {how} {ready}"
        facts = dict(kind="plan", outcome="proposed", secret=plan.secret_name, strategy=plan.strategy, finding=context[:300],
                     risks=plan.risks, blocked=bool(plan.blockers))
        return dict(answer=self._with_note(answer, facts), plan_id=plan.plan_id)

    def _with_note(self, answer, facts):
        note = self.llm.narrate(facts) if self.llm else None
        return f"{answer}\n\n*Pilot's note:* {note}" if note else answer

    # human decision and controlled execution ---------------------------------------------------------------------
    def approve(self, plan_id, actor):
        """Human-only entry point (called from an authenticated UI action, never from chat)."""
        plan = self._plan_for(plan_id, {"proposed"})
        if plan.blockers:
            raise RemediationError(plan.blockers[0])
        self._record(actor, "approved", plan.secret_name, f"plan {plan.plan_id}", required=True)
        plan.status, plan.approved_by, plan.approved_at = "approved", actor, _now()

    def reject(self, plan_id, actor):
        plan = self._plan_for(plan_id, {"proposed"})
        plan.status = "rejected"
        self._record(actor, "rejected", plan.secret_name, f"plan {plan.plan_id}")

    def run(self, plan_id, sso_credentials=None):
        """Agent tool: execute an approved plan and describe what the backend verified."""
        plan = self._plan_for(plan_id, {"approved"})
        try:
            self._record("agent", "execution_started", plan.secret_name, f"plan {plan.plan_id}; approved by {plan.approved_by}",
                         required=True)
            result = self.remediator.execute(plan, sso_credentials)
        except RemediationError as error:
            self._record("agent", "execution_refused", plan.secret_name, str(error))
            return f"I did not make any change: {error}"
        self._record("agent", f"execution_{plan.status}", plan.secret_name, f"plan {plan.plan_id}: {result['message']}")
        facts = dict(kind="result", outcome=result["outcome"], secret=plan.secret_name, strategy=plan.strategy,
                     detail=result["message"], rollback_available=bool(plan.status in {"executed", "failed"} and result.get("changed")))
        return self._with_note(self._explain(plan, result), facts)

    def rollback(self, plan_id, actor, sso_credentials=None):
        plan = self._plan_for(plan_id, {"executed", "failed"})
        try:
            self._record(actor, "rollback_started", plan.secret_name, f"plan {plan.plan_id}", required=True)
            result = self.remediator.rollback(plan, sso_credentials)
        except RemediationError as error:
            self._record(actor, "rollback_refused", plan.secret_name, str(error))
            return f"Rollback was not performed: {error}"
        self._record(actor, "rolled_back", plan.secret_name, f"plan {plan.plan_id}: {result['message']}")
        return f"Rolled back `{plan.secret_name}`. {result['message']}"

    def persisted_audit(self, limit=200):
        """Read the durable trail (Delta) when configured; raises AuditUnavailable if it cannot be read."""
        return self.sink.read(limit) if self.sink.durable else []

    def _plan_for(self, plan_id, statuses):
        plan = self.plans.get(plan_id)
        if not plan or plan.status not in statuses:
            raise RemediationError("That plan is not in a state that allows this action.")
        return plan

    @staticmethod
    def _explain(plan, result):
        name, outcome = plan.secret_name, result["outcome"]
        if outcome == "succeeded":
            return (f"Done. `{name}` was rotated and the backend verified the result. {result['message']} "
                    f"Previous version: `{result.get('previous_version', '-')}`.")
        if outcome == "in_progress":
            return f"Rotation of `{name}` is **not yet confirmed**. {result['message']}"
        recovery = (" The previous credential is retained; you can use **Roll back**." if result.get("changed") and
                    (result.get("new_version") or result.get("receipt")) else
                    " Nothing was changed." if result.get("changed") is False else "")
        return f"Rotation of `{name}` **failed**. {result['message']}{recovery}"
