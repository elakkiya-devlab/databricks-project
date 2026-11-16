"""SentinelPilot AWS remediation agent panel (shared by Demo and Live modes)."""

import pandas as pd
import streamlit as st

from backend.agent.llm import AgentLanguageModel
from backend.agent.remediation_agent import RemediationAgent
from backend.demo.agent_context import make_resolver
from backend.services.audit_sink import AuditUnavailable, DeltaAuditSink, MemoryAuditSink
from backend.services.aws_connection import AwsConfig
from backend.services.aws_remediation import AwsRemediator, ExecutionConfig, RemediationError
from backend.services.databricks_sync import DatabricksSync

SUGGESTIONS = ["Is AWS configured?", "List my AWS secrets", "Rotate secret sentinelx/prod/fivetran/credential", "Fix SX-1019"]
STATUS_LABEL = {"proposed": "Awaiting approval", "approved": "Approved", "rejected": "Rejected", "executed": "Executed and verified",
                "in_progress": "Requested, not confirmed", "failed": "Failed", "rolled_back": "Rolled back"}


def _actor():
    try:
        return st.context.headers.get("X-Forwarded-Email") or "console.user (local session)"
    except Exception:  # noqa: BLE001 - headers are unavailable outside a served session
        return "console.user (local session)"


def execution_enabled():
    return ExecutionConfig.from_env().enabled and AwsConfig.from_env().configured


def _agent(ws, copilot=None):
    if "aws_agent" not in st.session_state:
        try:
            sink, sink_error = DeltaAuditSink.from_env() or MemoryAuditSink(), ""
        except ValueError as error:
            sink, sink_error = MemoryAuditSink(), str(error)
        remediator = AwsRemediator(AwsConfig.from_env(), ExecutionConfig.from_env(), sync=DatabricksSync.from_env())
        knowledge = (lambda question: copilot.answer(question, st.session_state.setdefault("copilot_ctx", {}))["answer"]
                     ) if copilot is not None else None
        agent = RemediationAgent(remediator, make_resolver(ws) if ws is not None else None, AgentLanguageModel.from_env(),
                                 knowledge, sink)
        agent.sink_error = sink_error
        st.session_state["aws_agent"] = agent
    return st.session_state["aws_agent"]


def _say(role, content, plan_id=None):
    st.session_state.setdefault("agent_messages", []).append(dict(role=role, content=content, plan_id=plan_id))


def _plan_card(agent, plan, sso):
    label = f"{plan.secret_name} · {STATUS_LABEL[plan.status]}" + (f" · {plan.finding_id}" if plan.finding_id else "")
    with st.expander(label, expanded=plan.status == "proposed"):
        st.caption(f"Plan {plan.plan_id} · strategy: {plan.strategy.replace('_', ' ')} · {plan.secret_arn}")
        st.markdown("**Steps**\n" + "\n".join(f"{i}. {text}" for i, text in enumerate(plan.steps, 1)))
        st.markdown("**Verification**\n" + "\n".join(f"- {text}" for text in plan.verification))
        st.markdown("**Risks**\n" + "\n".join(f"- {text}" for text in plan.risks))
        if plan.approved_by:
            st.caption(f"Approved by {plan.approved_by} at {plan.approved_at}")
        if plan.result:
            show = {"succeeded": st.success, "in_progress": st.warning}.get(plan.result.get("outcome"), st.error)
            show(plan.result.get("message", "Execution in progress."))
        if plan.status == "proposed":
            for blocker in plan.blockers:
                st.warning(blocker)
            confirm = st.checkbox("I approve this exact plan and understand the risks above.", key=f"agent-confirm-{plan.plan_id}",
                                  disabled=bool(plan.blockers))
            approve, reject, _ = st.columns([2, 1, 3])
            if approve.button("Approve and execute", key=f"agent-approve-{plan.plan_id}", type="primary", icon=":material/verified:",
                              disabled=bool(plan.blockers) or not confirm):
                try:
                    agent.approve(plan.plan_id, _actor())
                    _say("assistant", agent.run(plan.plan_id, sso), plan.plan_id)
                except RemediationError as error:
                    _say("assistant", f"I did not make any change: {error}", plan.plan_id)
                st.rerun()
            if reject.button("Reject", key=f"agent-reject-{plan.plan_id}", icon=":material/cancel:"):
                agent.reject(plan.plan_id, _actor())
                _say("assistant", f"Plan `{plan.plan_id}` was rejected. No change was made.", plan.plan_id)
                st.rerun()
        elif plan.strategy in {"generated_value", "cross_platform_sync"} and plan.status in {"executed", "failed"} \
                and plan.result.get("changed"):
            if st.button("Roll back to previous credential", key=f"agent-rollback-{plan.plan_id}", icon=":material/undo:"):
                _say("assistant", agent.rollback(plan.plan_id, _actor(), sso), plan.plan_id)
                st.rerun()


def _platform_status(agent):
    sync, sink = agent.remediator.sync, agent.sink
    parts = [f"Databricks bindings: {len(sync.bindings)}" if sync and sync.bindings else "Databricks bindings: none",
             "Language model: on" if agent.llm else "Language model: off (deterministic routing)",
             f"Audit: Delta table `{sink.name}`" if sink.durable else "Audit: session only (set SENTINELX_AUDIT_TABLE to persist)"]
    st.caption(" · ".join(parts))
    for problem in [getattr(agent, "sink_error", ""), sync.config_error if sync else ""]:
        if problem:
            st.warning(problem)


def _audit_section(agent):
    if agent.audit_errors:
        st.error("Some audit events could not be written to the durable log: " + agent.audit_errors[-1])
    if agent.audit:
        with st.expander("Agent audit log (no secret values are recorded)"):
            st.dataframe(pd.DataFrame(agent.audit[::-1]), hide_index=True, width="stretch")
    if agent.sink.durable:
        with st.expander("Persisted audit trail (Delta)"):
            if st.button("Load latest events", key="agent-audit-load", icon=":material/history:"):
                try:
                    st.session_state["agent_persisted"] = agent.persisted_audit()
                except AuditUnavailable as error:
                    st.error(str(error))
            if st.session_state.get("agent_persisted"):
                st.dataframe(pd.DataFrame(st.session_state["agent_persisted"]), hide_index=True, width="stretch")


def agent_panel(ws=None, copilot=None):
    agent = _agent(ws, copilot)
    sso = st.session_state.get("aws_sso_creds")
    config, execution = AwsConfig.from_env(), ExecutionConfig.from_env()

    st.caption("SentinelPilot prepares rotation plans, and after you approve one it carries it out through controlled backend "
               "tools. It never sees AWS credentials or secret values and cannot approve its own plans.")
    if not config.configured:
        st.warning("**AWS is not configured.** Complete the AWS connection setup (AWS Integration page) before the agent can "
                   "reach Secrets Manager.")
    elif agent.remediator.blockers():
        st.info("Planning is available. Execution is blocked: " + agent.remediator.blockers()[0])
    else:
        st.success(f"Execution enabled for secrets under: {', '.join(execution.allowed_prefixes)}")
    _platform_status(agent)

    columns = st.columns(len(SUGGESTIONS))
    for column, text in zip(columns, SUGGESTIONS):
        if column.button(text, key=f"agent-suggest-{text}", width="stretch"):
            st.session_state["agent_pending"] = text
            st.rerun()

    for message in st.session_state.get("agent_messages", []):
        with st.chat_message(message["role"]):
            st.markdown(message["content"])
    pending = [plan for plan in agent.plans.values() if plan.status == "proposed"]
    if pending:
        st.markdown("**Plans awaiting your decision**")
        for plan in pending:
            _plan_card(agent, plan, sso)

    question = st.session_state.pop("agent_pending", None) or st.chat_input("Ask SentinelPilot, e.g. rotate sentinelx/prod/app/key")
    if question:
        _say("user", question)
        reply = agent.handle(question, sso)
        _say("assistant", reply["answer"], reply["plan_id"])
        st.rerun()

    history = [plan for plan in agent.plans.values() if plan.status != "proposed"]
    if history:
        st.markdown("**Plan history**")
        for plan in reversed(history):
            _plan_card(agent, plan, sso)
    _audit_section(agent)
