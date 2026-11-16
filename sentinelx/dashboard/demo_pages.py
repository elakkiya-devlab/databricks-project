"""Demo Mode pages. Every figure is computed from the shared DemoWorkspace; nothing reaches Databricks or AWS."""

import altair as alt
import pandas as pd
import streamlit as st
from shared import RISK_COLORS, metric_row, nav_button, navigate, risk_label, status_badge

from aws_page import aws_connection_page
from backend.demo.catalog import SEVERITY_DEFINITIONS, SEVERITY_ORDER, TYPE_LABELS
from backend.demo.copilot import SUGGESTED_QUESTIONS
from backend.demo.engine import APPROVER, DEMO_BADGE, OPERATOR, SIMULATION_LABEL, WorkflowError

ACTION_CENTER = "Remediation & Action Center"
COPILOT = "SentinelX AI Copilot"
CREDENTIAL_TYPES = [kind for kind in TYPE_LABELS if kind != "service_principal"]


def _date(value):
    return str(value) if value else "—"


def _expiry(item):
    days = item["days_to_expiry"]
    if item["expiry_date"] is None:
        return "No expiry"
    return f"Expired {-days}d ago" if days < 0 else ("Today" if days == 0 else f"In {days}d")


def _empty(message):
    st.info(message)


def _banner(ws):
    status_badge(f"{DEMO_BADGE.upper()} &nbsp; / &nbsp; SIMULATED APPROVALS &nbsp; / &nbsp; NO CLOUD WRITES")


def _finding_table(rows, height=330):
    st.dataframe(pd.DataFrame([{
        "Finding ID": row["finding_id"], "Asset Name": row["asset_name"], "Credential Type": row["type_label"],
        "Owner": row["owner"] or "Unassigned", "Risk Level": risk_label(row["severity"]),
        "Expiry Date": _date(row["expiry_date"]), "Finding": row["title"],
        "Recommended Remediation": row["recommended_action"], "Approval Status": row["approval_status"],
        "Remediation Status": row["remediation_status"]} for row in rows]),
        hide_index=True, width="stretch", height=height)


def open_finding(finding_id, screen="finding"):
    navigate(ACTION_CENTER, ac_screen=screen, ac_finding=finding_id)


def finding_picker(rows, key, label="Select a finding"):
    """Selectbox + shortcut buttons so every listed finding can be opened."""
    by_id = {row["finding_id"]: row for row in rows}
    chosen = st.selectbox(label, list(by_id), key=key,
                          format_func=lambda fid: f"{fid} — {by_id[fid]['asset_name']} ({by_id[fid]['title']})")
    return by_id[chosen]


def _open_buttons(finding_id, key):
    columns = st.columns(3)
    with columns[0]:
        st.button("Open finding", key=key + "-open", icon=":material/open_in_new:", on_click=open_finding, args=(finding_id,))
    with columns[1]:
        st.button("Remediation steps", key=key + "-steps", icon=":material/list_alt:", on_click=open_finding,
                  args=(finding_id, "steps"))
    with columns[2]:
        st.button("Ask AI", key=key + "-ask", icon=":material/smart_toy:", on_click=ask_ai, args=(finding_id,))


def ask_ai(finding_id):
    navigate(COPILOT, copilot_ctx={"finding_id": finding_id})


# ------------------------------------------------------------------------------------------------------------------
def executive_summary(ws):
    m = ws.metrics()
    metric_row([("Governance Score", f"{m['governance_score']} / 100"), ("Compliance", f"{m['compliance_percentage']}%"),
                ("Total Credentials", m["total_credentials"]), ("Expired Credentials", m["expired_credentials"])])
    metric_row([("High-Risk Assets", m["high_risk_assets"]), ("Open Remediation Actions", m["open_actions"]),
                ("Critical Findings", m["severity_counts"]["critical"]), ("Expiring within 30 days", m["expiring_30d"])])
    left, right = st.columns(2)
    with left:
        st.subheader("Risk distribution")
        data = pd.DataFrame([dict(Risk=level.title(), Assets=count) for level, count in m["risk_distribution"].items()])
        st.altair_chart(alt.Chart(data).mark_bar(cornerRadiusEnd=3).encode(
            x=alt.X("Assets:Q", title="Governed assets"), y=alt.Y("Risk:N", sort=[x.title() for x in SEVERITY_ORDER], title=None),
            color=alt.Color("Risk:N", scale=alt.Scale(domain=[x.title() for x in SEVERITY_ORDER],
                                                      range=[RISK_COLORS[x] for x in SEVERITY_ORDER]), legend=None),
            tooltip=["Risk:N", "Assets:Q"]).properties(height=240), width="stretch")
    with right:
        st.subheader("Governance by credential type")
        data = pd.DataFrame([dict(Type=item["type"], Score=item["score"], Compliant=f"{item['compliant']}/{item['total']}")
                             for item in m["by_type"]])
        st.altair_chart(alt.Chart(data).mark_bar(color="#167a72", cornerRadiusEnd=3).encode(
            x=alt.X("Score:Q", scale=alt.Scale(domain=[0, 100]), title="Governance score"),
            y=alt.Y("Type:N", sort="-x", title=None), tooltip=["Type:N", "Score:Q", "Compliant:N"]).properties(height=240),
            width="stretch")
    st.subheader("Priority findings")
    rows = ws.findings()[:8]
    if not rows:
        _empty("No open findings. All governed assets are compliant.")
        return
    _finding_table(rows, height=320)
    picked = finding_picker(rows, "exec-finding", "Open a priority finding")
    _open_buttons(picked["finding_id"], "exec")


def _asset_filters(assessed, key, kinds):
    columns = st.columns([2, 1, 1, 1, 1])
    query = columns[0].text_input("Search", key=key + "-q", placeholder="Name, ID, owner, or environment")
    chosen_kinds = columns[1].multiselect("Type", kinds, format_func=TYPE_LABELS.get, key=key + "-type")
    risks = columns[2].multiselect("Risk", SEVERITY_ORDER, format_func=str.title, key=key + "-risk")
    statuses = columns[3].multiselect("Compliance", ["Compliant", "At risk", "Non-compliant"], key=key + "-status")
    owners = sorted({item["owner"] or "Unassigned" for item in assessed})
    owner = columns[4].selectbox("Owner", ["All owners"] + owners, key=key + "-owner")
    term = query.casefold()
    return [item for item in assessed
            if (not chosen_kinds or item["credential_type"] in chosen_kinds)
            and (not risks or item["risk_level"] in risks) and (not statuses or item["policy_status"] in statuses)
            and (owner == "All owners" or (item["owner"] or "Unassigned") == owner)
            and term in " ".join(str(item[f] or "") for f in ("id", "name", "owner", "environment")).casefold()]


def _asset_rows(items):
    return pd.DataFrame([{
        "ID": item["id"], "Name": item["name"], "Credential Type": item["type_label"], "Owner": item["owner"] or "Unassigned",
        "Environment": item["environment"], "Risk": risk_label(item["risk_level"]), "Expiry": _expiry(item),
        "Expiry Date": _date(item["expiry_date"]), "Last Rotation": _date(item["last_rotation"]),
        "Compliance": item["policy_status"], "Score": item["score"], "Open Findings": ", ".join(item["open_findings"]) or "—"}
        for item in items])


def _asset_detail(ws, items, key):
    if not items:
        return
    by_id = {item["id"]: item for item in items}
    chosen = st.selectbox("Asset details", list(by_id), key=key + "-detail",
                          format_func=lambda identity: f"{identity} — {by_id[identity]['name']}")
    item = by_id[chosen]
    st.subheader(item["name"])
    st.caption(f"{item['type_label']} · {item['environment']} · {item['policy_status']}")
    st.dataframe(pd.DataFrame(ws.evidence(item["id"])), hide_index=True, width="stretch")
    if not item["open_findings"]:
        st.success("Compliant — no action required.")
        return
    rows = [ws.finding(fid) for fid in item["open_findings"]]
    _finding_table(rows, height=120)
    picked = finding_picker(rows, key + "-finding", "Open a finding for this asset")
    _open_buttons(picked["finding_id"], key)


def credential_governance(ws):
    assessed = [a for a in ws.asset_assessments() if a["is_credential"]]
    m = ws.metrics()
    metric_row([("Credentials", len(assessed)), ("Non-compliant", sum(a["policy_status"] != "Compliant" for a in assessed)),
                ("Expired", m["expired_credentials"]), ("Expiring ≤ 30 days", m["expiring_30d"]),
                ("Unassigned owner", sum(not a["owner"] for a in assessed))])
    st.subheader("Credential inventory")
    items = _asset_filters(assessed, "cred", CREDENTIAL_TYPES)
    if not items:
        _empty("No credentials match these filters.")
        return
    st.dataframe(_asset_rows(items), hide_index=True, width="stretch", height=380,
                 column_config={"Score": st.column_config.ProgressColumn("Score", min_value=0, max_value=100, format="%d")})
    st.caption(f"{len(items)} credentials shown / {len(assessed)} total")
    _asset_detail(ws, items, "cred")


def service_principals(ws):
    assessed = ws.asset_assessments()
    principals = [a for a in assessed if a["credential_type"] == "service_principal"]
    secrets = [a for a in assessed if a["credential_type"] == "sp_secret"]
    metric_row([("Service Principals", len(principals)), ("No owner", sum(not a["owner"] for a in principals)),
                ("Inactive", sum(not a["extra"]["active"] for a in principals)),
                ("Expiring secrets (30d)", sum(a["days_to_expiry"] is not None and 0 <= a["days_to_expiry"] <= 30 for a in secrets)),
                ("Expired secrets", sum(a["days_to_expiry"] is not None and a["days_to_expiry"] < 0 for a in secrets))])
    query = st.text_input("Search", key="sp-q", placeholder="Service principal, owner, or environment").casefold()
    rows = []
    for principal in principals:
        owned = [s for s in secrets if s["parent_id"] == principal["id"]]
        worst = min([principal["risk_level"]] + [s["risk_level"] for s in owned], key=SEVERITY_ORDER.index)
        row = {"ID": principal["id"], "Service Principal": principal["name"], "Owner": principal["owner"] or "Unassigned",
               "Environment": principal["environment"], "Status": "Active" if principal["extra"]["active"] else "Inactive",
               "Privileged": "Yes" if principal["extra"]["privileged"] else "No", "Last Used": _date(principal["last_used"]),
               "Secrets": len(owned), "Risk": risk_label(worst), "Open Findings": ", ".join(
                   principal["open_findings"] + [f for s in owned for f in s["open_findings"]]) or "—"}
        if query in " ".join(str(v) for v in row.values()).casefold():
            rows.append(row)
    if not rows:
        _empty("No service principals match this search.")
        return
    st.dataframe(pd.DataFrame(rows), hide_index=True, width="stretch", height=360)
    chosen = st.selectbox("Service principal details", [r["ID"] for r in rows], key="sp-detail",
                          format_func=lambda identity: f"{identity} — {next(r['Service Principal'] for r in rows if r['ID'] == identity)}")
    related = [a for a in assessed if a["id"] == chosen or a["parent_id"] == chosen and a["credential_type"] == "sp_secret"]
    st.subheader("Identity and credentials")
    st.dataframe(_asset_rows(related), hide_index=True, width="stretch")
    open_ids = [fid for a in related for fid in a["open_findings"]]
    if not open_ids:
        st.success("Compliant — no action required.")
        return
    findings = [ws.finding(fid) for fid in open_ids]
    _finding_table(findings, height=140)
    picked = finding_picker(findings, "sp-finding", "Open a finding for this principal")
    _open_buttons(picked["finding_id"], "sp")


def secret_governance(ws):
    today = ws.today
    assessed = {a["id"]: a for a in ws.asset_assessments()}
    secrets = [a for a in assessed.values() if a["credential_type"] == "aws_secret"]
    metric_row([("AWS secrets", len(secrets)), ("Out of sync / unverified", sum(a["extra"]["sync"] != "in_sync" for a in secrets)),
                ("Rotation disabled", sum(not a["extra"]["rotation_enabled"] for a in secrets)),
                ("Rotation due ≤ 7 days", sum(a["extra"]["next_rotation"] is not None
                                              and 0 <= (a["extra"]["next_rotation"] - today).days <= 7 for a in secrets)),
                ("Missing rotation evidence", sum(a["last_rotation"] is None for a in secrets))])
    st.caption("Sample AWS Secrets Manager metadata. Secret values are never collected or displayed.")
    rows = []
    for item in secrets:
        extra, bound = item["extra"], assessed.get(item["parent_id"])
        rows.append({"ID": item["id"], "Secret Name": item["name"], "Bound Databricks Credential": bound["name"] if bound else "—",
                     "Owner": item["owner"] or "Unassigned", "Environment": item["environment"],
                     "Rotation": "Enabled" if extra["rotation_enabled"] else "Disabled",
                     "Last Rotation": _date(item["last_rotation"]), "Next Rotation": _date(extra["next_rotation"]),
                     "Synchronization": extra["sync"].replace("_", " ").title(), "Risk": risk_label(item["risk_level"]),
                     "Open Findings": ", ".join(item["open_findings"]) or "—"})
    st.dataframe(pd.DataFrame(rows), hide_index=True, width="stretch", height=380)
    _asset_detail(ws, secrets, "secret")
    nav_button("Open AWS Integration", "AWS Integration", "secret-aws", icon=":material/cloud:")


def aws_integration(ws):
    secrets = []
    for item in ws.assets():
        if item["credential_type"] == "aws_secret":
            extra = item["extra"]
            secrets.append({"Secret": item["name"], "Region": extra["region"], "ARN (sample)": extra["arn"],
                            "Rotation": "Enabled" if extra["rotation_enabled"] else "Disabled",
                            "Last Rotation": _date(item["last_rotation"]), "Next Rotation": _date(extra["next_rotation"]),
                            "Sync": extra["sync"].replace("_", " ").title()})
    aws_connection_page(True, secrets)


def compliance_reports(ws):
    m = ws.metrics()
    metric_row([("Governance Score", f"{m['governance_score']} / 100"), ("Compliance", f"{m['compliance_percentage']}%"),
                ("Open Findings", m["open_findings"]), ("Total Findings", m["total_findings"])])
    st.caption(f"Generated {ws.today} from synthetic data · {m['governed_assets']} governed assets")
    st.subheader("Compliance by credential type")
    st.dataframe(pd.DataFrame([{"Credential Type": i["type"], "Assets": i["total"], "Compliant": i["compliant"],
                                "Compliance %": round(100 * i["compliant"] / i["total"], 1), "Governance Score": i["score"]}
                               for i in m["by_type"]]), hide_index=True, width="stretch")
    st.subheader("Findings by severity")
    st.dataframe(pd.DataFrame([{"Severity": risk_label(level), "Open": m["severity_counts"][level],
                                "Definition": SEVERITY_DEFINITIONS[level]} for level in SEVERITY_ORDER]),
                 hide_index=True, width="stretch")
    st.subheader("Export")
    left, right = st.columns(2)
    left.download_button("Download JSON", ws.report_json(), "sentinelx-demo-report.json", mime="application/json",
                         icon=":material/download:")
    right.download_button("Download CSV", ws.report_csv(), "sentinelx-demo-report.csv", mime="text/csv",
                          icon=":material/download:")


# ------------------------------------------------------------------------------------------------------------------
def copilot_page(ws, copilot):
    st.caption("Answers are calculated from the synthetic dataset. The Copilot explains findings and links to workflows; "
               "it never changes credentials or approves actions.")
    st.session_state.setdefault("copilot_messages", [])
    st.session_state.setdefault("copilot_ctx", {})
    focus = st.session_state.get("copilot_ctx", {}).get("finding_id")
    if focus:
        try:
            row = ws.finding(focus)
            st.info(f"Context: **{focus}** · {row['asset_name']} ({row['risk_level']}). Follow-up questions refer to this finding.")
            for index, question in enumerate([f"Why is {focus} classified as {row['severity']}?", "What are the remediation steps?",
                                              "Who owns it?"]):
                if st.button(question, key=f"copilot-ctx-{index}"):
                    st.session_state["copilot_pending"] = question
                    st.rerun()
        except KeyError:
            st.session_state["copilot_ctx"] = {}
    if st.button("Clear conversation", icon=":material/delete_sweep:"):
        st.session_state.update(copilot_messages=[], copilot_ctx={})
        st.rerun()

    st.markdown("**Suggested questions**")
    columns = st.columns(3)
    for index, suggestion in enumerate(SUGGESTED_QUESTIONS):
        if columns[index % 3].button(suggestion, key=f"copilot-suggestion-{index}", width="stretch"):
            st.session_state["copilot_pending"] = suggestion
            st.rerun()

    for number, message in enumerate(st.session_state["copilot_messages"]):
        with st.chat_message(message["role"]):
            st.markdown(message["content"])
            seen = set()
            for index, ref in enumerate(message.get("references", [])):
                fid = ref.get("finding_id")
                if not fid or fid in seen:
                    continue
                seen.add(fid)
                st.caption(f"{fid} · {ref['asset_name']}")
                row = st.columns(4)
                row[0].button(f"Open {fid}", key=f"cp-open-{number}-{index}", on_click=open_finding, args=(fid,))
                row[1].button("Remediation steps", key=f"cp-steps-{number}-{index}", on_click=open_finding, args=(fid, "steps"))
                row[2].button("Approval screen", key=f"cp-approve-{number}-{index}", on_click=open_finding, args=(fid, "approval"))
                if ref.get("action_id"):
                    row[3].button(f"Open {ref['action_id']}", key=f"cp-action-{number}-{index}", on_click=open_finding,
                                  args=(fid, "approval"))

    question = st.session_state.pop("copilot_pending", None) or st.chat_input("Ask about SentinelX findings, owners, expiry or approvals")
    if question:
        result = copilot.answer(question, st.session_state["copilot_ctx"])
        st.session_state["copilot_messages"] += [{"role": "user", "content": question},
                                                 {"role": "assistant", "content": result["answer"],
                                                  "references": result["references"]}]
        st.session_state["copilot_ctx"] = result["context"]
        st.rerun()


# ------------------------------------------------------------------------------------------------------------------
def _next_step(row):
    return {"none": "Request approval", "pending": "Awaiting approver", "approved": "Execute (simulated)",
            "rejected": "Review rejection"}[row["approval_state"]] if not row["resolved"] else "None — resolved"


def action_center(ws):
    screen = st.session_state.get("ac_screen", "list")
    finding_id = st.session_state.get("ac_finding")
    if screen != "list":
        try:
            ws.finding(finding_id)
        except KeyError:
            screen = "list"
    if screen == "list":
        return _action_list(ws)
    nav_button("Back to all findings", ACTION_CENTER, "ac-back", icon=":material/arrow_back:", ac_screen="list")
    {"finding": _finding_screen, "evidence": _evidence_screen, "steps": _steps_screen, "approval": _approval_screen,
     "audit": _audit_screen}[screen](ws, finding_id)


def _action_bar(finding, key):
    columns = st.columns(7)
    spec = [("View Finding", "finding", ":material/info:"), ("View Evidence", "evidence", ":material/fact_check:"),
            ("Ask AI", None, ":material/smart_toy:"), ("View Remediation Steps", "steps", ":material/list_alt:"),
            ("Request Approval", "approval", ":material/add_task:"), ("Execute Remediation", "approval", ":material/play_arrow:"),
            ("View Audit History", "audit", ":material/history:")]
    for column, (label, screen, icon) in zip(columns, spec):
        callback, args = (ask_ai, (finding["finding_id"],)) if screen is None else (open_finding, (finding["finding_id"], screen))
        column.button(label, key=f"{key}-{label}", icon=icon, on_click=callback, args=args, width="stretch")


def _action_list(ws):
    st.caption("Actionable findings from the synthetic dataset. Remediation here is simulated; no Databricks or AWS changes occur.")
    columns = st.columns(3)
    risks = columns[0].multiselect("Risk level", SEVERITY_ORDER, format_func=str.title, key="ac-risk")
    kinds = columns[1].multiselect("Credential type", list(TYPE_LABELS), format_func=TYPE_LABELS.get, key="ac-kind")
    flags = columns[2].multiselect("Status", ["Expired", "Expiring Soon", "Pending Approval", "Completed", "Unassigned Owner"],
                                   key="ac-flags")
    query = st.text_input("Search", key="ac-query", placeholder="Finding ID, asset, or owner")
    rows = ws.findings(severity=risks, credential_type=kinds, expired="Expired" in flags, expiring="Expiring Soon" in flags,
                       pending_approval="Pending Approval" in flags, completed="Completed" in flags,
                       unassigned="Unassigned Owner" in flags, query=query)
    if not rows:
        _empty("No findings match these filters.")
        return
    st.dataframe(pd.DataFrame([{
        "Finding ID": r["finding_id"], "Asset Name": r["asset_name"], "Credential Type": r["type_label"],
        "Owner": r["owner"] or "Unassigned", "Risk Level": risk_label(r["severity"]), "Expiry Date": _date(r["expiry_date"]),
        "Recommended Remediation": r["recommended_action"], "Approval Status": r["approval_status"],
        "Remediation Status": r["remediation_status"], "Action": _next_step(r)} for r in rows]),
        hide_index=True, width="stretch", height=380)
    st.caption(f"{len(rows)} findings")
    preselected = st.session_state.get("ac_finding")
    ids = [r["finding_id"] for r in rows]
    st.session_state.setdefault("ac-select", ids[0])
    if st.session_state["ac-select"] not in ids:
        st.session_state["ac-select"] = preselected if preselected in ids else ids[0]
    selected = finding_picker(rows, "ac-select")
    st.markdown(f"**{selected['title']}** — {selected['description']}")
    _action_bar(selected, "list")


def _finding_header(finding):
    st.title(f"{finding['finding_id']} — {finding['title']}")
    st.caption(f"{risk_label(finding['severity'])} · {finding['type_label']} · {finding['asset_name']} · {finding['environment']}")


def _finding_screen(ws, finding_id):
    guide = ws.guidance(finding_id)
    finding = guide["finding"]
    _finding_header(finding)
    status_badge(SIMULATION_LABEL, "warn")
    metric_row([("Risk", finding["risk_level"]), ("Owner", finding["owner"] or "Unassigned"),
                ("Expiry", _date(finding["expiry_date"])), ("Policy status", finding["policy_status"])])
    st.markdown(f"**Finding summary.** {guide['summary']}")
    st.markdown(f"**Affected identity or secret.** {guide['affected']}")
    st.markdown(f"**Why {finding['risk_level']}.** {guide['why_severity']}")
    st.markdown(f"**Business impact.** {guide['business_impact']}")
    st.markdown(f"**Applicable policy.** {guide['policy']}")
    st.markdown(f"**Current action status.** {guide['current_status']}")
    st.subheader("Evidence")
    st.dataframe(pd.DataFrame(guide["evidence"]), hide_index=True, width="stretch")
    st.subheader("Remediation guidance")
    st.markdown("**Recommended steps**\n\n" + "\n".join(f"{s['Step']}. {s['Action']}" for s in guide["steps"]))
    st.markdown("**Required permissions**\n\n" + "\n".join(f"- {p}" for p in guide["required_permissions"]))
    st.markdown(f"**Expected operational impact.** {guide['operational_impact']}")
    st.markdown(f"**Rollback / recovery.** {guide['rollback']}")
    _action_bar(finding, "detail")


def _evidence_screen(ws, finding_id):
    guide = ws.guidance(finding_id)
    _finding_header(guide["finding"])
    st.subheader("Evidence")
    st.dataframe(pd.DataFrame(guide["evidence"]), hide_index=True, width="stretch")
    st.caption("Evidence is metadata only. Secret values are never collected or displayed.")
    _action_bar(guide["finding"], "evidence")


def _steps_screen(ws, finding_id):
    guide = ws.guidance(finding_id)
    _finding_header(guide["finding"])
    status_badge(SIMULATION_LABEL, "warn")
    st.subheader("Recommended remediation steps")
    st.dataframe(pd.DataFrame(guide["steps"]), hide_index=True, width="stretch")
    st.markdown("**Required permissions**\n\n" + "\n".join(f"- {p}" for p in guide["required_permissions"]))
    st.markdown(f"**Expected operational impact.** {guide['operational_impact']}")
    st.markdown(f"**Rollback / recovery.** {guide['rollback']}")
    st.caption(f"Current status: {guide['current_status']}. In Demo Mode these steps simulate the workflow only.")
    _action_bar(guide["finding"], "steps")


def _approval_screen(ws, finding_id):
    finding = ws.finding(finding_id)
    _finding_header(finding)
    status_badge(SIMULATION_LABEL, "warn")
    action = ws.action_for_finding(finding_id)
    st.subheader("Approval and execution")
    st.caption(f"Simulated actors — requester: {OPERATOR}; approver: {APPROVER}. Approval and execution stay separate.")
    owner = None
    try:
        if finding["resolved"]:
            st.success(f"Resolved in simulation by {action['id']}. No cloud changes were performed.")
        elif action is None or action["status"] == "rejected":
            if action:
                st.warning(f"Previous request {action['id']} was rejected. {action.get('note') or ''}")
            if finding["action_type"] == "assign_owner":
                owner = st.text_input("Accountable owner", key="ac-owner", max_chars=120)
            st.markdown(f"Proposed action: **{finding['recommended_action']}**")
            if st.button("Request Approval (simulated)", key="ac-request", icon=":material/add_task:", type="primary"):
                created = ws.request_approval(finding_id, OPERATOR, owner)
                st.toast(f"{created['id']} created (simulated)")
                st.rerun()
        elif action["status"] == "awaiting_approval":
            st.info(f"**{action['id']}** is awaiting approval — requested by {action['requested_by']}.")
            columns = st.columns(2)
            if columns[0].button("Approve (simulated)", key="ac-approve", icon=":material/verified:", type="primary"):
                ws.decide(action["id"], True, APPROVER)
                st.rerun()
            if columns[1].button("Reject (simulated)", key="ac-reject", icon=":material/block:"):
                ws.decide(action["id"], False, APPROVER)
                st.rerun()
        elif action["status"] == "ready":
            st.success(f"**{action['id']}** is approved by {action['approver']} and ready for simulated execution.")
            confirmed = st.checkbox("I understand this simulates the change and performs no cloud writes.", key="ac-confirm")
            if st.button("Execute Remediation (simulated)", key="ac-execute", icon=":material/play_arrow:", type="primary",
                         disabled=not confirmed):
                ws.execute(action["id"], OPERATOR, confirmed)
                st.rerun()
    except WorkflowError as error:
        st.error(str(error))
    if finding["resolved"] or (action and action["status"] == "completed"):
        status_badge(SIMULATION_LABEL, "warn")
    _action_bar(finding, "approval")


def _audit_screen(ws, finding_id):
    finding = ws.finding(finding_id)
    _finding_header(finding)
    action = ws.action_for_finding(finding_id)
    st.subheader("Action history")
    if action is None:
        _empty("No remediation action has been requested for this finding yet.")
    else:
        st.caption(f"{action['id']} · {action['status_label']}")
        events = ws.audit(action["id"])
        if events:
            st.dataframe(pd.DataFrame(events), hide_index=True, width="stretch")
        else:
            _empty("No audit events recorded.")
    _action_bar(finding, "audit")


# ------------------------------------------------------------------------------------------------------------------
def audit_governance(ws):
    actions = ws.actions()
    metric_row([("Audit events", len(ws.audit())), ("Remediation actions", len(actions)),
                ("Awaiting approval", sum(a["approval"] == "pending" for a in actions)),
                ("Completed (simulated)", sum(a["status"] == "completed" for a in actions))])
    st.subheader("Remediation actions")
    st.dataframe(pd.DataFrame([{
        "Action ID": a["id"], "Finding": a["finding_id"], "Asset": a["asset_name"], "Action": a["action_label"],
        "Risk": risk_label(a["severity"]), "Approval": a["approval_label"], "Status": a["status_label"],
        "Requested By": a["requested_by"], "Approver": a["approver"] or "—"} for a in actions]),
        hide_index=True, width="stretch", height=320)
    by_id = {a["id"]: a for a in actions}
    chosen = st.selectbox("Open action", list(by_id), key="audit-action",
                          format_func=lambda identity: f"{identity} — {by_id[identity]['finding_id']} ({by_id[identity]['status_label']})")
    columns = st.columns(2)
    columns[0].button("View approval screen", key="audit-approval", on_click=open_finding, args=(by_id[chosen]["finding_id"], "approval"))
    columns[1].button("View audit history", key="audit-history", on_click=open_finding, args=(by_id[chosen]["finding_id"], "audit"))
    st.subheader("Audit history")
    st.caption("Synthetic events plus simulated events from this session. Events are not persisted.")
    st.dataframe(pd.DataFrame(ws.audit()), hide_index=True, width="stretch", height=300)
    if st.button("Reset demo data", key="audit-reset", icon=":material/restart_alt:"):
        ws.reset()
        st.session_state.pop("ac_screen", None)
        st.rerun()


def render(view, ws, copilot):
    _banner(ws)
    pages = {"Executive Summary": executive_summary, "Credential Governance": credential_governance,
             "Service Principals": service_principals, "Secret Governance": secret_governance,
             "AWS Integration": aws_integration, "Compliance Reports": compliance_reports,
             "Remediation & Action Center": action_center, "Audit & Governance": audit_governance}
    if view == COPILOT:
        copilot_page(ws, copilot)
    else:
        pages[view](ws)
