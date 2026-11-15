import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlencode

import altair as alt
import httpx
import pandas as pd
import streamlit as st

st.set_page_config(page_title="SentinelX | Identity Governance", page_icon=":material/shield:", layout="wide")
API = os.getenv("SENTINELX_API_URL", "http://127.0.0.1:8000")
COLORS = {"compliant": "#23845c", "attention": "#c89916", "high": "#e87932", "critical": "#ce424b"}
LABELS = {"service_principal": "Service principals", "sp_secret": "SP secrets", "pat": "PATs", "oauth": "OAuth",
          "application_credential": "Application credentials", "databricks_secret": "Databricks secrets", "aws_secret": "AWS secrets"}
st.markdown("""<style>
@import url('https://fonts.googleapis.com/css2?family=Source+Sans+3:wght@400;500;600;700&family=IBM+Plex+Mono:wght@400;500&display=swap');
:root { --ink: #24282b; --accent: #167a72; --line: #e2e6e6; }
html, body, [class*="css"], [data-testid="stApp"] { font-family: 'Source Sans 3', sans-serif; letter-spacing: 0; }
[data-testid="stAppViewContainer"] { background: #fcfdfd; }
[data-testid="stSidebar"] { background: #f0f3f2; border-right: 1px solid var(--line); }
.block-container { padding-top: 2rem; padding-bottom: 2rem; max-width: 1500px; }
h1 { font-size: 2.1rem !important; font-weight: 700 !important; letter-spacing: 0 !important; }
h2 { font-size: 1.4rem !important; letter-spacing: 0 !important; }
h3 { font-size: 1.1rem !important; letter-spacing: 0 !important; }
[data-testid="stMetric"] { border-top: 2px solid var(--line); padding: 12px 0; }
[data-testid="stMetricValue"] { font-family: 'IBM Plex Mono', monospace; font-size: 2rem; }
.environment { border-left: 3px solid #167a72; padding: 7px 12px; background: #edf7f4; color: #286054; font-size: .9rem; }
.brandmark { color: #167a72; font-family: 'IBM Plex Mono', monospace; font-size: .78rem; font-weight: 500; }
[data-testid="stDataFrame"] { border: 1px solid var(--line); border-radius: 4px; }
[data-testid="stHeader"] { background: transparent; }
</style>""", unsafe_allow_html=True)


def api(path, method="GET", role="reader", payload=None, raw=False):
    try:
        response = httpx.request(method, API + path, headers={"X-API-Key": os.getenv(f"SENTINELX_{role.upper()}_KEY", "")},
                                 json=payload, timeout=60)
        if response.status_code >= 400:
            st.error(response.json().get("detail", "API operation failed"))
            return None
        return response.text if raw else response.json()
    except (httpx.HTTPError, ValueError):
        st.error("Governance API unavailable")
        return None


def command(path, role="operator", payload=None):
    if api(path, "POST", role, payload) is not None:
        st.toast("Governance action recorded", icon=":material/check_circle:")
        st.rerun()


def metrics(items, labels):
    for column, (label, value) in zip(st.columns(len(labels)), labels):
        column.metric(label, value)


def inventory(items, key, demo):
    st.subheader("Inventory")
    columns = st.columns([2, 1, 1])
    query = columns[0].text_input("Search", placeholder="Identity, application, or owner", key=key + "search")
    risks = columns[1].multiselect("Risk", list(COLORS), format_func=str.title, key=key + "risk")
    owners = sorted({item["asset"]["owner"] or "Unassigned" for item in items})
    owner = columns[2].selectbox("Owner", ["All owners"] + owners, key=key + "owner")
    filtered = [item for item in items if (not risks or item["assessment"]["risk"] in risks)
                and (owner == "All owners" or (item["asset"]["owner"] or "Unassigned") == owner)
                and query.lower() in " ".join(str(item["asset"].get(field) or "") for field in ("name", "owner", "application", "id")).lower()]
    rows = [dict(Name=item["asset"]["name"], Type=LABELS[item["asset"]["kind"]], Owner=item["asset"]["owner"] or "Unassigned",
                 Score=item["assessment"]["score"], Risk=item["assessment"]["risk"].title(),
                 Age=item["assessment"]["age_days"], Expiry=item["assessment"]["days_remaining"],
                 Findings=len(item["assessment"]["findings"])) for item in filtered]
    if not rows:
        st.info("No matching assets")
        return
    selection = st.dataframe(pd.DataFrame(rows), hide_index=True, width="stretch", height=350,
                 column_config={"Score": st.column_config.ProgressColumn("Score", min_value=0, max_value=100, format="%d"),
                                "Age": st.column_config.NumberColumn("Age (days)"),
                                "Expiry": st.column_config.NumberColumn("Expires in (days)", format="%.1f")},
                 on_select="rerun", selection_mode="single-row", key=key + "table")
    st.caption(f"{len(filtered)} assets / {len(items)} total")
    selected_index = selection.selection.rows[0] if selection.selection.rows else None
    by_id = {item["asset"]["id"]: item for item in filtered}
    selected_id = st.selectbox("Asset details", list(by_id), index=selected_index,
                               format_func=lambda identity: by_id[identity]["asset"]["name"], key=key + "details")
    if selected_id is None:
        return
    selected = by_id[selected_id]
    asset = selected["asset"]
    st.subheader(asset["name"])
    lifecycle = {"Owner": asset["owner"] or "Unassigned", "Created": asset["created_at"] or "Unknown",
                 "Expires": asset["expires_at"] or "Unknown / not applicable", "Last rotation": asset["last_rotated_at"] or "Unknown",
                 "Last used": asset["last_used_at"] or "Unknown", "Synchronization": asset["sync_state"]}
    st.dataframe(pd.DataFrame(lifecycle.items(), columns=["Lifecycle", "Evidence"]), hide_index=True, width="stretch")
    findings = selected["assessment"]["findings"]
    if findings:
        st.dataframe(pd.DataFrame(findings)[["code", "recommendation"]], hide_index=True, width="stretch")
    if demo:
        choices = ["assign_owner"]
        if asset["kind"] == "sp_secret":
            choices += ["renew_sp"]
        elif asset["kind"] in {"aws_secret", "databricks_secret"}:
            choices += ["rotate_secret", "sync_secret"]
        with st.form(key + "proposal"):
            st.subheader("Remediation request")
            action = st.selectbox("Action", choices, format_func=lambda value: value.replace("_", " ").title())
            assigned_owner = st.text_input("Accountable owner", value=asset["owner"] or "")
            if st.form_submit_button("Submit request", icon=":material/add_task:"):
                command("/actions", payload=dict(asset_id=asset["id"], action=action, owner=assigned_owner or None))


def distribution(items, column, title):
    st.subheader(title)
    data = pd.DataFrame([{column: LABELS[item["asset"]["kind"]] if column == "Type" else item["assessment"]["risk"],
                          "Score": item["assessment"]["score"]} for item in items])
    if data.empty:
        st.info("No evidence collected")
        return
    if column == "Risk":
        chart = alt.Chart(data).mark_bar(cornerRadiusEnd=3).encode(x=alt.X("count():Q", title="Assets"),
                    y=alt.Y("Risk:N", sort=list(COLORS), title=None),
                    color=alt.Color("Risk:N", scale=alt.Scale(domain=list(COLORS), range=list(COLORS.values())), legend=None),
                    tooltip=["Risk:N", "count():Q"])
    else:
        chart = alt.Chart(data).mark_bar(color="#167a72", cornerRadiusEnd=3).encode(
                    x=alt.X("mean(Score):Q", scale=alt.Scale(domain=[0, 100]), title="Governance score"),
                    y=alt.Y("Type:N", title=None, sort="-x"), tooltip=["Type:N", alt.Tooltip("mean(Score):Q", format=".1f")])
    st.altair_chart(chart.properties(height=240), width="stretch")


def queue(demo, enabled):
    actions = api("/actions") or []
    st.subheader("Remediation queue")
    if not actions:
        st.info("No remediation requests")
        return
    st.dataframe(pd.DataFrame([{key: action[key] for key in ("id", "asset_id", "action", "status", "requester", "approver", "reviewed")}
                              for action in reversed(actions)]), hide_index=True, width="stretch")
    if not demo:
        return
    by_id = {item["id"]: item for item in actions}
    selected_id = st.selectbox("Request", list(by_id), format_func=lambda identity:
                              f"{by_id[identity]['action']} / {by_id[identity]['asset_id']} / {by_id[identity]['status']}")
    item = by_id[selected_id]
    if item.get("plan"):
        st.json(item["plan"], expanded=False)
    columns = st.columns(5)
    base = "/actions/" + item["id"]
    if columns[0].button("Dry run", icon=":material/science:", disabled=item["status"] not in {"pending", "approved"}, width="stretch"):
        command(base + "/dry-run")
    if columns[1].button("Approve", icon=":material/verified:", disabled=item["status"] != "pending" or not item["reviewed"], width="stretch"):
        command(base + "/decision", "approver", {"approve": True})
    if columns[2].button("Reject", icon=":material/block:", disabled=item["status"] != "pending" or not item["reviewed"], width="stretch"):
        command(base + "/decision", "approver", {"approve": False})
    if columns[3].button("Execute", icon=":material/play_arrow:", type="primary", disabled=item["status"] != "approved" or not enabled, width="stretch"):
        command(base + "/execute", payload={"dry_run": False})
    if columns[4].button("Request rollback", icon=":material/undo:", disabled=item["status"] not in {"succeeded", "failed", "recovery_required"} or item["action"] == "rollback", width="stretch"):
        command("/actions", payload=dict(asset_id=item["asset_id"], action="rollback", original_id=item["id"]))


def navigate_to_copilot(finding_identity):
    st.session_state["copilot_context_finding_id"] = finding_identity
    st.session_state["workspace_view"] = "SentinelX AI Copilot"


def navigate_to_finding(finding_identity):
    st.session_state["action_center_requested_finding"] = finding_identity
    st.session_state["workspace_view"] = "Remediation & Action Center"


def navigate_to_reports():
    st.session_state["workspace_view"] = "Compliance Reports"


def action_center(health):
    st.caption("Findings below are derived from the latest successful SentinelX inventory and policy assessment.")
    if health["mode"] == "live":
        if health["remediation_enabled"]:
            st.info("Live execution is API-only: use separate authenticated operator and approver clients after a successful dry-run preflight. This dashboard is read-only.")
        else:
            st.warning("Live remediation is disabled by API configuration. No finding can trigger a provider write.")
    assets = api("/assets") or []
    owners = sorted({item["asset"]["owner"] for item in assets if item["asset"].get("owner")})
    filters = st.columns(5)
    risks = filters[0].multiselect("Risk severity", ["critical", "high", "medium", "low"])
    kinds = filters[1].multiselect("Credential type", list(LABELS), format_func=lambda value: LABELS[value])
    expiry = filters[2].selectbox("Expiry", ["Any", "Expired", "Expiring"])
    unassigned = filters[3].checkbox("Unassigned owner")
    owner = filters[4].selectbox("Owner", ["All owners"] + owners)
    pending = st.checkbox("Pending approval")
    statuses = st.multiselect("Remediation status", [
        "not_requested", "pending", "approved", "rejected", "running", "succeeded", "failed",
        "recovery_required", "rolled_back",
    ])
    params = {}
    if risks:
        params["risk"] = ",".join(risks)
    if kinds:
        params["kind"] = ",".join(kinds)
    if expiry == "Expired":
        params["expired"] = "true"
    elif expiry == "Expiring":
        params["expiring"] = "true"
    if unassigned:
        params["unassigned"] = "true"
    if owner != "All owners":
        params["owner"] = owner
    if pending:
        params["pending_approval"] = "true"
    if statuses:
        params["remediation_status"] = ",".join(statuses)
    page = st.session_state.get("action_center_page", 1)
    params.update(page=page, page_size=50)
    result = api("/compliance/findings?" + urlencode(params))
    if result is None:
        return
    focused_id = st.session_state.get("action_center_requested_finding")
    if focused_id:
        focused = api("/compliance/findings/" + focused_id)
        if focused:
            result = dict(items=[focused], total=1, page=1, page_size=50)
            if st.button("Show all filtered findings", icon=":material/arrow_back:"):
                st.session_state.pop("action_center_requested_finding", None)
                st.rerun()
        else:
            st.session_state.pop("action_center_requested_finding", None)
    page_columns = st.columns([1, 4, 1])
    if page_columns[0].button("Previous", disabled=page <= 1):
        st.session_state["action_center_page"] = page - 1
        st.rerun()
    page_columns[1].caption(f"Page {result['page']} · {result['total']} matching findings")
    if page_columns[2].button("Next", disabled=page * result["page_size"] >= result["total"]):
        st.session_state["action_center_page"] = page + 1
        st.rerun()
    rows = result["items"]
    if not rows:
        st.info("No findings match these filters.")
        return
    st.dataframe(pd.DataFrame([{
        "Finding ID": row["finding_id"],
        "Asset / Credential": row["asset_name"],
        "Type": LABELS.get(row["credential_type"], row["credential_type"]),
        "Workspace / Environment": row["environment"],
        "Owner": row["owner"] or "Unassigned",
        "Risk": row["severity"].title(),
        "Finding": row["title"],
        "Expiry": row["expiry_date"] or "Unknown",
        "Recommended remediation": row["recommendation"],
        "Remediation status": row["remediation_status"],
        "Approval status": row["approval_status"],
        "Last updated": row["last_updated"] or "Unknown",
    } for row in rows]), hide_index=True, width="stretch", height=360)
    by_id = {row["finding_id"]: row for row in rows}
    selected_id = st.selectbox("Select a finding", list(by_id),
                               format_func=lambda identity: f"{by_id[identity]['asset_name']} — {by_id[identity]['title']}")
    selected = by_id[selected_id]
    st.subheader(selected["title"])
    st.write(f"**{selected['asset_name']}** · {selected['severity'].title()} · `{selected['finding_id']}`")
    st.write(selected["description"])
    st.write("**Recommended remediation:** " + selected["recommendation"])
    st.caption(f"Report reference: {selected['report_reference'] or 'not available'}")

    controls = st.columns(6)
    if controls[0].button("View Details", icon=":material/info:"):
        st.session_state["action_center_details"] = selected_id
    if controls[1].button("View Evidence", icon=":material/fact_check:"):
        st.session_state["action_center_evidence"] = selected_id
    controls[2].button("Ask AI", icon=":material/smart_toy:", on_click=navigate_to_copilot, args=(selected_id,))
    if controls[3].button("View Remediation Steps", icon=":material/list_alt:"):
        st.session_state["action_center_steps"] = selected_id
    if controls[4].button("View Execution History", icon=":material/history:", disabled=not selected.get("action_id")):
        st.session_state["action_center_history"] = selected["action_id"]

    if st.session_state.get("action_center_details") == selected_id:
        with st.expander("Finding details", expanded=True):
            st.write({
                "Finding ID": selected["finding_id"],
                "Credential type": selected["credential_type"],
                "Owner": selected["owner"] or "Unassigned",
                "Applicable policy": selected["policy"],
                "Business impact": selected["business_impact"],
                "Required permissions": selected["required_permissions"],
                "Expected operational impact": selected["expected_operational_impact"],
                "Rollback / recovery": selected["rollback"],
            })
    if st.session_state.get("action_center_evidence") == selected_id:
        with st.expander("Evidence from the current assessment", expanded=True):
            st.json(selected["evidence"], expanded=True)
    if st.session_state.get("action_center_steps") == selected_id:
        with st.expander("Remediation guidance", expanded=True):
            st.write(selected["recommendation"])
            st.write(selected["expected_operational_impact"])
            st.write("Supported action(s): " + (", ".join(selected["supported_actions"]) or "None; guidance only"))
            st.write("Rollback: " + selected["rollback"])

    if selected.get("action_id") and st.session_state.get("action_center_history") == selected["action_id"]:
        history = api("/remediation/actions/" + selected["action_id"] + "/history")
        if history is not None:
            with st.expander("Execution history", expanded=True):
                st.dataframe(pd.DataFrame(history), hide_index=True, width="stretch")

    action_choices = selected["supported_actions"]
    can_operate = bool(os.getenv("SENTINELX_OPERATOR_KEY"))
    can_approve = bool(os.getenv("SENTINELX_APPROVER_KEY"))
    if action_choices:
        choice = st.selectbox("Supported remediation", action_choices,
                              format_func=lambda value: value.replace("_", " ").title())
        owner = st.text_input("Accountable owner", key="finding_owner") if choice == "assign_owner" else None
        if st.button("Request Approval", icon=":material/add_task:",
                     disabled=not can_operate or (choice == "assign_owner" and not owner)):
            idempotency_state = f"action_center_idempotency:{selected_id}:{choice}"
            if idempotency_state not in st.session_state:
                st.session_state[idempotency_state] = uuid.uuid4().hex
            payload = dict(asset_id=selected["asset_id"], action=choice, finding_id=selected_id,
                           idempotency_key=st.session_state[idempotency_state])
            if owner:
                payload["owner"] = owner
            action = api("/remediation/actions", "POST", "operator", payload)
            if action:
                reviewed = api("/remediation/actions/" + action["id"] + "/dry-run", "POST", "operator")
                if reviewed:
                    st.session_state.pop(idempotency_state, None)
                    st.success("Dry run recorded. A separate approver must approve before execution.")
                    st.rerun()
        if health["mode"] == "demo" and selected.get("action_id"):
            status = selected["remediation_status"]
            action_base = "/remediation/actions/" + selected["action_id"]
            approval_columns = st.columns(3)
            if approval_columns[0].button("Approve", disabled=status != "pending" or selected["approval_status"] != "awaiting_approval" or not can_approve):
                command(action_base + "/approval", "approver", {"approve": True})
            if approval_columns[1].button("Reject", disabled=status != "pending" or selected["approval_status"] != "awaiting_approval" or not can_approve):
                command(action_base + "/approval", "approver", {"approve": False})
            if approval_columns[2].button("Execute Remediation", type="primary",
                    disabled=status != "approved" or not health["remediation_enabled"] or not can_operate):
                command(action_base + "/execute", payload={"dry_run": False})
    else:
        st.info("No automated action is supported for this finding. Follow the remediation guidance and owner approval process.")
    if not can_operate:
        st.caption("Request, approval and execution controls are unavailable because this dashboard has no operator credential.")


def copilot_page():
    st.caption("Grounded answers are computed from the latest report, current findings, and remediation action store. No credential values are provided to the Copilot.")
    if "copilot_messages" not in st.session_state:
        st.session_state["copilot_messages"] = []
    if st.button("Clear conversation", icon=":material/delete_sweep:"):
        st.session_state["copilot_messages"] = []
        st.session_state["copilot_context_finding_id"] = None
        st.rerun()

    suggestions = api("/copilot/suggestions") or {"items": []}
    st.markdown("**Suggested questions**")
    suggestion_columns = st.columns(3)
    for index, suggestion in enumerate(suggestions["items"]):
        if suggestion_columns[index % 3].button(suggestion, key="copilot-suggestion-" + str(index), width="stretch"):
            st.session_state["copilot_pending_question"] = suggestion
            st.rerun()

    for message_index, message in enumerate(st.session_state["copilot_messages"]):
        with st.chat_message(message["role"]):
            st.markdown(message["content"])
            if message.get("references"):
                with st.expander("Supporting findings and report references"):
                    st.dataframe(pd.DataFrame(message["references"]), hide_index=True, width="stretch")
                    for reference_index, reference in enumerate(message["references"]):
                        if reference.get("finding_id"):
                            st.button(
                                "Open " + reference["asset_name"] + " in Action Center",
                                key=f"copilot-finding-{message_index}-{reference_index}",
                                on_click=navigate_to_finding,
                                args=(reference["finding_id"],),
                            )
                        elif reference.get("type") == "report":
                            st.button(
                                "Open Compliance Reports",
                                key=f"copilot-report-{message_index}-{reference_index}",
                                on_click=navigate_to_reports,
                            )

    question = st.session_state.pop("copilot_pending_question", None)
    if question is None:
        question = st.chat_input("Ask about current SentinelX findings or actions")
    if question:
        st.session_state["copilot_messages"].append({"role": "user", "content": question})
        response = api("/copilot/chat", "POST", payload={
            "question": question,
            "context_finding_id": st.session_state.get("copilot_context_finding_id"),
        })
        if response:
            st.session_state["copilot_messages"].append({
                "role": "assistant", "content": response["answer"], "references": response["references"],
            })
            finding_refs = [reference for reference in response["references"] if reference.get("finding_id")]
            if len(finding_refs) == 1:
                st.session_state["copilot_context_finding_id"] = finding_refs[0]["finding_id"]
            st.rerun()


def compliance_reports(summary):
    st.subheader("Latest compliance report")
    latest = summary.get("latest")
    if not latest:
        st.warning("No successful report is available.")
        return
    metrics([], [("Governance score", f"{latest['score']} / 100"),
                 ("Compliance", f"{latest['compliance_percentage']}%"),
                 ("Findings", latest["findings"]),
                 ("Coverage", "Complete" if latest["coverage"]["complete"] else "Partial")])
    st.caption(f"Generated {latest['at']} · {latest['total']} discovered assets")
    columns = st.columns(2)
    for column, format in zip(columns, ["json", "csv"]):
        content = api("/report?format=" + format, raw=True)
        if content:
            column.download_button("Download " + format.upper(), content, "sentinelx-report." + format,
                                   mime="application/json" if format == "json" else "text/csv")
    history = api("/history") or []
    if history:
        st.subheader("Report history")
        st.line_chart(pd.DataFrame(history).set_index("at")[["score", "compliance_percentage"]],
                      color=["#167a72", "#c89916"], height=260)
        st.dataframe(pd.DataFrame(history[::-1]), hide_index=True, width="stretch")


with st.sidebar:
    logo = Path(__file__).parent / "assets" / "sentinelx.png"
    if logo.exists():
        st.image(str(logo), width=44)
    st.markdown("## SentinelX")
    st.caption("IDENTITY SECURITY OPERATIONS")
    view = st.radio("Workspace", ["Executive Summary", "Credential Governance", "Service Principals", "Secret Governance",
                                  "AWS Integration", "Compliance Reports", "SentinelX AI Copilot",
                                  "Remediation & Action Center", "Audit & Governance"],
                    label_visibility="collapsed", key="workspace_view")
    st.divider()
    st.caption("POLICY BASELINE")
    st.caption("Databricks + AWS Secrets Manager")


@st.fragment(run_every="30s")
def render():
    health, summary, items = api("/health"), api("/summary"), api("/assets")
    if not health or not summary or items is None:
        return
    demo = health["mode"] == "demo"
    heading, refresh = st.columns([5, 1])
    heading.markdown('<span class="brandmark">SENTINELX / GOVERNANCE CONTROL CENTER</span>', unsafe_allow_html=True)
    if refresh.button("Refresh", icon=":material/refresh:", width="stretch"):
        st.rerun()
    st.title(view)
    st.caption("Discover. Assess. Govern. Rotate. Remediate.")
    if demo:
        st.markdown('<div class="environment">DEMO DATA &nbsp; / &nbsp; SIMULATED APPROVALS &nbsp; / &nbsp; NO CLOUD WRITES</div>', unsafe_allow_html=True)
    else:
        st.caption("LIVE INVENTORY / READ-ONLY DASHBOARD")
    latest = summary.get("latest")
    if not latest:
        st.warning("No successful discovery snapshot. Check provider access and audit history.")
        return
    if not latest["coverage"]["complete"]:
        st.warning("Partial coverage. Compliance applies only to discovered assets.")
    age = (datetime.now(timezone.utc) - datetime.fromisoformat(latest["at"])).total_seconds()
    if age > int(os.getenv("SENTINELX_SCAN_INTERVAL", "300")) * 2:
        st.warning("Inventory is stale. Last successful scan: " + latest["at"])
    st.caption(f"Last discovery: {latest['at'][:19].replace('T', ' ')} UTC | Credential age policy: {latest['policy']['max_age_days']} days")
    if demo and st.button("Discover now", icon=":material/sync:"):
        command("/discover")
    if view == "SentinelX AI Copilot":
        copilot_page()
    elif view == "Remediation & Action Center":
        action_center(health)
    elif view == "Compliance Reports":
        compliance_reports(summary)
    elif view == "Executive Summary":
        metrics(items, [("Governance score", f"{summary['score']} / 100"), ("Compliance", f"{summary['compliance_percentage']}%"),
                        ("High-risk assets", summary["high_risk"]), ("Open actions", summary["open_actions"])])
        counts = summary["finding_counts"]
        metrics(items, [("Critical findings", counts["critical"]), ("High findings", counts["high"]),
                        ("Expired credentials", counts["expired"]), ("Expiring within 30 days", counts["expiring"])])
        left, right = st.columns(2)
        with left:
            distribution(items, "Risk", "Risk posture")
        with right:
            distribution(items, "Type", "Governance by domain")
        st.subheader("Priority findings")
        prioritized = [dict(Asset=item["asset"]["name"], Owner=item["asset"]["owner"] or "Unassigned",
                            Risk=item["assessment"]["risk"].title(), Score=item["assessment"]["score"], Recommendation=finding["recommendation"])
                       for item in sorted(items, key=lambda value: value["assessment"]["score"])[:8]
                       for finding in item["assessment"]["findings"][:1]]
        st.dataframe(pd.DataFrame(prioritized), hide_index=True, width="stretch")
    elif view == "Audit & Governance":
        history = api("/history") or []
        if history:
            st.subheader("Governance history")
            st.line_chart(pd.DataFrame(history).set_index("at")[["score", "compliance_percentage"]], color=["#167a72", "#c89916"], height=230)
        queue(demo, health["remediation_enabled"])
        audit = api("/audit")
        if audit:
            st.subheader("Audit history")
            st.caption("Hash chain: " + ("Verified" if audit["integrity"] else "INTEGRITY FAILURE"))
            st.dataframe(pd.DataFrame(audit["events"][::-1]), hide_index=True, width="stretch", height=300)
        export = st.columns(2)
        for column, format in zip(export, ["json", "csv"]):
            content = api("/report?format=" + format, raw=True)
            if content:
                column.download_button("Export " + format.upper(), content, "sentinelx-report." + format,
                                       mime="application/json" if format == "json" else "text/csv", icon=":material/download:")
    else:
        kinds = {"Credential Governance": {"pat", "oauth", "application_credential"},
                 "Service Principals": {"service_principal", "sp_secret"},
                 "Secret Governance": {"databricks_secret", "aws_secret"}, "AWS Integration": {"aws_secret"}}[view]
        chosen = [item for item in items if item["asset"]["kind"] in kinds]
        codes = [finding["code"] for item in chosen for finding in item["assessment"]["findings"]]
        average = round(sum(item["assessment"]["score"] for item in chosen) / len(chosen), 1) if chosen else "N/A"
        if view == "Service Principals":
            metrics(chosen, [("Service principals", sum(item["asset"]["kind"] == "service_principal" for item in chosen)),
                            ("Unowned principals", sum(not item["asset"]["owner"] and item["asset"]["kind"] == "service_principal" for item in chosen)),
                            ("Expiring secrets (30d)", sum(code.startswith("expires_") for code in codes)),
                            ("Expired secrets", codes.count("expired")), ("Health score", average)])
        elif view == "AWS Integration":
            metrics(chosen, [("AWS secrets", len(chosen)), ("Metadata aligned", sum(item["asset"]["sync_state"] == "metadata_aligned" for item in chosen)),
                            ("Drift / missing", sum(item["asset"]["sync_state"] in {"drift", "missing_counterpart"} for item in chosen)),
                            ("Rotation enabled", sum(item["asset"]["rotation_enabled"] is True for item in chosen))])
            failed = [item for item in api("/actions") or [] if item["status"] in {"failed", "recovery_required"} and item["action"] in {"sync_secret", "renew_sp"}]
            st.caption(f"Failed synchronizations / recovery actions: {len(failed)}")
        elif view == "Credential Governance":
            metrics(chosen, [("Credentials", len(chosen)), ("PATs", sum(item["asset"]["kind"] == "pat" for item in chosen)),
                            ("Expired", codes.count("expired")), ("Non-compliant", sum(not item["assessment"]["compliant"] for item in chosen)), ("Health score", average)])
            ages = pd.DataFrame([dict(Age=item["assessment"]["age_days"]) for item in chosen if item["asset"]["kind"] == "pat" and item["assessment"]["age_days"] is not None])
            if not ages.empty:
                st.subheader("PAT age distribution")
                st.altair_chart(alt.Chart(ages).mark_bar(color="#167a72").encode(x=alt.X("Age:Q", bin=alt.Bin(step=30), title="Age (days)"), y=alt.Y("count():Q", title="PATs")).properties(height=180), width="stretch")
        else:
            metrics(chosen, [("Secrets", len(chosen)), ("Stale secrets", codes.count("stale")),
                            ("Rotation violations", codes.count("rotation_overdue") + codes.count("rotation_disabled")),
                            ("Unknown rotation", codes.count("rotation_unknown")), ("Health score", average)])
            known = [item for item in chosen if item["assessment"]["rotation_age_days"] is not None]
            compliant = sum(item["assessment"]["rotation_age_days"] <= latest["policy"]["rotation_days"] and item["asset"]["rotation_enabled"] is not False for item in known)
            st.caption(f"Rotation compliance: {round(100 * compliant / len(chosen), 1) if chosen else 0}% | Unknown evidence counts as non-compliant")
        inventory(chosen, view, demo)


render()