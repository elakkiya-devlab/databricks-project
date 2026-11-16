"""Helpers shared by the dashboard pages."""

import streamlit as st

RISK_COLORS = {"critical": "#ce424b", "high": "#e87932", "medium": "#c89916", "low": "#23845c"}
RISK_ICONS = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}
PAGES = ["Executive Summary", "Credential Governance", "Service Principals", "Secret Governance", "AWS Integration",
         "Compliance Reports", "SentinelX AI Copilot", "Remediation & Action Center", "Audit & Governance"]


def metric_row(items):
    for column, (label, value) in zip(st.columns(len(items)), items):
        column.metric(label, value)


def risk_label(level):
    return f"{RISK_ICONS[level]} {level.title()}"


def navigate(page, **state):
    """Callback target: switch workspace page and pass identifiers to the destination page."""
    st.session_state["workspace_view"] = page
    for key, value in state.items():
        st.session_state[key] = value


def nav_button(label, page, key, icon=None, disabled=False, **state):
    return st.button(label, key=key, icon=icon, disabled=disabled, on_click=navigate, args=(page,), kwargs=state)


def status_badge(text, tone="info"):
    colors = {"info": ("#edf7f4", "#286054", "#167a72"), "warn": ("#fdf6e3", "#7a5c05", "#c89916"),
              "bad": ("#fdecee", "#8a2530", "#ce424b"), "good": ("#e8f5ee", "#1d6b49", "#23845c")}
    background, foreground, border = colors[tone]
    st.markdown(f'<div class="environment" style="background:{background};color:{foreground};'
                f'border-left-color:{border}">{text}</div>', unsafe_allow_html=True)
