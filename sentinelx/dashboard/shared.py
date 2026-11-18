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


def success_card(badge, heading, description, checks, details=()):
    """Enterprise-style green success card; `checks` are (label, ok) pairs, `details` are (label, value) pairs."""
    rows = "".join(
        f'<li style="margin:4px 0;color:{"#1d6b49" if ok else "#8a2530"}"><b>{"✓" if ok else "✗"}</b> {label}</li>'
        for label, ok in checks)
    meta = "".join(f'<div><span style="color:#5b6b66">{label}</span> <b>{value}</b></div>' for label, value in details)
    st.markdown(
        '<div style="background:#f3faf6;border:1px solid #bfe3cf;border-left:5px solid #23845c;border-radius:6px;'
        'padding:16px 20px;margin:8px 0 16px 0">'
        f'<span style="background:#23845c;color:#fff;border-radius:4px;padding:2px 10px;font-size:0.75rem;'
        f'font-weight:700;letter-spacing:0.06em">{badge}</span>'
        f'<div style="color:#1d6b49;font-size:1.15rem;font-weight:700;margin-top:10px">✓ {heading}</div>'
        f'<div style="color:#33433e;margin:6px 0 10px 0">{description}</div>'
        f'<ul style="list-style:none;padding:0;margin:0 0 10px 0">{rows}</ul>'
        f'<div style="font-size:0.85rem;line-height:1.6">{meta}</div></div>', unsafe_allow_html=True)
