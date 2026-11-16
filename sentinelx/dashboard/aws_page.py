"""Connect AWS Secrets Manager page (shared by Demo and Live modes)."""

import pandas as pd
import streamlit as st

from backend.services.aws_connection import (AUTH_METHODS, NOT_CONFIGURED_MESSAGE, REQUIRED_PERMISSIONS, AwsConfig,
                                             AwsConnector, AwsLoginError)

_STATE = ("aws_result", "aws_login_flow", "aws_sso_creds", "aws_last_success")


def aws_status():
    """Return ('Connected' | 'Not Connected', detail) from the last real connection check in this session."""
    result = st.session_state.get("aws_result")
    if result and result.connected:
        return "Connected", result.identity_arn
    if result:
        return "Not Connected", result.message
    return "Not Connected", "Connection not tested" if AwsConfig.from_env().configured else "Not configured"


def _disconnect():
    for key in _STATE:
        st.session_state.pop(key, None)


def _check(connector):
    result = connector.test_connection(st.session_state.get("aws_sso_creds"))
    st.session_state["aws_result"] = result
    if result.connected:
        st.session_state["aws_last_success"] = result.checked_at
    return result


def _login_panel(connector):
    flow = st.session_state.get("aws_login_flow")
    if not flow:
        return
    st.info("Complete sign-in with your organization's IAM Identity Center, then return here.")
    st.markdown(f"1. Open [the AWS sign-in page]({flow['verification_uri']}) in a new tab.\n"
                f"2. Confirm the code **{flow['user_code']}** matches and approve the request.\n"
                "3. Return here and select **Check sign-in status**.")
    if st.button("Check sign-in status", key="aws-poll", icon=":material/refresh:"):
        state, credentials = connector.poll_login(flow)
        if state == "authorized":
            st.session_state["aws_sso_creds"] = credentials
            st.session_state.pop("aws_login_flow", None)
            _check(connector)
            st.rerun()
        elif state == "pending":
            st.warning("Sign-in has not been completed yet.")
        else:
            st.session_state.pop("aws_login_flow", None)
            st.error("Sign-in expired or was denied. Start the connection again.")


def aws_connection_page(demo, sample_secrets=None):
    config = AwsConfig.from_env()
    connector = AwsConnector(config)
    result = st.session_state.get("aws_result")
    status, detail = aws_status()

    st.subheader("Connect AWS Secrets Manager")
    if not config.configured:
        st.warning(NOT_CONFIGURED_MESSAGE)
    elif status == "Connected":
        st.success(f"Connected — verified {st.session_state.get('aws_last_success', '')} as {detail}")
    elif result is not None and result.status == "login_required":
        st.warning(result.message)
    elif result is not None:
        st.error(result.message)
    else:
        st.info("AWS is configured but not connected. Select Test Connection to verify the identity and permissions.")
    if demo:
        st.caption("Demo Mode: inventory below is synthetic and is not read from AWS. No AWS writes are ever performed.")

    details = {
        "AWS account ID": config.account_id or "Not configured",
        "AWS region": config.region or "Not configured",
        "IAM Role ARN": config.role_arn or ("Not applicable (Identity Center)" if config.auth_method == "identity_center"
                                            else "Not configured"),
        "Authentication method": AUTH_METHODS.get(config.auth_method, "Not configured"),
        "Connection status": status,
        "Last successful connection": st.session_state.get("aws_last_success", "Never"),
    }
    st.dataframe(pd.DataFrame(details.items(), columns=["Setting", "Value"]), hide_index=True, width="stretch")

    left, middle, right, _ = st.columns([1, 1, 1, 3])
    if left.button("Test Connection", key="aws-test", icon=":material/lan:", width="stretch"):
        _check(connector)
        st.rerun()
    if middle.button("Connect", key="aws-connect", icon=":material/link:", type="primary", width="stretch",
                     disabled=not config.configured):
        if config.auth_method == "identity_center" and not st.session_state.get("aws_sso_creds"):
            try:
                st.session_state["aws_login_flow"] = connector.start_login()
            except AwsLoginError as error:
                st.error(str(error))
        else:
            _check(connector)
        st.rerun()
    if right.button("Disconnect", key="aws-disconnect", icon=":material/link_off:", width="stretch",
                    disabled=result is None and not st.session_state.get("aws_login_flow")):
        _disconnect()
        st.rerun()
    _login_panel(connector)
    if result is not None and result.permissions:
        st.caption("Checked permissions: " + ", ".join(
            f"{name} {'✓' if allowed else '✗'}" for name, allowed in result.permissions.items()))

    st.markdown("**Required permissions**")
    st.dataframe(pd.DataFrame(REQUIRED_PERMISSIONS, columns=["Permission", "Purpose"]), hide_index=True, width="stretch")
    with st.expander("Setup and authentication steps"):
        st.markdown(
            "- **IAM Role (recommended):** create a read-only discovery role trusting your approved federation identity, "
            "then set `SENTINELX_AWS_ACCOUNT_ID`, `SENTINELX_AWS_REGION`, `SENTINELX_AWS_ROLE_ARN` (and optionally "
            "`SENTINELX_AWS_EXTERNAL_ID`) as App environment values. The runtime must already hold a federated identity "
            "allowed to call `sts:AssumeRole`.\n"
            "- **IAM Identity Center:** set `SENTINELX_AWS_AUTH_METHOD=identity_center`, `SENTINELX_AWS_SSO_START_URL`, "
            "`SENTINELX_AWS_SSO_REGION`, and `SENTINELX_AWS_SSO_ROLE_NAME`. Sign-in uses the device-authorization flow, so "
            "no redirect callback or client secret is exposed in the browser.\n"
            "- Never place long-lived access keys in the repository, `app.yaml`, or the browser. Temporary credentials are "
            "held only in server memory for this session and are cleared on Disconnect.\n"
            "- Remediation roles are separate from this discovery connection and are validated by the remediation preflight.")

    if sample_secrets is not None:
        st.markdown("**AWS Secrets Manager inventory" + (" (sample data — not connected)**" if demo else "**"))
        st.dataframe(pd.DataFrame(sample_secrets), hide_index=True, width="stretch", height=320)
