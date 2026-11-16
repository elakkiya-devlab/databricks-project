import os
import unittest
from pathlib import Path
from unittest.mock import patch

from streamlit.testing.v1 import AppTest

from backend.demo.engine import SIMULATION_LABEL, DemoWorkspace

APP = str(Path(__file__).resolve().parents[1] / "dashboard/app.py")
CLEAN = {"DEMO_MODE": "true", "LIVE_MODE": "false"}
UNSET = ("SENTINELX_API_URL", "SENTINELX_READER_KEY", "SENTINELX_AWS_ACCOUNT_ID", "SENTINELX_AWS_REGION",
         "SENTINELX_AWS_ROLE_ARN", "SENTINELX_AWS_AUTH_METHOD", "SENTINELX_AWS_SSO_START_URL", "SENTINELX_MODEL_SERVING_ENDPOINT",
         "SENTINELX_AWS_EXECUTION_ENABLED", "SENTINELX_AWS_ALLOWED_SECRET_PREFIXES", "SENTINELX_AWS_REMEDIATION_ROLE_ARN")


def texts(ui):
    parts = [element.value for element in ui.markdown] + [element.value for element in ui.caption]
    parts += [element.value for element in ui.title] + [element.value for element in ui.subheader]
    parts += [element.value for element in ui.success] + [element.value for element in ui.info] + [element.value for element in ui.warning]
    return "\n".join(str(part) for part in parts)


class DemoDashboardTests(unittest.TestCase):
    def setUp(self):
        environment = {key: value for key, value in os.environ.items() if key not in UNSET}
        environment.update(CLEAN)
        patcher = patch.dict(os.environ, environment, clear=True)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.ui = AppTest.from_file(APP, default_timeout=60)
        self.ui.run()

    def go(self, page):
        self.ui.radio[0].set_value(page).run()
        self.assertFalse(self.ui.exception, page)
        self.assertFalse(self.ui.error, page)

    def button(self, key):
        return next(item for item in self.ui.button if item.key == key)

    def test_starts_without_api_and_shows_demo_status(self):
        self.assertFalse(self.ui.exception)
        self.assertFalse(self.ui.error)
        self.assertNotIn("Governance API unavailable", texts(self.ui))
        self.assertIn("Demo Mode — Synthetic Data", texts(self.ui))
        sidebar = "\n".join(element.value for element in self.ui.sidebar.markdown)
        self.assertIn("Backend", sidebar)
        self.assertIn("Not configured", sidebar)
        self.assertIn("Not Connected", sidebar)

    def test_every_page_renders_without_errors(self):
        for page in self.ui.radio[0].options:
            self.go(page)
        self.assertEqual(len(self.ui.radio[0].options), 9)

    def test_executive_summary_matches_dataset(self):
        metrics = DemoWorkspace().metrics()
        values = {item.label: item.value for item in self.ui.metric}
        self.assertEqual(values["Governance Score"], f"{metrics['governance_score']} / 100")
        self.assertEqual(values["Total Credentials"], str(metrics["total_credentials"]))
        self.assertEqual(values["Expired Credentials"], str(metrics["expired_credentials"]))
        self.assertEqual(values["Open Remediation Actions"], str(metrics["open_actions"]))
        self.assertEqual(values["High-Risk Assets"], str(metrics["high_risk_assets"]))

    def test_credential_inventory_search(self):
        self.go("Credential Governance")
        self.assertEqual(len(self.ui.dataframe[0].value), 31)
        self.ui.text_input(key="cred-q").input("pat-marcus").run()
        self.assertEqual(len(self.ui.dataframe[0].value), 2)

    def test_service_principal_and_secret_pages_show_data(self):
        self.go("Service Principals")
        self.assertEqual(len(self.ui.dataframe[0].value), 10)
        self.go("Secret Governance")
        self.assertEqual(len(self.ui.dataframe[0].value), 10)

    def test_copilot_suggestions_cite_findings_and_follow_up(self):
        self.go("SentinelX AI Copilot")
        self.button("copilot-suggestion-5").click().run()
        self.assertFalse(self.ui.exception)
        answers = [message for message in self.ui.chat_message if message.name == "assistant"]
        self.assertIn("SX-1001", answers[-1].markdown[0].value)
        self.ui.chat_input[0].set_value("Who owns it?").run()
        answers = [message for message in self.ui.chat_message if message.name == "assistant"]
        self.assertIn("Marcus Chen", answers[-1].markdown[0].value)
        self.assertIn("Demo Mode — Synthetic Data", answers[-1].markdown[0].value)

    def test_navigation_from_action_center_and_simulated_workflow(self):
        self.go("Remediation & Action Center")
        self.ui.selectbox(key="ac-select").select("SX-1001").run()
        self.button("list-View Finding").click().run()
        self.assertFalse(self.ui.exception)
        self.assertIn("SX-1001", self.ui.title[1].value)
        self.button("detail-Request Approval").click().run()
        self.assertIn(SIMULATION_LABEL, texts(self.ui))
        self.button("ac-approve").click().run()
        self.assertFalse(self.ui.error)
        self.ui.checkbox(key="ac-confirm").check().run()
        self.button("ac-execute").click().run()
        self.assertFalse(self.ui.exception)
        self.assertIn(SIMULATION_LABEL, texts(self.ui))
        self.assertNotIn("successfully renewed", texts(self.ui).lower())
        self.button("approval-View Audit History").click().run()
        self.assertTrue(any("execution_simulated" in str(frame.value.to_dict()) for frame in self.ui.dataframe))

    def test_simulated_approval_and_execution_pop_up_sentinelpilot(self):
        self.go("Remediation & Action Center")
        self.ui.selectbox(key="ac-select").select("SX-1001").run()
        self.button("list-View Finding").click().run()
        self.button("detail-Request Approval").click().run()
        self.button("ac-approve").click().run()
        popup = "\n".join(element.value for element in self.ui.markdown)
        self.assertIn("simulated approval was recorded", popup)
        self.assertIn("Recommended Remediation Plan", popup)
        self.assertIn("Finding Details – SX-1001", popup)
        self.assertIn("Can you prepare a remediation plan to rotate the AWS secret", popup)
        self.assertIn("no cloud changes were made", popup)
        self.assertIn("sentinelx/prod/ml-feature-store/oauth", popup)
        self.assertTrue(any("signin.aws.amazon.com" in str(element.proto) for element in self.ui.get("link_button")))
        self.assertTrue(any("AWS is not configured" in item.value for item in self.ui.warning))
        self.ui.checkbox(key="ac-confirm").check().run()
        self.button("ac-execute").click().run()
        self.assertIn("simulated execution was recorded", "\n".join(element.value for element in self.ui.markdown))
        self.assertFalse(self.button("pilot-continue").disabled)
        self.assertFalse(self.ui.exception)

    def test_ask_ai_opens_copilot_with_finding_context(self):
        self.go("Remediation & Action Center")
        self.ui.selectbox(key="ac-select").select("SX-1004").run()
        self.button("list-Ask AI").click().run()
        self.assertEqual(self.ui.radio[0].value, "SentinelX AI Copilot")
        self.assertIn("SX-1004", texts(self.ui))

    def test_aws_integration_page_does_not_claim_connection(self):
        self.go("AWS Integration")
        self.assertIn("Connect AWS Secrets Manager", texts(self.ui))
        self.assertTrue(any("AWS connection is not configured" in item.value for item in self.ui.warning))
        self.button("aws-test").click().run()
        self.assertFalse(self.ui.exception)
        self.assertFalse(self.ui.success)
        self.assertTrue(any("not configured" in item.value for item in self.ui.warning))
        self.assertEqual(len(self.ui.dataframe[-1].value), 10)

    def test_conflicting_mode_flags_fall_back_to_demo(self):
        with patch.dict(os.environ, {"DEMO_MODE": "true", "LIVE_MODE": "true"}):
            ui = AppTest.from_file(APP, default_timeout=60).run()
        self.assertFalse(ui.exception)
        self.assertIn("Demo Mode", texts(ui))


class LiveUnavailableTests(unittest.TestCase):
    def test_live_mode_shows_single_clear_banner(self):
        environment = {key: value for key, value in os.environ.items() if key not in UNSET}
        environment.update(DEMO_MODE="false", LIVE_MODE="true", SENTINELX_API_URL="http://127.0.0.1:9")
        with patch.dict(os.environ, environment, clear=True):
            ui = AppTest.from_file(APP, default_timeout=60).run()
        self.assertFalse(ui.exception)
        self.assertEqual(len(ui.error), 1)
        self.assertEqual(ui.error[0].value, "Governance API unavailable")


if __name__ == "__main__":
    unittest.main()
