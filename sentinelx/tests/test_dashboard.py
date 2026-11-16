import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient
from streamlit.testing.v1 import AppTest

from backend.api.app import create_app
from configs.settings import Settings
from tests.test_api import KEYS


class DashboardTests(unittest.TestCase):
    def test_views_and_action_center_workflow(self):
        with tempfile.TemporaryDirectory() as directory:
            app = create_app(Settings(keys=KEYS, db_path=str(Path(directory) / "test.db"), remediation_enabled=True))
            with TestClient(app) as client:
                def request(method, url, **kwargs):
                    kwargs.pop("timeout", None)
                    return client.request(method, url.replace("http://127.0.0.1:8000", ""), **kwargs)

                environment = {f"SENTINELX_{role.upper()}_KEY": key for role, key in KEYS.items()}
                environment["SENTINELX_API_URL"] = "http://127.0.0.1:8000"
                environment["DEMO_MODE"] = "false"
                environment["LIVE_MODE"] = "true"
                with patch.dict(os.environ, environment), patch("httpx.request", side_effect=request):
                    ui = AppTest.from_file(str(Path(__file__).resolve().parents[1] / "dashboard/app.py"))
                    ui.run(timeout=30)
                    self.assertFalse(ui.exception)
                    self.assertFalse(ui.error)
                    for view in ui.radio[0].options:
                        ui.radio[0].set_value(view).run(timeout=30)
                        self.assertFalse(ui.exception, view)
                        self.assertFalse(ui.error, view)
                        details = [element for element in ui.selectbox if element.label == "Asset details"]
                        if details:
                            details[0].select_index(0).run(timeout=30)
                            self.assertFalse(ui.exception, view + " details")
                            self.assertFalse(ui.error, view + " details")
                    ui.radio[0].set_value("Service Principals").run(timeout=30)
                    next(element for element in ui.text_input if element.label == "Search").input("pipeline-06/oauth-secret").run(timeout=30)
                    next(element for element in ui.selectbox if element.label == "Asset details").select_index(0).run(timeout=30)
                    next(element for element in ui.selectbox if element.label == "Action").select_index(1).run(timeout=30)
                    next(element for element in ui.button if element.label == "Submit request").click().run(timeout=30)
                    ui.radio[0].set_value("Audit & Governance").run(timeout=30)
                    for label in ("Dry run", "Approve", "Execute"):
                        next(element for element in ui.button if element.label == label).click().run(timeout=30)
                        self.assertFalse(ui.exception, label)
                        self.assertFalse(ui.error, label)
                    self.assertEqual(app.state.store.rows("actions")[0]["status"], "succeeded")

                    findings = request("GET", "http://127.0.0.1:8000/compliance/findings?page_size=50",
                                       headers={"X-API-Key": KEYS["reader"]}).json()["items"]
                    finding = next(item for item in findings if "assign_owner" in item["supported_actions"])
                    ui.radio[0].set_value("Remediation & Action Center").run(timeout=30)
                    selector = next(item for item in ui.selectbox if item.label == "Select a finding")
                    display = f"{finding['asset_name']} — {finding['title']}"
                    selector.select_index(selector.options.index(display)).run(timeout=30)
                    next(item for item in ui.button if item.label == "Ask AI").click().run(timeout=30)
                    self.assertEqual(ui.radio[0].value, "SentinelX AI Copilot")
                    next(item for item in ui.button if item.label == "What is the current governance score?").click().run(timeout=30)
                    self.assertFalse(ui.exception)
                    ui.radio[0].set_value("Remediation & Action Center").run(timeout=30)
                    selector = next(item for item in ui.selectbox if item.label == "Select a finding")
                    selector.select_index(selector.options.index(display)).run(timeout=30)
                    next(item for item in ui.text_input if item.label == "Accountable owner").input("Demo owner").run(timeout=30)
                    next(item for item in ui.button if item.label == "Request Approval").click().run(timeout=30)
                    self.assertFalse(ui.exception)
                    next(item for item in ui.button if item.label == "Approve").click().run(timeout=30)
                    self.assertFalse(ui.exception)
                    next(item for item in ui.button if item.label == "Execute Remediation").click().run(timeout=30)
                    self.assertFalse(ui.exception)
                    self.assertFalse(ui.error)