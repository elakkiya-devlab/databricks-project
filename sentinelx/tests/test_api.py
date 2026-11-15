import tempfile
import unittest
from pathlib import Path

from fastapi.testclient import TestClient

from backend.api.app import create_app
from configs.settings import Settings

KEYS = {role: role + "-" + "x" * 40 for role in ("reader", "operator", "approver")}


class APIIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.app = create_app(Settings(keys=KEYS, db_path=str(Path(self.directory.name) / "test.db"), remediation_enabled=True))
        self.client = self.enterContext(TestClient(self.app))

    def call(self, method, path, role="reader", **kwargs):
        return self.client.request(method, path, headers={"X-API-Key": KEYS[role]}, **kwargs)

    def test_auth_and_role_enforcement(self):
        self.assertEqual(self.client.get("/health").status_code, 401)
        self.assertEqual(self.call("POST", "/discover").status_code, 403)
        self.assertEqual(self.call("GET", "/assets").status_code, 200)

    def test_full_renewal_and_rollback_via_api(self):
        item = self.call("POST", "/actions", "operator", json={"asset_id": "db:sp-secret:2", "action": "renew_sp"}).json()
        route = "/actions/" + item["id"]
        self.assertEqual(self.call("POST", route + "/execute", "operator", json={"dry_run": False}).status_code, 409)
        self.assertEqual(self.call("POST", route + "/dry-run", "operator").status_code, 200)
        self.assertEqual(self.call("POST", route + "/decision", "approver", json={"approve": True}).status_code, 200)
        self.assertEqual(self.call("POST", route + "/execute", "operator", json={"dry_run": False}).json()["status"], "succeeded")
        rollback = self.call("POST", "/actions", "operator", json=dict(asset_id=item["asset_id"], action="rollback", original_id=item["id"])).json()
        route = "/actions/" + rollback["id"]
        self.call("POST", route + "/dry-run", "operator")
        self.call("POST", route + "/decision", "approver", json={"approve": True})
        self.assertEqual(self.call("POST", route + "/execute", "operator", json={"dry_run": False}).status_code, 200)
        self.assertTrue(self.call("GET", "/audit").json()["integrity"])

    def test_no_value_echo_and_reports(self):
        response = self.call("POST", "/actions", "operator", json={"asset_id": "test", "action": "renew_sp", "secret_value": "sensitive-marker"})
        self.assertEqual(response.status_code, 422)
        self.assertNotIn("sensitive-marker", response.text)
        self.assertNotIn("sensitive-marker", self.call("GET", "/audit").text)
        self.assertEqual(self.call("GET", "/report?format=csv").status_code, 200)
        self.assertEqual(self.call("GET", "/report").status_code, 200)