import tempfile
import unittest
from pathlib import Path

from fastapi.testclient import TestClient

from backend.api.app import create_app
from configs.settings import Settings
from tests.test_api import KEYS


class ComplianceCopilotAPITests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        settings = Settings(keys=KEYS, db_path=str(Path(self.directory.name) / "test.db"), remediation_enabled=True)
        self.app = create_app(settings)
        self.client = self.enterContext(TestClient(self.app))

    def call(self, method, path, role="reader", **kwargs):
        return self.client.request(method, path, headers={"X-API-Key": KEYS[role]}, **kwargs)

    def test_findings_are_stable_filterable_and_role_protected(self):
        self.assertEqual(self.client.get("/compliance/findings").status_code, 401)
        first = self.call("GET", "/compliance/findings?kind=sp_secret&page=1&page_size=1").json()
        again = self.call("GET", "/compliance/findings?kind=sp_secret&page=1&page_size=1").json()
        self.assertEqual(first["total"], again["total"])
        self.assertEqual(first["items"][0]["finding_id"], again["items"][0]["finding_id"])
        self.assertEqual(first["items"][0]["credential_type"], "sp_secret")
        self.assertNotIn("provider_id", first["items"][0])
        identity = first["items"][0]["finding_id"]
        self.assertEqual(self.call("GET", "/compliance/findings/" + identity).json()["finding_id"], identity)
        self.assertEqual(self.call("GET", "/compliance/findings/not-a-finding").status_code, 404)
        self.assertEqual(self.call("GET", "/compliance/findings?risk=unknown").status_code, 422)
        owned = next(row for row in self.call("GET", "/compliance/findings?page_size=200").json()["items"] if row["owner"])
        owner_filter = self.call("GET", "/compliance/findings", params={"owner": owned["owner"]}).json()
        self.assertTrue(all(row["owner"] == owned["owner"] for row in owner_filter["items"]))

    def test_copilot_answers_from_current_report_and_discloses_team_limit(self):
        score = self.call("GET", "/compliance/summary").json()["latest"]["score"]
        result = self.call("POST", "/copilot/chat", json={"question": "What is the current governance score?"}).json()
        self.assertIn(str(score), result["answer"])
        self.assertEqual(result["references"][0]["type"], "report")

        ownerless = self.call("POST", "/copilot/chat", json={"question": "Which identities have no assigned owner?"}).json()
        self.assertTrue(all(ref["code"] == "missing_owner" for ref in ownerless["references"]))
        self.assertTrue(all("finding-" in ref["finding_id"] for ref in ownerless["references"]))

        team = self.call("POST", "/copilot/chat",
                         json={"question": "Show critical findings belonging to my team"}).json()
        self.assertFalse(team["supported"])
        self.assertIn("team-scoped results are unavailable", team["answer"].lower())
        self.assertEqual(self.call("GET", "/copilot/suggestions").status_code, 200)

    def test_copilot_queries_are_grounded_in_matching_findings(self):
        findings = self.call("GET", "/compliance/findings?page_size=200").json()["items"]
        by_id = {row["finding_id"]: row for row in findings}
        cases = [
            ("What are the critical compliance findings?", lambda row: row["severity"] == "critical"),
            ("Which service-principal secrets have expired?", lambda row: row["credential_type"] == "sp_secret" and row["code"] == "expired"),
            ("Which credentials are approaching expiry?", lambda row: row["code"] in {"expires_7d", "expires_15d", "expires_30d"}),
            ("Which PAT tokens violate the configured age policy?", lambda row: row["credential_type"] == "pat" and row["code"] == "stale"),
        ]
        for question, predicate in cases:
            response = self.call("POST", "/copilot/chat", json={"question": question}).json()
            refs = [reference for reference in response["references"] if reference.get("finding_id")]
            self.assertTrue(all(predicate(by_id[ref["finding_id"]]) for ref in refs), question)

        priorities = self.call("POST", "/copilot/chat", json={
            "question": "What are the top five remediation priorities?"
        }).json()
        self.assertLessEqual(len(priorities["references"]), 5)
        synchronization = self.call("POST", "/copilot/chat", json={
            "question": "Are AWS Secrets Manager and Databricks secrets synchronized?"
        }).json()
        self.assertIn("does not prove", synchronization["answer"])

    def test_copilot_explains_a_selected_finding_and_uses_only_allowed_router_intents(self):
        finding = self.call("GET", "/compliance/findings").json()["items"][0]
        explanation = self.call("POST", "/copilot/chat", json={
            "question": "Why is this finding high risk?",
            "context_finding_id": finding["finding_id"],
        }).json()
        self.assertIn(finding["finding_id"], [ref.get("finding_id") for ref in explanation["references"]])
        self.assertIn(finding["code"], explanation["answer"])

        class InvalidIntentProvider:
            def classify(self, question, allowed_intents):
                return "execute_remediation"

        settings = Settings(keys=KEYS, db_path=str(Path(self.directory.name) / "router.db"))
        app = create_app(settings, copilot_intent_provider=InvalidIntentProvider())
        with TestClient(app) as client:
            response = client.post("/copilot/chat", headers={"X-API-Key": KEYS["reader"]},
                                   json={"question": "Please make a change"})
            self.assertFalse(response.json()["supported"])

    def test_action_center_keeps_approval_and_execution_separate(self):
        finding = next(
            row for row in self.call("GET", "/compliance/findings").json()["items"]
            if "assign_owner" in row["supported_actions"]
        )
        action = self.call("POST", "/remediation/actions", "operator", json={
            "asset_id": finding["asset_id"],
            "action": "assign_owner",
            "owner": "Test Owner",
            "finding_id": finding["finding_id"],
            "idempotency_key": "test-key-00000000001",
        })
        self.assertEqual(action.status_code, 201)
        identity = action.json()["id"]
        repeat = self.call("POST", "/remediation/actions", "operator", json={
            "asset_id": finding["asset_id"],
            "action": "assign_owner",
            "owner": "Test Owner",
            "finding_id": finding["finding_id"],
            "idempotency_key": "test-key-00000000001",
        })
        self.assertEqual(repeat.json()["id"], identity)
        reused_key = self.call("POST", "/remediation/actions", "operator", json={
            "asset_id": finding["asset_id"],
            "action": "assign_owner",
            "owner": "Different Owner",
            "finding_id": finding["finding_id"],
            "idempotency_key": "test-key-00000000001",
        })
        self.assertEqual(reused_key.status_code, 409)
        base = "/remediation/actions/" + identity
        self.assertEqual(self.call("GET", base).status_code, 200)
        self.assertEqual(self.call("POST", base + "/dry-run", "operator").status_code, 200)
        self.assertEqual(self.call("POST", base + "/approval", "operator", json={"approve": True}).status_code, 403)
        self.assertEqual(self.call("POST", base + "/approval", "approver", json={"approve": True}).status_code, 200)
        executed = self.call("POST", base + "/execute", "operator", json={"dry_run": False})
        self.assertEqual(executed.status_code, 200)
        self.assertEqual(executed.json()["status"], "succeeded")
        self.assertTrue(self.call("GET", base + "/history").json())

    def test_chat_rejects_secret_fields(self):
        result = self.call("POST", "/copilot/chat", json={
            "question": "What is the compliance score?",
            "secret_value": "must-not-be-accepted",
        })
        self.assertEqual(result.status_code, 422)
        self.assertNotIn("must-not-be-accepted", result.text)
