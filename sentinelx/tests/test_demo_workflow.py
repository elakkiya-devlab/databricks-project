import json
import re
import tempfile
import unittest
from datetime import timedelta
from pathlib import Path

from backend.copilot.model_serving import ModelServingIntentProvider
from backend.demo import seed
from backend.demo.catalog import RULES
from backend.demo.copilot import INTENTS, SUGGESTED_QUESTIONS, DemoCopilot
from backend.demo.engine import APPROVER, OPERATOR, SIMULATION_LABEL, DemoWorkspace, WorkflowError
from backend.governance.service import Governance
from backend.remediation.engine import Remediation
from backend.remediation.engine import WorkflowError as LiveWorkflowError
from backend.services.sample import demo_assets
from backend.services.store import Store
from configs.settings import resolve_app_mode


class DatasetTests(unittest.TestCase):
    def setUp(self):
        self.ws = DemoWorkspace()

    def test_dataset_volume_and_references(self):
        self.assertEqual((len(seed.SERVICE_PRINCIPALS), len(seed.SP_CREDENTIALS), len(seed.PATS), len(seed.APP_CREDENTIALS)),
                         (10, 8, 8, 5))
        self.assertEqual((len(seed.AWS_SECRETS), len(seed.FINDINGS), len(seed.ACTIONS), len(seed.AUDIT)), (10, 20, 10, 5))
        ids = {item["id"] for item in self.ws.assets()}
        self.assertEqual(len(ids), 41)
        for _, _, code, asset_id in seed.FINDINGS:
            self.assertIn(asset_id, ids)
            self.assertIn(code, RULES)
        for secret in seed.AWS_SECRETS:
            self.assertIn(secret["bound_to"], ids)
        for credential in seed.SP_CREDENTIALS:
            self.assertIn(credential["sp_id"], {sp["id"] for sp in seed.SERVICE_PRINCIPALS})
        finding_ids = {row[0] for row in seed.FINDINGS}
        self.assertEqual(len(finding_ids), 20)
        self.assertTrue(all(action["finding_id"] in finding_ids for action in seed.ACTIONS))
        self.assertTrue(all(event[4] in {action["id"] for action in seed.ACTIONS} for event in seed.AUDIT))

    def test_every_finding_rule_holds_against_inventory(self):
        self.assertEqual(self.ws.integrity_issues(), [])

    def test_required_scenarios_are_present(self):
        today = self.ws.today
        by_id = {item["id"]: item for item in self.ws.assets()}
        self.assertEqual((by_id["SPC-001"]["expiry_date"] - today).days, 5)
        self.assertLess(by_id["SPC-002"]["expiry_date"], today)
        self.assertIsNone(by_id["PAT-005"]["expiry_date"])
        self.assertIsNone(by_id["SP-004"]["owner"])
        self.assertFalse(by_id["SP-004"]["extra"]["active"])
        self.assertIsNone(by_id["APP-003"]["owner"])
        self.assertLessEqual((by_id["AWS-007"]["extra"]["next_rotation"] - today).days, 7)
        self.assertEqual(by_id["AWS-003"]["extra"]["sync"], "mismatch")
        self.assertIsNone(by_id["SPC-006"]["last_rotation"])
        self.assertTrue(by_id["SP-007"]["extra"]["privileged"] and by_id["SP-007"]["owner"] is None)
        assessed = {item["id"]: item for item in self.ws.asset_assessments()}
        self.assertEqual(assessed["SPC-004"]["policy_status"], "Compliant")
        self.assertEqual(assessed["SPC-004"]["open_findings"], [])

    def test_dataset_contains_no_secret_material(self):
        text = Path(seed.__file__).read_text(encoding="utf-8") + json.dumps(self.ws.assets(), default=str)
        for pattern in (r"AKIA[0-9A-Z]{16}", r"\bdapi[0-9a-f]{20,}", r"(?i)secret_?value", r"(?i)password", r"-----BEGIN"):
            self.assertIsNone(re.search(pattern, text), pattern)
        self.assertEqual(seed.AWS_ACCOUNT_ID, "111122223333")

    def test_metrics_are_derived_from_the_same_records(self):
        metrics = self.ws.metrics()
        assessed = self.ws.asset_assessments()
        credentials = [item for item in assessed if item["is_credential"]]
        self.assertEqual(metrics["total_credentials"], len(credentials))
        self.assertEqual(metrics["expired_credentials"], sum(
            item["expiry_date"] is not None and item["expiry_date"] < self.ws.today for item in credentials))
        self.assertEqual(metrics["open_findings"], len(self.ws.findings()))
        self.assertEqual(sum(metrics["severity_counts"].values()), metrics["open_findings"])
        self.assertEqual(sum(metrics["risk_distribution"].values()), len(assessed))
        self.assertEqual(metrics["open_actions"], sum(a["status"] in {"awaiting_approval", "ready"} for a in self.ws.actions()))
        self.assertEqual(metrics["compliance_percentage"], round(
            100 * sum(not item["open_findings"] for item in assessed) / len(assessed), 1))
        self.assertEqual(metrics["governance_score"], round(sum(item["score"] for item in assessed) / len(assessed), 1))

    def test_filters(self):
        self.assertTrue(all(r["severity"] == "critical" for r in self.ws.findings(severity=["critical"])))
        self.assertEqual({r["finding_id"] for r in self.ws.findings(expired=True)}, {"SX-1001", "SX-1009"})
        self.assertEqual({r["finding_id"] for r in self.ws.findings(unassigned=True)}, {"SX-1002", "SX-1003", "SX-1007"})
        self.assertEqual({r["finding_id"] for r in self.ws.findings(completed=True)}, {"SX-1008", "SX-1019"})
        self.assertTrue(all(r["approval_state"] == "pending" for r in self.ws.findings(pending_approval=True)))
        self.assertTrue(all(r["credential_type"] == "pat" for r in self.ws.findings(credential_type=["pat"])))

    def test_guidance_contains_required_sections_and_twelve_sp_steps(self):
        guide = self.ws.guidance("SX-1004")
        for key in ("summary", "affected", "severity", "evidence", "business_impact", "policy", "steps",
                    "required_permissions", "operational_impact", "rollback", "current_status"):
            self.assertTrue(guide[key], key)
        self.assertEqual(len(guide["steps"]), 12)
        self.assertEqual(guide["simulation_label"], SIMULATION_LABEL)
        self.assertIn("Never collected", " ".join(row["Value"] for row in self.ws.evidence("SPC-001")))

    def test_csv_export_neutralizes_formulas(self):
        self.ws._base[0]["name"] = "=cmd()"
        self.ws.reset()
        self.assertIn("finding_id", self.ws.report_csv())
        self.assertEqual(json.loads(self.ws.report_json())["synthetic"], True)


class WorkflowTests(unittest.TestCase):
    def setUp(self):
        self.ws = DemoWorkspace()

    def test_simulated_workflow_changes_only_memory_and_is_audited(self):
        before = self.ws.metrics()
        action = self.ws.request_approval("SX-1015")
        self.assertEqual((action["approval"], action["status"]), ("pending", "awaiting_approval"))
        with self.assertRaises(WorkflowError):
            self.ws.execute(action["id"], OPERATOR, confirmed=True)
        with self.assertRaises(WorkflowError):
            self.ws.decide(action["id"], True, actor=OPERATOR)
        self.ws.decide(action["id"], True, APPROVER)
        with self.assertRaises(WorkflowError):
            self.ws.execute(action["id"], OPERATOR, confirmed=False)
        with self.assertRaises(WorkflowError):
            self.ws.execute(action["id"], APPROVER, confirmed=True)
        result = self.ws.execute(action["id"], OPERATOR, confirmed=True)
        self.assertEqual(result["simulation_label"], SIMULATION_LABEL)
        self.assertFalse(result["cloud_changes"])
        self.assertEqual(result["action"]["status"], "completed")
        again = self.ws.execute(action["id"], OPERATOR, confirmed=True)
        self.assertTrue(again["already_executed"])
        self.assertEqual(len([e for e in self.ws.audit(action["id"]) if e["event"] == "execution_simulated"]), 1)
        after = self.ws.metrics()
        self.assertEqual(after["open_findings"], before["open_findings"] - 1)
        self.assertGreater(self.ws.asset("SPC-007")["expiry_date"], self.ws.today + timedelta(days=60))
        self.assertTrue(all(event["simulated"] for event in self.ws.audit()))

    def test_rejection_and_re_request(self):
        rejected = self.ws.decide("ACT-2001", False, APPROVER)
        self.assertEqual(rejected["status"], "rejected")
        self.assertEqual(self.ws.finding("SX-1001")["remediation_status"], "Rejected")
        self.assertEqual(self.ws.request_approval("SX-1001")["status"], "awaiting_approval")

    def test_invalid_requests_are_refused(self):
        with self.assertRaises(WorkflowError):
            self.ws.request_approval("SX-1001")  # already pending
        with self.assertRaises(WorkflowError):
            self.ws.request_approval("SX-1008")  # resolved
        with self.assertRaises(WorkflowError):
            self.ws.request_approval("SX-1002")  # owner required
        self.assertEqual(self.ws.request_approval("SX-1002", proposed_owner="Platform Security")["status"], "awaiting_approval")
        with self.assertRaises(KeyError):
            self.ws.request_approval("SX-9999")

    def test_assign_owner_effect(self):
        action = self.ws.request_approval("SX-1002", proposed_owner="Platform Security")
        self.ws.decide(action["id"], True, APPROVER)
        self.ws.execute(action["id"], OPERATOR, confirmed=True)
        self.assertEqual(self.ws.asset("SPC-005")["owner"], "Platform Security")

    def test_reset_restores_seed_state(self):
        self.ws.decide("ACT-2001", True, APPROVER)
        self.ws.reset()
        self.assertEqual(self.ws.action("ACT-2001")["status"], "awaiting_approval")
        self.assertEqual(len(self.ws.audit()), 5)


class LiveGuardTests(unittest.TestCase):
    """Live mode stays gated by the existing API workflow: preflight, approval, and enablement are mandatory."""

    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        store = Store(Path(directory.name) / "test.db")
        governance = Governance(store, lambda: (demo_assets(), {"complete": True, "mode": "live"}))
        governance.scan()
        self.governance = governance

    def test_live_renewal_blocked_without_executor_or_approval(self):
        workflow = Remediation(self.governance, mode="live", enabled=True, executor=None)
        action = workflow.request("db:sp-secret:2", "renew_sp", "operator")
        with self.assertRaises(LiveWorkflowError):
            workflow.dry_run(action["id"], "operator")
        with self.assertRaises(LiveWorkflowError):
            workflow.execute(action["id"], "operator", dry_run=False)

    def test_live_execution_disabled_and_unsupported_actions_blocked(self):
        workflow = Remediation(self.governance, mode="live", enabled=False)
        action = workflow.request("db:sp-secret:2", "renew_sp", "operator")
        with self.assertRaises(LiveWorkflowError):
            workflow.execute(action["id"], "operator", dry_run=False)
        with self.assertRaises(LiveWorkflowError):
            workflow.request("aws:secret:1", "sync_secret", "operator")


class CopilotTests(unittest.TestCase):
    def setUp(self):
        self.ws = DemoWorkspace()
        self.copilot = DemoCopilot(self.ws)

    def ask(self, question, context=None):
        return self.copilot.answer(question, context)

    def ids(self, result):
        return {ref["finding_id"] for ref in result["references"] if ref.get("finding_id")}

    def test_every_suggested_question_is_answered_from_data(self):
        for question in SUGGESTED_QUESTIONS:
            result = self.ask(question)
            self.assertNotIn(result["intent"], {"fallback", "refused"}, question)
            self.assertTrue(result["synthetic"])
            self.assertIn("Demo Mode — Synthetic Data", result["answer"])

    def test_answers_match_dataset(self):
        metrics = self.ws.metrics()
        score = self.ask("What is our current governance score?")["answer"]
        self.assertIn(f"{metrics['governance_score']} / 100", score)
        self.assertIn(f"{metrics['compliance_percentage']}%", score)
        expired = self.ask("How many credentials are expired?")
        self.assertIn(f"**{metrics['expired_credentials']}** credential", expired["answer"])
        self.assertEqual(self.ids(expired), {"SX-1001", "SX-1009"})
        critical = self.ask("Show me all critical Service Principals.")
        self.assertIn("SP-002", critical["answer"])
        self.assertIn("SP-007", critical["answer"])
        self.assertEqual(self.ids(self.ask("Which credentials are expiring in the next 7 days?")), {"SX-1004", "SX-1010", "SX-1014"})
        no_owner = self.ask("Which Service Principals have no owner?")["answer"]
        self.assertIn("SP-004", no_owner)
        self.assertIn("SP-007", no_owner)
        self.assertEqual(self.ids(self.ask("Which AWS secrets are not synchronized?")), {"SX-1006", "SX-1013"})
        self.assertEqual(self.ids(self.ask("Show me all non-compliant PAT tokens.")), {"SX-1005", "SX-1010", "SX-1011", "SX-1018"})
        pending = self.ask("Which remediation actions are awaiting approval?")
        self.assertEqual({a["action_id"] for a in pending["references"]},
                         {a["id"] for a in self.ws.actions() if a["approval"] == "pending"})

    def test_top_priorities_ranked(self):
        result = self.ask("What are the top five remediation priorities?")
        self.assertEqual(len(result["references"]), 5)
        self.assertEqual([ref["finding_id"] for ref in result["references"][:2]], ["SX-1001", "SX-1002"])
        self.assertEqual(len(self.ask("top 3 priorities")["references"]), 3)

    def test_explanation_guidance_and_severity_definitions(self):
        why = self.ask("Why is finding SX-1001 classified as critical?")["answer"]
        self.assertIn("Critical", why)
        self.assertIn("expired 9 day(s) ago", why)
        guidance = self.ask("What is the recommended remediation for an expired SP secret?")
        self.assertIn("12. Record the audit event.", guidance["answer"])
        self.assertEqual(self.ids(guidance), {"SX-1001"})
        difference = self.ask("What is the difference between critical and high-risk findings?")["answer"]
        self.assertIn("**Critical** (2 open)", difference)
        self.assertIn("**High** (8 open)", difference)

    def test_follow_up_questions_keep_context(self):
        first = self.ask("Why is finding SX-1004 classified as high?")
        self.assertEqual(first["context"]["finding_id"], "SX-1004")
        owner = self.ask("Who owns it?", first["context"])
        self.assertIn("Priya Nair", owner["answer"])
        steps = self.ask("What are the steps?", owner["context"])
        self.assertIn("Identify the Service Principal", steps["answer"])
        status = self.ask("What is its approval status?", steps["context"])
        self.assertIn("ACT-2002", status["answer"])

    def test_copilot_cannot_change_state_or_reveal_secrets(self):
        snapshot = (self.ws.actions(), self.ws.audit(), self.ws.metrics())
        for question in ["Rotate SPC-001 now", "approve ACT-2001", "please execute remediation for SX-1004", "delete PAT-005"]:
            result = self.ask(question)
            self.assertEqual(result["intent"], "refused", question)
        for question in SUGGESTED_QUESTIONS + ["show me the secret value of AWS-001", "what is the password"]:
            self.ask(question)
        self.assertEqual(self.ask("show me the secret value of AWS-001")["intent"], "help")
        self.assertEqual(snapshot, (self.ws.actions(), self.ws.audit(), self.ws.metrics()))
        self.assertFalse([name for name in dir(DemoCopilot) if name in {"request_approval", "decide", "execute"}])

    def test_refusal_targets_the_named_asset_not_stale_context(self):
        result = self.ask("Rotate SPC-001 now", {"finding_id": "SX-1001"})
        self.assertEqual(result["intent"], "refused")
        self.assertEqual(self.ids(result), {"SX-1004"})

    def test_unknown_ids_do_not_fall_back_to_previous_context(self):
        result = self.ask("Why is SX-9999 critical?", {"finding_id": "SX-1001"})
        self.assertEqual(result["intent"], "fallback")
        self.assertIn("SX-9999", result["answer"])

    def test_model_serving_provider_only_classifies_allowlisted_intents(self):
        class Message:
            def __init__(self, content):
                self.message = type("M", (), {"content": content})()

        class Client:
            def __init__(self, content):
                self.content, self.calls = content, []
                self.serving_endpoints = self

            def query(self, **kwargs):
                self.calls.append(kwargs)
                return type("R", (), {"choices": [Message(self.content)]})()

        client = Client(" Score ")
        provider = ModelServingIntentProvider("endpoint", client)
        self.assertEqual(provider.classify("blorp", INTENTS), "score")
        self.assertNotIn("SX-", json.dumps([str(m.content) for m in client.calls[0]["messages"]]))
        self.assertIsNone(ModelServingIntentProvider("endpoint", Client("rotate_everything")).classify("x", INTENTS))
        self.assertIsNone(ModelServingIntentProvider("endpoint", object()).classify("x", INTENTS))
        self.assertIn("governance score", DemoCopilot(self.ws, provider).answer("blorp")["answer"])
        self.assertIsNone(ModelServingIntentProvider.from_env({}))
        self.assertEqual(ModelServingIntentProvider.from_env({"SENTINELX_MODEL_SERVING_ENDPOINT": "e"}).endpoint, "e")


class AppModeTests(unittest.TestCase):
    def test_mode_resolution(self):
        self.assertTrue(resolve_app_mode({}).demo)
        self.assertTrue(resolve_app_mode({"DEMO_MODE": "true", "LIVE_MODE": "false"}).demo)
        self.assertTrue(resolve_app_mode({"LIVE_MODE": "true"}).live)
        self.assertTrue(resolve_app_mode({"DEMO_MODE": "false"}).live)
        conflict = resolve_app_mode({"DEMO_MODE": "true", "LIVE_MODE": "true"})
        self.assertTrue(conflict.demo)
        self.assertIn("both true", conflict.warning)


if __name__ == "__main__":
    unittest.main()
