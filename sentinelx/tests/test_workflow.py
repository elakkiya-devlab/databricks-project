import tempfile
import unittest
from pathlib import Path

from backend.governance.service import Governance
from backend.remediation.engine import Remediation, WorkflowError
from backend.services.sample import demo_assets
from backend.services.store import Store


class WorkflowTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.store = Store(Path(self.directory.name) / "test.db")
        self.governance = Governance(self.store, lambda: (demo_assets(), {"complete": True, "mode": "demo"}))
        self.governance.scan()
        self.workflow = Remediation(self.governance, enabled=True)

    def approved(self):
        action = self.workflow.request("db:sp-secret:2", "renew_sp", "operator")
        self.workflow.dry_run(action["id"], "operator")
        self.workflow.decide(action["id"], "approver")
        return action

    def test_requires_dry_run_and_separate_approval(self):
        item = self.workflow.request("db:sp-secret:2", "renew_sp", "operator")
        with self.assertRaises(WorkflowError):
            self.workflow.decide(item["id"], "approver")
        self.workflow.dry_run(item["id"], "operator")
        with self.assertRaises(WorkflowError):
            self.workflow.decide(item["id"], "operator")

    def test_execution_and_approved_rollback(self):
        action = self.approved()
        before = self.store.get("assets", action["asset_id"])["asset"]
        self.workflow.execute(action["id"], "operator", dry_run=False)
        after = self.store.get("assets", action["asset_id"])["asset"]
        self.assertNotEqual(before["expires_at"], after["expires_at"])
        rollback = self.workflow.request(action["asset_id"], "rollback", "operator", original_id=action["id"])
        self.workflow.dry_run(rollback["id"], "operator")
        self.workflow.decide(rollback["id"], "approver")
        self.workflow.execute(rollback["id"], "operator", dry_run=False)
        self.assertEqual(self.store.get("assets", action["asset_id"])["asset"], before)
        self.assertTrue(self.store.verify_audit())

    def test_audit_mode_and_replay_blocked(self):
        action = self.approved()
        self.workflow.enabled = False
        with self.assertRaises(WorkflowError):
            self.workflow.execute(action["id"], "operator", dry_run=False)
        self.workflow.enabled = True
        self.workflow.execute(action["id"], "operator", dry_run=False)
        with self.assertRaises(WorkflowError):
            self.workflow.execute(action["id"], "operator", dry_run=False)

    def test_stale_approval_blocked(self):
        action = self.approved()
        self.governance.rescore(action["asset_id"], {"owner": "changed"}, "operator")
        with self.assertRaises(WorkflowError):
            self.workflow.execute(action["id"], "operator", dry_run=False)

    def test_failed_discovery_retains_snapshot(self):
        before = self.store.rows("assets")
        self.governance.collector = lambda: (_ for _ in ()).throw(RuntimeError("provider unavailable"))
        with self.assertRaises(RuntimeError):
            self.governance.scan()
        self.assertEqual(before, self.store.rows("assets"))