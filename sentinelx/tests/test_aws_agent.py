import os
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from botocore.exceptions import ClientError
from streamlit.testing.v1 import AppTest

from backend.agent.remediation_agent import RemediationAgent
from backend.demo.agent_context import make_resolver
from backend.demo.engine import DemoWorkspace
from backend.services.aws_connection import AwsConfig
from backend.services.aws_remediation import AwsRemediator, ExecutionConfig, RemediationError

ACCOUNT = "111122223333"
ROLE = "arn:aws:iam::111122223333:role/sentinelx-discovery"
WRITE_ROLE = "arn:aws:iam::111122223333:role/sentinelx-remediation"
NAME = "sentinelx/prod/legacy-reporting/api-key"
ARN = f"arn:aws:secretsmanager:us-east-1:{ACCOUNT}:secret:{NAME}-AbCdEf"
ORIGINAL = "version-original-0000000000000000"
APP = str(Path(__file__).resolve().parents[1] / "dashboard/app.py")


def error(code):
    return ClientError({"Error": {"Code": code, "Message": "x"}}, "Operation")


class FakeSts:
    def __init__(self, account=ACCOUNT, calls=None):
        self.account, self.calls = account, calls

    def assume_role(self, **arguments):
        self.calls.append(("assume_role", arguments["RoleArn"]))
        return {"Credentials": {"AccessKeyId": "ASIAFAKE", "SecretAccessKey": "fake", "SessionToken": "fake"}}

    def get_caller_identity(self):
        return {"Account": self.account, "Arn": "arn:aws:sts::x"}


class FakeSecrets:
    """Minimal Secrets Manager with real version-stage semantics and a record of every write."""

    def __init__(self, rotation_enabled=False, fail_put=None, rotation_completes=True):
        self.stages = {ORIGINAL: ["AWSCURRENT"]}
        self.rotation_enabled, self.fail_put, self.rotation_completes = rotation_enabled, fail_put, rotation_completes
        self.writes, self.written_values = [], []

    def describe_secret(self, SecretId):
        return {"Name": NAME, "ARN": ARN, "RotationEnabled": self.rotation_enabled,
                "VersionIdsToStages": {key: list(value) for key, value in self.stages.items()}}

    def list_secrets(self, **arguments):
        return {"SecretList": [{"Name": NAME, "ARN": ARN, "RotationEnabled": self.rotation_enabled,
                                "LastRotatedDate": datetime(2026, 1, 1, tzinfo=timezone.utc)}]}

    def put_secret_value(self, SecretId, ClientRequestToken, SecretString):
        if self.fail_put:
            raise error(self.fail_put)
        self.writes.append("put_secret_value")
        self.written_values.append(SecretString)
        for names in self.stages.values():
            if "AWSCURRENT" in names:
                names.remove("AWSCURRENT")
                names.append("AWSPREVIOUS")
        self.stages[ClientRequestToken] = ["AWSCURRENT"]

    def rotate_secret(self, SecretId, ClientRequestToken, RotateImmediately):
        self.writes.append("rotate_secret")
        if self.rotation_completes:
            self.put_secret_value(SecretId, ClientRequestToken, "native")
            self.written_values.clear()

    def update_secret_version_stage(self, SecretId, VersionStage, MoveToVersionId, RemoveFromVersionId):
        self.writes.append("update_secret_version_stage")
        self.stages[RemoveFromVersionId].remove(VersionStage)
        self.stages[MoveToVersionId] = [VersionStage]


def build(secrets=None, account=ACCOUNT, configured=True, execution=None, **config):
    secrets = secrets or FakeSecrets()
    calls = []
    clients = {"sts": FakeSts(account, calls), "secretsmanager": secrets}
    settings = AwsConfig(**dict(account_id=ACCOUNT, region="us-east-1", role_arn=ROLE, auth_method="assume_role", **config)) \
        if configured else AwsConfig()
    execution = execution or ExecutionConfig(True, ("sentinelx/",), WRITE_ROLE, wait_seconds=0)
    remediator = AwsRemediator(settings, execution, lambda service, **kwargs: clients[service], sleep=lambda seconds: None)
    return RemediationAgent(remediator, make_resolver(DemoWorkspace())), secrets, calls


def approved_plan(agent, request=f"rotate {NAME}"):
    plan_id = agent.handle(request)["plan_id"]
    agent.approve(plan_id, "approver@example.com")
    return plan_id


class AwsAgentTests(unittest.TestCase):
    def test_reports_aws_not_configured_without_calling_aws(self):
        def explode(*args, **kwargs):
            raise AssertionError("AWS must not be called")

        agent = RemediationAgent(AwsRemediator(AwsConfig(), ExecutionConfig(), explode))
        for request in ("Is AWS configured?", "list my secrets", f"rotate {NAME}"):
            answer = agent.handle(request)["answer"]
            self.assertIn("AWS is not configured", answer, request)
        self.assertEqual(agent.plans, {})

    def test_plan_makes_no_changes_and_chat_cannot_approve(self):
        agent, secrets, _ = build()
        reply = agent.handle(f"rotate {NAME}")
        plan = agent.plans[reply["plan_id"]]
        self.assertEqual((plan.status, plan.strategy), ("proposed", "generated_value"))
        self.assertIn("ENTIRE secret value", " ".join(plan.risks))
        self.assertIn("can't approve", agent.handle("approve and execute it")["answer"])
        with self.assertRaises(RemediationError):
            agent.run(reply["plan_id"])
        self.assertEqual(plan.status, "proposed")
        self.assertEqual(secrets.writes, [])

    def test_approved_generated_value_rotation_is_verified_and_never_leaks_the_value(self):
        agent, secrets, calls = build()
        plan_id = approved_plan(agent)
        message = agent.run(plan_id)
        plan = agent.plans[plan_id]
        self.assertEqual(plan.status, "executed")
        self.assertIn("Done", message)
        self.assertEqual(secrets.writes, ["put_secret_value"])
        self.assertIn(("assume_role", WRITE_ROLE), calls)
        value = secrets.written_values[0]
        self.assertGreaterEqual(len(value), 32)
        self.assertNotIn(value, repr((message, plan.view(), agent.audit)))
        self.assertEqual(secrets.stages[ORIGINAL], ["AWSPREVIOUS"])
        with self.assertRaises(RemediationError):
            agent.run(plan_id)

    def test_native_rotation_confirmed_or_honestly_pending(self):
        agent, secrets, _ = build(FakeSecrets(rotation_enabled=True))
        plan_id = approved_plan(agent)
        self.assertEqual(agent.plans[plan_id].strategy, "native_rotation")
        self.assertIn("Done", agent.run(plan_id))
        slow, secrets, _ = build(FakeSecrets(rotation_enabled=True, rotation_completes=False))
        plan_id = approved_plan(slow)
        self.assertIn("not yet confirmed", slow.run(plan_id))
        self.assertEqual(slow.plans[plan_id].status, "in_progress")

    def test_execution_disabled_or_out_of_scope_is_blocked(self):
        agent, secrets, _ = build(execution=ExecutionConfig(False, ("sentinelx/",), WRITE_ROLE))
        plan_id = agent.handle(f"rotate {NAME}")["plan_id"]
        with self.assertRaises(RemediationError):
            agent.approve(plan_id, "approver@example.com")
        scoped, secrets, _ = build(execution=ExecutionConfig(True, ("other/",), WRITE_ROLE))
        plan_id = scoped.handle(f"rotate {NAME}")["plan_id"]
        self.assertIn("outside the allowed prefixes", scoped.plans[plan_id].blockers[0])
        with self.assertRaises(RemediationError):
            scoped.approve(plan_id, "approver@example.com")
        self.assertEqual(secrets.writes, [])

    def test_changed_secret_after_approval_is_refused(self):
        agent, secrets, _ = build()
        plan_id = approved_plan(agent)
        secrets.stages = {"someone-else-0000000000000000000": ["AWSCURRENT"]}
        self.assertIn("did not make any change", agent.run(plan_id))
        self.assertEqual(secrets.writes, [])

    def test_aws_denial_is_explained_and_no_success_is_claimed(self):
        agent, secrets, _ = build(FakeSecrets(fail_put="AccessDeniedException"))
        plan_id = approved_plan(agent)
        message = agent.run(plan_id)
        self.assertIn("failed", message)
        self.assertIn("Nothing was changed", message)
        self.assertEqual(agent.plans[plan_id].status, "failed")
        self.assertNotIn("Done", message)

    def test_wrong_account_stops_before_any_call_to_secrets_manager(self):
        agent, secrets, _ = build(account="999999999999")
        self.assertIn("does not match", agent.handle(f"rotate {NAME}")["answer"])
        self.assertEqual(agent.plans, {})

    def test_rollback_restores_previous_version(self):
        agent, secrets, _ = build()
        plan_id = approved_plan(agent)
        agent.run(plan_id)
        self.assertIn("Rolled back", agent.rollback(plan_id, "approver@example.com"))
        self.assertEqual(secrets.stages[ORIGINAL], ["AWSCURRENT"])
        self.assertEqual(agent.plans[plan_id].status, "rolled_back")
        self.assertIn("needs a human decision", agent.handle("roll back the rotation")["answer"])

    def test_finding_ids_resolve_through_the_governance_dataset(self):
        agent, _, _ = build()
        reply = agent.handle("please fix SX-1019")
        self.assertIsNotNone(reply["plan_id"])
        self.assertEqual(agent.plans[reply["plan_id"]].secret_name, NAME)
        self.assertEqual(agent.plans[reply["plan_id"]].finding_id, "SX-1019")
        self.assertIn("SX-1019", reply["answer"])
        self.assertIn("no bound AWS secret", agent.handle("fix SX-1018")["answer"])
        bound = agent.handle("fix SX-1001")
        self.assertIn("bound AWS secret `sentinelx/prod/ml-feature-store/oauth`", bound["answer"])
        self.assertEqual(agent.plans[bound["plan_id"]].finding_id, "SX-1001")

    def test_list_returns_metadata_only(self):
        agent, _, _ = build()
        answer = agent.handle("list my AWS secrets")["answer"]
        self.assertIn(NAME, answer)
        self.assertIn("In scope", answer)


class AwsAgentDashboardTests(unittest.TestCase):
    def test_approve_and_execute_flow_in_the_dashboard(self):
        secrets = FakeSecrets()
        clients = {"sts": FakeSts(calls=[]), "secretsmanager": secrets}
        environment = {key: value for key, value in os.environ.items() if not key.startswith("SENTINELX_")}
        environment.update(DEMO_MODE="true", LIVE_MODE="false", SENTINELX_AWS_ACCOUNT_ID=ACCOUNT, SENTINELX_AWS_REGION="us-east-1",
                           SENTINELX_AWS_ROLE_ARN=ROLE, SENTINELX_AWS_EXECUTION_ENABLED="true",
                           SENTINELX_AWS_ALLOWED_SECRET_PREFIXES="sentinelx/", SENTINELX_AWS_REMEDIATION_ROLE_ARN=WRITE_ROLE)
        with patch.dict(os.environ, environment, clear=True), \
                patch("backend.services.aws_connection.boto3.client", lambda service, **kwargs: clients[service]):
            ui = AppTest.from_file(APP, default_timeout=60).run()
            ui.radio[0].set_value("SentinelX AI Copilot").run()
            ui.button_group(key="assistant_mode").set_value("SentinelPilot (AWS agent)").run()
            ui.chat_input[0].set_value(f"rotate {NAME}").run()
            self.assertFalse(ui.exception)
            self.assertEqual(secrets.writes, [])
            approve = next(item for item in ui.button if item.key.startswith("agent-approve-"))
            self.assertTrue(approve.disabled)
            next(item for item in ui.checkbox if item.key.startswith("agent-confirm-")).check().run()
            next(item for item in ui.button if item.key.startswith("agent-approve-")).click().run()
            self.assertFalse(ui.exception)
            self.assertEqual(secrets.writes, ["put_secret_value"])
            self.assertTrue(any("Done" in item.value for item in ui.markdown))

    def test_agent_tab_says_aws_not_configured(self):
        unset = ("SENTINELX_API_URL", "SENTINELX_AWS_ACCOUNT_ID", "SENTINELX_AWS_REGION", "SENTINELX_AWS_ROLE_ARN",
                 "SENTINELX_AWS_AUTH_METHOD", "SENTINELX_AWS_SSO_START_URL", "SENTINELX_AWS_EXECUTION_ENABLED")
        environment = {key: value for key, value in os.environ.items() if key not in unset}
        environment.update(DEMO_MODE="true", LIVE_MODE="false")
        with patch.dict(os.environ, environment, clear=True):
            ui = AppTest.from_file(APP, default_timeout=60).run()
            ui.radio[0].set_value("SentinelX AI Copilot").run()
            ui.button_group(key="assistant_mode").set_value("SentinelPilot (AWS agent)").run()
            self.assertFalse(ui.exception)
            self.assertTrue(any("AWS is not configured" in item.value for item in ui.warning))
            ui.chat_input[0].set_value("rotate sentinelx/prod/app/key").run()
            self.assertFalse(ui.exception)
            self.assertTrue(any("AWS is not configured" in item.value for item in ui.markdown))
