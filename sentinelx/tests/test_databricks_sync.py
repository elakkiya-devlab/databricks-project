import json
import unittest
from types import SimpleNamespace

from databricks.sdk.service.sql import StatementState

from backend.agent.llm import AgentLanguageModel
from backend.agent.remediation_agent import RemediationAgent
from backend.services.audit_sink import AuditUnavailable, DeltaAuditSink, MemoryAuditSink
from backend.services.aws_connection import AwsConfig
from backend.services.aws_remediation import AwsRemediator, ExecutionConfig, RemediationError
from backend.services.databricks_sync import DatabricksSync, load_bindings
from tests.test_aws_agent import ACCOUNT, ARN, NAME, ROLE, WRITE_ROLE, FakeSts

ORIGINAL = "version-original-0000000000000000"
CLIENT_ID = "app-client-id"
OLD_SECRET, NEW_SECRET, NEW_PAT = "OLDSECRETVALUE-123", "NEWSECRETVALUE-456", "dapiNEWTOKENVALUE0123456789abcdef"


class SyncSecrets:
    """Secrets Manager fake with stage semantics, values per version and a write record."""

    def __init__(self, value):
        self.stages, self.values, self.writes = {ORIGINAL: ["AWSCURRENT"]}, {ORIGINAL: value}, []
        self.rotation_enabled = False

    def describe_secret(self, SecretId):
        return {"Name": NAME, "ARN": ARN, "RotationEnabled": self.rotation_enabled,
                "VersionIdsToStages": {key: list(value) for key, value in self.stages.items()}}

    def list_secrets(self, **arguments):
        return {"SecretList": [{"Name": NAME, "ARN": ARN, "RotationEnabled": False}]}

    def get_secret_value(self, SecretId, VersionId):
        return {"SecretString": self.values[VersionId]}

    def put_secret_value(self, SecretId, ClientRequestToken, SecretString, VersionStages=None):
        self.writes.append(("put", tuple(VersionStages or ["AWSCURRENT"])))
        self.values[ClientRequestToken] = SecretString
        if VersionStages:
            self.stages[ClientRequestToken] = list(VersionStages)
            return
        for names in self.stages.values():
            if "AWSCURRENT" in names:
                names.remove("AWSCURRENT")
                names.append("AWSPREVIOUS")
        self.stages[ClientRequestToken] = ["AWSCURRENT"]

    def update_secret_version_stage(self, SecretId, VersionStage, MoveToVersionId=None, RemoveFromVersionId=None):
        self.writes.append(("stage", VersionStage))
        if RemoveFromVersionId:
            self.stages[RemoveFromVersionId].remove(VersionStage)
            if VersionStage == "AWSCURRENT":
                self.stages[RemoveFromVersionId].append("AWSPREVIOUS")
        if MoveToVersionId:
            self.stages[MoveToVersionId] = [name for name in self.stages[MoveToVersionId] if name != "AWSPREVIOUS"] + [VersionStage]


class FakeWorkspace:
    def __init__(self):
        self.values, self.stamps, self.deleted_tokens = {"client_secret": OLD_SECRET, "token": "dapiOLD"}, {}, []
        outer = self
        self.secrets = SimpleNamespace(
            list_secrets=lambda scope: [SimpleNamespace(key=key, last_updated_timestamp=outer.stamps.get(key, 0)) for key in outer.values],
            put_secret=lambda scope, key, string_value: (outer.values.__setitem__(key, string_value), outer.stamps.__setitem__(key, 9 * 10**15)))
        self.token_management = SimpleNamespace(
            create_obo_token=lambda application_id, lifetime_seconds, comment: SimpleNamespace(
                token_value=NEW_PAT, token_info=SimpleNamespace(token_id="new-token-id")),
            delete=lambda token_id: outer.deleted_tokens.append(token_id))


class FakeAccount:
    def __init__(self):
        self.deleted = []
        outer = self
        self.service_principals = SimpleNamespace(get=lambda id: SimpleNamespace(application_id=CLIENT_ID))
        self.service_principal_secrets = SimpleNamespace(
            list=lambda service_principal_id: [SimpleNamespace(id="old-sp-secret")],
            create=lambda service_principal_id, lifetime, scopes: SimpleNamespace(id="new-sp-secret", secret=NEW_SECRET),
            delete=lambda service_principal_id, secret_id: outer.deleted.append(secret_id))


SP_BINDING = dict(name="etl", kind="service_principal_secret", aws_secret=NAME, scope="etl", key="client_secret",
                  service_principal_id="42", client_id=CLIENT_ID, scopes=["all-apis"], lifetime_days=90,
                  rollback_contract_verified_by_owner=True)
PAT_BINDING = dict(name="ci-pat", kind="pat", aws_secret=NAME, scope="etl", key="token", application_id=CLIENT_ID,
                   lifetime_days=30, rollback_contract_verified_by_owner=True)


def sp_payload(secret=OLD_SECRET):
    return json.dumps(dict(client_id=CLIENT_ID, client_secret=secret, secret_id="old-sp-secret"))


def build(binding=SP_BINDING, value=None, validator=None, host="https://adb.example.net", sink=None, llm=None, **extra):
    secrets = SyncSecrets(value or (sp_payload() if binding["kind"] != "pat" else "dapiOLD"))
    workspace, account = FakeWorkspace(), FakeAccount()
    sync = DatabricksSync(load_bindings(json.dumps([binding])), host, "acct-1", workspace, account,
                          validator or (lambda client_id, secret: None), lambda token: None, **extra)
    clients = {"sts": FakeSts(calls=[]), "secretsmanager": secrets}
    config = AwsConfig(account_id=ACCOUNT, region="us-east-1", role_arn=ROLE, auth_method="assume_role")
    remediator = AwsRemediator(config, ExecutionConfig(True, ("sentinelx/",), WRITE_ROLE), lambda service, **kwargs: clients[service],
                               sleep=lambda seconds: None, sync=sync)
    return RemediationAgent(remediator, llm=llm, sink=sink), secrets, workspace, account


def approved(agent):
    plan_id = agent.handle(f"rotate {NAME}")["plan_id"]
    agent.approve(plan_id, "approver@example.com")
    return plan_id


class CrossPlatformSyncTests(unittest.TestCase):
    def test_bound_secret_plans_a_cross_platform_rotation(self):
        agent, secrets, workspace, _ = build()
        reply = agent.handle(f"rotate {NAME}")
        plan = agent.plans[reply["plan_id"]]
        self.assertEqual((plan.strategy, plan.binding, plan.blockers), ("cross_platform_sync", "etl", []))
        self.assertIn("etl/client_secret", " ".join(plan.steps))
        self.assertEqual(secrets.writes, [])
        self.assertEqual(workspace.values["client_secret"], OLD_SECRET)

    def test_missing_databricks_configuration_blocks_approval(self):
        agent, _, _, _ = build(host="")
        plan_id = agent.handle(f"rotate {NAME}")["plan_id"]
        self.assertIn("DATABRICKS_HOST", agent.plans[plan_id].blockers[0])
        with self.assertRaises(RemediationError):
            agent.approve(plan_id, "approver@example.com")

    def test_service_principal_secret_is_synced_and_verified(self):
        agent, secrets, workspace, _ = build()
        plan_id = approved(agent)
        message = agent.run(plan_id)
        plan = agent.plans[plan_id]
        self.assertEqual(plan.status, "executed", message)
        self.assertEqual(workspace.values["client_secret"], NEW_SECRET)
        new_version = plan.result["new_version"]
        self.assertEqual(json.loads(secrets.values[new_version])["client_secret"], NEW_SECRET)
        self.assertIn("AWSCURRENT", secrets.stages[new_version])
        self.assertNotIn("AWSPENDING", secrets.stages[new_version])
        phases = [row["detail"].split(": ")[-1] for row in agent.audit if row["event"] == "sync_phase"]
        self.assertEqual(phases[0], "intent")
        self.assertEqual(phases[-1], "validated")
        self.assertNotIn(NEW_SECRET, repr((message, plan.view(), agent.audit)))
        self.assertNotIn(OLD_SECRET, repr((message, plan.view(), agent.audit)))

    def test_validation_failure_changes_nothing_in_databricks_and_rolls_back_cleanly(self):
        def reject(client_id, secret):
            raise ValueError("New credential failed OAuth validation")

        agent, secrets, workspace, account = build(validator=reject)
        plan_id = approved(agent)
        message = agent.run(plan_id)
        plan = agent.plans[plan_id]
        self.assertEqual(plan.status, "failed")
        self.assertIn("failed OAuth validation", message)
        self.assertIn("Roll back", message)
        self.assertEqual(workspace.values["client_secret"], OLD_SECRET)
        self.assertIn("AWSCURRENT", secrets.stages[ORIGINAL])
        self.assertIn("Rolled back", agent.rollback(plan_id, "approver@example.com"))
        self.assertEqual(account.deleted, ["new-sp-secret"])
        self.assertEqual(plan.status, "rolled_back")
        self.assertEqual(workspace.values["client_secret"], OLD_SECRET)

    def test_rollback_after_a_completed_sync_restores_both_platforms(self):
        agent, secrets, workspace, account = build()
        plan_id = approved(agent)
        agent.run(plan_id)
        self.assertIn("Rolled back", agent.rollback(plan_id, "approver@example.com"))
        self.assertEqual(workspace.values["client_secret"], OLD_SECRET)
        self.assertIn("AWSCURRENT", secrets.stages[ORIGINAL])
        self.assertEqual(account.deleted, ["new-sp-secret"])

    def test_aws_contract_violation_stops_before_creating_credentials(self):
        agent, secrets, workspace, account = build(value="not-json")
        plan_id = approved(agent)
        self.assertIn("OAuth JSON contract", agent.run(plan_id))
        self.assertEqual(agent.plans[plan_id].status, "failed")
        self.assertEqual((secrets.writes, account.deleted), ([], []))

    def test_pat_is_created_validated_and_synced_then_rolled_back(self):
        agent, secrets, workspace, _ = build(PAT_BINDING)
        plan_id = approved(agent)
        message = agent.run(plan_id)
        plan = agent.plans[plan_id]
        self.assertEqual(plan.status, "executed", message)
        self.assertEqual(workspace.values["token"], NEW_PAT)
        self.assertEqual(secrets.values[plan.result["new_version"]], NEW_PAT)
        self.assertNotIn(NEW_PAT, repr((message, plan.view(), agent.audit)))
        agent.rollback(plan_id, "approver@example.com")
        self.assertEqual(workspace.values["token"], "dapiOLD")
        self.assertEqual(workspace.deleted_tokens, ["new-token-id"])

    def test_invalid_bindings_are_rejected(self):
        for broken in (dict(SP_BINDING, rollback_contract_verified_by_owner=False), dict(SP_BINDING, lifetime_days=0),
                       {k: v for k, v in SP_BINDING.items() if k != "client_id"}):
            with self.assertRaises(ValueError):
                load_bindings(json.dumps([broken]))
        sync = DatabricksSync.from_env({"SENTINELX_SYNC_BINDINGS": "{oops", "DATABRICKS_HOST": "adb.example.net"})
        self.assertIn("not valid JSON", sync.config_error)
        self.assertEqual(sync.host, "https://adb.example.net")


class FakeStatements:
    def __init__(self, fail=False):
        self.calls, self.fail = [], fail

    def execute_statement(self, statement, warehouse_id, wait_timeout, parameters):
        if self.fail:
            raise RuntimeError("warehouse down")
        self.calls.append((statement, {item.name: item.value for item in parameters}))
        return SimpleNamespace(status=SimpleNamespace(state=StatementState.SUCCEEDED),
                               result=SimpleNamespace(data_array=[["e1", "2026-01-01", "s", "a", "approved", NAME, "d"]]))


class AuditPersistenceTests(unittest.TestCase):
    def test_delta_sink_creates_table_and_inserts_with_parameters(self):
        statements = FakeStatements()
        sink = DeltaAuditSink("main.sentinelx.agent_audit", "wh-1", SimpleNamespace(statement_execution=statements))
        sink.append(dict(event_id="e1", at="2026-01-01T00:00:00+00:00", session_id="s", actor="a", event="approved",
                         target=NAME, detail="x'; DROP TABLE y; --"))
        self.assertIn("CREATE TABLE IF NOT EXISTS `main`.`sentinelx`.`agent_audit`", statements.calls[0][0])
        statement, parameters = statements.calls[1]
        self.assertNotIn("DROP", statement)
        self.assertIn("DROP TABLE", parameters["detail"])
        self.assertEqual(sink.read()[0]["event"], "approved")

    def test_table_name_must_be_a_three_part_identifier(self):
        for bad in ("audit", "a.b", "a.b.c; DROP", "a.b.c.d"):
            with self.assertRaises(ValueError):
                DeltaAuditSink(bad, "wh")
        self.assertIsNone(DeltaAuditSink.from_env({}))
        with self.assertRaises(ValueError):
            DeltaAuditSink.from_env({"SENTINELX_AUDIT_TABLE": "a.b.c"})

    def test_agent_events_reach_the_durable_sink(self):
        statements = FakeStatements()
        sink = DeltaAuditSink("main.sentinelx.agent_audit", "wh-1", SimpleNamespace(statement_execution=statements))
        agent, _, _, _ = build(sink=sink)
        agent.run(approved(agent))
        events = [params["event"] for statement, params in statements.calls if statement.startswith("INSERT")]
        self.assertEqual(events[:3], ["plan_created", "approved", "execution_started"])
        self.assertIn("execution_executed", events)
        self.assertTrue(all(row["persisted"] for row in agent.audit))

    def test_unavailable_durable_log_blocks_changes_fail_closed(self):
        sink = DeltaAuditSink("main.sentinelx.agent_audit", "wh-1", SimpleNamespace(statement_execution=FakeStatements(fail=True)))
        agent, secrets, workspace, account = build(sink=sink)
        plan_id = agent.handle(f"rotate {NAME}")["plan_id"]
        with self.assertRaises(RemediationError):
            agent.approve(plan_id, "approver@example.com")
        self.assertEqual(agent.plans[plan_id].status, "proposed")
        self.assertTrue(agent.audit_errors)
        self.assertEqual((secrets.writes, workspace.values["client_secret"], account.deleted), ([], OLD_SECRET, []))
        with self.assertRaises(AuditUnavailable):
            sink.read()

    def test_memory_sink_is_default_and_not_durable(self):
        agent, _, _, _ = build()
        self.assertIsInstance(agent.sink, MemoryAuditSink)
        self.assertEqual(agent.persisted_audit(), [])


class FakeServing:
    def __init__(self, *replies):
        self.replies = list(replies)
        self.serving_endpoints = SimpleNamespace(query=self.query)

    def query(self, name, max_tokens, temperature, messages):
        return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content=self.replies.pop(0)))])


class LanguageModelTests(unittest.TestCase):
    def llm(self, *replies):
        return AgentLanguageModel("endpoint", FakeServing(*replies))

    def test_interprets_free_text_into_an_allowlisted_tool_then_plans(self):
        agent, secrets, _, _ = build(llm=self.llm('{"tool": "plan_rotation", "target": "etl-oauth-not-found"}',
                                                   '{"tool": "plan_rotation", "target": "legacy-reporting"}', "Looks fine."))
        self.assertIn("couldn't find a secret matching", agent.handle("please get the credentials renewed for etl")["answer"])
        reply = agent.handle("could you refresh the legacy reporting key for me")
        self.assertIsNotNone(reply["plan_id"])
        self.assertEqual(agent.plans[reply["plan_id"]].secret_name, NAME)
        self.assertEqual(secrets.writes, [])

    def test_model_output_outside_the_allowlist_is_ignored(self):
        for reply in ('{"tool": "execute_plan", "target": "x"}', "not json", '{"tool": "plan_rotation", "target": "a b; rm -rf /"}'):
            agent, _, _, _ = build(llm=self.llm(reply))
            answer = agent.handle("do something clever")
            self.assertIsNone(answer["plan_id"])
            self.assertEqual(agent.plans, {})

    def test_model_cannot_approve_or_run_anything(self):
        agent, secrets, _, _ = build(llm=self.llm('{"tool": "approve", "target": null}'))
        agent.handle(f"rotate {NAME}")
        self.assertEqual(secrets.writes, [])
        self.assertIn("can't approve", agent.handle("please go ahead and approve it")["answer"])
        self.assertEqual(secrets.writes, [])

    def test_governance_questions_are_delegated_to_the_deterministic_copilot(self):
        agent, _, _, _ = build(llm=self.llm('{"tool": "ask_governance", "target": null}'))
        agent.knowledge = lambda question: "3 critical findings."
        self.assertEqual(agent.handle("how risky are we overall")["answer"], "3 critical findings.")

    def test_notes_are_added_but_rejected_when_they_contradict_or_leak(self):
        agent, _, _, _ = build(llm=self.llm("Review the risks before approving.", "Rotated successfully!"))
        self.assertIn("Pilot's note", agent.handle(f"rotate {NAME}")["answer"])
        plan_id = list(agent.plans)[0]
        agent.approve(plan_id, "approver@example.com")
        outcome = agent.run(plan_id)
        self.assertIn("Done", outcome)
        failing, _, _, _ = build(validator=lambda c, s: (_ for _ in ()).throw(ValueError("bad")),
                                 llm=self.llm("Everything completed successfully."))
        plan_id = failing.handle(f"rotate {NAME}")["plan_id"]
        failing.approve(plan_id, "approver@example.com")
        text = failing.run(plan_id)
        self.assertIn("failed", text)
        self.assertNotIn("Pilot's note", text)
        leaky = self.llm("The key is dapiABCDEF0123456789ABCDEF01234567.")
        self.assertIsNone(leaky.narrate(dict(outcome="succeeded")))
