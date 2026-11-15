import json
import unittest
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock

import boto3
from botocore.stub import Stubber

from backend.remediation.live import RenewalExecutor
from backend.services.providers import LiveCollector

ARN = "arn:aws:secretsmanager:us-east-1:123456789012:secret:sentinelx/demo-ABC123"


class ProviderIntegrationTests(unittest.TestCase):
    def test_aws_metadata_with_botocore_stubber(self):
        client = boto3.client("secretsmanager", region_name="us-east-1", aws_access_key_id="test", aws_secret_access_key="test")
        with Stubber(client) as stub:
            stub.add_response("list_secrets", {"SecretList": [{"ARN": ARN, "Name": "sentinelx/demo"}]}, {})
            stub.add_response("describe_secret", dict(ARN=ARN, Name="sentinelx/demo", CreatedDate=datetime.now(timezone.utc),
                RotationEnabled=True, Tags=[{"Key": "Owner", "Value": "Platform"}]), {"SecretId": ARN})
            collector = LiveCollector({}, workspace=MagicMock(), aws=client)
            assets = list(collector.aws_secrets())
            self.assertEqual(assets[0].owner, "Platform")
            self.assertNotIn("SecretString", assets[0].to_dict())
            stub.assert_no_pending_responses()

    def test_databricks_secret_metadata_not_rotation_evidence(self):
        workspace = MagicMock()
        workspace.secrets.list_scopes.return_value = [SimpleNamespace(name="prod")]
        workspace.secrets.list_secrets.return_value = [SimpleNamespace(key="oauth", last_updated_timestamp=1700000000000)]
        assets = list(LiveCollector({}, workspace=workspace).databricks_secrets())
        self.assertIsNone(assets[0].created_at)
        self.assertIsNone(assets[0].last_rotated_at)
        workspace.secrets.get_secret.assert_not_called()

    def executor(self, fail_validation=False):
        account, workspace, aws = MagicMock(), MagicMock(), MagicMock()
        account.service_principals.get.return_value = SimpleNamespace(application_id="application-id")
        account.service_principal_secrets.list.return_value = [SimpleNamespace(id="old-secret")]
        account.service_principal_secrets.create.return_value = SimpleNamespace(id="new-secret", secret="sensitive-new")
        workspace.secrets.list_secrets.return_value = [SimpleNamespace(key="oauth")]
        versions = {"old-version": ["AWSCURRENT"]}
        aws.describe_secret.side_effect = lambda **kwargs: {"VersionIdsToStages": {key: list(value) for key, value in versions.items()}}
        aws.get_secret_value.return_value = {"SecretString": json.dumps(dict(client_id="application-id", client_secret="sensitive-old", secret_id="old-secret"))}

        def put(**kwargs):
            versions[kwargs["ClientRequestToken"]] = kwargs["VersionStages"]

        def stage(**kwargs):
            label = kwargs["VersionStage"]
            if kwargs.get("RemoveFromVersionId"):
                versions[kwargs["RemoveFromVersionId"]].remove(label)
            if kwargs.get("MoveToVersionId"):
                versions[kwargs["MoveToVersionId"]].append(label)

        aws.put_secret_value.side_effect = put
        aws.update_secret_version_stage.side_effect = stage
        validator = MagicMock(side_effect=ValueError("validation failed") if fail_validation else None)
        config = {"bindings": {"1": dict(aws_secret_id=ARN, client_id="application-id", scope="prod", key="oauth",
                  lifetime_days=90, scopes=["all-apis"], rollback_contract_verified_by_owner=True)}}
        executor = RenewalExecutor(config, workspace=workspace, account=account, aws=aws, validator=validator)
        asset = dict(parent_id="db:sp:1", provider_id="old-secret")
        return executor, asset, workspace, account, aws

    def test_live_renewal_staging_checkpoint_and_rollback(self):
        executor, asset, workspace, account, aws = self.executor()
        checkpoints = []
        receipt = executor.renew(asset, lambda item: checkpoints.append(item.copy()))
        self.assertEqual(receipt["phase"], "validated")
        self.assertNotIn("sensitive", json.dumps(checkpoints))
        account.service_principal_secrets.delete.assert_not_called()
        executor.rollback(receipt)
        self.assertEqual(aws.describe_secret()["VersionIdsToStages"]["old-version"], ["AWSCURRENT"])
        self.assertEqual(workspace.secrets.put_secret.call_args.kwargs["string_value"], "sensitive-old")

    def test_validation_failure_does_not_publish_to_databricks(self):
        executor, asset, workspace, account, aws = self.executor(fail_validation=True)
        checkpoints = []
        with self.assertRaises(ValueError):
            executor.renew(asset, lambda item: checkpoints.append(item.copy()))
        workspace.secrets.put_secret.assert_not_called()
        self.assertEqual(checkpoints[-1]["phase"], "aws_staged")
        executor.rollback(checkpoints[-1])

    def test_dry_run_never_reads_material(self):
        executor, asset, workspace, account, aws = self.executor()
        executor.preflight(asset)
        aws.get_secret_value.assert_not_called()
        account.service_principal_secrets.create.assert_not_called()