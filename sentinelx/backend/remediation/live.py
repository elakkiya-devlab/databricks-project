import json
import uuid

import httpx

from backend.services.providers import clients


class RenewalExecutor:
    def __init__(self, config, workspace=None, account=None, aws=None, validator=None):
        self.config = config
        if workspace is None:
            workspace, account, aws = clients(config, executor=True)
        self.workspace, self.account, self.aws = workspace, account, aws
        self.validator = validator or self.validate_oauth

    def preflight(self, asset):
        parent = asset["parent_id"].removeprefix("db:sp:")
        mapping = self.config.get("bindings", {}).get(parent)
        if not self.account or not mapping:
            raise ValueError("Account executor and explicit AWS binding are required")
        required = {"aws_secret_id", "client_id", "scope", "key", "lifetime_days", "scopes", "rollback_contract_verified_by_owner"}
        if not required.issubset(mapping) or not mapping["scopes"] or not 1 <= mapping["lifetime_days"] <= 730:
            raise ValueError("Binding requires AWS destination, existing scope/key, lifetime and OAuth scopes")
        if mapping["rollback_contract_verified_by_owner"] is not True:
            raise ValueError("Owner must attest that AWS current material is the Databricks rollback source")
        principal = self.account.service_principals.get(id=parent)
        if principal.application_id != mapping["client_id"]:
            raise ValueError("Binding does not match the service principal application ID")
        if asset["provider_id"] not in {item.id for item in self.account.service_principal_secrets.list(service_principal_id=parent)}:
            raise ValueError("Source credential no longer exists")
        if mapping["key"] not in {item.key for item in self.workspace.secrets.list_secrets(scope=mapping["scope"])}:
            raise ValueError("Rollback requires an existing Databricks secret key")
        metadata = self.aws.describe_secret(SecretId=mapping["aws_secret_id"])
        versions = metadata.get("VersionIdsToStages", {})
        current = [identity for identity, stages in versions.items() if "AWSCURRENT" in stages]
        if len(current) != 1 or any("AWSPENDING" in stages for stages in versions.values()):
            raise ValueError("Exactly one current version and no unfinished rotation are required")
        return parent, mapping, current[0]

    def renew(self, asset, checkpoint):
        parent, mapping, previous = self.preflight(asset)
        old = json.loads(self.aws.get_secret_value(SecretId=mapping["aws_secret_id"], VersionId=previous)["SecretString"])
        if old.get("client_id") != mapping["client_id"] or old.get("secret_id") != asset["provider_id"] or not old.get("client_secret"):
            raise ValueError("AWS rollback material must be the bound OAuth credential JSON")
        receipt = dict(parent_id=parent, aws_secret_id=mapping["aws_secret_id"], previous_version=previous,
                       new_version=str(uuid.uuid4()), new_secret_id=None, scope=mapping["scope"], key=mapping["key"],
                       phase="intent")
        checkpoint(receipt)
        generated = self.account.service_principal_secrets.create(service_principal_id=parent,
                            lifetime=f"{mapping['lifetime_days'] * 86400}s", scopes=mapping["scopes"])
        receipt.update(new_secret_id=generated.id, phase="credential_created")
        checkpoint(receipt)
        if not generated.secret:
            raise ValueError("Provider did not return newly created credential material")
        payload = json.dumps(dict(client_id=mapping["client_id"], client_secret=generated.secret, secret_id=generated.id))
        self.aws.put_secret_value(SecretId=mapping["aws_secret_id"], ClientRequestToken=receipt["new_version"],
                                  SecretString=payload, VersionStages=["AWSPENDING"])
        receipt["phase"] = "aws_staged"
        checkpoint(receipt)
        self.validator(mapping["client_id"], generated.secret)
        self.workspace.secrets.put_secret(scope=mapping["scope"], key=mapping["key"], string_value=generated.secret)
        receipt["phase"] = "databricks_updated"
        checkpoint(receipt)
        self.aws.update_secret_version_stage(SecretId=mapping["aws_secret_id"], VersionStage="AWSCURRENT",
                                             MoveToVersionId=receipt["new_version"], RemoveFromVersionId=previous)
        receipt["phase"] = "promoted"
        checkpoint(receipt)
        self.aws.update_secret_version_stage(SecretId=mapping["aws_secret_id"], VersionStage="AWSPENDING",
                                             RemoveFromVersionId=receipt["new_version"])
        state = self.aws.describe_secret(SecretId=mapping["aws_secret_id"])["VersionIdsToStages"]
        if "AWSCURRENT" not in state.get(receipt["new_version"], []):
            raise ValueError("AWS rotation validation failed")
        receipt["phase"] = "validated"
        checkpoint(receipt)
        return receipt

    def validate_oauth(self, client_id, secret):
        host = self.config["executor"]["host"].rstrip("/")
        with httpx.Client(timeout=30) as client:
            response = client.post(host + "/oidc/v1/token", auth=(client_id, secret),
                                   data={"grant_type": "client_credentials", "scope": "all-apis"})
            if response.status_code != 200 or not response.json().get("access_token"):
                raise ValueError("New credential failed OAuth validation")

    def rollback(self, receipt):
        if not receipt:
            raise ValueError("Recovery receipt is required")
        state = self.aws.describe_secret(SecretId=receipt["aws_secret_id"])["VersionIdsToStages"]
        current = next((identity for identity, stages in state.items() if "AWSCURRENT" in stages), None)
        if current not in {receipt["previous_version"], receipt["new_version"]}:
            raise ValueError("A newer rotation exists; rollback requires manual reconciliation")
        old = json.loads(self.aws.get_secret_value(SecretId=receipt["aws_secret_id"],
                        VersionId=receipt["previous_version"])["SecretString"])
        self.workspace.secrets.put_secret(scope=receipt["scope"], key=receipt["key"], string_value=old["client_secret"])
        if current != receipt["previous_version"]:
            self.aws.update_secret_version_stage(SecretId=receipt["aws_secret_id"], VersionStage="AWSCURRENT",
                        MoveToVersionId=receipt["previous_version"], RemoveFromVersionId=current)
        if "AWSPENDING" in state.get(receipt["new_version"], []):
            self.aws.update_secret_version_stage(SecretId=receipt["aws_secret_id"], VersionStage="AWSPENDING",
                                                 RemoveFromVersionId=receipt["new_version"])
        validated = self.aws.describe_secret(SecretId=receipt["aws_secret_id"])["VersionIdsToStages"]
        if "AWSCURRENT" not in validated.get(receipt["previous_version"], []):
            raise ValueError("Rollback validation failed")