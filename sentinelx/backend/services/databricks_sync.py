"""Cross-platform credential sync: rotate a Databricks credential and keep its AWS Secrets Manager copy in step.

Only credentials declared in SENTINELX_SYNC_BINDINGS can be touched. Each binding names the AWS secret, the Databricks
secret scope/key that consumers read, and the Databricks identity. New credential values exist only in this process's
memory and flow Databricks -> AWS (staged) -> validation -> Databricks secret scope -> AWS promoted. Receipts and
errors contain identifiers and phases, never values.

Binding JSON (list), for example:
  {"name": "etl-oauth", "kind": "service_principal_secret", "aws_secret": "sentinelx/prod/etl/oauth",
   "scope": "etl", "key": "client_secret", "service_principal_id": "123", "client_id": "<application id>",
   "scopes": ["all-apis"], "lifetime_days": 90, "rollback_contract_verified_by_owner": true}
  {"name": "ci-pat", "kind": "pat", "aws_secret": "sentinelx/dev/ci/pat", "scope": "ci", "key": "token",
   "application_id": "<service principal application id>", "lifetime_days": 30, "rollback_contract_verified_by_owner": true}
The service_principal_secret AWS payload is JSON {client_id, client_secret, secret_id}; the pat AWS payload is the token string.
"""

import json
import os
import uuid
from dataclasses import dataclass

from backend.remediation.live import RenewalExecutor

SP_SECRET, PAT = "service_principal_secret", "pat"
COMMON = ("name", "kind", "aws_secret", "scope", "key", "lifetime_days")
REQUIRED = {SP_SECRET: ("service_principal_id", "client_id", "scopes"), PAT: ("application_id",)}


class SyncError(Exception):
    """A sync failure with a user-safe message and the receipt needed for rollback (identifiers only)."""

    def __init__(self, message, receipt=None):
        super().__init__(message)
        self.receipt = receipt or {}


@dataclass(frozen=True)
class SyncBinding:
    name: str
    kind: str
    aws_secret: str
    scope: str
    key: str
    lifetime_days: int
    service_principal_id: str = ""
    client_id: str = ""
    application_id: str = ""
    scopes: tuple = ()
    rollback_contract_verified_by_owner: bool = False

    @property
    def platform_label(self):
        return "Databricks service principal secret" if self.kind == SP_SECRET else "Databricks PAT"


def load_bindings(raw):
    if not raw or not raw.strip():
        return []
    try:
        items = json.loads(raw)
    except ValueError as error:
        raise ValueError("SENTINELX_SYNC_BINDINGS is not valid JSON.") from error
    if not isinstance(items, list):
        raise ValueError("SENTINELX_SYNC_BINDINGS must be a JSON list.")
    bindings, names = [], set()
    for item in items:
        if not isinstance(item, dict) or item.get("kind") not in REQUIRED:
            raise ValueError(f"Each binding needs a kind of {SP_SECRET} or {PAT}.")
        missing = [field for field in COMMON + REQUIRED[item["kind"]] if not item.get(field)]
        if missing:
            raise ValueError(f"Binding {item.get('name', '?')} is missing: {', '.join(missing)}.")
        if not isinstance(item["lifetime_days"], int) or not 1 <= item["lifetime_days"] <= 730:
            raise ValueError(f"Binding {item['name']} lifetime_days must be 1-730.")
        if item.get("rollback_contract_verified_by_owner") is not True:
            raise ValueError(f"Binding {item['name']} needs rollback_contract_verified_by_owner=true (owner attestation).")
        if item["name"] in names:
            raise ValueError(f"Duplicate binding name {item['name']}.")
        names.add(item["name"])
        known = {field: item[field] for field in SyncBinding.__dataclass_fields__ if field in item}
        known["scopes"] = tuple(item.get("scopes", ()))
        bindings.append(SyncBinding(**known))
    return bindings


def _safe(error):
    return str(error) if isinstance(error, ValueError) else f"{type(error).__name__}"


class DatabricksSync:
    def __init__(self, bindings=(), host="", account_id="", workspace=None, account=None, validator=None, pat_validator=None,
                 config_error=""):
        self.bindings, self.account_id, self.config_error = list(bindings), account_id, config_error
        self.host = host if not host or host.startswith("http") else "https://" + host
        self._workspace, self._account = workspace, account
        self._validator, self._pat_validator = validator, pat_validator

    @classmethod
    def from_env(cls, environ=None):
        env = os.environ if environ is None else environ
        try:
            bindings, error = load_bindings(env.get("SENTINELX_SYNC_BINDINGS", "")), ""
        except ValueError as problem:
            bindings, error = [], str(problem)
        return cls(bindings, env.get("DATABRICKS_HOST", "").strip().rstrip("/"),
                   env.get("SENTINELX_DATABRICKS_ACCOUNT_ID", "").strip(), config_error=error)

    # lookup and readiness ----------------------------------------------------------------------------------------
    def binding_for(self, name, arn=""):
        return next((item for item in self.bindings if item.aws_secret in {name, arn}), None)

    def readiness(self, binding):
        if self.config_error:
            return self.config_error
        if not self.host:
            return "Databricks is not configured (DATABRICKS_HOST)."
        if binding.kind == SP_SECRET and not self.account_id:
            return "Databricks account ID is not configured (SENTINELX_DATABRICKS_ACCOUNT_ID)."
        return ""

    def workspace(self):
        if self._workspace is None:
            from databricks.sdk import WorkspaceClient
            self._workspace = WorkspaceClient(host=self.host)
        return self._workspace

    def account(self):
        if self._account is None and self.account_id:
            from databricks.sdk import AccountClient
            self._account = AccountClient(host=os.environ.get("SENTINELX_DATABRICKS_ACCOUNT_HOST", "https://accounts.cloud.databricks.com"),
                                          account_id=self.account_id)
        return self._account

    # execution ---------------------------------------------------------------------------------------------------
    def renew(self, binding, aws, checkpoint):
        receipts = {}

        def record(receipt):
            receipts.update(receipt, binding=binding.name, kind=binding.kind)
            checkpoint(dict(receipts))

        try:
            workspace = self.workspace()
            started = _now_ms()
            if binding.kind == SP_SECRET:
                receipt = self._sp_executor(binding, workspace, aws).renew(self._sp_asset(binding, aws), record)
            else:
                receipt = self._pat_renew(binding, workspace, aws, record)
            receipt = dict(receipt, binding=binding.name, kind=binding.kind)
            receipt["databricks_secret_verified"] = self._secret_updated(workspace, binding, started)
        except SyncError:
            raise
        except Exception as error:  # noqa: BLE001 - only identifiers and the exception type are surfaced
            raise SyncError(f"Credential sync stopped at phase '{receipts.get('phase', 'preflight')}': {_safe(error)}.",
                            dict(receipts)) from error
        if receipt["databricks_secret_verified"] is False:
            raise SyncError("Credential sync finished but Databricks does not show the secret as updated.", receipt)
        return receipt

    def rollback(self, binding, aws, receipt):
        try:
            workspace = self.workspace()
            if binding.kind == SP_SECRET:
                self._sp_executor(binding, workspace, aws).rollback(receipt)
                revoked = self._revoke(lambda: self.account().service_principal_secrets.delete(
                    service_principal_id=receipt["parent_id"], secret_id=receipt["new_secret_id"]),
                    receipt.get("new_secret_id"))
            else:
                self._pat_rollback(binding, workspace, aws, receipt)
                revoked = self._revoke(lambda: workspace.token_management.delete(token_id=receipt["new_token_id"]),
                                       receipt.get("new_token_id"))
        except Exception as error:  # noqa: BLE001
            raise SyncError(f"Rollback did not complete: {_safe(error)}.", receipt) from error
        return revoked

    @staticmethod
    def _revoke(action, identifier):
        if not identifier:
            return False
        try:
            action()
            return True
        except Exception:  # noqa: BLE001 - revoking the unused credential is best effort
            return False

    # service principal secrets (reuses the existing, tested renewal executor) ----------------------------------------
    def _sp_executor(self, binding, workspace, aws):
        config = {"executor": {"host": self.host}, "bindings": {binding.service_principal_id: dict(
            aws_secret_id=binding.aws_secret, client_id=binding.client_id, scope=binding.scope, key=binding.key,
            lifetime_days=binding.lifetime_days, scopes=list(binding.scopes),
            rollback_contract_verified_by_owner=binding.rollback_contract_verified_by_owner)}}
        return RenewalExecutor(config, workspace, self.account(), aws, validator=self._validator)

    def _sp_asset(self, binding, aws):
        data = aws.describe_secret(SecretId=binding.aws_secret)
        current = [version for version, stages in data.get("VersionIdsToStages", {}).items() if "AWSCURRENT" in stages]
        if len(current) != 1:
            raise ValueError("The AWS secret must have exactly one current version")
        try:
            payload = json.loads(aws.get_secret_value(SecretId=binding.aws_secret, VersionId=current[0])["SecretString"])
            secret_id = payload["secret_id"]
        except (ValueError, KeyError, TypeError) as error:
            raise ValueError("The AWS secret does not follow the OAuth JSON contract (client_id, client_secret, secret_id)") from error
        return {"parent_id": f"db:sp:{binding.service_principal_id}", "provider_id": secret_id}

    # personal access tokens -------------------------------------------------------------------------------------
    def _pat_renew(self, binding, workspace, aws, checkpoint):
        if binding.key not in {item.key for item in workspace.secrets.list_secrets(scope=binding.scope)}:
            raise ValueError("Rollback requires an existing Databricks secret key")
        metadata = aws.describe_secret(SecretId=binding.aws_secret)
        stages = metadata.get("VersionIdsToStages", {})
        current = [version for version, names in stages.items() if "AWSCURRENT" in names]
        if len(current) != 1 or any("AWSPENDING" in names for names in stages.values()):
            raise ValueError("Exactly one current version and no unfinished rotation are required")
        receipt = dict(aws_secret_id=binding.aws_secret, previous_version=current[0], new_version=str(uuid.uuid4()),
                       scope=binding.scope, key=binding.key, new_token_id=None, phase="intent")
        checkpoint(receipt)
        created = workspace.token_management.create_obo_token(
            application_id=binding.application_id, lifetime_seconds=binding.lifetime_days * 86400, comment="SentinelX rotation")
        token = created.token_value
        receipt.update(new_token_id=created.token_info.token_id, phase="credential_created")
        checkpoint(receipt)
        if not token:
            raise ValueError("Provider did not return the new token")
        aws.put_secret_value(SecretId=binding.aws_secret, ClientRequestToken=receipt["new_version"], SecretString=token,
                             VersionStages=["AWSPENDING"])
        receipt["phase"] = "aws_staged"
        checkpoint(receipt)
        (self._pat_validator or self._validate_pat)(token)
        workspace.secrets.put_secret(scope=binding.scope, key=binding.key, string_value=token)
        receipt["phase"] = "databricks_updated"
        checkpoint(receipt)
        aws.update_secret_version_stage(SecretId=binding.aws_secret, VersionStage="AWSCURRENT",
                                        MoveToVersionId=receipt["new_version"], RemoveFromVersionId=current[0])
        receipt["phase"] = "promoted"
        checkpoint(receipt)
        aws.update_secret_version_stage(SecretId=binding.aws_secret, VersionStage="AWSPENDING",
                                        RemoveFromVersionId=receipt["new_version"])
        final = aws.describe_secret(SecretId=binding.aws_secret)["VersionIdsToStages"]
        if "AWSCURRENT" not in final.get(receipt["new_version"], []):
            raise ValueError("AWS rotation validation failed")
        receipt["phase"] = "validated"
        checkpoint(receipt)
        return receipt

    def _validate_pat(self, token):
        from databricks.sdk import WorkspaceClient
        try:
            WorkspaceClient(host=self.host, token=token, auth_type="pat").current_user.me()
        except Exception as error:  # noqa: BLE001
            raise ValueError("New token failed validation") from error

    def _pat_rollback(self, binding, workspace, aws, receipt):
        state = aws.describe_secret(SecretId=receipt["aws_secret_id"])["VersionIdsToStages"]
        current = next((version for version, stages in state.items() if "AWSCURRENT" in stages), None)
        if current not in {receipt["previous_version"], receipt["new_version"]}:
            raise ValueError("A newer rotation exists; rollback requires manual reconciliation")
        old = aws.get_secret_value(SecretId=receipt["aws_secret_id"], VersionId=receipt["previous_version"])["SecretString"]
        workspace.secrets.put_secret(scope=receipt["scope"], key=receipt["key"], string_value=old)
        if current != receipt["previous_version"]:
            aws.update_secret_version_stage(SecretId=receipt["aws_secret_id"], VersionStage="AWSCURRENT",
                                            MoveToVersionId=receipt["previous_version"], RemoveFromVersionId=current)
        if "AWSPENDING" in state.get(receipt["new_version"], []):
            aws.update_secret_version_stage(SecretId=receipt["aws_secret_id"], VersionStage="AWSPENDING",
                                            RemoveFromVersionId=receipt["new_version"])
        restored = aws.describe_secret(SecretId=receipt["aws_secret_id"])["VersionIdsToStages"]
        if "AWSCURRENT" not in restored.get(receipt["previous_version"], []):
            raise ValueError("Rollback validation failed")

    @staticmethod
    def _secret_updated(workspace, binding, started_ms):
        for item in workspace.secrets.list_secrets(scope=binding.scope):
            if item.key == binding.key:
                stamp = getattr(item, "last_updated_timestamp", None)
                return None if stamp is None else stamp >= started_ms - 5000
        return False


def _now_ms():
    import time
    return int(time.time() * 1000)
