"""Deterministic AWS Secrets Manager remediation tools used by the SentinelPilot agent.

The agent never holds AWS credentials or secret values. This module validates the plan, the human approval, the target
secret and the AWS account before any write, then verifies the outcome from version-stage metadata only.

Strategies:
  * native_rotation  - secretsmanager:RotateSecret when the secret already has rotation enabled.
  * generated_value  - a new random value is generated in memory, written with PutSecretValue, and never returned or logged.
"""

import logging
import os
import secrets
import time
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone

from botocore.exceptions import BotoCoreError, ClientError

from backend.services.aws_connection import NOT_CONFIGURED_MESSAGE, AwsConnector, LoginRequired, _client_error
from backend.services.databricks_sync import SyncError

log = logging.getLogger("sentinelx.aws_remediation")

NATIVE, GENERATED, SYNC = "native_rotation", "generated_value", "cross_platform_sync"
ERROR_HINTS = {
    "AccessDeniedException": "The AWS role is not allowed to perform this operation. Grant the permission listed on the "
                             "AWS Integration page to the remediation role.",
    "ResourceNotFoundException": "The secret was not found in the connected AWS account and region.",
    "InvalidRequestException": "AWS rejected the request; the secret may be scheduled for deletion or already rotating.",
    "InvalidParameterException": "AWS rejected a request parameter; check the secret's rotation configuration.",
    "ThrottlingException": "AWS throttled the request. Retry after a short wait; a new plan and approval are required.",
    "LimitExceededException": "AWS secret version limit reached. Remove deprecated versions, then plan again.",
    "ResourceExistsException": "A conflicting version already exists. Plan again to get a fresh version token.",
}


class RemediationError(Exception):
    """A failure whose message is safe to show to users and the agent (never contains secret material)."""


@dataclass
class ExecutionConfig:
    enabled: bool = False
    allowed_prefixes: tuple = ()
    remediation_role_arn: str = ""
    wait_seconds: int = 60

    @classmethod
    def from_env(cls, environ=None):
        env = os.environ if environ is None else environ
        read = lambda name: env.get("SENTINELX_AWS_" + name, "").strip()  # noqa: E731
        prefixes = tuple(item.strip() for item in read("ALLOWED_SECRET_PREFIXES").split(",") if item.strip())
        return cls(read("EXECUTION_ENABLED").lower() in {"1", "true", "yes"}, prefixes, read("REMEDIATION_ROLE_ARN"))


@dataclass
class RotationPlan:
    plan_id: str
    secret_name: str
    secret_arn: str
    strategy: str
    current_version: str
    steps: list
    verification: list
    risks: list
    blockers: list
    finding_id: str = ""
    binding: str = ""
    created_at: str = field(default_factory=lambda: _now())
    status: str = "proposed"  # proposed | approved | rejected | executed | in_progress | failed | rolled_back
    approved_by: str = ""
    approved_at: str = ""
    result: dict = field(default_factory=dict)

    def view(self):
        return asdict(self)


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _iso(value):
    return value.isoformat(timespec="seconds") if hasattr(value, "isoformat") else (str(value) if value else "")


def _describe_error(error):
    if isinstance(error, ClientError):
        code = error.response.get("Error", {}).get("Code", "Unknown")
        return f"{ERROR_HINTS.get(code, 'AWS rejected the request.')} (AWS error: {code})"
    return _client_error(error)


class AwsRemediator:
    def __init__(self, config, execution, client_factory=None, sleep=time.sleep, sync=None):
        self.config, self.execution, self._sleep, self.sync = config, execution, sleep, sync
        self.phase_listener = None
        self.connector = AwsConnector(config, client_factory)
        self._client = self.connector._client

    # readiness -------------------------------------------------------------------------------------------------
    def not_configured(self):
        return "" if self.config.configured else NOT_CONFIGURED_MESSAGE

    def allowed(self, name):
        return any(name.startswith(prefix) for prefix in self.execution.allowed_prefixes)

    def blockers(self, name=None):
        found = []
        if not self.execution.enabled:
            found.append("Execution is disabled. Set SENTINELX_AWS_EXECUTION_ENABLED=true to let the agent act after approval.")
        if not self.execution.allowed_prefixes:
            found.append("No allowed secret prefix is configured (SENTINELX_AWS_ALLOWED_SECRET_PREFIXES).")
        elif name is not None and not self.allowed(name):
            found.append(f"Secret is outside the allowed prefixes: {', '.join(self.execution.allowed_prefixes)}.")
        if self.config.auth_method == "assume_role" and not self.execution.remediation_role_arn:
            found.append("No remediation role is configured (SENTINELX_AWS_REMEDIATION_ROLE_ARN).")
        return found

    def _secrets_client(self, sso_credentials, write):
        role = self.execution.remediation_role_arn if write and self.config.auth_method == "assume_role" else None
        try:
            credentials = self.connector._credentials(sso_credentials, role_arn=role,
                                                      session_name="sentinelx-agent-" + ("write" if write else "read"))
            identity = self._client("sts", region_name=self.config.region, **credentials).get_caller_identity()
        except LoginRequired as error:
            raise RemediationError("Sign in with IAM Identity Center on the AWS Integration page first.") from error
        except (BotoCoreError, ClientError) as error:
            raise RemediationError(_describe_error(error)) from error
        if identity.get("Account") != self.config.account_id:
            raise RemediationError("The authenticated AWS account does not match the configured account ID.")
        return self._client("secretsmanager", region_name=self.config.region, **credentials)

    def _describe(self, client, secret_id):
        try:
            data = client.describe_secret(SecretId=secret_id)
        except (BotoCoreError, ClientError) as error:
            raise RemediationError(_describe_error(error)) from error
        if data.get("DeletedDate"):
            raise RemediationError("The secret is scheduled for deletion.")
        stages = data.get("VersionIdsToStages", {})
        current = [version for version, names in stages.items() if "AWSCURRENT" in names]
        return data, stages, current[0] if len(current) == 1 else ""

    # read tools ------------------------------------------------------------------------------------------------
    def list_secrets(self, sso_credentials=None, limit=50):
        client = self._secrets_client(sso_credentials, write=False)
        rows, token = [], None
        try:
            while len(rows) < limit:
                page = client.list_secrets(MaxResults=min(100, limit - len(rows)), **({"NextToken": token} if token else {}))
                rows += [dict(name=item["Name"], arn=item["ARN"], rotation_enabled=bool(item.get("RotationEnabled")),
                              last_rotated=_iso(item.get("LastRotatedDate")), last_changed=_iso(item.get("LastChangedDate")),
                              agent_scope="In scope" if self.allowed(item["Name"]) else "Out of scope")
                         for item in page.get("SecretList", [])]
                token = page.get("NextToken")
                if not token:
                    break
        except (BotoCoreError, ClientError) as error:
            raise RemediationError(_describe_error(error)) from error
        return rows

    def plan_rotation(self, target, sso_credentials=None, finding_id=""):
        client = self._secrets_client(sso_credentials, write=False)
        data, _, current = self._describe(client, target)
        name = data["Name"]
        native = bool(data.get("RotationEnabled"))
        binding = self.sync.binding_for(name, data["ARN"]) if self.sync else None
        if binding:
            steps = ["Confirm the secret, AWS account and declared binding match this plan.",
                     f"Create a new {binding.platform_label} in Databricks (the value stays in backend memory).",
                     "Stage it in AWS Secrets Manager as a pending version.",
                     "Validate the new credential against Databricks before using it.",
                     f"Write it to the Databricks secret scope key {binding.scope}/{binding.key}.",
                     "Promote the AWS version to current so AWS and Databricks hold the same credential."]
            risks = ["The previous Databricks credential is not revoked by this plan; it stays valid until it expires or an owner "
                     "revokes it. Rollback revokes the new credential and restores the previous one.",
                     "Consumers of either store receive the new credential after promotion."]
            if native:
                risks.append("AWS native rotation is bypassed on purpose so the two platforms cannot drift.")
            verification = ["Validate the new credential with Databricks before any consumer receives it.",
                            "Confirm the Databricks secret scope key shows a fresh update timestamp.",
                            "Re-read AWS version-stage metadata and confirm the new version is AWSCURRENT.",
                            "Write an audit event per phase without any secret material."]
            blockers = self.blockers(name)
            reason = self.sync.readiness(binding)
            return RotationPlan(plan_id=uuid.uuid4().hex[:12], secret_name=name, secret_arn=data["ARN"], strategy=SYNC,
                                current_version=current, steps=steps, verification=verification, risks=risks,
                                blockers=blockers + ([reason] if reason else []), finding_id=finding_id, binding=binding.name)
        if native:
            steps = ["Confirm the secret and AWS account match this plan.", "Request native rotation (RotateSecret, immediately).",
                     "Wait for AWS to finish the rotation and promote the new version."]
            risks = ["Rotation runs the secret's configured rotation function; consumers must tolerate the new value."]
        else:
            steps = ["Confirm the secret and AWS account match this plan.",
                     "Generate a new random value inside the backend (the agent never sees it).",
                     "Write it as a new version with PutSecretValue; AWS keeps the old version as AWSPREVIOUS."]
            risks = ["The ENTIRE secret value is replaced with a random string. Structured (JSON) secrets such as database "
                     "or OAuth credentials will lose their other fields.",
                     "Applications reading this secret must pick up the new value; the previous version stays recoverable "
                     "through rollback until AWS removes it."]
        verification = ["Re-read version-stage metadata (no secret values) and confirm the new version is AWSCURRENT.",
                        "Record an audit event without any secret material."]
        if not native:
            verification.insert(1, "Confirm the previous version is retained as AWSPREVIOUS for rollback.")
        return RotationPlan(plan_id=uuid.uuid4().hex[:12], secret_name=name, secret_arn=data["ARN"],
                            strategy=NATIVE if native else GENERATED, current_version=current, steps=steps,
                            verification=verification, risks=risks, blockers=self.blockers(name), finding_id=finding_id)

    # write tools -----------------------------------------------------------------------------------------------
    def execute(self, plan, sso_credentials=None):
        """Execute exactly the approved plan. Updates plan.status/result and returns the result."""
        if plan.status != "approved" or not plan.approved_by:
            raise RemediationError("This plan has no human approval and cannot be executed.")
        blockers = self.blockers(plan.secret_name)
        if blockers:
            raise RemediationError(blockers[0])
        if plan.strategy == SYNC:
            self._binding(plan)
        client = self._secrets_client(sso_credentials, write=True)
        _, _, current = self._describe(client, plan.secret_arn)
        if not current or current != plan.current_version:
            plan.status = "failed"
            raise RemediationError("The secret changed after this plan was created. Create and approve a new plan.")
        try:
            runner = {NATIVE: self._rotate_native, SYNC: self._sync_rotate}.get(plan.strategy, self._put_generated)
            result = runner(client, plan)
        except (BotoCoreError, ClientError) as error:
            plan.status, plan.result = "failed", dict(outcome="failed", message=_describe_error(error), changed=False)
            log.warning("AWS rotation failed for plan %s", plan.plan_id)
            return plan.result
        except RemediationError as error:
            plan.status, plan.result = "failed", dict(outcome="failed", message=str(error) + " The final state is unverified.",
                                                      changed=None)
            return plan.result
        plan.status = {"succeeded": "executed", "in_progress": "in_progress"}.get(result["outcome"], "failed")
        plan.result = result
        return result

    def _rotate_native(self, client, plan):
        client.rotate_secret(SecretId=plan.secret_arn, ClientRequestToken=str(uuid.uuid4()), RotateImmediately=True)
        deadline = time.monotonic() + self.execution.wait_seconds
        while True:
            _, stages, current = self._describe(client, plan.secret_arn)
            if current and current != plan.current_version and not any("AWSPENDING" in names for names in stages.values()):
                return dict(outcome="succeeded", changed=True, new_version=current, previous_version=plan.current_version,
                            message="Native rotation completed and the new version is AWSCURRENT.")
            if time.monotonic() >= deadline:
                return dict(outcome="in_progress", changed=True, previous_version=plan.current_version,
                            message="Rotation was requested but AWS has not finished within the wait window. "
                                    "It is NOT confirmed; check the secret's version stages before relying on it.")
            self._sleep(5)

    def _put_generated(self, client, plan):
        token = str(uuid.uuid4())
        client.put_secret_value(SecretId=plan.secret_arn, ClientRequestToken=token, SecretString=secrets.token_urlsafe(32))
        _, stages, current = self._describe(client, plan.secret_arn)
        verified = current == token and "AWSPREVIOUS" in stages.get(plan.current_version, [])
        if verified:
            return dict(outcome="succeeded", changed=True, new_version=token, previous_version=plan.current_version,
                        message="A new value was written; the new version is AWSCURRENT and the old one is AWSPREVIOUS.")
        return dict(outcome="failed", changed=True, new_version=token, previous_version=plan.current_version,
                    message="The value was written but version-stage verification did not match the expected state. "
                            "Inspect the secret before retrying; rollback is available if the new version is current.")

    def _binding(self, plan):
        binding = self.sync.binding_for(plan.secret_name, plan.secret_arn) if self.sync else None
        if not binding or binding.name != plan.binding:
            raise RemediationError("The Databricks binding for this plan is no longer configured.")
        reason = self.sync.readiness(binding)
        if reason:
            raise RemediationError(reason)
        return binding

    def _sync_rotate(self, client, plan):
        binding = self._binding(plan)

        def checkpoint(receipt):
            plan.result = dict(plan.result, receipt=dict(receipt))
            if self.phase_listener:
                self.phase_listener(plan, receipt.get("phase", ""))

        try:
            receipt = self.sync.renew(binding, client, checkpoint)
        except SyncError as error:
            receipt = error.receipt or plan.result.get("receipt", {})
            changed = receipt.get("phase", "intent") != "intent"
            return dict(outcome="failed", changed=changed, receipt=receipt, new_version=receipt.get("new_version"),
                        previous_version=receipt.get("previous_version"),
                        message=str(error) + (" Use Roll back to restore the previous credential and revoke the new one."
                                              if changed else " No credential was created."))
        _, _, current = self._describe(client, plan.secret_arn)
        if current != receipt["new_version"]:
            return dict(outcome="failed", changed=True, receipt=receipt, new_version=receipt["new_version"],
                        previous_version=receipt["previous_version"],
                        message="The sync finished but AWS does not show the new version as current. Roll back or inspect the secret.")
        note = "" if receipt.get("databricks_secret_verified") else " The Databricks secret timestamp could not be independently confirmed."
        return dict(outcome="succeeded", changed=True, receipt=receipt, new_version=receipt["new_version"],
                    previous_version=receipt["previous_version"],
                    message=f"The {binding.platform_label} was rotated, validated, written to Databricks secret "
                            f"{binding.scope}/{binding.key}, and AWS now serves the same new version.{note}")

    def rollback(self, plan, sso_credentials=None):
        if plan.strategy == SYNC:
            return self._rollback_sync(plan, sso_credentials)
        if plan.status not in {"executed", "failed"} or plan.strategy != GENERATED or not plan.result.get("new_version"):
            raise RemediationError("Only a generated-value or cross-platform rotation with a recorded new version can be rolled back.")
        blockers = self.blockers(plan.secret_name)
        if blockers:
            raise RemediationError(blockers[0])
        client = self._secrets_client(sso_credentials, write=True)
        _, _, current = self._describe(client, plan.secret_arn)
        new, previous = plan.result["new_version"], plan.result["previous_version"]
        if current != new:
            raise RemediationError("A newer version exists; rollback needs manual reconciliation.")
        try:
            client.update_secret_version_stage(SecretId=plan.secret_arn, VersionStage="AWSCURRENT", MoveToVersionId=previous,
                                               RemoveFromVersionId=new)
        except (BotoCoreError, ClientError) as error:
            raise RemediationError(_describe_error(error)) from error
        _, _, restored = self._describe(client, plan.secret_arn)
        if restored != previous:
            raise RemediationError("Rollback was requested but the previous version is not AWSCURRENT. Inspect the secret.")
        plan.status = "rolled_back"
        return dict(outcome="rolled_back", message="The previous version is AWSCURRENT again.")

    def _rollback_sync(self, plan, sso_credentials):
        receipt = plan.result.get("receipt") or {}
        if plan.status not in {"executed", "failed"} or receipt.get("phase", "intent") == "intent":
            raise RemediationError("There is no completed credential change to roll back for this plan.")
        blockers = self.blockers(plan.secret_name)
        if blockers:
            raise RemediationError(blockers[0])
        binding = self._binding(plan)
        client = self._secrets_client(sso_credentials, write=True)
        try:
            revoked = self.sync.rollback(binding, client, receipt)
        except SyncError as error:
            raise RemediationError(str(error)) from error
        _, _, current = self._describe(client, plan.secret_arn)
        if current != receipt.get("previous_version"):
            raise RemediationError("Rollback ran but the previous AWS version is not current. Inspect the secret.")
        plan.status = "rolled_back"
        return dict(outcome="rolled_back", message="The previous credential is restored in Databricks and AWS. "
                    + ("The unused new credential was revoked." if revoked else
                       "The new credential could not be revoked automatically; revoke it manually."))

