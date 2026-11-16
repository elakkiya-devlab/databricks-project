"""AWS Secrets Manager connection checks using short-lived credentials only.

Supported authentication:
  * assume_role      - STS AssumeRole into SENTINELX_AWS_ROLE_ARN with the runtime's ambient federated identity.
  * identity_center  - IAM Identity Center (SSO OIDC device authorization) followed by sso:GetRoleCredentials.

No long-lived access keys are read, stored, or displayed. Only read-only calls are made: GetCallerIdentity,
ListSecrets (MaxResults=1), and the SSO/OIDC login APIs. Secret values are never requested.
"""

import os
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError, NoCredentialsError

NOT_CONFIGURED_MESSAGE = ("AWS connection is not configured. Complete the connection setup to enable live AWS inventory "
                          "and secret synchronization.")
AUTH_METHODS = {"assume_role": "IAM Role (STS AssumeRole)", "identity_center": "IAM Identity Center (device authorization)"}
REQUIRED_PERMISSIONS = [
    ("sts:GetCallerIdentity", "Validate the connected identity (checked)"),
    ("secretsmanager:ListSecrets", "Discover secret inventory metadata (checked)"),
    ("secretsmanager:DescribeSecret", "Read rotation and version-stage metadata (discovery role)"),
    ("secretsmanager:PutSecretValue / UpdateSecretVersionStage", "Stage and promote rotated values (separate remediation role only)"),
    ("kms:Decrypt / kms:GenerateDataKey", "Use the secret's KMS key via Secrets Manager (remediation role only)"),
]
_CLIENT_CONFIG = Config(connect_timeout=5, read_timeout=10, retries={"max_attempts": 2})


@dataclass
class AwsConfig:
    account_id: str = ""
    region: str = ""
    role_arn: str = ""
    auth_method: str = ""
    external_id: str = ""
    sso_start_url: str = ""
    sso_region: str = ""
    sso_role_name: str = ""

    @classmethod
    def from_env(cls, environ=None):
        env = os.environ if environ is None else environ
        read = lambda name: env.get("SENTINELX_AWS_" + name, "").strip()  # noqa: E731
        method = read("AUTH_METHOD") or ("identity_center" if read("SSO_START_URL") else "assume_role" if read("ROLE_ARN") else "")
        return cls(read("ACCOUNT_ID"), read("REGION"), read("ROLE_ARN"), method, read("EXTERNAL_ID"),
                   read("SSO_START_URL"), read("SSO_REGION") or read("REGION"), read("SSO_ROLE_NAME"))

    def missing(self):
        required = {"assume_role": ("account_id", "region", "role_arn"),
                    "identity_center": ("account_id", "region", "sso_start_url", "sso_region", "sso_role_name")}
        if self.auth_method not in required:
            return ["auth_method"]
        return [name for name in required[self.auth_method] if not getattr(self, name)]

    @property
    def configured(self):
        return not self.missing()


@dataclass
class ConnectionResult:
    status: str  # connected | failed | not_configured | login_required
    message: str
    checked_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds"))
    identity_arn: str = ""
    account_id: str = ""
    permissions: dict = field(default_factory=dict)

    @property
    def connected(self):
        return self.status == "connected"


def _client_error(error):
    if isinstance(error, ClientError):
        code = error.response.get("Error", {}).get("Code", "Unknown")
        return f"AWS rejected the request ({code})."
    if isinstance(error, NoCredentialsError):
        return "No AWS identity is available to the application for the configured role."
    return f"AWS could not be reached ({type(error).__name__})."


class AwsConnector:
    def __init__(self, config, client_factory=None):
        self.config = config
        self._client = client_factory or (lambda service, **kwargs: boto3.client(service, config=_CLIENT_CONFIG, **kwargs))

    def test_connection(self, sso_credentials=None):
        """Return the real connection state; `connected` only after identity and permission checks pass."""
        config = self.config
        if not config.configured:
            return ConnectionResult("not_configured", NOT_CONFIGURED_MESSAGE)
        try:
            credentials = self._credentials(sso_credentials)
        except LoginRequired:
            return ConnectionResult("login_required", "Sign in with IAM Identity Center to continue.")
        except (BotoCoreError, ClientError) as error:
            return ConnectionResult("failed", _client_error(error))
        try:
            sts = self._client("sts", region_name=config.region, **credentials)
            identity = sts.get_caller_identity()
        except (BotoCoreError, ClientError) as error:
            return ConnectionResult("failed", _client_error(error))
        if identity.get("Account") != config.account_id:
            return ConnectionResult("failed", "The authenticated AWS account does not match the configured account ID.",
                                    identity_arn=identity.get("Arn", ""), account_id=identity.get("Account", ""))
        permissions = {"sts:GetCallerIdentity": True}
        try:
            self._client("secretsmanager", region_name=config.region, **credentials).list_secrets(MaxResults=1)
            permissions["secretsmanager:ListSecrets"] = True
        except (BotoCoreError, ClientError) as error:
            permissions["secretsmanager:ListSecrets"] = False
            return ConnectionResult("failed", "Identity verified, but required Secrets Manager permission is missing. "
                                              + _client_error(error), identity_arn=identity["Arn"],
                                    account_id=identity["Account"], permissions=permissions)
        return ConnectionResult("connected", "Identity and Secrets Manager read access verified.",
                                identity_arn=identity["Arn"], account_id=identity["Account"], permissions=permissions)

    def _credentials(self, sso_credentials):
        config = self.config
        if config.auth_method == "identity_center":
            if not sso_credentials or sso_credentials.get("expiration", 0) <= time.time() * 1000:
                raise LoginRequired
            return dict(aws_access_key_id=sso_credentials["access_key_id"], aws_secret_access_key=sso_credentials["secret_access_key"],
                        aws_session_token=sso_credentials["session_token"])
        arguments = dict(RoleArn=config.role_arn, RoleSessionName="sentinelx-connection-check", DurationSeconds=900)
        if config.external_id:
            arguments["ExternalId"] = config.external_id
        assumed = self._client("sts", region_name=config.region).assume_role(**arguments)["Credentials"]
        return dict(aws_access_key_id=assumed["AccessKeyId"], aws_secret_access_key=assumed["SecretAccessKey"],
                    aws_session_token=assumed["SessionToken"])

    # IAM Identity Center device authorization -----------------------------------------------------------------
    def start_login(self):
        config = self.config
        if config.auth_method != "identity_center" or not config.configured:
            raise AwsLoginError("IAM Identity Center is not configured.")
        try:
            oidc = self._client("sso-oidc", region_name=config.sso_region)
            registration = oidc.register_client(clientName="sentinelx-governance", clientType="public")
            authorization = oidc.start_device_authorization(
                clientId=registration["clientId"], clientSecret=registration["clientSecret"], startUrl=config.sso_start_url)
        except (BotoCoreError, ClientError) as error:
            raise AwsLoginError(_client_error(error)) from error
        return dict(client_id=registration["clientId"], client_secret=registration["clientSecret"],
                    device_code=authorization["deviceCode"], user_code=authorization["userCode"],
                    verification_uri=authorization.get("verificationUriComplete") or authorization["verificationUri"],
                    interval=int(authorization.get("interval", 5)), expires_at=time.time() + int(authorization.get("expiresIn", 600)))

    def poll_login(self, flow):
        """Return ('pending'|'expired'|'failed'|'authorized', credentials_or_None)."""
        if time.time() >= flow["expires_at"]:
            return "expired", None
        config = self.config
        try:
            token = self._client("sso-oidc", region_name=config.sso_region).create_token(
                clientId=flow["client_id"], clientSecret=flow["client_secret"], deviceCode=flow["device_code"],
                grantType="urn:ietf:params:oauth:grant-type:device_code")
        except ClientError as error:
            code = error.response.get("Error", {}).get("Code")
            if code in {"AuthorizationPendingException", "SlowDownException"}:
                return "pending", None
            return ("expired" if code == "ExpiredTokenException" else "failed"), None
        except BotoCoreError:
            return "failed", None
        try:
            role = self._client("sso", region_name=config.sso_region).get_role_credentials(
                roleName=config.sso_role_name, accountId=config.account_id, accessToken=token["accessToken"])["roleCredentials"]
        except (BotoCoreError, ClientError):
            return "failed", None
        return "authorized", dict(access_key_id=role["accessKeyId"], secret_access_key=role["secretAccessKey"],
                                  session_token=role["sessionToken"], expiration=role["expiration"])


class LoginRequired(Exception):
    pass


class AwsLoginError(Exception):
    pass
