from datetime import datetime, timezone

import boto3
from databricks.sdk import AccountClient, WorkspaceClient

from backend.models.asset import Asset


def timestamp(value):
    if value is None or value == 0 or value == -1:
        return None
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc).isoformat()
    return datetime.fromtimestamp(value / 1000, timezone.utc).isoformat()


def clients(config, executor=False):
    credentials = config.get("executor" if executor else "discovery", {})
    if not all(credentials.get(key) for key in ("host", "client_id", "client_secret")):
        raise ValueError("Explicit OAuth service principal configuration is required")
    if not credentials["host"].startswith("https://"):
        raise ValueError("Databricks host must use HTTPS")
    common = dict(client_id=credentials["client_id"], client_secret=credentials["client_secret"], auth_type="oauth-m2m")
    workspace = WorkspaceClient(host=credentials["host"], **common)
    account = AccountClient(host=config.get("account_host", "https://accounts.cloud.databricks.com"),
                            account_id=config["account_id"], **common) if config.get("account_id") else None
    session = boto3.Session(region_name=config.get("aws_region", "us-east-1"),
                            profile_name=config.get("aws_executor_profile" if executor else "aws_profile"))
    return workspace, account, session.client("secretsmanager")


class LiveCollector:
    def __init__(self, config, workspace=None, account=None, aws=None):
        self.config = config
        if workspace is None:
            workspace, account, aws = clients(config)
        self.workspace, self.account, self.aws = workspace, account, aws

    def __call__(self):
        assets, errors, completed = [], [], []

        def collect(name, function):
            try:
                batch = list(function())
                assets.extend(batch)
                completed.append(name)
            except Exception as error:
                errors.append(dict(module=name, error=type(error).__name__))

        collect("service_principals", self.principals)
        collect("sp_secrets", self.sp_secrets)
        collect("pats", self.pats)
        collect("databricks_secrets", self.databricks_secrets)
        collect("aws_secrets", self.aws_secrets)
        for fields in self.config.get("registry_assets", []):
            assets.append(Asset(**fields))
        overrides = self.config.get("metadata_overrides", {})
        allowed = {"owner", "application", "created_at", "expires_at", "last_used_at", "last_rotated_at",
                   "active", "privileged", "binding"}
        for asset in assets:
            fields = overrides.get(asset.id, {})
            if set(fields) - allowed:
                raise ValueError("Registry contains unsupported metadata fields")
            for key, value in fields.items():
                setattr(asset, key, value)
            asset.__post_init__()
        return assets, dict(mode="live", complete=not errors, completed=completed, errors=errors,
                            assumptions=["Ownership/activity/privilege evidence may require an owner registry",
                                         "Metadata alignment does not prove secret-value equality"])

    def principals(self):
        for principal in self.workspace.service_principals.list():
            yield Asset(id=f"db:sp:{principal.id}", name=principal.display_name or principal.id,
                        kind="service_principal", source="databricks", provider_id=principal.id,
                        application=principal.application_id, active=principal.active,
                        privileged=True if any(role.value == "account_admin" for role in principal.roles or []) else None)

    def sp_secrets(self):
        if not self.account:
            raise ValueError("Account client is required for secret inventory")
        for principal in self.account.service_principals.list():
            for secret in self.account.service_principal_secrets.list(service_principal_id=principal.id):
                mapping = self.config.get("bindings", {}).get(principal.id)
                yield Asset(id=f"db:sp-secret:{principal.id}:{secret.id}", name=f"{principal.display_name or principal.id}/{secret.id}",
                            kind="sp_secret", source="databricks", provider_id=secret.id, parent_id=f"db:sp:{principal.id}",
                            created_at=secret.create_time, expires_at=secret.expire_time, active=principal.active,
                            application=principal.application_id, binding=principal.id if mapping else None,
                            rotation_supported=bool(mapping))

    def pats(self):
        for token in self.workspace.token_management.list():
            yield Asset(id=f"db:pat:{token.token_id}", name=f"PAT {token.token_id}", kind="pat", source="databricks",
                        provider_id=token.token_id, created_at=timestamp(token.creation_time),
                        expires_at=timestamp(token.expiry_time))

    def databricks_secrets(self):
        for scope in self.workspace.secrets.list_scopes():
            for secret in self.workspace.secrets.list_secrets(scope=scope.name):
                binding = next((identity for identity, mapping in self.config.get("bindings", {}).items()
                                if mapping.get("scope") == scope.name and mapping.get("key") == secret.key), None)
                yield Asset(id=f"db:secret:{scope.name}:{secret.key}", name=f"{scope.name}/{secret.key}",
                            kind="databricks_secret", source="databricks", binding=binding)

    def aws_secrets(self):
        for page in self.aws.get_paginator("list_secrets").paginate():
            for item in page.get("SecretList", []):
                metadata = self.aws.describe_secret(SecretId=item["ARN"])
                tags = {tag["Key"]: tag["Value"] for tag in metadata.get("Tags", [])}
                yield Asset(id=f"aws:secret:{item['ARN']}", name=item["Name"], kind="aws_secret", source="aws",
                            provider_id=item["ARN"], owner=tags.get("Owner"), application=tags.get("Application"),
                            binding=next((identity for identity, mapping in self.config.get("bindings", {}).items()
                                          if mapping["aws_secret_id"] == item["ARN"]), None),
                            created_at=timestamp(metadata.get("CreatedDate")),
                            last_rotated_at=timestamp(metadata.get("LastRotatedDate")),
                            rotation_enabled=metadata.get("RotationEnabled", False))