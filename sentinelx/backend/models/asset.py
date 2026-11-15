from dataclasses import asdict, dataclass
from datetime import datetime, timezone

KINDS = {"service_principal", "sp_secret", "pat", "oauth", "application_credential", "databricks_secret", "aws_secret"}


def utcnow():
    return datetime.now(timezone.utc)


def parse_time(value):
    if not value:
        return None
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("Dates must include a timezone")
    return parsed.astimezone(timezone.utc)


@dataclass
class Asset:
    id: str
    name: str
    kind: str
    source: str
    owner: str | None = None
    application: str | None = None
    created_at: str | None = None
    expires_at: str | None = None
    last_used_at: str | None = None
    last_rotated_at: str | None = None
    active: bool | None = None
    privileged: bool | None = None
    rotation_enabled: bool | None = None
    binding: str | None = None
    sync_state: str = "unverified"
    rotation_supported: bool = False
    provider_id: str | None = None
    parent_id: str | None = None

    def __post_init__(self):
        if self.kind not in KINDS or self.source not in {"databricks", "aws"}:
            raise ValueError("Unsupported asset kind or source")
        if not self.id or not self.name:
            raise ValueError("Asset identity is required")
        for field in ("created_at", "expires_at", "last_used_at", "last_rotated_at"):
            parse_time(getattr(self, field))

    def to_dict(self):
        return asdict(self)