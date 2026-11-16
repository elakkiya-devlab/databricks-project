import json
import os
from dataclasses import dataclass, field
from pathlib import Path

from cryptography.fernet import Fernet


@dataclass(frozen=True)
class AppMode:
    demo: bool
    warning: str = ""

    @property
    def live(self):
        return not self.demo


def _flag(value):
    return value.strip().lower() in {"1", "true", "yes", "on"}


def resolve_app_mode(environ=None):
    """DEMO_MODE (default true) and LIVE_MODE select the dashboard data source; ambiguity resolves to safe demo."""
    env = os.environ if environ is None else environ
    live = _flag(env.get("LIVE_MODE", ""))
    demo = _flag(env["DEMO_MODE"]) if "DEMO_MODE" in env else not live
    if "DEMO_MODE" in env and not demo:
        live = True
    if demo and live:
        return AppMode(True, "DEMO_MODE and LIVE_MODE are both true; running in Demo Mode (no cloud access).")
    return AppMode(demo=not live)


@dataclass
class Settings:
    mode: str = "demo"
    db_path: str = ".local/sentinelx.db"
    remediation_enabled: bool = False
    scan_interval: int = 300
    max_age_days: int = 30
    rotation_days: int = 30
    inactivity_days: int = 30
    keys: dict = field(default_factory=dict, repr=False)
    provider: dict = field(default_factory=dict, repr=False)

    def __post_init__(self):
        if self.mode not in {"demo", "live"} or self.scan_interval < 10:
            raise ValueError("Invalid mode or scan interval")
        if set(self.keys) != {"reader", "operator", "approver"}:
            raise ValueError("Three role-specific API keys are required")
        if any(len(value) < 32 for value in self.keys.values()) or len(set(self.keys.values())) != 3:
            raise ValueError("API keys must be distinct and at least 32 characters")

    @classmethod
    def from_env(cls):
        provider = {}
        if os.getenv("SENTINELX_CONFIG_FILE"):
            payload = Path(os.environ["SENTINELX_CONFIG_FILE"]).read_bytes()
            provider = json.loads(Fernet(os.environ["SENTINELX_CONFIG_KEY"].encode()).decrypt(payload))
        return cls(mode=os.getenv("SENTINELX_MODE", "demo"),
                   db_path=os.getenv("SENTINELX_DB_PATH", ".local/sentinelx.db"),
                   remediation_enabled=os.getenv("SENTINELX_REMEDIATION_ENABLED", "false").lower() == "true",
                   scan_interval=int(os.getenv("SENTINELX_SCAN_INTERVAL", "300")),
                   max_age_days=int(os.getenv("SENTINELX_MAX_AGE_DAYS", "30")),
                   rotation_days=int(os.getenv("SENTINELX_ROTATION_DAYS", "30")),
                   inactivity_days=int(os.getenv("SENTINELX_INACTIVITY_DAYS", "30")),
                   keys={role: os.getenv(f"SENTINELX_{role.upper()}_KEY", "") for role in ("reader", "operator", "approver")},
                   provider=provider)