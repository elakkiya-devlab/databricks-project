import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cryptography.fernet import Fernet, InvalidToken

from backend.governance.service import compare_bindings
from backend.models.asset import Asset
from configs.settings import Settings
from scoring.engine import assess
from tests.test_api import KEYS
from tests.test_scoring import NOW, credential


class SecurityTests(unittest.TestCase):
    def test_expired_is_always_critical(self):
        self.assertEqual(assess(credential(expires_at=NOW.isoformat()), now=NOW)["risk"], "critical")

    def test_configuration_is_encrypted_and_wrong_key_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            key = Fernet.generate_key()
            file = Path(directory) / "config.enc"
            file.write_bytes(Fernet(key).encrypt(json.dumps({"marker": "sensitive-config"}).encode()))
            self.assertNotIn(b"sensitive-config", file.read_bytes())
            environment = {"SENTINELX_CONFIG_FILE": str(file), "SENTINELX_CONFIG_KEY": key.decode(),
                           **{f"SENTINELX_{role.upper()}_KEY": value for role, value in KEYS.items()}}
            with patch.dict("os.environ", environment):
                self.assertEqual(Settings.from_env().provider["marker"], "sensitive-config")
                with patch.dict("os.environ", {"SENTINELX_CONFIG_KEY": Fernet.generate_key().decode()}):
                    with self.assertRaises(InvalidToken):
                        Settings.from_env()

    def test_missing_and_drift_sync(self):
        first = Asset("first", "first", "databricks_secret", "databricks", binding="mapped",
                      last_rotated_at="2026-11-12T00:00:00+00:00", rotation_enabled=True)
        compare_bindings([first])
        self.assertEqual(first.sync_state, "missing_counterpart")
        second = Asset("second", "second", "aws_secret", "aws", binding="mapped",
                       last_rotated_at="2026-11-12T00:00:00Z", rotation_enabled=False)
        compare_bindings([first, second])
        self.assertEqual(first.sync_state, "drift")
        second.rotation_enabled = True
        compare_bindings([first, second])
        self.assertEqual(first.sync_state, "metadata_aligned")

    def test_keys_must_be_distinct(self):
        with self.assertRaises(ValueError):
            Settings(keys={role: "x" * 40 for role in KEYS})