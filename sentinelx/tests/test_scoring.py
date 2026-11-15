import unittest
from datetime import datetime, timedelta, timezone

from backend.models.asset import Asset
from scoring.engine import Policy, assess

NOW = datetime(2026, 11, 12, tzinfo=timezone.utc)


def credential(**changes):
    fields = dict(id="test", name="test", kind="sp_secret", source="databricks",
                  owner="platform", created_at=(NOW - timedelta(days=5)).isoformat(),
                  expires_at=(NOW + timedelta(days=60)).isoformat(), last_rotated_at=NOW.isoformat(),
                  active=True, privileged=False)
    fields.update(changes)
    return Asset(**fields)


class ScoringTests(unittest.TestCase):
    def test_healthy_and_expired_orphan(self):
        self.assertEqual(assess(credential(), now=NOW)["score"], 100)
        result = assess(credential(owner=None, expires_at=NOW.isoformat()), now=NOW)
        self.assertEqual(result["risk"], "critical")
        self.assertIn("expired", [item["code"] for item in result["findings"]])

    def test_expiry_buckets(self):
        for days, code in [(7, "expires_7d"), (15, "expires_15d"), (30, "expires_30d")]:
            with self.subTest(days=days):
                result = assess(credential(expires_at=(NOW + timedelta(days=days)).isoformat()), now=NOW)
                self.assertEqual([item["code"] for item in result["findings"]], [code])

    def test_unknown_is_not_healthy(self):
        self.assertFalse(assess(credential(active=None, expires_at=None), now=NOW)["compliant"])

    def test_default_age_policy(self):
        result = assess(credential(created_at=(NOW - timedelta(days=31)).isoformat()), now=NOW)
        self.assertIn("stale", [item["code"] for item in result["findings"]])

    def test_rejects_secret_fields(self):
        with self.assertRaises(TypeError):
            credential(secret_value="never store this")

    def test_invalid_policy(self):
        with self.assertRaises(ValueError):
            Policy(max_age_days=0)