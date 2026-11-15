import argparse
import json
from pathlib import Path

from backend.governance.service import Governance
from backend.models.asset import utcnow
from backend.services.providers import LiveCollector
from backend.services.sample import demo_assets
from backend.services.store import Store
from configs.settings import Settings
from scoring.engine import Policy


def main():
    parser = argparse.ArgumentParser(description="One audit-only scan for a scheduler or Databricks job")
    parser.add_argument("--output-dir", default=".local/reports")
    args = parser.parse_args()
    settings = Settings.from_env()
    store = Store(settings.db_path)
    collector = LiveCollector(settings.provider) if settings.mode == "live" else lambda: (demo_assets(), {"mode": "demo", "complete": True, "errors": []})
    governance = Governance(store, collector, Policy(settings.max_age_days, settings.rotation_days, settings.inactivity_days))
    try:
        report = governance.scan("batch-scanner")
    except Exception:
        raise SystemExit("Discovery failed; previous snapshot retained. Consult audit history.") from None
    directory = Path(args.output_dir)
    directory.mkdir(parents=True, exist_ok=True)
    stamp = utcnow().strftime("%Y%m%dT%H%M%S%fZ")
    (directory / (stamp + ".json")).write_text(json.dumps(dict(report=report, inventory=store.rows("assets"),
        audit=store.rows("audits")), indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))
    if not report["coverage"]["complete"]:
        raise SystemExit(2)


if __name__ == "__main__":
    main()