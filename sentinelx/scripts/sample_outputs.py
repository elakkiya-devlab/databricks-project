import json
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from backend.governance.service import Governance
from backend.remediation.engine import Remediation
from backend.services.sample import demo_assets
from backend.services.store import Store


def main():
    root = Path(__file__).resolve().parents[1]
    anchor = datetime(2026, 11, 12, tzinfo=timezone.utc)
    assets = demo_assets(anchor)
    with tempfile.TemporaryDirectory() as directory:
        store = Store(Path(directory) / "sample.db")
        governance = Governance(store, lambda: (assets, {"mode": "demo", "complete": True, "errors": []}))
        before = governance.scan("demo-operator")
        workflow = Remediation(governance, enabled=True)
        item = workflow.request("db:sp-secret:6", "renew_sp", "demo-operator")
        workflow.dry_run(item["id"], "demo-operator")
        workflow.decide(item["id"], "demo-approver")
        workflow.execute(item["id"], "demo-operator", dry_run=False)
        after = governance.summarize()
        bundle = dict(simulated=True, before=before, after=after,
                      findings_removed=before["findings"] - after["findings"],
                      audit_integrity=store.verify_audit(), action=store.get("actions", item["id"]))
        (root / "configs/sample_assets.json").write_text(json.dumps([asset.to_dict() for asset in assets], indent=2), encoding="utf-8")
        (root / "docs/sample_output.json").write_text(json.dumps(bundle, indent=2), encoding="utf-8")
        print(json.dumps({key: bundle[key] for key in ("simulated", "findings_removed", "audit_integrity")}, indent=2))


if __name__ == "__main__":
    main()