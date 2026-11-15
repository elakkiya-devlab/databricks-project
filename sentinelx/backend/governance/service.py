import json
from collections import defaultdict

from backend.models.asset import Asset, parse_time, utcnow
from scoring.engine import Policy, assess


def compare_bindings(assets):
    groups = defaultdict(list)
    for asset in assets:
        if asset.binding:
            groups[asset.binding].append(asset)
    for group in groups.values():
        sources = {asset.source for asset in group}
        dates = [parse_time(asset.last_rotated_at) for asset in group]
        rotation_modes = {asset.rotation_enabled for asset in group if asset.rotation_enabled is not None}
        state = "missing_counterpart" if len(sources) < 2 else "unverified" if not all(dates) else (
            "metadata_aligned" if len(set(dates)) == 1 and len(rotation_modes) <= 1 else "drift")
        for asset in group:
            asset.sync_state = state
    return assets


class Governance:
    def __init__(self, store, collector, policy=None):
        self.store, self.collector, self.policy = store, collector, policy or Policy()

    def scan(self, actor="scheduler"):
        try:
            assets, coverage = self.collector()
            if not coverage["complete"] and self.store.rows("assets"):
                raise ValueError("Partial discovery cannot replace an existing complete inventory")
            identities = [asset.id for asset in assets]
            if len(identities) != len(set(identities)):
                raise ValueError("Duplicate asset IDs in provider or registry inventory")
            overlays = {item["id"]: item["changes"] for item in self.store.rows("overlays")}
            for asset in assets:
                for field, value in overlays.get(asset.id, {}).items():
                    setattr(asset, field, value)
            assets = compare_bindings(assets)
            results = [dict(asset=asset.to_dict(), assessment=assess(asset, self.policy)) for asset in assets]
            results.sort(key=lambda item: item["assessment"]["score"])
            report = self.summarize(results)
            report.update(at=utcnow().isoformat(), coverage=coverage, policy=self.policy.__dict__)
            with self.store.connect() as connection:
                connection.execute("DELETE FROM assets")
                for item in results:
                    connection.execute("INSERT INTO assets VALUES(?,?)", (item["asset"]["id"], json.dumps(item)))
                connection.execute("INSERT INTO runs(body) VALUES(?)", (json.dumps(dict(report=report, inventory=results)),))
                self.store.event(actor, "discovery", str(len(assets)), "complete" if coverage["complete"] else "partial", connection)
            return report
        except Exception:
            self.store.event(actor, "discovery", outcome="failed; previous snapshot retained")
            raise

    def summarize(self, results=None):
        results = results if results is not None else self.store.rows("assets")
        total = len(results)
        compliant = sum(item["assessment"]["compliant"] for item in results)
        actions = self.store.rows("actions")
        return dict(total=total, score=round(sum(item["assessment"]["score"] for item in results) / total, 1) if total else None,
                    compliance_percentage=round(100 * compliant / total, 1) if total else None,
                    high_risk=sum(item["assessment"]["risk"] in {"high", "critical"} for item in results),
                    open_actions=sum(item["status"] not in {"succeeded", "rejected", "rolled_back"} for item in actions),
                    findings=sum(len(item["assessment"]["findings"]) for item in results))

    def rescore(self, identity, changes, actor):
        with self.store.connect() as connection:
            row = connection.execute("SELECT body FROM assets WHERE id=?", (identity,)).fetchone()
            if not row:
                raise KeyError(identity)
            item = json.loads(row[0])
            previous = connection.execute("SELECT body FROM overlays WHERE id=?", (identity,)).fetchone()
            merged = json.loads(previous[0])["changes"] if previous else {}
            merged.update(changes)
            connection.execute("INSERT OR REPLACE INTO overlays VALUES(?,?)",
                               (identity, json.dumps(dict(id=identity, changes=merged))))
            item["asset"].update(changes)
            item["assessment"] = assess(Asset(**item["asset"]), self.policy)
            connection.execute("UPDATE assets SET body=? WHERE id=?", (json.dumps(item), identity))
            self.store.event(actor, "metadata_update", identity, connection=connection)