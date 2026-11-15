import hashlib
import json
import uuid
from datetime import datetime, timedelta

from backend.models.asset import utcnow


def fingerprint(asset):
    return hashlib.sha256(json.dumps(asset, sort_keys=True).encode()).hexdigest()


class WorkflowError(ValueError):
    pass


class Remediation:
    def __init__(self, governance, mode="demo", enabled=False, executor=None):
        self.governance, self.store = governance, governance.store
        self.mode, self.enabled, self.executor = mode, enabled, executor

    def request(self, asset_id, action, actor, owner=None, original_id=None, finding_id=None, idempotency_key=None):
        asset = self.store.get("assets", asset_id)["asset"]
        if action not in {"renew_sp", "rotate_secret", "sync_secret", "assign_owner", "rollback"}:
            raise WorkflowError("Unsupported action; irreversible actions are intentionally unavailable")
        if action == "renew_sp" and asset["kind"] != "sp_secret":
            raise WorkflowError("Renewal requires a service principal secret")
        if action in {"rotate_secret", "sync_secret"} and asset["kind"] not in {"aws_secret", "databricks_secret"}:
            raise WorkflowError("A secret asset is required")
        if self.mode == "live" and action not in {"renew_sp", "assign_owner", "rollback"}:
            raise WorkflowError("Standalone live rotation/sync lacks a verified rollback contract")
        if action == "assign_owner" and (not owner or len(owner) > 120):
            raise WorkflowError("An accountable owner of 1-120 characters is required")
        if action == "rollback":
            original = self.store.get("actions", original_id)
            if original["asset_id"] != asset_id or original["action"] == "rollback" or original["status"] not in {
                    "succeeded", "failed", "recovery_required"}:
                raise WorkflowError("Original action is not recoverable")
            if original["status"] != "succeeded" and not original.get("receipt"):
                raise WorkflowError("No provider mutation to roll back")
        item = dict(id=str(uuid.uuid4()), asset_id=asset_id, action=action, requester=actor, approver=None,
                    owner=owner, original_id=original_id, status="pending", created_at=utcnow().isoformat(),
                    updated_at=utcnow().isoformat(), finding_id=finding_id, idempotency_key=idempotency_key, before=asset,
                    fingerprint=fingerprint(asset), reviewed=False, receipt=None, mode=self.mode)
        with self.store.connect() as connection:
            if idempotency_key:
                existing = [json.loads(row[0]) for row in connection.execute("SELECT body FROM actions")]
                for previous in existing:
                    if previous.get("idempotency_key") != idempotency_key:
                        continue
                    same_request = all(previous.get(field) == item.get(field) for field in (
                        "asset_id", "action", "requester", "owner", "original_id", "finding_id",
                    ))
                    if not same_request:
                        raise WorkflowError("Idempotency key was already used for a different request")
                    return previous
            connection.execute("INSERT INTO actions VALUES(?,?)", (item["id"], json.dumps(item)))
            self.store.event(actor, "request_" + action, item["id"], connection=connection)
        return item

    def update(self, identity, actor, operation, mutate):
        with self.store.connect() as connection:
            row = connection.execute("SELECT body FROM actions WHERE id=?", (identity,)).fetchone()
            if not row:
                raise KeyError(identity)
            item = json.loads(row[0])
            mutate(item)
            item["updated_at"] = utcnow().isoformat()
            connection.execute("UPDATE actions SET body=? WHERE id=?", (json.dumps(item), identity))
            self.store.event(actor, operation, identity, item["status"], connection)
        return item

    def dry_run(self, identity, actor):
        def mutate(item):
            if item["status"] not in {"pending", "approved"}:
                raise WorkflowError("Action is no longer reviewable")
            if fingerprint(self.store.get("assets", item["asset_id"])["asset"]) != item["fingerprint"]:
                raise WorkflowError("Inventory changed; create a new request")
            if self.mode == "live" and item["action"] == "renew_sp":
                if not self.executor:
                    raise WorkflowError("Live executor is not configured")
                self.executor.preflight(item["before"])
            item["reviewed"] = True
            item["plan"] = dict(mode=self.mode, action=item["action"], target=item["asset_id"],
                                provider_writes=False, rollback="Restore prior metadata or AWS version; retain old OAuth secret")
        return self.update(identity, actor, "dry_run", mutate)

    def decide(self, identity, actor, approve=True):
        def mutate(item):
            if item["status"] != "pending" or not item["reviewed"]:
                raise WorkflowError("A pending action with a reviewed dry run is required")
            if actor == item["requester"]:
                raise WorkflowError("Requester cannot approve their own action")
            item.update(status="approved" if approve else "rejected", approver=actor,
                        approved_at=utcnow().isoformat())
        return self.update(identity, actor, "approve" if approve else "reject", mutate)

    def execute(self, identity, actor, dry_run=True):
        if dry_run:
            return self.dry_run(identity, actor)
        if not self.enabled:
            raise WorkflowError("Audit mode prohibits execution")

        def claim(item):
            if item["status"] != "approved" or not item["reviewed"]:
                raise WorkflowError("Separate approval and dry run are required")
            if actor == item["approver"]:
                raise WorkflowError("Approver cannot execute their own approval")
            if item["mode"] != self.mode:
                raise WorkflowError("Execution mode changed; create a new request")
            if utcnow() - datetime.fromisoformat(item["approved_at"]) > timedelta(hours=24):
                raise WorkflowError("Approval expired; create a new request")
            if fingerprint(self.store.get("assets", item["asset_id"])["asset"]) != item["fingerprint"]:
                raise WorkflowError("Inventory changed; create a new request")
            binding = item["before"].get("binding")
            for other in self.store.rows("actions"):
                blocked = other["status"] in {"running", "recovery_required"} or other["status"] == "failed" and other.get("receipt")
                if blocked and other["id"] != item.get("original_id") and (
                        other["asset_id"] == item["asset_id"] or binding and other["before"].get("binding") == binding):
                    raise WorkflowError("A related action is executing or awaiting recovery")
            if item["action"] == "rollback":
                original = self.store.get("actions", item["original_id"])
                if original["status"] == "rolled_back":
                    raise WorkflowError("Original action was already rolled back")
            item["status"] = "running"

        item = self.update(identity, actor, "execution_started", claim)
        try:
            if item["action"] == "rollback":
                original = self.store.get("actions", item["original_id"])
                if self.mode == "live" and original["action"] != "assign_owner":
                    self.executor.rollback(original["receipt"])
                else:
                    changes = {"owner": original["before"]["owner"]} if self.mode == "live" else original["before"]
                    self.governance.rescore(item["asset_id"], changes, actor)
                self.update(original["id"], actor, "original_restored", lambda record: record.update(status="rolled_back"))
            elif item["action"] == "assign_owner":
                self.governance.rescore(item["asset_id"], {"owner": item["owner"]}, actor)
            elif self.mode == "demo":
                now = utcnow()
                changes = dict(created_at=now.isoformat(), last_rotated_at=now.isoformat(), sync_state="metadata_aligned")
                if item["action"] == "renew_sp":
                    changes["expires_at"] = (now + timedelta(days=90)).isoformat()
                self.governance.rescore(item["asset_id"], changes, actor)
            else:
                def checkpoint(receipt):
                    self.update(identity, actor, "provider_checkpoint", lambda record: record.update(receipt=receipt.copy()))
                receipt = self.executor.renew(item["before"], checkpoint)
                self.update(identity, actor, "provider_validated", lambda record: record.update(receipt=receipt))
            return self.update(identity, actor, "execution_succeeded", lambda record: record.update(status="succeeded"))
        except Exception:
            self.update(identity, actor, "execution_failed", lambda record: record.update(status="failed"))
            raise WorkflowError("Execution failed; inspect audit/checkpoints and request rollback before retrying") from None