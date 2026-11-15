import asyncio
import csv
import hmac
import io
import json
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, ConfigDict, Field

from backend.copilot.service import ComplianceCopilot, SUGGESTED_QUESTIONS
from backend.governance.service import Governance
from backend.governance.findings import build_findings
from backend.models.asset import parse_time, utcnow
from backend.remediation.engine import Remediation, WorkflowError
from backend.remediation.live import RenewalExecutor
from backend.services.providers import LiveCollector
from backend.services.sample import demo_assets
from backend.services.store import Store
from configs.settings import Settings
from scoring.engine import Policy


class Proposal(BaseModel):
    model_config = ConfigDict(extra="forbid")
    asset_id: str = Field(min_length=1, max_length=512)
    action: str
    owner: str | None = Field(default=None, max_length=120)
    original_id: str | None = None
    finding_id: str | None = Field(default=None, max_length=64)
    idempotency_key: str | None = Field(default=None, min_length=16, max_length=128)


class ChatRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    question: str = Field(min_length=1, max_length=1000)
    context_finding_id: str | None = Field(default=None, max_length=64)


class Execution(BaseModel):
    model_config = ConfigDict(extra="forbid")
    dry_run: bool = True


class Decision(BaseModel):
    model_config = ConfigDict(extra="forbid")
    approve: bool = True


def create_app(settings=None, collector=None, executor=None, copilot_intent_provider=None):
    settings = settings or Settings.from_env()
    store = Store(settings.db_path)
    if collector is None:
        if settings.mode == "demo":
            runs = store.rows("runs")
            anchor = parse_time(runs[0]["report"]["at"]) if runs else utcnow()

            def collector():
                return demo_assets(anchor), dict(mode="demo", complete=True, errors=[])
        else:
            collector = LiveCollector(settings.provider)
    governance = Governance(store, collector, Policy(settings.max_age_days, settings.rotation_days, settings.inactivity_days))
    if settings.mode == "live" and settings.remediation_enabled and executor is None:
        executor = RenewalExecutor(settings.provider)
    workflow = Remediation(governance, settings.mode, settings.remediation_enabled, executor)
    copilot = ComplianceCopilot(copilot_intent_provider)

    async def periodic():
        while True:
            await asyncio.sleep(settings.scan_interval)
            try:
                await asyncio.to_thread(governance.scan)
            except Exception:
                pass

    @asynccontextmanager
    async def lifespan(app):
        for action in store.rows("actions"):
            if action["status"] == "running":
                workflow.update(action["id"], "system", "restart_recovery", lambda item: item.update(status="recovery_required"))
        try:
            await asyncio.to_thread(governance.scan, "startup")
        except Exception:
            pass
        task = asyncio.create_task(periodic())
        yield
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

    app = FastAPI(title="SentinelX Governance API", version="0.1.0", lifespan=lifespan,
                  docs_url=None, redoc_url=None, openapi_url=None)
    app.state.store, app.state.governance, app.state.workflow, app.state.copilot = store, governance, workflow, copilot

    @app.middleware("http")
    async def audit_requests(request, call_next):
        role = next((role for role, key in settings.keys.items()
                     if hmac.compare_digest(request.headers.get("X-API-Key", ""), key)), None)
        request.state.actor = role
        if not role:
            store.event("anonymous", "http", outcome="unauthorized")
            return JSONResponse(status_code=401, content={"detail": "Authentication required"})
        try:
            response = await call_next(request)
        except Exception:
            store.event(role, "http", outcome="internal_error")
            return JSONResponse(status_code=500, content={"detail": "Operation failed; consult audit history"})
        route = request.scope.get("route")
        store.event(role, request.method + " " + (route.path if route else "unknown_route"), outcome=str(response.status_code))
        return response

    def require(*roles):
        def dependency(request: Request):
            if request.state.actor not in roles:
                raise HTTPException(403, "Role does not permit this operation")
            return request.state.actor
        return dependency

    reader = require("reader", "operator", "approver")
    operator = require("operator")
    approver = require("approver")

    @app.exception_handler(WorkflowError)
    async def workflow_error(request, error):
        return JSONResponse(status_code=409, content={"detail": str(error)})

    @app.exception_handler(KeyError)
    async def missing(request, error):
        return JSONResponse(status_code=404, content={"detail": "Record not found"})

    @app.exception_handler(RequestValidationError)
    async def invalid(request, error):
        return JSONResponse(status_code=422, content={"detail": "Invalid metadata request; values and extra fields are forbidden"})

    @app.get("/health")
    def health(actor=Depends(reader)):
        return dict(status="ok", mode=settings.mode, remediation_enabled=settings.remediation_enabled,
                    audit_integrity=store.verify_audit())

    @app.get("/compliance/summary")
    @app.get("/summary")
    def summary(actor=Depends(reader)):
        runs = store.rows("runs")
        findings = current_findings()
        return dict(**governance.summarize(), latest=runs[-1]["report"] if runs else None,
                    finding_counts={
                        "critical": sum(item["severity"] == "critical" for item in findings),
                        "high": sum(item["severity"] == "high" for item in findings),
                        "expired": sum(item["code"] == "expired" for item in findings),
                        "expiring": sum(item["code"] in {"expires_7d", "expires_15d", "expires_30d"} for item in findings),
                        "total": len(findings),
                    })

    @app.get("/assets")
    def assets(actor=Depends(reader)):
        return store.rows("assets")

    @app.post("/discover")
    def discover(actor=Depends(operator)):
        return governance.scan(actor)

    @app.get("/history")
    def history(actor=Depends(reader)):
        return [item["report"] for item in store.rows("runs")]

    @app.get("/audit")
    def audit(actor=Depends(reader)):
        return dict(integrity=store.verify_audit(), events=store.rows("audits")[-1000:])

    @app.get("/actions")
    def actions(actor=Depends(reader)):
        return store.rows("actions")

    def current_findings():
        runs = store.rows("runs")
        latest = runs[-1]["report"] if runs else {}
        return build_findings(
            store.rows("assets"),
            store.rows("actions"),
            latest.get("at"),
            latest.get("policy", governance.policy.__dict__),
            settings.mode,
            settings.remediation_enabled,
        )

    @app.get("/compliance/findings")
    def compliance_findings(
        risk: str | None = None,
        kind: str | None = None,
        expired: bool | None = None,
        expiring: bool | None = None,
        unassigned: bool | None = None,
        owner: str | None = Query(default=None, max_length=120),
        pending_approval: bool | None = None,
        remediation_status: str | None = None,
        query: str | None = Query(default=None, max_length=200),
        page: int = Query(default=1, ge=1),
        page_size: int = Query(default=50, ge=1, le=200),
        actor=Depends(reader),
    ):
        rows = current_findings()
        if risk:
            values = {value.strip().lower() for value in risk.split(",")}
            if not values <= {"critical", "high", "medium", "low"}:
                raise HTTPException(422, "Unsupported risk filter")
            rows = [row for row in rows if row["severity"] in values]
        if kind:
            kinds = {value.strip() for value in kind.split(",")}
            if not kinds <= {"service_principal", "sp_secret", "pat", "oauth", "application_credential",
                             "databricks_secret", "aws_secret"}:
                raise HTTPException(422, "Unsupported credential type filter")
            rows = [row for row in rows if row["credential_type"] in kinds]
        if expired is not None:
            rows = [row for row in rows if (row["code"] == "expired") is expired]
        if expiring is not None:
            codes = {"expires_7d", "expires_15d", "expires_30d"}
            rows = [row for row in rows if (row["code"] in codes) is expiring]
        if unassigned is not None:
            rows = [row for row in rows if (not row["owner"]) is unassigned]
        if owner is not None:
            rows = [row for row in rows if row["owner"] == owner]
        if pending_approval is not None:
            pending = {"pending_review", "awaiting_approval"}
            rows = [row for row in rows if (row["approval_status"] in pending) is pending_approval]
        if remediation_status:
            statuses = {value.strip() for value in remediation_status.split(",")}
            rows = [row for row in rows if row["remediation_status"] in statuses]
        if query:
            term = query.casefold()
            rows = [row for row in rows if term in " ".join(
                str(row.get(field) or "") for field in ("finding_id", "asset_id", "asset_name", "owner", "code", "title", "recommendation")
            ).casefold()]
        total = len(rows)
        start = (page - 1) * page_size
        return dict(items=rows[start:start + page_size], total=total, page=page, page_size=page_size)

    @app.get("/compliance/findings/{identity}")
    def compliance_finding(identity: str, actor=Depends(reader)):
        result = next((row for row in current_findings() if row["finding_id"] == identity), None)
        if result is None:
            raise HTTPException(404, "Finding not found in the current report")
        return result

    @app.get("/remediation/actions")
    def remediation_actions(
        status: str | None = None,
        page: int = Query(default=1, ge=1),
        page_size: int = Query(default=50, ge=1, le=200),
        actor=Depends(reader),
    ):
        rows = store.rows("actions")
        if status:
            statuses = {value.strip() for value in status.split(",")}
            if not statuses <= {"pending", "approved", "rejected", "running", "succeeded", "failed",
                                "recovery_required", "rolled_back"}:
                raise HTTPException(422, "Unsupported remediation status filter")
            rows = [row for row in rows if row["status"] in statuses]
        rows = list(reversed(rows))
        total = len(rows)
        start = (page - 1) * page_size
        return dict(items=rows[start:start + page_size], total=total, page=page, page_size=page_size)

    @app.get("/remediation/actions/{identity}")
    def remediation_action(identity: str, actor=Depends(reader)):
        return store.get("actions", identity)

    @app.get("/remediation/actions/{identity}/history")
    def remediation_action_history(identity: str, actor=Depends(reader)):
        store.get("actions", identity)
        return [event for event in store.rows("audits") if event["target"] == identity]

    @app.get("/copilot/suggestions")
    def copilot_suggestions(actor=Depends(reader)):
        return {"items": SUGGESTED_QUESTIONS}

    @app.post("/copilot/chat")
    def copilot_chat(body: ChatRequest, actor=Depends(reader)):
        runs = store.rows("runs")
        latest = runs[-1]["report"] if runs else {}
        summary_data = dict(**governance.summarize(), latest=latest or None)
        return copilot.answer(
            body.question,
            current_findings(),
            summary_data,
            store.rows("actions"),
            store.rows("assets"),
            latest.get("at"),
            body.context_finding_id,
        )

    @app.post("/remediation/actions", status_code=201)
    @app.post("/actions", status_code=201)
    def propose(body: Proposal, actor=Depends(operator)):
        if body.finding_id:
            finding = next((row for row in current_findings() if row["finding_id"] == body.finding_id), None)
            if not finding or finding["asset_id"] != body.asset_id:
                raise HTTPException(422, "Finding does not match the current asset inventory")
            if body.action not in finding["supported_actions"]:
                raise HTTPException(409, "This finding has no supported remediation action in the current mode")
        return workflow.request(body.asset_id, body.action, actor, body.owner, body.original_id,
                                body.finding_id, body.idempotency_key)

    @app.post("/remediation/actions/{identity}/dry-run")
    @app.post("/actions/{identity}/dry-run")
    def dry_run(identity: str, actor=Depends(operator)):
        return workflow.dry_run(identity, actor)

    @app.post("/remediation/actions/{identity}/approval")
    @app.post("/actions/{identity}/decision")
    def decide(identity: str, body: Decision, actor=Depends(approver)):
        return workflow.decide(identity, actor, body.approve)

    @app.post("/remediation/actions/{identity}/execute")
    @app.post("/actions/{identity}/execute")
    def execute(identity: str, body: Execution, actor=Depends(operator)):
        result = workflow.execute(identity, actor, body.dry_run)
        if not body.dry_run:
            try:
                governance.scan(actor)
            except Exception:
                pass
        return result

    @app.get("/report")
    def report(format: str = "json", actor=Depends(reader)):
        if format == "json":
            return Response(json.dumps(dict(summary=governance.summarize(), inventory=store.rows("assets"))),
                            media_type="application/json", headers={"Content-Disposition": "attachment; filename=sentinelx-report.json"})
        if format != "csv":
            raise HTTPException(400, "Supported formats: json, csv")
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["id", "name", "kind", "owner", "score", "risk"])
        for item in store.rows("assets"):
            asset, assessed = item["asset"], item["assessment"]
            fields = [asset["id"], asset["name"], asset["kind"], asset["owner"] or "", assessed["score"], assessed["risk"]]
            writer.writerow(["'" + value if isinstance(value, str) and value.lstrip().startswith(("=", "+", "-", "@")) else value for value in fields])
        return Response(output.getvalue(), media_type="text/csv",
                        headers={"Content-Disposition": "attachment; filename=sentinelx-report.csv"})

    @app.get("/openapi.json")
    def schema(actor=Depends(reader)):
        return app.openapi()

    return app