"""Audit sinks for the SentinelPilot agent: in-memory (session) and Delta (durable, via the SQL Statement Execution API).

Rows contain event metadata only. Callers must never put secret material in `detail`; values are truncated as a backstop.
Make the Delta table append-only for the App identity (grant INSERT and SELECT, not UPDATE/DELETE/MODIFY) and rely on
Delta history for tamper evidence.
"""

import logging
import os
import re
import uuid

log = logging.getLogger("sentinelx.audit")

TABLE = re.compile(r"^[A-Za-z0-9_]+\.[A-Za-z0-9_]+\.[A-Za-z0-9_]+$")
COLUMNS = ("event_id", "at", "session_id", "actor", "event", "target", "detail")
DDL = ("CREATE TABLE IF NOT EXISTS {table} (event_id STRING, at TIMESTAMP, session_id STRING, actor STRING, event STRING, "
       "target STRING, detail STRING) USING DELTA")
INSERT = ("INSERT INTO {table} VALUES (:event_id, CAST(:at AS TIMESTAMP), :session_id, :actor, :event, :target, :detail)")
SELECT = "SELECT event_id, at, session_id, actor, event, target, detail FROM {table} ORDER BY at DESC LIMIT {limit}"


class AuditUnavailable(Exception):
    """The durable audit trail could not be written."""


class MemoryAuditSink:
    durable = False

    def __init__(self):
        self.rows = []

    def append(self, row):
        self.rows.append(dict(row))

    def read(self, limit=200):
        return list(reversed(self.rows))[:limit]


class DeltaAuditSink:
    durable = True

    def __init__(self, table, warehouse_id, client=None):
        if not TABLE.match(table or ""):
            raise ValueError("SENTINELX_AUDIT_TABLE must be catalog.schema.table using letters, digits and underscores")
        self.table = ".".join(f"`{part}`" for part in table.split("."))
        self.name, self.warehouse_id, self._client, self._ready = table, warehouse_id, client, False

    @classmethod
    def from_env(cls, environ=None, client=None):
        env = os.environ if environ is None else environ
        table, warehouse = env.get("SENTINELX_AUDIT_TABLE", "").strip(), env.get("SENTINELX_SQL_WAREHOUSE_ID", "").strip()
        if not table:
            return None
        if not warehouse:
            raise ValueError("SENTINELX_SQL_WAREHOUSE_ID is required when SENTINELX_AUDIT_TABLE is set")
        return cls(table, warehouse, client)

    def _statements(self):
        if self._client is None:
            from databricks.sdk import WorkspaceClient
            self._client = WorkspaceClient()
        return self._client.statement_execution

    def _run(self, statement, parameters=None):
        from databricks.sdk.service.sql import StatementParameterListItem, StatementState
        try:
            response = self._statements().execute_statement(
                statement=statement, warehouse_id=self.warehouse_id, wait_timeout="30s",
                parameters=[StatementParameterListItem(name=key, value=value, type="STRING") for key, value in (parameters or {}).items()])
        except Exception as error:  # noqa: BLE001 - surface only the exception type
            raise AuditUnavailable(f"Audit table is unreachable ({type(error).__name__}).") from error
        state = getattr(getattr(response, "status", None), "state", None)
        if state != StatementState.SUCCEEDED:
            raise AuditUnavailable(f"Audit statement did not succeed ({getattr(state, 'value', state)}).")
        return response

    def append(self, row):
        if not self._ready:
            self._run(DDL.format(table=self.table))
            self._ready = True
        values = {key: str(row.get(key, ""))[:500] for key in COLUMNS}
        values["event_id"] = values["event_id"] or uuid.uuid4().hex
        self._run(INSERT.format(table=self.table), values)

    def read(self, limit=200):
        response = self._run(SELECT.format(table=self.table, limit=int(limit)))
        rows = getattr(getattr(response, "result", None), "data_array", None) or []
        return [dict(zip(COLUMNS, row)) for row in rows]
