# Audit Boundary

`backend/services/store.py::Store.event` appends a SHA-256 hash chain in the same
SQLite transaction as action transitions. HTTP audit records role, route template,
status and time, not request bodies/headers. Verification is not immutable storage;
use external chain-digest anchoring for production evidence.