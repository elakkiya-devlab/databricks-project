# Databricks Client Boundary

Implementation: `backend/services/providers.py::clients` forces OAuth M2M and
constructs separate discovery/executor clients. Do not add a root `databricks/__init__.py`:
it would shadow the official SDK. REST OAuth validation is in `backend/remediation/live.py`.