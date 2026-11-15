# Synchronization Contract

Bindings explicitly map workload SP numeric IDs to AWS ARN and Databricks scope/key.
Metadata comparison is in `backend/governance/service.py::compare_bindings`.
Value-equivalence attestation and recovery prerequisites are in `docs/onboarding.md`.