# Hackathon Demo and Presentation

## Five-Minute Walkthrough

1. Start `python -m scripts.dev`. Open the printed local dashboard URL. The demo
   banner must show simulated data/approvals and no cloud writes.
2. Executive Summary: show the 64-asset inventory, governance score, compliance,
   high-risk asset count, and cross-domain risk bars. Explain that unknown evidence
   is not treated as compliance.
3. Service Principals: show 12 identities, ownerless candidates, expired secrets,
   and expiry-window findings. Select `pipeline-06/oauth-secret` in the inventory.
   Choose `Renew Sp`, submit a remediation request. Current demo renewal updates
   only that selected metadata asset; it does not perform cloud cutover.
4. Audit & Governance: select the pending request, run Dry run. Show that execution
   remains disabled until Approve. Approve using the demo's simulated separate actor,
   then Execute. A live deployment requires separate API clients, not UI actor simulation.
5. Return to Executive Summary and Service Principals. Show fewer findings and the
   renewed expiry. View historical score/compliance trends and verified audit chain.
   Export JSON/CSV for evidence. The companion `docs/sample_output.json` records a
   simulated before/after result and removed finding count.
6. Request rollback on the succeeded action, repeat Dry run and Approve, then Execute.
   Verify the original expiry/risk returns and the original request is `rolled_back`.
7. AWS Integration: show known metadata alignment, drift, disabled rotation, and
   recovery counts. Explain that metadata cannot prove secret-value equality.

Use Credential Governance to show PAT age/expiry and ownerless credentials, and
Secret Governance for stale/rotation-unknown inventory. Do not demonstrate a real
rotation against an unapproved shared workspace during the hackathon.

## Copilot and Action Center

1. Open SentinelX AI Copilot and ask "What are the critical compliance findings?"
   Follow the finding references to the Action Center. Try an expiry, owner, PAT
   age, synchronization, score, and pending-approval question.
2. Select a finding in Remediation & Action Center. Show its stable finding ID,
   report timestamp, evidence, policy thresholds, recommendation, required
   permissions, operational impact, and rollback boundary.
3. Use Ask AI to open the Copilot with that finding as context. Ask why it was
   classified at that severity or what remediation is supported.
4. For a finding with an eligible demo action, request approval. Show the dry
   run, approve as the separate demo actor, and execute as the operator. The demo
   changes only local metadata. Unsupported live actions remain guidance-only.
5. Explain that the default Copilot uses deterministic structured queries and
   report citations. No Model Serving endpoint is configured, and the Copilot
   cannot initiate, approve, or execute remediation.

## Presentation Narrative

**Opening:** "Automation has an identity problem. The accounts that run our data
pipelines often have no accountable owner, and their credentials outlive the workloads."

**Discovery:** "SentinelX makes non-human identities and credential metadata visible
across Databricks and AWS, without turning the dashboard into a secret-exposure surface."

**Assessment:** "We measure age, expiry, owner, activity, rotation and privilege
evidence. An unknown is a finding, not a green check. Our baseline is a 30-day policy."

**Governance:** "Every remediation begins with a dry run and separate approval.
We reject stale approvals and duplicate execution, and retain a historical evidence trail."

**Mandatory renewal:** "For a supported Databricks OAuth-secret binding, the executor
creates a new secret, stages it in AWS, validates OAuth, updates Databricks, and
promotes the version. We preserve the previous version and credential for rollback."

**Measured value:** "The demo reports governance-score change, compliant asset
percentage, critical/high-risk assets, findings removed, and remediation completion.
These are simulated improvements, not production customer statistics."

**Honest close:** "Not every credential has a safe rotation API. SentinelX identifies
those boundaries and routes them to actionable recommendations. Our next step is
workload validators, real SSO actors, durable distributed execution and external audit anchors."

## Acceptance Checklist

- All six dashboard views render on desktop/mobile; no credentials in exports.
- Inventory includes all seven types; expiry buckets and 30-day policy are tested.
- Execution without dry run/approval fails; reader and approver cannot execute.
- Approved simulated renewal improves the selected asset; approved rollback restores it.
- Provider contract tests verify AWS staging and OAuth-validation failure behavior.
- Live acceptance remains separately gated on workspace, account, IAM and owner mapping.