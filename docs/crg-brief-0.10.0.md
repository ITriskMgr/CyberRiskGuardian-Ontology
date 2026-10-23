# Brief: update CyberRiskGuardian to use CRGO 0.10.0

**For:** Claude working in the CyberRiskGuardian (CRG) repository (`github.com/ITriskMgr/CyberRiskGuardian`).
**From:** the CRGO project, release v0.10.0 (tag `v0.10.0`, 2026-10-13) of the CyberRiskGuardian Ontology (`github.com/ITriskMgr/CyberRiskGuardian-Ontology`).
**Goal:** a new minor version of the CRG plugin that uses CRGO 0.10.0's policy, compliance, audit, detection and response knowledge without changing CRG's formulas or evidence discipline.

This brief builds on the 0.9.1 brief (`docs/crg-brief-0.9.1.md` in the CRGO repository at tag `v0.10.0`): everything there still holds (the dss/v1 contract, tenant rules, "CRGO computes no risk", the MediBec regression). Read both, inspect the CRG repository as it is now, plan, show the plan to the project owner, and build only after approval.

---

## 1. What is new in CRGO 0.10.0

| Area | What CRG can now use |
|---|---|
| **Policy management** (`crgo-policy`) | Policy documents with **versions** (draft, under review, approved, published, retired, superseded), each statement tied to one exact version with a modality (must, must not, should, may); clauses, guidelines (never binding), policy families, review dates and triggers, acknowledgements (never compliance), training requirements. |
| **Compliance management** (`crgo-compliance`) | Compliance programme and objectives; reviewed interpretations of obligations (with a legal-review state and a privilege flag); regulatory authorities; **framework adoption** (an organisation commits to, e.g., CSF 2.0 for a scope); compliance assessment campaigns; provision versions; **deadlines** (calendar dates or e.g. 72 hours after an incident confirmation) and **regulatory submissions** with receipts; regulatory exemptions (only an authority grants them); root-cause categories. |
| **Mappings with qualification** | A *mapping assertion* says how a policy statement or control corresponds to an obligation (exact, full or partial coverage, broader, narrower, related, conflicting), against which edition, why, with what confidence and who reviewed it. A mapping is never evidence of compliance. |
| **Audit management** | Audit function and charter, methodology, **plan entries** (deferred or cancelled with reason and authoriser), engagement type and state, workpapers (no sole self-review), **observations** (preliminary, not findings), quality reviews; findings and nonconformities share closure and reopening. |
| **Security monitoring** (`crgo-siem`) | Telemetry sources and their health, event records (pointers, not payloads), normalisation to **OCSF 1.9.0** classes, organisation detection strategies adapting **ATT&CK 19.2 detection strategies** (697), analytics (1,758) and data components (106), detection rules and their status, **coverage** of scenarios and techniques (validated only by an effective detection test), detection gaps, threat indicators with source confidence, TLP 2.0 markings. |
| **Response** (`crgo-soar`) | Investigations and case status, incident category and severity, **playbooks** and their versions, steps and triggers, response actions with a **risk class** (read-only, administrative, containment, destructive), **approval gates** and approval decisions, execution records with attempt identifiers, response evidence, forensic artefacts, incident impact, communications (a regulator notice is also a regulatory submission), recovery verification, response measurements (time to contain…), playbook simulations. |
| **Two read contracts** | `compliance/v1` and `secops/v1`, through two new MCP tools (section 2). Both read only. |

Reference documents: `CHANGELOG.md` (0.10.0), `docs/adr/ADR-010-policy-compliance-audit-management.md`, `docs/adr/ADR-011-security-operations-boundary.md`, `contracts/compliance/v1/README.md`, `contracts/secops/v1/README.md`, `AGENTS.md`.

## 2. New MCP tools

Pin CRGO to tag `v0.10.0`. Tools 1–8 are unchanged (see the 0.9.1 brief).

| Tool | Returns |
|---|---|
| `crgo_compliance_context(org_graph_files, organization, as_of)` | `obligations` (applicability, latest compliance state and date, **evidence status**: current / expired / judged-insufficient / none, owners, supporting statements with mapping type and review state, implementing measures with their latest result, open findings); `directiveVersions` (state, effective date, review due, **reviewOverdue**); `exceptions` (active, risk acceptance, legal provisions concerned and those **without a regulatory exemption**); `deadlines` (computed due time, answered or not); `findings` (open, root causes, **overdue actions**); `caveats`. |
| `crgo_secops_context(org_graph_files, organization, as_of)` | `scenarios` (coverage with **validatedByTest**, detection gaps, playbooks with **simulationPassed**); `detectionRules` (status, version, required telemetry with health); `untriagedAlerts` (with **crownJewel**); `approvalGates`; `executionsWithoutValidApproval` (reason: absent, expired, revoked, not-yet-valid, wrong-authority, not-corresponding, not-granted); `openRegulatoryTriage`; `caveats`. |

Both are dated (records after `as_of` are ignored), tenant-filtered (another organisation's records are withheld and the caveats say so) and return `{"error": true, "code": …}` with `UNKNOWN_ORGANISATION`, `REFERENCE_NAMESPACE` or `SCHEMA_INVALID` (bad date). Examples: `contracts/compliance/v1/examples/compliance-context.nordelle.json`, `contracts/secops/v1/examples/secops-context.nordelle.json` (synthetic).

The organisation graph is the one CRG already produces with `crg2rdf.py` (0.9.1 brief, section 4). The new records (policies, mappings, deadlines, rules, playbooks…) are added by the organisation or by CRG into that graph under the organisation's base; CRGO's synthetic Nordelle files (`tests/samples/nordelle-pca.ttl`, `nordelle-secops.ttl`) show every pattern.

## 3. Where it fits in CRG's workflow

| CRG step | Use of CRGO 0.10.0 |
|---|---|
| 1 Evidence register | `evidenceStatus` from compliance/v1 flags evidence that had expired or was judged insufficient: record it as an evidence gap, not as support. |
| 2 Context, obligations | Use `obligations` for the legal and contractual picture, framework adoptions for voluntary commitments, `deadlines` for upcoming filings, `exceptions` whose `provisionsWithoutExemption` is non-empty as a compliance exposure (an internal exception cannot waive a law). |
| 2 Incidents and findings | `findings` with overdue actions and `openRegulatoryTriage` are evidence of weak control operation and of pending obligations. |
| 8 Existing controls | Measures' latest results now exclude single detection tests and playbook simulations, which test one rule or playbook, not the control. Use `scenarios[].coverage` (validated by test or not) and `detectionRules[].requiredSources[].health` as evidence for detective controls; a rule needing silent telemetry does not detect. `executionsWithoutValidApproval` is evidence about response-control operation. |
| 9 Quantify | Untested or degraded coverage, detection gaps and unsimulated playbooks are reasons for lower confidence in detection and response factors — analyst judgement, with the CRGO record cited. CRGO gives no numbers. |
| 12–14 Treatment | Candidate treatments: validate coverage by a detection test, restore telemetry, simulate playbooks, close overdue corrective actions, obtain a regulatory exemption or remove an exception. |
| 16–17 Decisions | Approvals and acceptances stay human decisions; CRG may draft decision records, never mark them approved. |
| QC review | Add checks: no obligation called compliant from a mapping, acknowledgement or attestation; no incident or attribution inferred from an alert or indicator; no response action presented as authorised by CRGO; TLP-marked material respected in reports. |

## 4. Rules that must not be broken (additions to the 0.9.1 list)

1. A mapping, policy statement, acknowledgement or attestation is never compliance. Only a dated compliance determination with evidence states a compliance state.
2. An alert or an indicator match is never an incident or an attribution. Incidents are confirmed by incident confirmations.
3. Nothing CRGO returns authorises a response action; approval gaps are audit signals.
4. Coverage counts as validated only with an effective detection test of the rule or strategy providing it.
5. Source confidence (e.g. STIX 0–100) is not a probability and must not feed CRG likelihoods directly.
6. Respect TLP markings on threat intelligence in reports.
7. Licensed standards (ISO 37301 and its 2024 amendment, IIA, ISACA…) stay identifiers and paraphrases only.

## 5. Suggested plan

1. Inventory the CRG repository (current plugin version, skills, agents, scripts).
2. Pin CRGO v0.10.0 in the README; no `.mcp.json` change is needed beyond the 0.9.1 registration.
3. Extend the contract helper (`scripts/crgo_contract.py` or equivalent) to call `crgo_compliance_context` and `crgo_secops_context` for the assessment date, store the JSON under the git-ignored `output/`, and pass the relevant parts to the analysts.
4. Update the `cyber-risk-assessment` SKILL.md steps 1, 2, 8, 9, 12–14 and the QC checklist as in section 3; add a "Compliance posture" table (obligation, applicability, state, evidence status, exceptions without exemption, next deadline) and a "Detection and response readiness" table (scenario, coverage validated, gaps, playbook simulated) to the report template.
5. Agents: `risk-scenario-analyst` (obligations, deadlines, triage), `risk-quantifier` (coverage and telemetry as evidence), `risk-qc-reviewer` (section 4 rules).
6. Bump the plugin version, sync configs, validate, and keep the MediBec regression at 84,305 / 41,023 (since CRG 2.1.0 and CRGO 0.10.1; 84,491 / 41,104 before).

## 6. Acceptance tests

- On CRGO's synthetic Nordelle files, `crgo_compliance_context(…, "2026-10-12")` shows Loi 25 s. 10 partially satisfied, s. 3.8 satisfied on evidence judged insufficient, the EDR exception concerning s. 10 without exemption, the GDPR 72-hour deadline unanswered; CRG reports these as gaps, not as compliance.
- `crgo_secops_context` shows ransomware coverage validated by a test, credential-compromise coverage untested with a detection gap, the ransomware playbook not simulated, the October kiosk isolation without valid approval (expired pre-authorisation), two incidents with undetermined GDPR reportability; CRG uses them as evidence and flags the approval gap without calling the action authorised or not.
- A date before 2026-06-10 shows no validated coverage (dated records respected).
- No report states compliance from a mapping, infers an incident from an alert, or reproduces licensed text; the MediBec regression is unchanged.

## 7. Known limits of CRGO 0.10.0

- No write-back for the new areas: updates to policies, mappings, rules or playbooks are made in the organisation's graph by the organisation or CRG, with provenance.
- Rule, alert, case and approval statuses are as last recorded; point-in-time history of statuses needs dated records (e.g. new versions, decision records).
- TAXII collections, OpenTelemetry attributes and CACAO agents/targets are not modelled.
- Incident category and severity, root causes and other scales are CRGO's own.
