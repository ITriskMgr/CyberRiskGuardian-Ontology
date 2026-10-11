# Remaining-gaps specification: Phase 0 audit and plan

Prepared 2026-10-11 for *CRGO Knowledge Expansion: Remaining GRC, Cybersecurity and Operational Knowledge Domains, with a Formal Interface to the Separate CyberRiskGuardian DSS* (draft v1.0, 11 October 2026). Baseline: CRGO repository at `6e8c8c5` (branch `v0.9`, 0.9.0 approved, unreleased) plus the GRCA plan approved on 2026-10-11 (`grca_phase0.md`, decisions G1–G5). CyberRiskGuardian inspected at commit `f0cd36e` (version 1.1.0) in the project owner's folder.

## 1. The DSS as it actually exists (spec §2, §8: "inventory DSS artifacts")

| Artifact | Where | What it offers |
|---|---|---|
| Claude agent plugin `cyberriskguardian` | `plugins/cyberriskguardian/` | skills (risk assessment, scenario selection, budget calibration, governance textbook), commands, three agents, output styles, session hooks |
| MCP server `crg-calculator` | `plugins/cyberriskguardian/mcp/crg_server.py` | tools `crg_risk`, `cvss4_score`, `budget_target`, `budget_check`, `sensitivity` (environment defaults: appetite 0.30, factor 1000) |
| JSON assessment files | skill assets: `scenario-template.json`; example `examples/medibec/source/data30.json`, `budget.json` | the de facto data contract today |
| Word report generation | `package.json` (docx) | output only |

There is **no REST or GraphQL endpoint**. The specification's `GET /v1/knowledge/risk-context` and `POST /v1/assessments` are proposals; the contract must be expressed against what exists: JSON exchange documents validated by JSON Schema, served to the DSS through CRGO's MCP server (`pipeline/mcp/crgo_server.py`, already used by your Claude desktop app) and read back through the CRG bridge (`pipeline/crg/crg2rdf.py`, MediBec round trip exact since 0.4.0).

## 2. The 20 domain packages against CRGO 0.9.0 plus the approved GRCA plan

Status: **IMPLEMENTED** · **PARTIAL** · **PLANNED** (in the approved GRCA sprint) · **MISSING**. Evidence paths are in the repository.

| # | Domain (priority) | Status | Evidence / overlap |
|---|---|---|---|
| D01 | Policy, standard, procedure, exception (P0) | MISSING → PLANNED part | GRCA WP5 adds waiver/exception; policy statement, standard, procedure, baseline, compensating control, exception approval and expiry review are new |
| D02 | IT service and operations (P0) | PARTIAL | `ServiceAsset`, `BusinessProcess`, `dependsOn` (core); no change request, release, ticket, problem, SLA, service owner |
| D03 | Enterprise architecture and dependencies (P0) | PARTIAL | assets, processes, objectives, `dependsOn` (transitive), `supportsProcess`, supplier role (0.9.0); no capability, application service, data flow, API, trust boundary; CQ-15-like blast radius reachable through existing properties |
| D04 | Risk registers and aggregation metadata (P0) | PARTIAL | risk assessment, estimates, CRG quantities, sensitivity cases; no register, register entry, aggregation method, correlation assumption, escalation |
| D05 | Control lifecycle and effectiveness (P0) | PARTIAL → PLANNED | control (objective), control measure (implementation), control assessment with result and evidence (0.9.0); GRCA WP3–4 add assessor line and evidence validity; design vs deployment vs operation, deficiency and period are new |
| D06 | Incident, crisis, lessons learned (P0) | PARTIAL | `Incident` (BFO process) distinct from scenario; `triggersObligation`; no alert, confirmed incident vs event, containment, crisis, reportable breach, timeline, lesson learned |
| D07 | Decision rights, sign-off, accountability (P0) | PARTIAL → PLANNED | risk treatment decision, risk acceptance (authority, expiry), `decidedBy`; GRCA WP2 adds governing bodies, roles, delegation, temporal role assignment |
| D08 | Estimate uncertainty and epistemic status (P0) | PARTIAL → PLANNED | estimate with bounds, sample size, confidence, rationale; assumption, observation (0.9.0); sensitivity cases (crg); GRCA WP1 adds knowledge status; distributions are new |
| D09 | Regulatory change and temporal validity (P0) | PARTIAL → PLANNED | instruments with dates, OWL-Time in-force interval, dated PDF snapshots with checksums (0.9.0); GRCA WP5 adds instrument version, regulatory change, supersession; reassessment trigger is new |
| D10 | Graph quality and ontology lifecycle (P0) | IMPLEMENTED (mostly) | source records, change report, SHACL, reasoners, CQ suites, release tags (0.9.0); import batch and validation result as RDF are new |
| D11 | Projects and benefit realisation (P1) | PARTIAL | treatment initiative (dates, owner, cost, success indicator) |
| D12 | Software supply chain (P1) | MISSING | CWE/CAPEC/KEV only; no SBOM, package, VEX |
| D13 | Identity, authorisation, SoD (P1) | MISSING | asset category *identity* only |
| D14 | OT, physical, safety (P1) | PARTIAL | connected device, facility asset, impact dimension *safety*; no zone/conduit, hazard model |
| D15 | Financing, insurance, transfer (P1) | PARTIAL | treatment option *share*; no policy, coverage, exclusion |
| D16 | Metrics and maturity (P1) | PARTIAL | key risk indicator with thresholds and frequency; no metric definition vs observation, maturity |
| D17 | Human factors and insider risk (P1) | PARTIAL | threat source types; insider scenarios in the library |
| D18 | Data lifecycle, lineage, retention (P1) | PARTIAL | processing activity, data categories, transfers (0.9.0); Loi 25/GDPR destruction and retention provisions; no dataset lineage, retention rule |
| D19 | Sector profiles and bundles (P1) | PARTIAL | sector in the library, applicability conditions (0.9.0); no profile or bundle object |
| D20 | Attack paths and simulation inputs (P2) | PARTIAL | scenario steps (`ScenarioStep`, `nextStep`), ATT&CK links; no prerequisite or privilege state |

## 3. Proposed scope for 0.9.0 (in addition to the approved GRCA sprint)

The specification's first sprint asks for the system-boundary ADR, identifier and named-graph policy, read and write contracts, and two P0 vertical slices: **policy exception management (D01)** and **control operating effectiveness (D05)**. Folded with the GRCA work, I propose:

| # | Work package | Deliverable |
|---|---|---|
| R1 | ADR-007 CRGO / DSS boundary | what CRGO may and may not do (no scoring, optimisation, approval or legal opinion as OWL consequences); forbidden cross-boundary functions; tenant and disclosure policy |
| R2 | ADR-008 identifiers and graph layers | reference TBox, source ABox, per-organisation graphs (one file or named graph per tenant, tenant IRI base), derived analytical results; deprecation and migration notices |
| R3 | DSS contract v1 (`contracts/dss/v1/`) | JSON Schemas for the read document (risk context: scenario, assets, candidate obligations with applicability and unresolved facts, control links with mapping status, evidence references, `asOf`, ontology release) and the write-back document (assessment result with model, version, inputs, `computedAt`, status *proposed*); error cases; examples from Nordelle; served through two new tools of CRGO's MCP server (`crgo_risk_context`, `crgo_submit_assessment`, the latter writing to a *proposed* graph only) |
| R4 | D01 policy and exception slice | policy, policy statement, technical standard, procedure, baseline, exception (scoped to role, asset, period, approving authority), compensating control, exception approval, expiry review; obligation → control objective → policy statement → procedure | 
| R5 | D05 control effectiveness slice | control design, deployment and operation distinguished; operating-effectiveness assessment over a period and population; control deficiency; latest verified status per asset and date |
| R6 | D07 and D08 completions (cheap given GRCA WP1–2) | approval record, rejection, deferral, decision rationale, conflict of interest; estimate distribution, hypothesis, evidence quality |
| R7 | D09 completion | instrument version, amendment, reassessment trigger; CQ: which assessments need review after an amendment (uses the dated legal snapshots) |
| R8 | D06 minimal | event, alert, confirmed incident, reportable breach, incident timeline, lesson learned; incident observations *support, do not prove* scenario likelihood |
| R9 | Competency questions | CQ-01, 04, 05, 06, 07, 08, 16, 17, 18 of this specification, with the mandatory fixture kinds of §10.1 (positive, negative, unknown, temporal, tenant, conflict, DSS-proposed, quality) |

Deferred to the next version: D02 IT operations, D03 architecture objects (capability, data flow, API, trust boundary), D04 risk registers, and the P1/P2 packages D11–D20.

## 4. Decisions needed

| # | Decision | Recommendation |
|---|---|---|
| R-a | Scope for 0.9.0 | the GRCA sprint plus R1–R9 above; D02–D04 and D11–D20 in the next version |
| R-b | DSS contract form | JSON Schema documents exchanged through CRGO's MCP server and files (what CyberRiskGuardian supports today), rather than a REST service CyberRiskGuardian does not have |
| R-c | Tenant separation | one graph file per organisation under its own IRI base (as Nordelle uses `https://example.org/crgo-sample/nordelle/`), never merged into the reference files |
| R-d | Private copies of licensed texts | licensed full texts you download stay in `data/raw/` (never committed) and may feed a private build (`ontology/vocab-private/`, as already done for CSA CCM); the public CRGO files carry only identifiers, short titles with attribution and CRGO paraphrases. Your permission to use the texts does not extend to republishing them in the public repository |
