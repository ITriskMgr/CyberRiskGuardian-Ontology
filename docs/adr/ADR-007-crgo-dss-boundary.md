# ADR-007 Boundary between CRGO and the CyberRiskGuardian decision-support system

Status: approved (0.9.0, project owner, 2026-10-11). Remaining-gaps specification sections 2, 8 and 11; decision R-b (2026-10-11).

## Context
CyberRiskGuardian (CRG) is a separate decision-support system: a Claude plugin with skills, agents and the MCP calculator `crg-calculator` (`crg_risk`, `cvss4_score`, `budget_target`, `budget_check`, `sensitivity`), and JSON assessment files. It has no REST or GraphQL interface. The specification's `GET /v1/knowledge/risk-context` and `POST /v1/assessments` are proposals, not endpoints.

## Decision
**CRGO may**: state reference knowledge (vocabularies, scenarios, legal instruments, applicability conditions), organisation facts given to it, links and their review status, applicability evaluations (applicable, not applicable, potentially applicable, unknown), assessments and audit records made by identified people, and results the DSS writes back, kept as proposed risk estimates.

**CRGO must not**, as OWL or SHACL consequences or in its tools: compute risk scores, optimise portfolios or budgets, approve or accept a risk, approve funding, give a legal opinion, or turn a mapping into a compliance conclusion. These belong to the DSS (calculations) or to people (decisions).

**Exchange** (contract `dss/v1`, `contracts/dss/v1/`): JSON documents validated by JSON Schema 2020-12.
- Read: `crgo_risk_context` (MCP tool of `pipeline/mcp/crgo_server.py`) returns the risk context of one organisation and scenario at a date: scenario (a hypothesis), assets, candidate obligations with applicability, unresolved conditions and compliance state, control measures with their latest results per assessor line and open findings, estimates with assumptions, distributions and evidence quality, evidence references, ontology release, caveats.
- Write: `crgo_submit_assessment` accepts a DSS result whose status is `proposed`, with model, model version, computation time, inputs and the SHA-256 of the input document, and stores it as an `analytical result` (knowledge status *risk estimate*, governance status *proposed*) in the organisation's own proposed graph file.
- Errors: `SCHEMA_INVALID`, `UNKNOWN_ORGANISATION`, `UNKNOWN_SUBJECT`, `TENANT_MISMATCH`, `REFERENCE_NAMESPACE`, `STATUS_NOT_PROPOSED`, `MODEL_VERSION_MISSING`, `INPUT_UNKNOWN`.

**Incompatible assumptions recorded**: the specification's example uses `modelVersion: "TBD"`; the contract rejects it (`MODEL_VERSION_MISSING`), since a result without a model version cannot be reproduced. Its `organizationId: "org-demo"` becomes an IRI under the organisation's base (ADR-008). Its `resultRef` is replaced by the result value and unit, because CRG returns numbers, not stored result objects.

## Alternatives
A REST service in front of CRGO was rejected: CRG cannot call one today, and it would add hosting and authentication that the project does not need. Letting the DSS write approved results was rejected: approval is a human act (GAPS section 8.3).

## Counterexample and test
`tests/contracts/test_dss_contract.py` (29 checks): the context conforms to its schema and contains no risk score; a write-back is stored only as proposed; nine invalid documents (`contracts/dss/v1/examples/invalid/`) each return their error code. SHACL shape `AnalyticalResult` rejects a write-back result labelled as anything but a risk estimate (fixture `neg-grca-dss-result-as-fact`); CQ-16 lists proposed DSS results and detects one used as the subject of a decision.
