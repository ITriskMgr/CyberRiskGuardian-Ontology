# DSS contract dss/v1

The data contract between CRGO and the CyberRiskGuardian decision-support system (ADR-007; tenant rules in ADR-008).

CyberRiskGuardian has no REST interface, so the specification's proposed `GET /v1/knowledge/risk-context` and `POST /v1/assessments` are carried by two tools of CRGO's MCP server (`pipeline/mcp/crgo_server.py`). The same functions can be called from Python (`pipeline/contracts/dss.py`) or used through files.

| Specification proposal | dss/v1 | Schema |
|---|---|---|
| `GET /v1/knowledge/risk-context?organization=…&scenario=…` | `crgo_risk_context(org_graph_files, organization, scenario, as_of)` | `risk-context.schema.json` |
| `POST /v1/assessments` | `crgo_submit_assessment(document, org_graph_files)` | `assessment-result.schema.json` |
| errors (not specified) | error document | `error.schema.json` |

## What CRGO returns and accepts

- The **risk context** gives the scenario (always an analytical hypothesis), affected and dependent assets, candidate obligations with the applicability state for the organisation, unresolved conditions, the compliance state and any evidence gap, the organisation's control measures with their latest result per assessor line (self-assessment, second line, internal audit, external) and open findings, estimates with assumptions, distribution and evidence quality, evidence references, the ontology release and caveats. It contains no risk score.
- A **write-back** must have the status `proposed`, a model and model version, the computation time, the inputs it used and the SHA-256 of the input document. CRGO stores it as an analytical result with the knowledge status *risk estimate* and the status *proposed* in `<organisation file>-dss-proposed.ttl`, next to the organisation's own files. It never writes into CRGO's reference files, and a write-back is never an approval, a risk acceptance or a funding decision.

## Differences from the specification's examples

| Specification | dss/v1 | Why |
|---|---|---|
| `"organizationId": "org-demo"` | an IRI under the organisation's own base, never `https://w3id.org/crgo/` | tenant separation (ADR-008) |
| `"modelVersion": "TBD"` | rejected with `MODEL_VERSION_MISSING` | a result without a model version cannot be reproduced |
| `"resultRef": "result-01"` | `result: {value, unit}` | CyberRiskGuardian returns numbers (CRG risk units, ratios, currency), not stored result objects |
| `"inputs": ["assessment-input-01"]` | IRIs of the organisation's records or CRGO reference IRIs, plus `inputDocumentSha256` | inputs must resolve; the checksum identifies the exact input document |
| `"status": "proposed"` | the only value allowed | approval is a separate human act |

## Examples

- `examples/risk-context.nordelle-ransomware.json`: context for the synthetic Nordelle ransomware scenario on 2026-10-11.
- `examples/assessment-result.nordelle-ransomware.json`: a CyberRiskGuardian `crg_risk` result written back (synthetic value).
- `examples/invalid/*.json`: nine documents that must be refused, each with its expected error code in `tests/contracts/test_dss_contract.py`.

All organisation data in the examples is synthetic.
