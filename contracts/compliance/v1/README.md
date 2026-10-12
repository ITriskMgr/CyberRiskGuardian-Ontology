# Contract compliance/v1 (read only)

What CRGO gives an application about one organisation's obligations, policy and directive versions, exceptions, deadlines and findings at a date (decision D11; ADR-010).

| Call | Schema |
|---|---|
| MCP tool `crgo_compliance_context(org_graph_files, organization, as_of)` or `pipeline/contracts/views.py` `compliance_context(...)` | `compliance-context.schema.json` |
| errors | `error.schema.json` (`UNKNOWN_ORGANISATION`, `REFERENCE_NAMESPACE`) |

Rules:
- Read only: there is no write-back. Updates to the organisation's graph remain the application's, with provenance.
- Tenant separation as in dss/v1 (ADR-008): the organisation's base is the one its graph declares (`vann:preferredNamespaceUri`); records under another organisation's base are withheld, and the withholding is reported in the caveats.
- Dated: records made after `as_of` are ignored; states are the latest recorded on or before it.
- A compliance state is the organisation's latest recorded determination. A mapping, a policy statement, an acknowledgement or an attestation is never reported as compliance; the evidence status says whether the evidence relied on had expired or was judged insufficient.
- The application keeps its own identifiers: an application UUID is recorded as `localIdentifier` on the organisation's IRI for the record (decision S7).

Example: `examples/compliance-context.nordelle.json` (synthetic Nordelle data, as of 2026-10-12). Tests: `tests/contracts/test_views_contract.py`.
