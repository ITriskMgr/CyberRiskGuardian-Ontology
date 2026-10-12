# Contract secops/v1 (read only)

What CRGO gives an application about one organisation's detection coverage, detection rules and their telemetry, untriaged alerts, approval gates, executions without a valid approval and open regulatory triage at a date (decision S10; ADR-011).

| Call | Schema |
|---|---|
| MCP tool `crgo_secops_context(org_graph_files, organization, as_of)` or `pipeline/contracts/views.py` `secops_context(...)` | `secops-context.schema.json` |
| errors | `error.schema.json` (`UNKNOWN_ORGANISATION`, `REFERENCE_NAMESPACE`) |

Rules:
- Read only: there is no write-back. Updates to the organisation's graph remain the application's, with provenance.
- Tenant separation as in dss/v1 (ADR-008): the organisation's base is the one its graph declares (`vann:preferredNamespaceUri`); records under another organisation's base are withheld, and the withholding is reported in the caveats.
- Dated: records made after `as_of` are ignored; states are the latest recorded on or before it.
- Coverage counts as validated only when supported by a detection test found effective. Approval gaps are audit signals: nothing in this document, and no inference in CRGO, authorises a response action.
- The application keeps its own identifiers: an application UUID is recorded as `localIdentifier` on the organisation's IRI for the record (decision S7).

Example: `examples/secops-context.nordelle.json` (synthetic Nordelle data, as of 2026-10-12). Tests: `tests/contracts/test_views_contract.py`.
