# CRGO 0.11.2 — release notes (2026-11-12)

Patch release for CyberRiskGuardian Desktop 1.9.3 (build specification 1.9.3, workstream W5). It adds the contract
`library-proposal/v1` and seven MCP tools; it adds, changes or deprecates **no term** (change report in this folder:
1,598 terms before and after; the +120 cross-references are the proposal file counted on one side, as in 0.11.1).

## What is new

| Tool | What it does |
|---|---|
| `crgo_group_candidates` | Screening candidates (CRGO terms only) -> family proposals (same near-duplicate cluster, or same theme + ATT&CK technique + asset category), unique proposals (alone in a cluster) and own scenarios with a theme gap. Rule `crgo-grouping/1`. |
| `crgo_validate_scenario` | Findings for one scenario: library or theme match, revoked techniques with their successor, CWE consistent with the techniques, vocabulary; linked controls and obligations. Rule `crgo-validation/1`. Never an error for unknown vocabulary. |
| `crgo_propose_library_scenario` | A library-scenario proposal into the installation's store folder, status *proposed*. Never parameters or figures; never identifiers CRGO does not hold. |
| `crgo_list_proposals` | Proposals in the store, with their decisions and public status. |
| `crgo_approve_proposal` / `crgo_reject_proposal` | Decision with approver and date (reason required for a rejection). An approval adds the scenario to **this installation's** ontology (`approved/crgo-local-extension.json`), not to CRGO. |
| `crgo_export_contribution` | Contribution file for ITriskMgr/CyberRiskGuardian-Ontology (an `authored_scenarios.json` entry plus `cwe`, status *proposed*), written to the folder for ontology proposals. Nothing is sent. |

The rules, normalisation, tie-breaks, ids, output shapes and error codes are in `contracts/library-proposal/v1/README.md`.
The offline port in CyberRiskGuardian must reproduce `contracts/library-proposal/v1/examples/golden-grouping.json`
exactly.

The identification export (`data/export/crgo-identification.json`) now carries per scenario `primary_theme` and
`cluster` (static near-duplicate clusters: 1,817 library scenarios in 1,377 clusters) and a `grouping` block with the
ATT&CK, CWE and theme-rule reference data the offline port needs: 10,214,401 -> 10,374,505 bytes (+1.6 %).

## For CyberRiskGuardian (snapshot and helper)

- `tools/build_crgo.py`: copy the export's top-level `grouping` block into the snapshot (per-scenario `cluster` and
  `primary_theme` already survive `strip()`), bump the snapshot schema to `crg-crgo-snapshot/3`. Expected growth about
  160 KB (about +2.5 % of the 6.43 MB 0.11.1 snapshot).
- Grouping and validation are usable when the CRGO release is 0.11.2 or later, or when
  `contracts/library-proposal/v1/` exists in the checkout.
- `store_dir` and `out_dir` must be existing absolute folders outside the CRGO repository; the tools never choose one.

## Determinism

Both paths compute from the same data (the snapshot is built from the export; library clusters are never recomputed
in the browser), with integer arithmetic, sorts that end on an identifier, NFC + lower-case text, ASCII regex semantics
and hashed group ids; results carry `algorithm`, `release` and the local extension's sha256. `crgo_sweep` and
`crgo_identify` now break ties by scenario IRI, so they no longer depend on `PYTHONHASHSEED`; sweep's query-dependent
near-duplicate merging is otherwise unchanged and can differ from the static grouping clusters.

## Checks

Run without ROBOT (not downloadable in the build sandbox): every Python suite of `scripts/check.sh` passed (see
`CHANGELOG.md`), plus `tests/mcp/test_mcp_errors.py` (80 calls). The ROBOT reasoning and profile steps and the SHACL and
pitfall steps that need the ROBOT merge were not run for this patch; the ontology content they check is unchanged since
0.11.1 apart from version annotations. Run `WITH_LIBRARY=1 ./scripts/check.sh` with ROBOT before tagging.
