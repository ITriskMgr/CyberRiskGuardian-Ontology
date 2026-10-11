# Sprint 1 plan (proposed): foundations for 0.9.0

Prepared 2026-10-11. Scope is finite and P0 only (§8, §15 Stages 1–2, §21). Gap numbers refer to
`docs/baseline/gap_analysis.md`. Nothing in this plan is started until the project owner approves it.

## Release plan

| Version | Content | Exit |
|---|---|---|
| **0.9.0** | EU GDPR (approved) + Sprint 1 below | owner checkpoint, all gates green, change report against 0.8.0 |
| **0.9.5** | Sprint 2: exposures and CVSS / EPSS / KEV observations (G8), BIA (G12), treatment portfolios and an external optimiser contract (G13), remaining CQ-01, 06, 09, 10, 12–16, OSCAL adapter, ISO/IEC 27001 clauses 4–10 identifiers, risk-method constructs (ISO/IEC 27005, SP 800-30, Open FAIR) authored without copied text | as above against 0.9.0 |
| **1.0.0** | Sprint 3: P1 sources chosen at the 0.9.5 checkpoint (candidates: CIS Controls, NIS2, DORA, NIST Privacy Framework, ATT&CK groups and software), full acceptance demonstration of §22, developer guide; stability commitment | all §17 items |

## Sprint 1 work packages

| # | Work package | Deliverables | Acceptance test | Gaps |
|---|---|---|---|---|
| 1 | Design records | `docs/adr/ADR-001` foundation and namespace policy (documents current practice), ADR-002 scenario / incident / observation, ADR-003 control objective / implementation / assessment, ADR-004 instrument / provision / obligation / applicability / determination, ADR-005 mapping semantics, ADR-006 provenance and time. Each with alternatives, chosen pattern, counterexample and test | each ADR names the fixture that proves it | §5 |
| 2 | Provenance and time | PROV-O and OWL-Time imported (W3C, OWL 2 DL compatible); `source record` class with the §7 fields, one individual per row of `source_registry.csv`; vocabulary concepts and mappings point to their source record; dated `observation` class; `assumption` class | SHACL: every imported concept has a source record with version and retrieval date | G10, G11 |
| 3 | Compliance module `crgo-grc` | legal instrument (jurisdiction, issuer, effective period), provision (the existing SKOS concepts), applicability condition, applicability assessment and compliance determination with the two state value sets, evidence-gap status. Instrument individuals for Loi 25, A-2.1, R-22.1, PIPEDA, OSFI B-13, GDPR with dates | CQ-07 and CQ-08 pass on positive, negative and *unknown* fixtures; no query infers noncompliance from missing data | G1, G2 |
| 4 | Privacy core (only what applicability needs) | processing activity, data category, controller / processor role, data subjects' location; GDPR Art. 3(2) and Loi 25 / PIPEDA / A-2.1 scope conditions expressed against them | sample organisation gets GDPR *potentially applicable* only when it offers services to people in the EU | G17 |
| 5 | Control assessment | control assessment act (date, scope, procedure, result, assessor) evaluating a control measure, supported by evidence | CQ-04 and CQ-05 pass; SHACL forbids a control measure being `owl:sameAs` a control | G-ctrl |
| 6 | Organisation dependencies | supplier, dependency (asset or process depends on supplier / service) | used by the sample organisation; prepares CQ-15 | G12 (part) |
| 7 | Mapping semantics | typed sub-properties of `skos:relatedMatch` (e.g. *countered by*, *instance of weakness*, *supported by control*, *comparable obligation*), each with domain scheme, range scheme and direction; existing correspondences re-typed, annotations kept; low-confidence proposals moved to `mappings-proposed.ttl` | every correspondence has a typed predicate; SHACL rejects an approved mapping without approver; SKOS queries unchanged (CQ01–CQ27 still pass) | G4, G5 |
| 8 | EPSS and KEV as data | dated EPSS observation (probability, percentile, 30-day horizon, score date, model version) linked to the CVE; KEV date added and ransomware use typed; the 0.8.0 EPSS *likelihood* individuals deprecated with a replacement link | SHACL from §13 (probability 0–1, one CVE, date, publisher); CQ26 rewritten and passing | G6, G7 |
| 9 | Sample organisation | fictional online ordering company (§22): cloud application, payment provider, identities, supplier; two hypothetical scenarios (credential compromise, ransomware) with assessments, control assessments, applicability and determinations including *unknown*. Every individual marked synthetic, in `tests/samples/` | loads with the full ontology, consistent, SHACL-conformant | §21 task 5 |
| 10 | Competency questions | CQ-03, CQ-04, CQ-05, CQ-07, CQ-08, CQ-11, each with expected answer, positive and negative fixture, absent-data and contradictory-observation cases | all pass in `scripts/check.sh` | G15 |
| 11 | Change report | `scripts/change_report.py` comparing two tags: added, deprecated and altered terms, axioms and mappings; output in `releases/0.9.0/` | report against `v0.8.0` produced and reviewed | G16 |
| 12 | Housekeeping | `CITATION.cff` to 0.9.0; GDPR corrigendum check; `docs/baseline/` regenerated at the end | — | C2, C7 |

Each package is one commit on `v0.9`, followed by a full `scripts/check.sh` run. Failures are reported, not hidden.

## Effort

About 12 working sessions of the kind used for 0.7.0 and 0.8.0. Packages 3, 7 and 9 are the largest.

## Decisions needed from the project owner

| # | Decision | Recommendation |
|---|---|---|
| D1 | Release numbering | Fold Sprint 1 into 0.9.0 with the GDPR, as the specification's 0.9.0 → 0.9.5 → 1.0.0 path suggests, rather than releasing the GDPR alone first |
| D2 | Module strategy | Keep the four existing modules unchanged; new content in new modules (gap analysis §D) |
| D3 | Mapping model | Typed sub-properties of `skos:relatedMatch` with the existing annotations, not reified individuals for every link |
| D4 | EPSS | Re-model as dated observations and deprecate the approved 0.8.0 *likelihood* individuals, with a replacement link |
| D5 | ISO / COBIT / CCM titles | Keep the short titles with attribution (common practice, already in NOTICE), or reduce to identifiers only |
| D6 | Legal snapshots | You save PDFs of P-39.1, C-1.1, A-2.1, R-22.1 (with r. 1, r. 2), PIPEDA and B-13 from the official sites into `CRGO-downloads/`; I record their checksums and dates. Without them CQ-12 waits for the next consolidation |
| D7 | Sample organisation | Use a new fictional company as in §22, not one of your teaching cases, so the cases stay usable for measuring recall |
