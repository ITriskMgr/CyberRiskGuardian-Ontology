# ADR-004 Instrument, provision, obligation, applicability and compliance

Status: proposed (0.9.0). Specification sections 5 (Regulations, Legal temporality), 9, 13.

## Decision
- **Legal instrument** (new): the statute, regulation or guideline as a whole, with official citation, jurisdiction, kind, publication, in-force interval (OWL-Time, only when the text states the date), application date, last amendment and consolidation date, and its source record (dated PDF snapshot with checksum).
- **Provision**: the existing concepts of the legal vocabularies (Loi 25, A-2.1, R-22.1, PIPEDA, GDPR, OSFI B-13), each linked by `provision of` to its instrument (179 links). `legal obligation` (since 0.1.0) remains the class for a duty as prescribed.
- **Applicability condition** (new, 19, of which 5 interpretive): a CRGO paraphrase of a scope rule (territory, organisation type, processing, data category, exception) with a citation and a machine-readable test `role|test|plain-or-interpretive`.
- **Applicability assessment** (new): a dated record of the state (applicable, not applicable, potentially applicable, unknown) for one organisation and instrument, with the conditions met, not met and undetermined, produced by `pipeline/grc/applicability.py`.
- **Compliance determination** (new): a dated record by an assessor of the state (satisfied, partially satisfied, unsatisfied, not assessed, undetermined), with evidence or an explicit evidence gap, optionally based on control assessments.

**Applicability is evaluated, never inferred by class membership.** The evaluator reads the organisation profile as given: a listed value is a fact; an unlisted value counts as absent only for the properties the profile declares complete (`profile complete for`), and is otherwise unknown. Missing data never yields *not applicable*. (An earlier draft read every property with at least one value as complete; the independent review showed this turned partial profiles into *not applicable*.) The assessment date is compared with the date the instrument applies from. A condition marked interpretive (for example GDPR Art. 3(2) targeting, PIPEDA cross-border scope for a Québec enterprise) can only yield *potentially applicable*, which signals review by a qualified person. The conditions are proposed until approved and are not legal advice.

**A mapping is not compliance.** Correspondences between obligations (`comparable obligation`) and links from scenarios to obligations never create a compliance determination; a *satisfied* determination must cite evidence.

## Alternatives
OWL class restrictions ("organisations established in Québec that process personal information are Loi25Subject") were rejected: under the open world, a missing fact would silently leave the class empty, and legal interpretation would be hidden in axioms. Rule languages (SWRL) were rejected for the same reason and for OWL 2 DL decidability.

## Counterexample and test
`tests/spec_cq` (CQ-07): Nordelle gives Loi 25 applicable, GDPR and PIPEDA potentially applicable; a Québec-only variant that does not state where it monitors behaviour or where it transfers data gives GDPR and PIPEDA *unknown*, and *not applicable* once it states them; removing the processing activity (and its completeness declaration) gives Loi 25 *unknown* and CQ-07u names the missing fact; an enterprise that is also a public body gives A-2.1 applicable and Loi 25 excluded by its s. 3 exception; a Québec insurer regulated by OSFI gives B-13 applicable and PIPEDA not applicable; an Ontario-type firm selling into Québec gives Loi 25 potentially applicable and PIPEDA applicable; an EU-established firm assessed in 2017 gives the GDPR not yet applicable. SHACL: a determination with neither evidence nor gap, and an assessment without state, are rejected (`tests/shacl/neg-determination-no-evidence`, `neg-applicability-no-state`).

## Open points (for the project owner and qualified review)
Provision-level in-force dates beyond the Loi 25 vocabulary; the C-1.1 biometrics condition (purpose of identity verification not modelled as data); PIPEDA scope for Québec enterprises with interprovincial transfers; P-39.1 s. 3, paras. 2-3 (data-scoped exclusions) and health bodies holding non-health information; a processing role stated per activity cannot express being processor for one party and controller for another.
