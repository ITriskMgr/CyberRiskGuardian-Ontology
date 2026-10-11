# Changelog

All notable changes to the CyberRiskGuardian Ontology (CRGO). Versions follow [semantic versioning](https://semver.org/) as applied to ontologies: a minor version adds terms or data; term IRIs (`https://w3id.org/crgo/CRGO_nnnnnnn`) never change meaning or disappear, and retired terms are deprecated, not deleted. Each version records who approved what in `src/approvals.tsv`; design reasons are in `docs/decisions.md`.

## [0.9.0] — 2026-10-11, prepared for review

EU GDPR, and Sprint 1 of the v0.8 → v1.0 implementation specification: sources and provenance, legal applicability and compliance, control assessment, typed cross-references, EPSS as observations. The GDPR content was approved by the project owner on 2026-10-11; the Sprint 1 additions await review (`docs/review-0.9.0.md`). The four 0.8.0 modules are unchanged (decision D2); the change report against v0.8.0 is in `releases/0.9.0/`.

### Added
- **GDPR** (approved): vocabulary of 40 provisions of Regulation (EU) 2016/679 from the Official Journal text, English and French; 25 correspondences to Loi 25 (19 comparable, 6 partly comparable); scenario detail lists GDPR provisions; CQ27.
- **Five new modules** (138 new terms, CRGO_0000337 to CRGO_0000474):
  - `crgo-evidence`: source record, observation (disjoint from estimate), assumption; aligned to PROV-O and OWL-Time, imported as OWL 2 DL slices.
  - `crgo-org`: organisation type, jurisdictions, processing activity, processing role, personal data categories, supplier role, and *profile complete for*, which declares the facts a profile lists completely.
  - `crgo-vuln`: EPSS observation, KEV date added and ransomware use as data.
  - `crgo-grc`: legal instrument, applicability condition, applicability assessment (applicable, not applicable, potentially applicable, unknown), compliance determination (satisfied, partially satisfied, unsatisfied, not assessed, undetermined), control assessment (effective, partly effective, ineffective, not tested).
  - `crgo-mapping`: 11 typed correspondence relations, sub-properties of `skos:relatedMatch` / `skos:closeMatch`.
- **Source records** (`ontology/vocab/sources.ttl`): 29 sources with issuer, version, retrieval date, licence, what CRGO redistributes and SHA-256 checksums; every vocabulary, the mappings, the library and the legal instruments point to them. Dated PDF snapshots of P-39.1, C-1.1, A-2.1 (with r. 0.1 and r. 3.1), R-22.1 (with r. 1 and r. 2), PIPEDA and OSFI B-13 recorded (supplied by the project owner).
- **Legal instruments** (`ontology/vocab/legal.ttl`): 11 instruments with citations, jurisdictions and the dates printed in the texts (the GDPR in-force interval as OWL-Time); 179 *provision of* links from the legal vocabularies; 19 applicability conditions with machine-readable tests (5 interpretive).
- **Applicability evaluator** (`pipeline/grc/applicability.py`): evaluates the conditions over an organisation profile and the assessment date; an unlisted fact counts as absent only where the profile declares that property complete, otherwise it gives *unknown*, never *not applicable*; an interpretive condition gives only *potentially applicable*; an instrument is not applicable before the date it applies from.
- **Synthetic test company** Nordelle Market inc. (`tests/samples/`, decision D7): profile, suppliers, processing, a 2026 assessment with two hypothetical scenarios, estimates with assumptions, three control measures and assessments, four compliance determinations, applicability results. Clearly marked synthetic; not empirically validated.
- **Specification competency questions** CQ-03, 04, 05, 07, 08 and 11 (`tests/spec_cq/`, 27 checks with negative, absent-data, date and contradictory-observation fixtures).
- **Quality gates**: 26 new SHACL shapes (16 written for the new classes: source records, observations including contradictory EPSS scores, vocabularies without a source, legal instruments, applicability, compliance with evidence or an evidence gap and evidence for any satisfied state, control assessments, measure ≠ control, typed mappings, the federal legal order never used as a place; 10 for new functional properties); 11 new SHACL negative fixtures, each checked for the message it must trigger, and 1 OWL negative fixture (observation ≠ estimate); `scripts/check.sh` step 13 (sample consistency, OWL 2 DL, specification CQs).
- **Design records** ADR-001 to ADR-006 (`docs/adr/`); Stage 0 baseline, source registry, gap analysis and sprint plan (`docs/baseline/`); change report script (`scripts/change_report.py`).

### Changed
- After an independent review (2026-10-11), before release: the Loi 25 territorial test covers enterprises active in Québec without an establishment (interpretive); the PIPEDA rule for all federally regulated financial institutions was removed (only federal works such as banks are federal undertakings) and a commercial-activity condition added; PIPEDA citations corrected (s. 4(1)(a)-(b), SOR/2003-374); British Columbia and Alberta separated from the other provinces; the C-1.1 condition scoped to identity verification; P-39.1 s. 3, paras. 2-3 documented as out of scope.
- **EPSS** (decision D4): the 1,739 values are dated EPSS observations (probability, percentile, 30-day horizon, score date, model version, source record). The 0.8.0 *likelihood* individuals are deprecated stubs pointing to their replacements; scenario detail and CQ26 read the observations.
- **Cross-references** (decision D3): every correspondence also carries its typed relation; SKOS triples and annotations are unchanged.
- **Proposed links kept apart** (gap G5): `ontology/vocab/mappings-proposed.ttl` (120 low-confidence D3FEND links) and `data/abox/crgo-library-proposed.ttl` (library links of unapproved groups) are not imported by `crgo-full`; the query store still loads them.
- w3id.org rules generalised for the new modules, import slices and the proposal file (local copy in `w3id/`; the live rules need a pull request).

### Not included
- The UK GDPR and the 2018 corrigendum to the GDPR. Organisation-specific exposures, BIA, treatment portfolios and the remaining specification CQs are planned for 0.9.5 (`docs/baseline/sprint_1_plan.md`).

## [0.8.0] — 2026-10-11, approved

Calibration evidence, other sectors and other legal regimes. Approved in full by the project owner on 2026-10-11, including the written scenarios AUTH-001 to AUTH-006 and their links.

### Added
- **Exploitation probability:** FIRST EPSS scores (2026-10-04) for the 1,739 KEV vulnerabilities, as likelihood estimates; scenario evidence now gives the median and maximum EPSS of the exploited vulnerabilities behind its techniques and weaknesses.
- **Sector frequencies:** 111 estimates from the VERIS Community Database: for 9 sectors and all sectors, the share of confirmed public incidents (2015–2025) involving each theme or threat-source type; mass campaigns counted once (the 2023 MOVEit breach alone was 613 of 842 education records). `crgo_sweep` reports them when a profile names a sector.
- **Legal regimes:** Québec public-sector Act A-2.1 (18 obligations, verified on LégisQuébec), PIPEDA (13 provisions, verified on the Justice Laws Website), OSFI B-13 (3 domains, 17 principles). Cross-references: Loi 25 ↔ A-2.1 (15, same obligation), Loi 25 ↔ PIPEDA (10, comparable obligation), B-13 ↔ CSF 2.0 categories (42). Scenario detail lists a scenario's obligations under each regime.
- **NIST crosswalks** (files supplied by the project owner): CSF 2.0 → SP 800-53 (707, derived from NIST's CSF 1.1 mapping and the CSF 2.0 withdrawal records) and SP 800-53 → ISO/IEC 27002 (418, NIST OLIR). 6,858 CSF and ISO links carry `corroborated by`: CSF high 92%, medium 71%, low 41%; ISO high 76%, medium 58%, low 38%.
- **French labels and definitions** for all CSF 2.0 functions, categories and subcategories, from NIST's French translation.
- **Other sectors:** three scenarios from the ACRB evaluation (ATM jackpotting, outage from an expired certificate, incomplete asset inventory); banking and payments synonyms; healthcare-worded scenarios ranked slightly lower when the profile has no health term; four commonly assessed risks proposed (vendor remote access, insider fraud, asset inventory gaps, certificate expiry).
- Competency questions CQ24–CQ26 (proposed).

### Not yet included
- GDPR: the PDF supplied is the UK GDPR (legislation.gov.uk), not the EU Regulation; which text to model is left to the project owner (resolved in 0.9.0).

## [0.7.0] — 2026-10-11, approved

Public sources added to the ontology. Approved by group on 2026-10-11: the new term, the four vocabularies, the cross-references published by MITRE and CISA, and the high- and medium-confidence judged links; low-confidence judged links stay *proposed*.

### Added
- Vocabularies: MITRE CWE (943 weaknesses, from D3FEND 1.6.0), MITRE D3FEND (270 defensive techniques), MITRE CAPEC (559 attack patterns), CISA KEV (1,739 actively exploited vulnerabilities). Sources, versions and licences in `NOTICE.md`.
- `ontology/vocab/mappings.ttl`: 10,337 cross-references between vocabularies, each with its source, confidence and status: CAPEC→ATT&CK (270), CAPEC→CWE (1,212), ATT&CK→SP 800-53 from MITRE CTID (5,236), KEV→ATT&CK from CTID (1,183), KEV→CWE from CISA (1,616), ATT&CK→D3FEND judged for the 212 techniques the library uses (820).
- CWE references on 590 scenarios (1,135 links, judged), carried by the scenario's weakness description.
- 680 SP 800-53 links proposed from the CTID mapping, filtered to controls usual for the same techniques.
- Corroboration: 2,152 existing SP 800-53 links carry `corroborated by` naming the CTID mapping that supports them. Within CTID's control families, 83% of high-, 74% of medium- and 54% of low-confidence links are corroborated.
- New term, proposed: `corroborated by` (annotation property, crgo-gov).
- Identification interface: scenario detail now lists CWE weaknesses, D3FEND countermeasures and KEV exploitation evidence (counts and ransomware use); controls show their corroboration.
- Competency questions CQ21–CQ23 (proposed) on CWE, D3FEND and KEV.

### Rejected during the work
- Inferring ATT&CK→D3FEND from shared digital artifacts, D3FEND's own method, was tried in two variants and rejected after independent review (40-link samples: 14 correct, 15 weak, 11 wrong; then 16, 12, 12). Judged links replaced it (45-link sample: 28 correct, 16 weak, 1 wrong).

## [0.6.0] — 2026-10-10, approved

### Added
- Loi 25 pass 2: the 176 library families tagged with a privacy impact whose only Loi 25 link was P-39.1 s. 10 (added by rule) were judged against Loi 25 for the other obligations: 558 links (H 77, M 234, L 247) in their own approval group (`links/loi25-pass2/<confidence>`). The 311 high- and medium-confidence links are approved by group; the 247 low-confidence links stay *proposed*. Up to four links per family, so that the four incident obligations (s. 3.5 first and second paragraphs, s. 3.7, s. 3.8) fit. Judgements and prompt: `data/library/loi25_pass2.jsonl`, `data/library/loi25_pass2_prompt.md`.
- 497 R-22.1 equivalents of the new links on health-information families, by the 0.4.0 rule (proposed).

### Notes
- Nine of the 176 families were judged not to involve personal information (listed in the review workbook); they keep s. 10 from their privacy-impact tag, which may be wrong.

## [0.5.0] — 2026-10-10, approved

Release preparation (Phase 5). No change to the classes, properties or logical axioms of 0.4.0.

### Added
- Documentation site (WIDOCO 1.4.25), bilingual English and French, with a WebVOWL diagram and downloadable serialisations (Turtle, RDF/XML, N-Triples, JSON-LD): `docs/doc/`, generated by `scripts/make_docs.py`. Landing page: `docs/index.html`. Built for GitHub Pages (main branch, `/docs` folder).
- FAIR metadata on every module and on the umbrella ontology: French description, abstract in both languages, publisher, contributor statement for the AI drafting assistant, issue and modification dates, prior version, status, bibliographic citation, code repository, homepage.
- w3id.org redirect rules and registration instructions: `w3id/crgo/.htaccess`, `w3id/HOWTO.md`. `scripts/check_w3id.py` resolves every CRGO IRI in the published files (31,386) against the rules, for both browser and RDF requests.
- `CITATION.cff`, this changelog, release notes (`docs/release-notes-0.5.0.md`) and the extension plan (`docs/roadmap.md`).

### Changed
- Deferred item L12: the definition of "2023 scenario-generator notebook v2-1b" no longer carries the notebook's defects; they moved to its review note (re-approved 2026-10-10).
- Version strings set to 0.5.0 in the modules, the full ontology, the library, the vocabularies, the SHACL shapes and the JSON export.

## [0.4.0] — 2026-10-10, approved (tag `v0.4.0`, commit 7e87dc6)

Validation and the identification interface for CyberRiskGuardian (Phase 4).

### Added
- 20 competency questions as SPARQL tests (`tests/cq/`), all passing.
- SHACL shapes (`shapes/crgo-shapes.ttl`, 48 node shapes): functional properties, value ranges, provenance of computed quantities, governance on every link annotation; 8 negative tests.
- Local scan for the mechanically checkable OOPS! pitfalls (`scripts/check_pitfalls.py`): no critical pitfall.
- Identification interface (requirement R1): `pipeline/query/identify.py`, an MCP server (`pipeline/mcp/crgo_server.py`), a JSON export of every scenario (`data/export/crgo-identification.json`), with 18 commonly assessed risks and a synonym list approved by the project owner.
- Three library scenarios written to fill gaps found in the blind test: F1812 cloud tenant takeover through token theft or app consent, F1813 disclosure through staff use of generative-AI tools, F1814 interception or tampering of HL7/DICOM clinical messages. Their links are proposed.
- Vocabulary `lrsss`: 54 obligations of Québec's Act respecting health and social services information (CQLR c. R-22.1) and its regulations, with 2,292 rule-based links on 517 scenarios (proposed).
- Disjointness: value-set classes pairwise disjoint; library and assessment scenarios disjoint.
- Blind identification evaluations: MediBec (recall 0.52 blind, 0.62 after tuning on it, not independent) and ACRB (0.76, independent).

### Known issue
- At tag `v0.4.0`, the modules and the scenario library still carry `owl:versionInfo "0.3.0"` and the 0.3.0 version IRIs (only `crgo-full` says 0.4.0); the version number was not raised when 0.4.0 was built. The content is that of 0.4.0. Fixed from 0.5.0 on.

### Fixed
- Family identifiers frozen (`data/library/family_ids.tsv`); holdout leak through assessment scenarios; synonym expansion dropping the original keyword; loose matching of commonly assessed risks.

## [0.3.0] — 2026-10-10, approved (tag `v0.3.0`, commit 0b53f7c)

### Added
- Framework links for every library family: 19,709 links to ATT&CK, NIST CSF 2.0, SP 800-53 Rev. 5, ISO/IEC 27002:2022 and Loi 25, each annotated with confidence, proposer and status. The 17,967 high- and medium-confidence links are approved by group; the 1,742 low-confidence links stay proposed.
- New property `hasRelevantRequirement` (approved).
- Case-based estimates from the teaching cases (67 case scenarios, 273 families recalibrated), as calibration aids rather than organisational evidence.
- Loi 25 s. 10 (security measures); 161 revoked or deprecated ATT&CK techniques kept as deprecated concepts with their replacements.
- `ontology/crgo-full.ttl`: modules, scenario library and vocabularies in one consistent OWL 2 DL import closure.

## [0.2.0] — 2026-10-10, approved (tag `v0.2.0`, commit 0a10839)

### Added
- Scenario library: the 2,158 rows of the 2023 scenario generator, repaired and merged into 1,811 scenario families, as instance data (`data/abox/crgo-library.ttl`). Values are re-read from the generator's answers; risk is recomputed with CRG v1.0c where all inputs are stated.
- SKOS vocabularies: 23 scenario themes (approved), NIST CSF 2.0, SP 800-53 Rev. 5, ISO/IEC 27002:2022 titles, COBIT 2019, Loi 25, CSA CCM v4.1 domains, MITRE ATT&CK. CCM v4.1 controls load into a private file only.
- CRG bridge: conversion of CyberRiskGuardian assessments to CRGO, checked by a round trip on the MediBec assessment.
- 7 new or changed terms (approved).

## [0.1.0] — 2026-10-08, approved (tag `v0.1.0`, commit e27d539)

### Added
- First release: the modules crgo-gov, crgo-core, crgo-measure and crgo-crg, and the umbrella crgo, on BFO-2020 with an extract of the Common Core Ontologies 2.2. English and French labels and definitions, governance annotations on every term. Consistent under HermiT and ELK, in the OWL 2 DL profile.
