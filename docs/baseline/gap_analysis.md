# CRGO gap analysis against the v0.8 → v1.0 specification (Stage 0)

Prepared 2026-10-11. Compares the repository (`docs/baseline/baseline_inventory.md`) with the specification's
sections 2–13 and 17. Each gap names the specification clause it comes from, what exists, what is missing, and a
proposed stage. "Exists" means present in the files and covered by a passing check, not just planned.

## A. What CRGO already satisfies

| Specification requirement | Where it is met |
|---|---|
| Persistent, namespace-controlled IRIs, never derived from labels (§5 Identity) | opaque `CRGO_nnnnnnn` IRIs, `src/ids.tsv`, w3id.org live; library IRIs from stable family ids |
| Modular OWL 2 DL with BFO/CCO alignment documented (§3) | 4 modules + umbrella; per-term alignment and OntoClean notes; HermiT, ELK, DL profile |
| Hypothetical scenario ≠ observed incident (§5 Risk classes, §6) | `risk scenario` (description) vs `incident` (occurrent); negative fixtures |
| Control objective ≠ implementation (§5 Controls) | `control` (prescription, organisation-independent) vs `control measure` (organisation-specific, status, owner, evidence) |
| Explicit assessment records, not permanent scores (§3) | `risk assessment` is a planned act with method, horizon and appetite; values are `estimate` individuals with scale, bounds, rationale, evidence and confidence |
| CRG formulae kept apart from standards formulae (§11) | `crgo-crg` module separate from the generic `crgo-measure` layer |
| Governance on every element; AI suggestions never silently approved (§13) | status, confidence, rationale, evidence source, proposed by / approved by / date on every term and link; SHACL negative fixture *approved without approver*; owner approval ledger |
| Separation of evidence kinds (non-negotiable rule 3) | `evidence basis` value set: documented, external, expert, inference, AI estimate |
| Source rights respected (rule 4) | ISO/COBIT/CCM identifiers and titles only; VCDB counts only; NOTICE.md |
| Distinct reasoning, validation and numeric computation (rule 5, §11) | reasoners, SHACL, SPARQL CQs, and the CRG computation in Python with the MediBec regression |
| Engineering quality gate (§2) | `scripts/check.sh`, all passing |
| Baseline preservation, queryable (§2) | release tags and version IRIs |

## B. Gaps

Severity: **H** blocks an acceptance test of §2; **M** weakens a required property; **L** improvement.

### Compliance (§9, §5 Regulations, §5 Legal temporality)
- **G1 (H) No applicability or determination model.** Obligations exist as SKOS concepts (paraphrased provisions) plus the class `legal obligation`, and scenarios link to them (`triggers obligation`). There is no legal instrument / provision / obligation / applicability condition separation, no organisation-specific `ApplicabilityAssessment` or `ComplianceDetermination`, and none of the required states (applicable, not applicable, potentially applicable, unknown; satisfied, partially satisfied, unsatisfied, not assessed, undetermined). `other_regimes` currently answers with a free-text caution. → Sprint 1.
- **G2 (M) Legal temporality is text.** In-force dates, consolidation dates and amendments sit in notes and version strings. No effective period, amendment or repeal as data. → Sprint 1 (instrument level), Sprint 2 (provision level).
- **G3 (M) No dated legal snapshots.** LégisQuébec, Justice Laws and OSFI texts were read online and not stored; only the EU and UK GDPR PDFs have checksums. CQ-12 (provisions changed between two dated snapshots) cannot be answered. → needs the project owner to save PDFs (decision D6).

### Mappings (§3, §5 Mappings, §7 MappingAssertion)
- **G4 (M) One predicate carries many meanings.** 11,539 of 11,554 correspondences use `skos:relatedMatch` for meanings as different as *technique countered by defensive technique*, *vulnerability is an instance of weakness*, *subcategory supported by control* and *comparable obligation*. The meaning and direction are in a comment string. Source, confidence, status, approver and approval date (`xsd:date`) are present (OWL axiom annotations). There is no coverage degree, no source or recording date as data, and the approval group is not stored. → Sprint 1 (decision D3).
- **G5 (L) Proposals not quarantined.** Proposed items (e.g. 120 low-confidence D3FEND links) live in the same files as approved ones, distinguished by status. The specification asks for a proposal graph. → Sprint 1, as a separate file and SHACL rule.

### Vulnerability and intelligence (§10, §5 Confidence, §13)
- **G6 (H) EPSS is modelled as scenario-style likelihood.** The 1,739 EPSS values are `likelihood` estimates on KEV concepts. The specification forbids conflating probability of exploitation activity with probability of scenario occurrence. The 30-day horizon and the percentile are in comments; the score date only in the evidence label. → Sprint 1: dated `EPSSObservation`, the 0.8.0 individuals deprecated with a replacement link (decision D4, because they were approved).
- **G7 (M) KEV dates and ransomware use are text.** `dateAdded` and *known ransomware use* sit in `skos:note`. → Sprint 1 (typed data).
- **G8 (M) No published-vulnerability vs exposure split.** There is no `AssetExposure`, CVE / product / version, or CVSS observation with vector and date as a dated record (CVSS inputs exist only inside CRG computations). CQ-01 cannot be answered. → Sprint 2.
- **G9 (L) CTID mappings are for ATT&CK 16.1, the vocabulary is 19.2.** 1 technique not found; revoked or renamed techniques are not reported. → Sprint 2 (version-aware adapter).

### Provenance, time and units (§3, §7, §13)
- **G10 (M) No PROV-O, OWL-Time or QUDT.** Provenance uses 11 CRGO annotation properties; dates are `xsd:date` annotation values or strings; source versions exist at scheme level only; no import timestamp per entity; currency is a code property, probabilities are unitless decimals. → Sprint 1 (PROV-O and OWL-Time alignment, source records), units in Sprint 2.
- **G11 (M) No `Assumption` or `Observation` class.** Assumptions sit in rationale text; observations are estimates. → Sprint 1.

### Organisation, resilience, decision (§4, §6, §11)
- **G12 (M) No supplier or dependency model, no BIA.** Business process, objective, asset and service asset exist; supplier, dependency, RTO, RPO, recovery capability do not. CQ-15 cannot be answered. → Sprint 1 (supplier, dependency), Sprint 2 (BIA).
- **G13 (M) Treatment comparison is partial.** Treatment initiatives have costs, decisions and acceptances with expiry exist; there is no portfolio, prerequisite, overlap or alternative-assumption structure, and no external optimiser contract. CQ-09, CQ-10, CQ-14, CQ-16 are not answerable. → Sprint 2.
- **G-ctrl (M) No control assessment.** `control measure` holds status and effectiveness estimates, but there is no dated `ControlAssessment` act with test procedure, scope, result and evidence. CQ-04 and CQ-05 are only partly answerable. → Sprint 1.

### Licensing (rule 4, §8 licensing gate)
- **G14 (M) Copyrighted titles.** ISO/IEC 27002 control titles (93), COBIT objective names (40) and CCM domain names (17) are reproduced. They were taken from secondary public listings, not licensed copies. Short titles are commonly cited, but the specification asks for an explicit permission inventory. → decision D5.

### Tests and change control (§12, §17)
- **G15 (H) The specification's competency questions are almost all unanswerable today.** Of CQ-01 to CQ-16, only CQ-02 (techniques for a weakness, through CAPEC and KEV) can be answered fully from current data; CQ-04, CQ-05 and CQ-11 partly (control measure status and effectiveness estimates; scheme-level source versions). The others need organisation-specific exposure, control assessment, compliance determination and treatment portfolio records. The existing 27 CQs are library and identification questions; they have positive assertions but no per-question negative or absent-data fixtures. → Sprint 1 implements 6, Sprint 2 the rest.
- **G16 (M) No machine-readable change report.** Changes between releases are in the changelog prose. The specification requires additions, altered axioms, deprecations and mapping changes per release. → Sprint 1 (script comparing two tags).
- **G17 (L) Privacy and AI modules absent.** No processing activity, data category or controller / processor role (needed to evaluate GDPR applicability beyond Art. 3(2)); no AI system, model or agent. → privacy core in Sprint 1 (only what applicability needs), AI in a later stage.

## C. Suspected defects and uncertain facts

1. The 0.4.0 version IRI file is labelled "0.3.0" (known, in the changelog).
2. `CITATION.cff` still says 0.5.0; 0.6.0–0.8.0 did not update it.
3. 63 KEV → CWE references were skipped because those CWE ids are absent from D3FEND's CWE subset; CWE coverage is therefore incomplete.
4. The CWE version behind D3FEND 1.6.0 is not stated anywhere; recorded as unknown.
5. ISO/IEC 27005 clause numbers in `evidence source` annotations are marked "to verify against the licensed text" and have not been verified.
6. Library CRG estimates are 2023 values calibrated on teaching cases; they are generic calibration aids, not evidence about any organisation. This is documented but should become explicit `Assumption` records (G11).
7. The GDPR corrigendum (OJ L 127, 23.5.2018) has not been reviewed.

## D. Specification items I propose to adapt rather than follow literally

| Item | Proposal | Reason |
|---|---|---|
| §4 thirteen modules | Keep the four existing modules unchanged and add new modules only for new content: `crgo-grc`, `crgo-mapping`, `crgo-org` (supplier, dependency, BIA), `crgo-vuln`, later `crgo-privacy`, `crgo-ai` | Moving approved terms between modules changes nothing for users of the IRIs but churns review and documentation; the specification itself says not to impose structure without assessment (§14) |
| §14 folder layout | Keep the current layout; map each specification folder to the existing one in the design document | Working build, documentation site and w3id rules depend on it |
| §3 reified MappingAssertion individuals for all relations | Typed sub-properties of `skos:relatedMatch` (one per meaning, with direction) keeping the existing axiom annotations; reified `MappingReview` records only where a review exists | 11,554 + 24,871 annotated links already carry provenance; reifying all of them adds about 200,000 triples for no new information, and SKOS consumers keep working |
| §15 Stage 3 standards adapters (ISO 27005, 31000, FAIR, 27001) | Method constructs and clause identifiers authored independently, no text; 27001 clauses 4–10 as identifiers and CRGO paraphrases | Licensing gate |

## E. Risk log (Stage 0)

| Risk | Likelihood | Effect | Mitigation |
|---|---|---|---|
| Scope of 0.9.0 grows beyond review capacity | high | approvals stall | finite sprints; each ends at a checkpoint |
| Changing approved 0.8.0 content (EPSS, mappings) | medium | breaks consumers, voids approvals | additive changes, deprecation with replacement, owner decisions D3–D4 |
| Legal interpretation in applicability conditions | medium | wrong advice | conditions are CRGO paraphrases with citations, status *proposed*, owner review; results phrased as *potentially applicable* |
| Copyright on standard titles | low–medium | takedown or licence issue | decision D5 |
| Fictional sample data mistaken for real | low | misleading demonstrations | every sample individual labelled synthetic, separate file, SHACL check |
