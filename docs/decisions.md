# Design decisions — CRGO 0.8.0

This file records why the ontology looks the way it does.

**Approval.** On 2026-10-08 the project owner, Marc-André Léger, reviewed the
term workbook and approved all terms of version 0.1.0. Each term now carries
status `approved`, `approvedBy` Marc-André Léger and `approvalDate` 2026-10-08;
the decisions are recorded in `src/approvals.tsv`, and the build applies them.
The deferred items in section 5 remain open for later versions.

## 1. Decisions taken with the project owner (Phase 1)

| # | Decision |
|---|---|
| Scope | Start a new core ontology aligned with CyberRiskGuardian (CRG); MOACCO is not extended and is retired (Q8) |
| Q1 / Q-A | BFO-2020 (ISO/IEC 21838-2) is the upper ontology; DOLCE is an optional alignment module, later |
| Q2 | The quantitative model is CRG's (Excel Guide v1.0c / `crg_calc.py`) |
| Q3 | `Asset` is a rigid class; context-dependent value goes on `AssetValuation` |
| Q4 | Phase 3 instance data = the 2,158 generated library rows |
| Q5 | Generic only (no sector extensions in 0.1) |
| Q6 | Framework vocabularies: NIST CSF 2.0, ISO/IEC 27002:2022 (IDs + titles), Loi 25, SP 800-53, CCM v4.1, COBIT, and CRG's other frameworks |
| Q7 / Q-C | New public repository under ITriskMgr, named "CyberRiskGuardian Ontology" |
| Q9 | Student content may be used, anonymised |
| Q-B | Licensed framework vocabularies are added to the ontology (as SKOS, Phase 3) |
| Q-D | Licence CC BY-NC 4.0, same as CRG |
| Q-E | Option 3: repair and consolidate the library rows before loading (Phase 3) |

## 2. Architecture

- **Modules.** `gov` (governance vocabulary), `core` (domain classes and relations), `measure` (method-independent estimates and scales), `crg` (the CRG v1.0c model). A different risk method can be added as a sibling of `crg` without touching `core`.
- **Imports.** BFO-2020 core unmodified; a ROBOT BOT extract of CCO 2.2 (82 classes) from a seed list in `imports/cco-seeds.txt`. CCO is used for information content entities, artifacts, facilities, agents, plans, objectives, algorithms, measurements, vulnerability and *is about*.
- **Layers.** TBox in `ontology/`; SKOS value sets for controlled lists (each list is also an OWL class whose members are individuals, so they can be used as object-property values); ABox only in tests until Phase 3.
- **IRIs.** Opaque `CRGO_nnnnnnn` identifiers, minted once and kept in `src/ids.tsv`; names live in labels. Version IRIs follow `https://w3id.org/crgo/0.1.0/<module>`.
- **Generated Turtle.** All terms are specified in `src/spec_core.py` and `src/spec_props.py`; `src/build.py` writes the modules and adds the governance annotations, so no term can be missing them.

## 3. Modelling decisions

### 3.1 Risk scenario as a description
A risk scenario is a reified n-ary descriptive information content entity, not a process: it describes something that might happen. Its parts (threat source, threat event, weakness, consequence) are also descriptions, because library scenarios have no organisation and nothing real to point to. When an assessment does identify real entities, the scenario can additionally point to them (`affectsAsset`, `initiatedBy`, `exploits`). `LibraryScenario` and `AssessmentScenario` are the two uses. The negative fixture `neg-scenario-is-process` checks that a scenario cannot also be a process.

### 3.2 Vulnerabilities and BFO bearers (HermiT finding)
The first positive fixture was inconsistent: a vulnerability (a BFO disposition) was said to inhere in a software asset, but in BFO-2020 dispositions inhere only in material entities, and software is a generically dependent continuant. Rather than weaken BFO, CRGO:
- restricts `Vulnerability` (⊑ CCO Vulnerability) to material bearers: devices, installed copies, facilities, people, organisations;
- adds `weaknessOf`, a relation with no domain or range, as the documented shortcut for "inheres in" when the asset is software or information;
- uses `VulnerabilityDescription` for weaknesses as reported (CVE text, audit finding) and `ControlGap` for missing controls.

### 3.3 Assets
`Asset` is rigid (Q3) with an intrinsic definition (the kinds of entity that process, store, transmit or protect information or deliver services). Subclasses sit under the BFO/CCO category they belong to, which makes category mistakes detectable (`neg-information-is-hardware`):

| Class | Parent |
|---|---|
| InformationAsset | CCO information content entity |
| SoftwareAsset | CCO prescriptive ICE (code directs computation) |
| HardwareAsset, ConnectedDevice, NetworkAsset | CCO material artifact |
| FacilityAsset | CCO facility |
| ServiceAsset | BFO realizable entity: the provider's capability to deliver the service |

Primary/supporting tier and criticality are anti-rigid, so they are values on `AssetValuation` (`hasAssetTier`), not subclasses. `BusinessProcess` is not an asset. Threat source is a role (`ThreatSourceRole`), never a class of agent (`neg-role-is-asset-object`).

### 3.4 Controls
`Control` (fr *mesure de sécurité*) is the prescription — what should be done, as in ISO/IEC 27002 or CRG's control catalogue. `ControlMeasure` (fr *mesure de sécurité appliquée*) is the record of that control in a given organisation, with its status, owner and evidence. `ControlEffectiveness` is an estimate about a control measure. Framework requirements are prescriptive ICEs grouped by `Framework`; crosswalks to the SKOS framework vocabularies use `mapsToRequirement` (no domain or range) and `hasExternalReference`.

### 3.5 Quantities
CCO's value properties (*has decimal value* etc.) have the domain *information bearing entity*, so using them on an estimate would make the estimate a bearer. CRGO defines its own `numericValue` (no domain, functional data property). Estimates are measurement ICEs; the generic layer (`Likelihood`, `ImpactEstimate`, `RiskLevel`, `ControlEffectiveness`) is method-independent, and the CRG parameters and KRI quantities are subclasses of it. Each value records its scale, method, rationale, evidence and confidence, mirroring CRG's `{v, qual, rat, ev, conf}`.

### 3.6 Profile
OWL 2 DL, kept in OWL 2 EL where possible: no inverse properties, no functional object properties (cardinalities move to SHACL in Phase 4). Known EL exception: the `xsd:boolean` range of *is crown jewel*.

### 3.7 Governance annotations
Local annotation properties (`governanceStatus`, `confidence`, `confidenceRationale`, `evidenceSource` ⊑ `dcterms:source`, `derivedFrom`, `proposedBy`, `approvedBy`, `approvalDate`, `introducedIn`, `reviewNote`). PROV-O was not used directly because its properties are object properties; using them as annotations would pun and break OWL 2 DL. A PROV mapping can be published separately. Status changes to `approved` only with the project owner's explicit approval, recorded with `approvedBy` and `approvalDate`.

## 4. Independent review — what changed

An independent modelling review of the first draft found 6 High, 11 Medium and 17 Low issues.

| Item | Resolution |
|---|---|
| H1 Scenario parts pointed to individuals | Added `ThreatSourceDescription`, `VulnerabilityDescription`, `AssetCategory`, `hasThreatSourceDescription`, `hasVulnerabilityDescription`, `affectsAssetCategory` |
| H2 ControlGap as a disposition | `ControlGap` is now a descriptive ICE with `missingControl`; `PredisposingCondition` stays a disposition, for conditions borne by the organisation or site |
| H3 ServiceAsset as a process | Now a realizable entity (provider capability) |
| H4 Asset defined relationally | Intrinsic definition; value moved to `AssetValuation` |
| H5 No control effectiveness | Added `ControlEffectiveness` |
| H6 Vulnerability definition | Restricted to material bearers (see 3.2) |
| M1 EnvironmentalHazard | Removed; environmental sources are a `ThreatSourceType` value on a description |
| M2 SoftwareAsset under bare GDC | Moved under CCO prescriptive ICE |
| M3 No generic likelihood/impact/risk layer | Added in `measure` |
| M4 Primary/supporting assets | `AssetTier` value set and `hasAssetTier` |
| M5 Framework mapping | Added `Framework`, `partOfFramework`, `hasExternalReference`; `mapsToRequirement` has no domain or range |
| M6 Description classes labelled as things | Relabelled "… description" |
| M8 Names colliding with BFO relations | `dependsOn` → "relies on asset", `locatedIn` → "housed in", `hasDisposition` → "has selection disposition" |
| M9 CRG key coverage (part) | Added `background`, `treatmentSummary`, `caseAppetite`, `PreTreatmentRatio` |
| M10 Hard-coded 12-month horizon | Now "the horizon of the assessment" |
| M11 French terminology | *prévue*, *obsolète*, ISO 27005 treatment terms, *maintien*, *réduction du risque obtenue* |
| L1–L5, L9, L11, L14, L16 | Applied (appétit pour le risque, mesure de sécurité, French state labels, process wording, threat presence definition, `monitors` range open, non-negative risk scale, evidence register entry) |
| L8 | Relabelled "scenario criticality μ(E)", defined as strategic importance |
| L10 | Cost-effectiveness states that the cost basis is given with the value |

## 5. Deferred items

| Item | Deferred to | Note |
|---|---|---|
| M7 `ControlMeasure` vs `mitigatedBy` semantics | 0.2.0 | A record does not itself reduce likelihood; consider "recorded as mitigated by" |
| M9 rest: CRG consequence-dimension keys, evidence-basis strings, `SOURCE`, `SENS_IDS`, totals, explicit central case, [0.05, 0.99] clamp | done in Phase 3 | See `docs/crg-mapping.md`; totals and allocations are not converted (derivable) |
| ATT&CK technique link, CVE/CWE identifiers | ATT&CK done in Phase 3; CVE/CWE later | ATT&CK concepts are linked with `hasExternalReference`; no CVE/CWE vocabulary yet |
| L6 `NormativeRequirement` parent for frameworks and laws | 0.2.0 | `LegalObligation` currently sits directly under prescriptive ICE |
| L7 `LegacyKRIQuantity` | 0.2.0 review | Not used: Phase 3 keeps the 2023 notebook KRIs only as legacy columns in `data/library/rows.csv`, so the class can be deprecated |
| L12 Defect notes inside `MethodNotebook2023` definition | Phase 5 | Move to `reviewNote` |
| L13 Type for the drafting agent | 0.2.0 | Candidate: `prov:SoftwareAgent`, outside the DL core |
| L15 Owners as positions | Phase 4 | SHACL or a role-based pattern |
| L17 Incident → scenario link, threat-source characteristics (SP 800-30 D-3 to D-5), risk register | Phase 5 extension plan | |
| DOLCE alignment module | Phase 5 | Optional (Q-A) |
| w3id.org redirect registration | release | After approval |

## 6. Phase 3 — instance data and vocabularies (0.2.0 draft)

### 6.1 Scenario library (decision Q-E, option 3)
`pipeline/library/repair.py` rebuilds the 2,158 rows of the 2023 generator; `REPAIR_REPORT.md` has the counts.

- Values are re-read from the raw LLM answer. Where the answer states nothing, the field stays empty; the notebook's block-mean fill is kept only as a legacy column. Where the spreadsheet held a different round value, the answer's value is used and the row is flagged "conflict".
- 13 rows with no answer are dropped; 2,145 remain.
- Risk is recomputed with CRG v1.0c (appetite 0.30, factor 1,000) only when all eight parameters and a CVSS score are stated: 1,162 rows. The 2023 CVSS values are LLM estimates of v3.1 scores, recorded as such.
- Duplicates are merged into 1,811 families (same theme, Jaccard ≥ 0.8 on name tokens). Family values are medians of the members, with minimum, maximum and count.
- Each row gets one of 23 scenario themes, from the scenario name when it matches and otherwise from the source category (`category_map.tsv`). The 225 categories survive as `category_raw`.
- Threat source types, asset categories and impact dimensions are keyword extractions: low confidence, for review.
- "Montreal Regional Hospital" is replaced by "the organisation" in every text field; the sector is recorded as `applicableSector` "healthcare".
- All library numbers carry confidence *low* and evidence basis *AI estimate requiring validation*.

Two independent spot checks read the raw answers by hand:

| Check | Sample | Numeric fields correct | Main findings, now fixed |
|---|---|---|---|
| 1 | 60 rows (seed 42) | 569 / 600 (94.8%) | values beyond a short window missed; "0 to 1" scale bounds and examples read as values |
| 2 | 70 rows (seed 7), after fixes for check 1 | 680 / 700 (97.1%) | repeated cost mentions summed (doubled costs); "51% attack" read as a value |

After the fixes for check 2, the 70 rows of that sample give 698 / 700 (one value from a secondary "final assessment" block, one garbled CVSS line). That figure is no longer independent, since the sample guided the fixes. Theme fit was 83–85% and threat-source plausibility 86–88% in the two checks; both are improved but not re-measured.

### 6.2 Vocabularies
One SKOS scheme per framework in `ontology/vocab/`, built by `pipeline/vocab/build_vocab.py` from machine-readable or verified sources (`data/frameworks/` keeps each row's sources). Concepts carry `skos:notation` (the official identifier), labels, broader links, a source and status *proposed*. Withdrawn NIST items are kept as deprecated concepts so that old mappings resolve.

| Scheme | Source | Concepts |
|---|---|---|
| theme | CRGO | 23 |
| csf2 | NIST OSCAL catalogue (usnistgov/oscal-content, pinned commit) | 225 |
| sp800-53r5 | NIST OSCAL catalogue, Rev. 5.2.0 | 1,216 |
| iso27002-2022 | ISO table of contents, cross-checked with four public mappings; English titles only (no official French list found) | 97 |
| cobit2019 | ISACA COBIT 2019 introduction, SFIA mapping | 45 |
| loi25 | LégisQuébec, section by section; en and fr | 30 |
| ccm41 | AWS v4.1 guide and ISMS Core; domains only | 17 |
| attack | MITRE attack-stix-data, Enterprise 19.2 | 712 |

Scenario themes link through the existing `hasScenarioCategory`; framework concepts through `hasExternalReference` and `mapsToRequirement`.

### 6.3 CRG bridge
`pipeline/crg/crg2rdf.py` converts a CRG assessment file to CRGO and computes every risk number with CRG's own `crg_calc.py`. On the MediBec case it reproduces CRG's regression totals (84,491 estimated, 41,104 residual) and all 20 stored sensitivity cases; the result is consistent under HermiT. Field mapping and lossy fields: `docs/crg-mapping.md`.

### 6.4 Ontology changes in 0.2.0 (approved 2026-10-10)
- New: `applicableSector`, `suggestedMitigation` (core); `lowerBound`, `upperBound`, `sampleSize` (measure); evidence basis value *exercise or simulation evidence* (`EvExercise`), so that CRG's "Exercise evidence (validate)" is not mistaken for documented evidence.
- Reworded: `hasThreatSourceType` no longer mentions the removed EnvironmentalHazard class; returned to *proposed* for re-approval.
- Terms record the release that introduced them (`introducedIn` 0.1.0 or 0.2.0).

## 7. Decisions taken at the Phase 3 checkpoint (2026-10-09)

| # | Question | Decision | Effect |
|---|---|---|---|
| D1 | CIS Controls v8.1 (CC BY-NC-ND 4.0) | Leave out | No CIS vocabulary. The verified list is not kept in the repository. |
| D2 | CSA CCM v4.1 controls (redistribution not allowed) | Load into a private file | `pipeline/vocab/build_ccm_private.py` reads the project owner's licensed CCM bundle from `data/private/` and writes `ontology/vocab-private/ccm41-controls.ttl`. Both folders are git-ignored. The public `ccm41.ttl` keeps the 17 domains. |
| D3 | ISO/IEC 27002:2022 identifiers and titles in the public repository | Yes | `ontology/vocab/iso27002-2022.ttl` is published with the notice in `NOTICE.md`. |
| D4 | COBIT 2019 or COBIT 7 | Stay with COBIT 2019 | `cobit2019.ttl` stays as is; the scope note about COBIT 7 is kept for information. |

**Approval of 0.2.0 (2026-10-10).** The project owner approved the 7 new or changed terms and the 23 scenario themes, with no changes requested to the category map or the library families. Framework concepts stay *proposed*: they reproduce external catalogues and are approved with their source rather than term by term.

## 8. Requirements carried forward

**R1 — Support threat, vulnerability and risk identification in CyberRiskGuardian (2026-10-10).** One of the ontology's main uses is to help CyberRiskGuardian, itself built on Claude, identify threats, vulnerabilities and risk scenarios for an organisation. Consequences for the next phases:
- Phase 4 competency questions and SPARQL tests start from identification questions, for example: given an asset category, sector or theme, which threat events, threat source types, weaknesses and library scenarios apply; which ATT&CK techniques and controls (CSF, SP 800-53, ISO/IEC 27002) relate to them; which Loi 25 obligations a scenario can trigger.
- The links that identification needs are mostly text today: library scenarios have threat-event and weakness descriptions but no ATT&CK, control or obligation links. A mapping step (scenario family → ATT&CK technique, family → control requirement), with confidence and review status on each link, is the main gap to close.
- CyberRiskGuardian consumes JSON. Identification results need a compact JSON export (and a query interface, for example a SPARQL endpoint or an MCP tool) that returns candidates with their provenance and confidence, so that Claude cites sources and keeps "AI estimate — validation required" labels.
- Library values are priors for a fictitious healthcare organisation; identification output must say so and never present them as organisational evidence (CRG evidence discipline).

## 9. Scenario library with framework links and case estimates (0.3.0, approved 2026-10-10)

Requested by the project owner: build the 1,811 scenarios into the ontology as actual risks, with links to the frameworks, and use other sources for estimates, starting with the teaching cases in Drive.

### 9.1 Framework links
- Every family was judged by Claude against the complete list of valid identifiers (method and rules: `pipeline/links/README.md`): 19,709 links. ATT&CK techniques attach to the family's threat event description (`hasExternalReference`); CSF 2.0, SP 800-53 and ISO/IEC 27002 to the scenario (`hasRelevantRequirement`, new); Loi 25 obligations through `triggersObligation`.
- Each link is an assertion annotated with its confidence, `proposedBy` Claude and status *proposed* (OWL 2 axiom annotations), so a consumer can filter by confidence.
- Coverage: every family has CSF, SP 800-53 and ISO links; 1,111 have ATT&CK techniques (the others are control gaps, accidents or environmental events); 762 have Loi 25 obligations.
- P-39.1 s. 10 (security measures) was added to the Loi 25 vocabulary after the review pointed out its absence, and linked by rule to every family that involves personal information (marked as rule-based on each link).
- Independent check (50 random families, 510 links): 83% correct, 99% at least defensible, 4 wrong (all low confidence). High-confidence links: 97% correct, none wrong. Main weakness: omissions, especially ATT&CK steps described in the event sequence. Use: accept high links with light review, review medium, treat low as suggestions.
- A bug in the first reference list (ISO identifiers such as 5.10 read as numbers and shown as "5.1") made 228 ISO choices ambiguous; those were judged again with the corrected list.
- ATT&CK 19.2 revoked several well-known identifiers (for example T1562 Impair Defenses → T1685, T1656 Impersonation → T1684.001). The vocabulary keeps the 161 revoked or deprecated techniques as deprecated concepts with `dcterms:isReplacedBy` where MITRE gives a replacement, so older tools still resolve.
- During judgement, each family's threat source types were also re-assessed and replace the keyword guesses; where the judge proposed a different theme, it is added as a second theme (medium confidence) and the approved theme is kept.

### 9.2 Case-based estimates
- Source: the fictional teaching cases in Drive (CanaRetail, ACRB, MediBec, Chez Pierre: instructor annex values; Maple Rotisserie and CNIC have no scenario values) and the worked CyberRiskGuardian assessment of MediBec (30 scenarios). Extraction with verbatim quotes and locations: `data/library/case_scenarios.json`.
- The 67 case scenarios become library scenarios of their own (sector from the case), each `refines` the families it matches (333 matches, graded high or medium; one case scenario, DLL hijacking, has no family).
- 273 matched families receive a second, case-calibrated set of estimates (median of the matching case values, with count and range), confidence *medium* when based on high-grade matches, else *low*; the 2023 LLM values stay alongside, confidence *low*.
- Case CVSS scores are recomputed from the vectors: the scores stated in the cases did not match their vectors in any of the 30 checked. ACRB gives no criticality value, so its risk cannot be computed.
- Evidence basis is *external evidence* with the note "calibration aids, not organisational evidence", following CyberRiskGuardian's evidence rules.

### 9.3 Packaging
- `ontology/crgo-full.ttl` imports the core modules, the scenario library and the vocabularies; it is in OWL 2 DL and consistent under HermiT.
- `queries/identify-by-asset-category.rq` is a first identification query (asset category → scenarios → ATT&CK techniques, controls and obligations, with confidence). In rdflib it takes minutes over the full graph; a triple store is needed for interactive use by CyberRiskGuardian (Phase 4).
- New term, proposed: `hasRelevantRequirement`.

**Approval of 0.3.0 (2026-10-10).** The project owner approved `hasRelevantRequirement` and approved the framework links by group: all high- and medium-confidence links (17,967) now carry status *approved*, `approvedBy` Marc-André Léger and `approvalDate` 2026-10-10 on their axiom annotation. The 1,742 low-confidence links remain *proposed* and should be read as suggestions. Second themes and case-scenario matches were not part of the link groups and stay *proposed*.

## 10. Phase 4 — validation and identification (0.4.0 draft, 2026-10-10)

### 10.1 What was built
- **Query store.** `pipeline/query/store.py` loads the repository files into an embedded Oxigraph store with subclass and subproperty closure (about 8 s). The first identification query fell from about 7 minutes (rdflib) to 0.25 s.
- **Competency questions.** 20 questions in `tests/cq/` (14 identification, 2 estimation, 2 assessment, 2 governance or quality), each a SPARQL query with an expected result. All pass. Answers: `build/cq-report.md`.
- **SHACL shapes.** `shapes/crgo-shapes.ttl` (generated by `src/build_shapes.py`, 48 node shapes): the 21 functional object properties deferred from Phase 2, value ranges (unit interval, resilience in (0, 1], CVSS 0–10, non-negative risk), one numeric value per estimate, provenance of computed quantities, required labels, themes and links on library scenarios, and governance on every link annotation (approved links need approver and date). All data conforms; 8 negative tests each violate as expected.
- **Pitfall scan.** The OOPS! service is not reachable from the build environment, so 18 mechanically checkable OOPS! pitfalls were implemented locally (`scripts/check_pitfalls.py`). No critical pitfall. For review: 13 sibling-class groups without disjointness, 30 properties with open domain or range (by design).
- **Identification interface (requirement R1).** `pipeline/query/identify.py` (sweep, identify, scenario, controls for a technique, scenarios for a control), an MCP server for CyberRiskGuardian (`pipeline/mcp/crgo_server.py`, works with mcp 1.x and 2.x) and a JSON export of all 1,878 scenarios. Guide: `docs/crg-integration.md`.
- **Fixes found on the way.** Family identifiers are now frozen in `data/library/family_ids.tsv` (they could shift on a rerun); 516 library scenarios whose names state a weakness now carry a vulnerability description (rule-based, proposed); the one case scenario with no matching family (MediBec DLL hijacking) is linked directly; case scenarios carry a theme; the TBox test fixture now carries the values and labels the shapes require.

### 10.2 Blind identification test (MediBec)
An agent playing CyberRiskGuardian read only the MediBec profile, used the interface with MediBec held out, and its candidate list was compared with the 30 scenarios of the expert assessment.

| Run | Interface | Recall | Notes |
|---|---|---|---|
| 1 | first version | 0.53 | Not blind: library estimates calibrated on the MediBec expert assessment influenced the ranking; holdout added |
| 2 | holdout, sweep, synonyms | 0.52 | First truly blind run for the library; exposed a holdout leak through assessment scenarios and a diluted sweep |
| 3 | leak fixed, focused sweep, commonly assessed risks | 0.62 | Not independent: synonyms and the list of commonly assessed risks were written after seeing MediBec's misses |

The fair figure is about 0.5 for a first pass; a new case must be used for the next measurement. Misses fall into three groups: scenarios the library holds but the interface did not surface; scenarios surfaced but not chosen among near-duplicates; and three risks the library lacks (cloud tenant takeover through token theft or app consent, staff pasting data into generative-AI tools, HL7/DICOM interception). Two bugs found by run 3 (a keyword replaced by its synonym group; loose matches for commonly assessed risks) were fixed afterwards.

### 10.3 Decisions of the project owner (2026-10-10)

| Proposal | Decision | Result |
|---|---|---|
| 20 competency questions as the test suite | Approved | `tests/cq/`, run by `scripts/check.sh` |
| 18 commonly assessed risks and the synonym list | Approved | `pipeline/query/identify.py` (BASELINE, SYNONYMS) |
| Three missing library scenarios | Approved | F1812 cloud tenant takeover through token theft or app consent; F1813 disclosure through staff use of generative-AI tools; F1814 interception or tampering of HL7/DICOM clinical messages. Written by Claude, links proposed, no estimates yet |
| Disjointness | Approved | Value-set classes pairwise disjoint (stated in each module for the value sets it sees); LibraryScenario disjoint from AssessmentScenario. Two negative fixtures check them |
| Québec health-information act | Approved | Vocabulary `lrsss` (54 obligations of CQLR c. R-22.1 and its regulations r. 1 and r. 2, verified on LégisQuébec; scope in `data/frameworks/lrsss_scope.md`). It applies to private professional offices and specialised medical centres (s. 4, Schedule II) and, for the health information they hold, replaces the private-sector Act (P-39.1 s. 3, para. 3). 2,292 rule-based links give the R-22.1 equivalent of each Loi 25 obligation on the 517 library scenarios that concern health information; they stay proposed |
| Fill missing Loi 25 links | Clarification requested | About 176 scenarios reach personal information without the privacy impact tag, so they carry no Loi 25 obligation; re-judging them for Loi 25 only is pending a decision |
| Measure recall on another case | Done | ACRB (regional bank, not used in any tuning): recall 0.76 on 19 expected risks (12 covered, 5 partly, 2 missed), see 10.4 |

### 10.4 Independent identification test (ACRB)
Run blind with `holdout=["ACRB"]` on a case that played no part in tuning. Reference: the case author's 15 library scenarios, 10 annex scenarios and the 2022 incident, merged into 19 distinct risks. Recall 0.76: 12 covered, 5 partly, 2 missed. Of the 7 imperfect items, 3 are in the library but were not surfaced, 3 were surfaced but not chosen, and 2 are absent (ATM malware; certificate expiry). Observations for the next round, not applied so as to keep ACRB usable as a clean benchmark: no banking and payment vocabulary in the synonyms; a whole-profile sweep matches most of the library, so two-concept risks (vendor + remote access, insider + fraud, API + enumeration) need targeted queries; healthcare wording in the generic library adds noise for other sectors. Report: `docs/identification-eval-acrb.md`.

## 11. Phase 5 — documentation and release preparation (0.5.0, approved 2026-10-10)

- **Documentation.** WIDOCO 1.4.25 generates a bilingual site from the four modules (imports removed; the 20 BFO and CCO terms referenced keep their labels and definitions so that the pages are readable). The generated Introduction and References are replaced by hand-written sections (`docs/site-src/`). Published by GitHub Pages from `/docs` on main.
- **Identifiers.** `w3id/crgo/.htaccess` serves the documentation to browsers and Turtle to RDF clients (303 redirects). Version IRIs resolve to the files at the release tag, so the tags must exist on GitHub. Vocabulary concepts and library individuals resolve to the file that defines them, not to a page per concept.
- **Metadata.** Every module carries FAIR header metadata; the AI drafting assistant is named as a contributor, with the statement that every element was approved by the creator.
- **No logical change to the TBox.** 0.5.0 adds or removes no class, property or logical axiom. One definition changed (L12, below).
- **Check script.** ROBOT now runs with a 6 GB Java heap by default (`ROBOT_JAVA_ARGS` overrides it); HermiT ran out of memory on crgo-full with the JVM default.
- **Next steps.** `docs/roadmap.md`.

**Decisions of the project owner (2026-10-10).** 0.5.0 approved for publication under that number; 1.0.0 waits until the w3id.org identifiers resolve. L12 approved: the defect notes of "2023 scenario-generator notebook v2-1b" moved from its definition to its review note, and the term was re-approved. The about 176 scenarios that reach personal information without a privacy impact tag are to be judged against Loi 25 (next draft, links proposed until reviewed). The owner enables GitHub Pages, creates the tags and submits the w3id.org request, with step-by-step guidance.

## 12. Loi 25 pass 2 (0.6.0 draft, 2026-10-10)

Decided by the project owner at the Phase 5 checkpoint. Population: the 176 families tagged `DimPrivacy` with no judged Loi 25 obligation (only s. 10 by rule). An earlier description of them as "without the privacy impact tag" was wrong; the spot-check (`docs/links-spotcheck.md`) defines them as above.

- **Method.** Same as 0.3.0 (Claude judges each family against the full list of Loi 25 obligations, with confidence H/M/L), Loi 25 only, s. 10 excluded (already present), penalty provisions and the s. 3.6 definition excluded as links.
- **Three iterations, measured honestly.** Version 1 applied the notification trio by template and never cited s. 3.5 (1st para.), which 0.3.0 used in 22% of judged families; an independent review of 40 families found 42 omissions. Version 2 added the post-incident duty but, with three slots, dropped notification entirely. Version 3 allows four links, grades the incident obligations together and asks for notification where serious injury is plausible. A different reviewer graded 40 families not used in the first review: 133 links, 77 correct, 54 defensible, 2 wrong (both low confidence); high 24/1/0, medium 37/7/0; 5 omissions; 7 confidence grades questioned. Version 3 is kept.
- **Exception to the three-link limit.** Pass 2 allows four Loi 25 links per family (the 0.3.0 limit was three); the 0.3.0 links are unchanged, so their families can lack s. 3.5 (1st para.) where the limit squeezed it out.
- **Governance.** All 558 links are *proposed*, in their own group `links/loi25-pass2/<confidence>`, so the 0.3.0 approvals of `links/loi25/H` and `links/loi25/M` do not extend to them.
- **Reviewer caveat.** Most library scenarios are set in a hospital; in Québec a public hospital falls under the public-sector access act (CQLR c. A-2.1), not P-39.1. The library uses P-39.1 because the generator's organisation is treated as a private health body (and R-22.1 for health information); a public-sector deployment needs A-2.1 (roadmap).

**Decision of the project owner (2026-10-10).** Pass 2 links approved by group: high (77) and medium (234) approved; low (247) stay proposed, as in 0.3.0. The 497 R-22.1 rule equivalents stay proposed with the other R-22.1 links.

## 13. Public sources (0.7.0 draft, 2026-10-11)

Requested by the project owner: grow and improve the ontology with internet sources (crosswalks, D3FEND, CWE and CAPEC, exploitation data; incident data and legal frameworks follow in 0.8.0).

### 13.1 What could be reached
GitHub-hosted sources could be downloaded: MITRE CTID Mappings Explorer, D3FEND, MITRE CTI (CAPEC), CISA KEV (mirror), VERIS. Blocked from the build environment: cwe.mitre.org, capec.mitre.org, d3fend.mitre.org, FIRST EPSS, NIST csrc (OLIR crosswalks CSF↔800-53↔ISO). CWE was taken from D3FEND, which carries 943 CWE weaknesses with their hierarchy; CAPEC from the STIX bundle. EPSS and the NIST crosswalks need a file from the project owner.

### 13.2 Modelling
- New vocabularies are SKOS schemes like the others; vocabulary-to-vocabulary references are `skos:relatedMatch` assertions in `mappings.ttl`, annotated (OWL 2 axiom annotations) with source, confidence, comment (the relation, for example "technique mitigated by control") and status, grouped for approval as `mappings/<source>`.
- Scenario CWE links are `hasExternalReference` from the scenario's vulnerability description; 108 scenarios without one received a description node labelled "Weakness exploited in: …".
- D3FEND is used as a vocabulary of countermeasures linked to ATT&CK techniques, not to scenarios directly; the identification interface derives a scenario's countermeasures through its techniques. D3FEND's own OWL classes are not imported: its upper structure differs from BFO/CCO (an official D3FEND–CCO alignment exists, `mappings/d3fend-cco.ttl` in the D3FEND repository, for a later alignment module).
- KEV vulnerabilities are evidence of exploitation for techniques and weaknesses, never an inventory of an organisation's vulnerabilities.
- New annotation property `corroborated by` (proposed) records an independent source supporting a link.

### 13.3 Measurements
- CTID corroboration of the existing SP 800-53 links (within CTID's control families AC, CA, CM, SC, SI, CP, IA, SA, RA, MP, SR; 594 links in other families cannot be checked): high 83%, medium 74%, low 54%. The gradient supports the 0.3.0 confidence grades.
- CTID-based proposals (independent review, 40): medium 6 useful, 1 redundant, 0 wrong of 7; low 16 useful, 10 redundant, 7 wrong of 33. Recommendation: approve medium, keep low as suggestions.
- CWE pass (independent review of 40 scenarios, 59 links, batches 1–5): high 11 correct, 1 defensible; medium 18, 13, 2 wrong; low 2, 10, 2 wrong; all 10 "no weakness" judgements right. Two rules applied afterwards: CWE-1104 replaced by CWE-1395 unless end-of-life is stated; CWE-311/312 lowered from high to medium where encryption is not mentioned. A second CWE batch (162 scenarios outside the first scope that name a weakness) was added after a competency question exposed the gap; it was spot-checked, not sampled.
- D3FEND: artifact-based inference rejected twice (see changelog); judged links: 28 correct, 16 weak, 1 wrong on 45 (high 9/10 correct). Main weakness: threshold and reputation defences paired with techniques built to evade them.

**Decision of the project owner (2026-10-11).** All groups decided as recommended: `corroborated by` approved; CWE, D3FEND, CAPEC and KEV vocabularies approved as whole vocabularies (`<scheme>/*`); CAPEC, CTID and KEV cross-references approved; judged ATT&CK→D3FEND, scenario→CWE and CTID-proposed SP 800-53 links approved for high and medium confidence, low stays proposed; CQ21–CQ23 added to the test suite.

## 14. Calibration, sectors and legal regimes (0.8.0 draft, 2026-10-11)

### 14.1 Evidence for calibration
- **EPSS** (file retrieved by CyberRiskGuardian, scores of 2026-10-04): kept only for the KEV vulnerabilities, as `Likelihood` estimates of each KEV concept with a FIRST evidence item. KEV vulnerabilities are exploited by definition, so their EPSS is high (median 0.49 against 0.007 for all 382,621 scored vulnerabilities); the interface says it is evidence of exploitation in the wild, not a value for CRG's probability of exploitation.
- **VCDB** (CC BY-SA 4.0): only derived counts are stored, with attribution, so CRGO's CC BY-NC licence is not affected by share-alike terms. Shares are computed per sector (NAICS two-digit groups) for confirmed incidents of 2015–2025, with rules from VERIS fields to CRGO themes and threat-source types (`pipeline/external/vcdb.py`). Mass campaigns are counted once per sector (VCDB campaign identifiers, and five named supply-chain compromises), after the MOVEit breach was found to make up 613 of 842 education records. VCDB comes from public reports and over-represents disclosed breaches and sectors with mandatory reporting.
- No library estimate was changed: the new evidence sits beside the 2023 values for an analyst (or CyberRiskGuardian) to use.

### 14.2 Legal regimes
- A-2.1 and PIPEDA provisions were verified on the official consolidated texts (LégisQuébec, current to 2026-08-12; Justice Laws, current to 2026-05-26); OSFI B-13 from OSFI's page. Labels and definitions are CRGO paraphrases.
- Regimes are connected through correspondences, not by duplicating scenario links: a scenario's Loi 25 obligations give its A-2.1 obligations (`skos:closeMatch`, same obligation) and its PIPEDA provisions (`skos:relatedMatch`, comparable); its CSF links give the B-13 principles (`skos:relatedMatch` from principle to CSF category). Which regime applies depends on the organisation, and the interface says so.
- Independent review: Loi 25 ↔ A-2.1 15/15 correct; Loi 25 ↔ PIPEDA 7 correct, 3 partial (fixed: risk factors are in s. 10.1(8); express consent in Sch. 1, 4.3.6; disposal clause 4.7.5 is not the destruction duty); B-13 ↔ CSF 21 correct, 11 partial, 0 wrong (missing categories added: GV.OV, GV.SC, RS.CO, RS.AN, PR.AT, ID.RA for change management; DE.CM removed from service monitoring).

### 14.3 NIST crosswalks
- NIST publishes the SP 800-53 mapping for CSF 1.1, not 2.0; the CSF 2.0 export records where each withdrawn 1.1 subcategory went ("Incorporated into …", "Moved to …"). Chaining the two gives a derived CSF 2.0 → SP 800-53 mapping (confidence medium). The OLIR mapping of SP 800-53 to ISO/IEC 27001:2022 is used for its Annex A references, which are the ISO/IEC 27002 controls (confidence high).
- Corroboration of CSF and ISO links uses the scenario's own SP 800-53 links as the bridge, so it measures consistency across frameworks rather than independent correctness, unlike the CTID check of 0.7.0.

### 14.4 Other sectors
- Three generic scenarios written from the ACRB findings (F1815–F1817), reviewed independently (20 correct, 11 defensible, 1 wrong link; the ATM scenario narrowed to jackpotting, missing controls added).
- Banking synonyms, a small ranking penalty for healthcare wording when the profile has no health term, and four proposed commonly assessed risks. These changes were derived from the ACRB evaluation, so ACRB can no longer measure them; the next recall measurement needs a new case from another sector.

**Decision of the project owner (2026-10-11).** 0.8.0 approved in full: the three vocabularies, all cross-references, the CSF French labels, the EPSS and VCDB evidence, the written scenarios AUTH-001 to AUTH-006 with their links (each through its own group `links/authored/<key>`), the four added commonly assessed risks, the banking synonyms and ranking change, and CQ24–CQ26. GDPR is left open: the text supplied is the UK GDPR.

## 15. EU General Data Protection Regulation (0.9.0 draft, 2026-10-11)

- **Text.** The project owner supplied the Official Journal PDF of Regulation (EU) 2016/679 (OJ L 119, 4.5.2016; CELEX 32016R0679) after the 0.8.0 review found that the earlier file was the UK GDPR. The UK GDPR is not modelled; it is a separate regime that would get its own vocabulary if needed. The 2018 corrigendum was not reviewed.
- **Scope.** 40 provisions chosen for cybersecurity risk assessment and for parity with the Loi 25 vocabulary: what makes the Regulation apply to an organisation outside the EU (Art. 3(2)), the breach and pseudonymisation definitions, security and breach duties and their exemptions, accountability and governance, transfers, and the consequences (corrective powers, compensation, fines and the factors that set them). Notations are `GDPR Art. n(p)(x)`.
- **Correspondences.** As for PIPEDA, `skos:relatedMatch` from the Loi 25 obligation to the GDPR provision: the duties are comparable, not identical. An independent review (20 correct, 6 partial, 1 leaning wrong) led to these changes: the six partial correspondences (5(2)↔3.1, 9↔12, 22↔12.1, 24↔3.2, 35(1)↔3.3, 37(1)↔3.1) get confidence low with the reason stated; the 4% fine tier (Art. 83(5)) corresponds to Loi 25's administrative maximum (s. 90.12), not to its penal fines (s. 91), because both GDPR tiers are administrative; Art. 33(2) (processor notifies the controller) corresponds to s. 18.3; the definitions of Arts. 13, 17, 30, 83(4) and 83(5) were completed (exceptions, the 250-employee exemption, all infringements of the 4% tier); the scope label covers processors; and Arts. 4(5), 6(1), 33(3), 58(2) and 83(2) were added.
- **Differences an analyst should keep in mind.** Notification thresholds differ (GDPR: risk, 72 hours, and high risk for individuals; Loi 25: risk of serious injury, promptly). The GDPR impact assessment is triggered by high risk, the Loi 25 one by any information-system project. A data protection officer is required only in listed cases, whereas Loi 25 always has a person in charge.

## 16. v0.8 → v1.0 specification: Stage 0 decisions (2026-10-11)

The project owner supplied *CRGO v0.8 to v1.0 Claude Implementation Specification* (11 October 2026). Stage 0 produced `docs/baseline/` (inventory, source registry, gap analysis, Sprint 1 plan). **Decisions of the project owner (2026-10-11):**
- D1: the GDPR and Sprint 1 are released together as 0.9.0.
- D2: the four existing modules stay unchanged; new content goes into new modules.
- D3: each mapping meaning gets its own relation (sub-property of `skos:relatedMatch`), keeping the existing annotations; no reified record per link.
- D4: EPSS scores become dated observations; the approved 0.8.0 *likelihood* individuals are deprecated with a pointer to their replacement.
- D5: ISO/IEC 27002, COBIT and CCM short titles are kept, with attribution.
- D6: the project owner downloads the official PDFs of the Québec and federal texts and OSFI B-13; CRGO records their dates and checksums.
- D7: a new fictional test company is built; the teaching cases stay reserved for measuring identification recall.

## 17. Sprint 1 of the v0.8 → v1.0 specification (0.9.0, prepared 2026-10-11)

Built while the project owner was away ("Complete all the work now and proceed to get everything ready", 2026-10-11), within decisions D1–D7. Design records: `docs/adr/ADR-001` to `ADR-006`. Points decided by Claude in the owner's absence, for review:
- **Modules and names**: `crgo-evidence`, `crgo-org`, `crgo-vuln`, `crgo-grc`, `crgo-mapping`; control assessment placed in `crgo-grc` rather than a separate assurance module.
- **W3C imports as slices**: neither PROV-O nor OWL-Time is OWL 2 DL as published, so ROBOT BOT modules are imported (as for CCO). OWL-Time instants use `time:inXSDDateTimeStamp`, because HermiT rejects `xsd:date` literals.
- **Dates left unknown rather than guessed**: the Québec Acts' original in-force dates and OSFI B-13's effective date are not printed in the PDFs used, so no in-force interval is asserted for them; the GDPR interval (2016-05-24, applying from 2018-05-25) comes from its Art. 99.
- **Reading of organisation profiles** in the applicability evaluator (ADR-004): unlisted values count as absent only where the profile declares the property complete (*profile complete for*), recorded as an Assumption on every assessment.
- **Interpretive conditions** (5) can only yield *potentially applicable*.
- **Independent review (2026-10-11)** of the Sprint 1 work found 4 high, 8 medium and 5 low issues (missing data turned into *not applicable*; Loi 25 territorial test; PIPEDA rules for financial institutions, citations and commercial activity; jurisdiction of the federal order used as a place; satisfied determinations without evidence; untested exception; vacuous checks; counts). All were fixed before release, except the documented open points of ADR-004.
- **Proposed links**: library links whose approval group is unapproved move to `crgo-library-proposed.ttl`; links proposed without a group (second themes, case-to-family *refines*, rule-added weaknesses) stay in the library because identification depends on them; to be revisited.
- **Specification adaptations** listed in `docs/baseline/gap_analysis.md` section D (no thirteen-module split, no folder migration, no reified record per link, no single-scenario constraint on risk assessments, since a CRG assessment covers many scenarios).

**Decision of the project owner (2026-10-11, 14:28).** 0.9.0 approved: the five term groups (138 terms), the 29 source records, the 11 legal instruments, all 19 applicability conditions including the 5 interpretive ones (option a), ADR-001 to ADR-006, the Sprint 1 test assets; opening the w3id.org pull request and publishing the release approved.

## 18. GRCA specification and the remaining-gaps specification (2026-10-11)

The project owner supplied *CRGO GRCA Audit: Claude Implementation Specification* (v1.0) and *CRGO Knowledge Expansion: Remaining GRC, Cybersecurity and Operational Knowledge Domains, with a Formal Interface to the Separate CyberRiskGuardian DSS* (draft v1.0; called the remaining-gaps specification here: 20 domain packages and a CRGO–CyberRiskGuardian DSS contract). Phase 0 of the first: `docs/baseline/grca_phase0.md`. **Decisions of the project owner (2026-10-11, 15:10):**
- G1: the GRCA work is folded into 0.9.0 (no separate 0.10.0); the remaining-gaps work is also to be added to this version.
- G2: three new modules, `crgo-governance`, `crgo-audit` (with remediation) and `crgo-assurance`; compliance additions in `crgo-grc`.
- G3: the 0.9.0 control assessment is reused as the test execution, with who performed it (management, second line, internal audit, external assurer).
- G4: all 3,715 SP 800-53A assessment objectives are imported.
- G5: the project owner states that he is allowed to use the IIA, ISACA, ISO, COSO and AICPA texts and asked Claude to find them online.

## 19. Remaining-gaps scope, DSS contract, tenants and licensed texts (2026-10-11)

Phase 0 of the remaining-gaps specification: `docs/baseline/remaining_gaps_phase0.md`. **Decisions of the project owner (2026-10-11):**
- R-a: 0.9.0 = the GRCA sprint plus packages R1–R9 (DSS boundary, identifiers and graph layers, DSS contract, policy and exceptions, control effectiveness, decision and uncertainty records, regulatory change, minimal incidents, competency questions); D02–D04 and D11–D20 move to the next version.
- R-b: the DSS contract is JSON Schema documents exchanged through CRGO's MCP server, with two new tools, `crgo_risk_context` (read) and `crgo_submit_assessment` (write, stored as *proposed*); "the contract the document asks for should use what exists".
- R-c: one graph per organisation under its own IRI base (never `https://w3id.org/crgo/`); reference files never point to organisation IRIs; recorded in ADR-008 and enforced by a check ("apply R-c as described", 15:43).
- R-d: after G5, rather than Claude retrieving them online, the project owner supplied the licensed documents himself (IIA GIAS and Topical Requirements, ISACA ITAF, AICPA TSC, COSO ERM summary, ISO 19011, 27007, 27008, 37301, 37302 previews); they are used "as-is" but published as identifiers, short titles with attribution and CRGO's own paraphrases, as for ISO/IEC 27002; full texts may feed a private build only.

**Points decided by Claude while building, for review** (`docs/review-0.9.0-grca.md`):
- A fourth new module, `crgo-incident`, for package R8, which G2 did not foresee.
- Group approvals of 2026-10-11 (`terms/evidence`, `terms/grc`, `terms/mapping`, `sources/records`) are scoped to what existed then (`GROUP_SCOPE` in `src/build.py`; record list in `pipeline/vocab/build_legal.py`), so terms and records added to those groups afterwards stay proposed.
- Free-text data properties of the new modules have no datatype range, so that English and French values can carry language tags (a tagged literal against `xsd:string` made the sample inconsistent).
- Evidence quality, deficiency severity, finding significance and engagement rating use CRGO's own scales: the documents held name no common scale, and the PCAOB terms were not used because the standard was not available.
- None of the IIA documents held states an effective date; publication dates are recorded and flagged. COSO English titles are CRGO translations. Two ISO/IEC TS 27008 headings keep the source's typos. The COSO presentation file was rejected as a source (it shows the 2016 draft).
- SP 800-53A: two objectives of SI-2(7) have no label in the 5.2.0 catalogue and get derived identifiers; seven method labels repeat in the catalogue, so method notations are built from the 800-53 control label; organisation-defined parameters are shown as `[organization-defined: label]`.
- The specification's DSS example values `modelVersion: "TBD"` and `organizationId: "org-demo"` are not accepted by the contract (ADR-007).
- The MediBec teaching case keeps its `https://w3id.org/crgo/data/medibec/` IRIs (grandfathered in ADR-008).

**Answers of the project owner to the review points (2026-10-11, 18:04):**
- `crgo-incident` is kept as a separate module.
- The IIA effective dates are not available; the publication dates stay, flagged as such.
- COSO English titles as CRGO translations: accepted.
- CRGO's own scales for evidence quality, deficiency severity and finding significance: accepted.
- The alternative label "hypothesis" is removed from the approved term *assumption* (CRGO_0000339), so that it no longer competes with *analytical hypothesis*; the term is otherwise unchanged and stays approved.
- w3id.org: the open pull request #6862 is not merged (upstream `master` still carries only the original CRGO rules of #6858, checked by git fetch at 18:10); the extra commit stays local until the project owner decides.
