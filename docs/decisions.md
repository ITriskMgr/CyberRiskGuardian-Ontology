# Design decisions — CRGO 0.2.0

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
