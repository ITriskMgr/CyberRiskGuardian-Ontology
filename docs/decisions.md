# Design decisions — CRGO 0.1.0 (Phase 2 draft)

This file records why the ontology looks the way it does. Every term is
`proposed`; a decision here is a design choice awaiting review, not an approval.

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
| M7 `ControlMeasure` vs `mitigatedBy` semantics | review | A record does not itself reduce likelihood; consider "recorded as mitigated by" |
| M9 rest: CRG consequence-dimension keys, evidence-basis strings, `SOURCE`, `SENS_IDS`, totals, explicit central case, [0.05, 0.99] clamp | Phase 3 | Handled in the CRG JSON-LD bridge and mapping table |
| ATT&CK technique link, CVE/CWE identifiers | Phase 3 | Arrive with the SKOS vocabularies |
| L6 `NormativeRequirement` parent for frameworks and laws | review | `LegalObligation` currently sits directly under prescriptive ICE |
| L7 `LegacyKRIQuantity` | Phase 3 | Keep only if the 2023 notebook values are loaded |
| L12 Defect notes inside `MethodNotebook2023` definition | Phase 5 | Move to `reviewNote` |
| L13 Type for the drafting agent | review | Candidate: `prov:SoftwareAgent`, outside the DL core |
| L15 Owners as positions | Phase 4 | SHACL or a role-based pattern |
| L17 Incident → scenario link, threat-source characteristics (SP 800-30 D-3 to D-5), risk register | Phase 5 extension plan | |
| DOLCE alignment module | Phase 5 | Optional (Q-A) |
| w3id.org redirect registration | release | After approval |
