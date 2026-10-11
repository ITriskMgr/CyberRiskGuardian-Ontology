# CRGO baseline inventory (Stage 0)

Prepared 2026-10-11 for the implementation specification *CRGO v0.8 to v1.0* (Stage 0, §15 and §16 item 1).
All figures below were counted from the repository files at commit `381f7f5` on branch `v0.9`: module, vocabulary,
mapping, SHACL and test counts by `scripts/inventory.py` (machine-readable output: `docs/baseline/metrics.json`), library
counts from the output of `pipeline/library/build_abox.py`. An independent check of about 80 claims found the corrections
now included. Sources, versions,
licences and checksums of the raw files are in `docs/baseline/source_registry.csv`.

## 1. Baseline and rollback

| Item | Value |
|---|---|
| Released baseline | **0.8.0**, tag `v0.8.0` = commit `7ebb3a1` on `main`; GitHub release v0.8.0 (latest) |
| Later commit on `main` | `b1ddebb` (README and w3id HOWTO only; no ontology change) |
| Work branch | `v0.9` from `b1ddebb`: 0.9.0 draft (EU GDPR), approved by the project owner 2026-10-11, **not released, not pushed** |
| Permanent identifiers | `https://w3id.org/crgo/…` live since perma-id/w3id.org#6858; version IRIs `https://w3id.org/crgo/<version>/<module>` resolve to the tagged files |
| Rollback | every release is a tag; `git checkout v0.8.0` restores the baseline, and the version IRIs keep 0.8.0 queryable after later releases. Nothing on `main` changes until a release is approved. |
| Raw sources | `data/raw/` is not versioned (licences and size); checksums are recorded in the source registry so that a rebuild can be verified |

## 2. Ontology modules (TBox)

| Module | Classes | Object props | Data props | Annotation props | Individuals | Imports |
|---|---|---|---|---|---|---|
| `crgo-gov` | 2 | 1 | 0 | 11 | 11 | — |
| `crgo-core` | 49 | 59 | 32 | 0 | 62 | BFO-2020, CCO 2.2 slice, gov |
| `crgo-measure` | 7 | 5 | 6 | 0 | 7 | core |
| `crgo-crg` | 27 | 10 | 6 | 0 | 41 | measure |
| `crgo` (umbrella) | — | — | — | — | — | the four modules |
| `crgo-full` | — | — | — | — | — | umbrella, library, 17 vocabularies, mappings |

336 term identifiers minted (`src/ids.tsv`); 335 governed terms, all approved (`src/approvals.tsv`, 403 approval rows, all *Approve*).
Individuals are value-set members (status, confidence, evidence basis, control status, tiers, CRG dispositions…).

Main classes already present (relevant to the specification): risk scenario, library scenario, assessment scenario,
incident (distinct from scenario), threat source / threat event / vulnerability descriptions, consequence description,
asset and asset categories, asset valuation (CIA requirements, crown jewel), business process, business objective,
control (prescription), control measure (organisation-specific implementation, with status and evidence), control gap
finding, framework requirement, legal obligation, risk assessment (planned act with method, horizon, appetite),
estimate with likelihood / impact estimate / control effectiveness / risk level (bounds, scale, rationale, confidence,
sample size), key risk indicator, treatment initiative, treatment option, risk treatment decision, risk acceptance
(authority, expiry), evidence register entry with evidence basis (documented, external, expert, inference, AI estimate),
and the CyberRiskGuardian computation layer (threat presence, probability of exploitation, damages, resilience,
criticality, estimated / tolerated / mitigated / residual risk, sensitivity cases), kept apart from the generic layer.

## 3. Vocabularies (SKOS, `ontology/vocab/`)

| Scheme | Concepts | Of which deprecated | French labels | Version |
|---|---|---|---|---|
| loi25 (P-39.1, C-1.1) | 31 | 0 | 31 | LégisQuébec 2026-10-08 |
| a21 | 18 | 0 | 18 | current to 2026-08-12 |
| lrsss (R-22.1, r. 1, r. 2) | 54 | 0 | 54 | LégisQuébec 2026-10-10 |
| pipeda | 13 | 0 | 13 | current to 2026-05-26 |
| osfi-b13 | 20 | 0 | 20 | July 2022 (3 domains + 17 principles) |
| **gdpr** (0.9.0, approved, unreleased) | 40 | 0 | 40 | OJ L 119, 4.5.2016 |
| csf2 | 225 | 91 | 134 | 2.0 |
| sp800-53r5 | 1,216 | 182 | 0 | 5.2.0 |
| iso27002-2022 | 97 | 0 | 0 | 93 controls + 4 themes |
| cobit2019 | 45 | 0 | 0 | 40 objectives + 5 domains |
| ccm41 | 17 | 0 | 0 | domains only |
| attack | 873 | 161 | 0 | Enterprise 19.2 |
| capec | 559 | 0 | 0 | 3.9 |
| cwe | 943 | 0 | 0 | as carried by D3FEND 1.6.0 |
| d3fend | 270 | 0 | 0 | 1.6.0 |
| kev | 1,739 | 0 | 0 | catalogue 2026.10.08 |
| theme | 23 | 0 | 23 | CRGO |

**Mappings** (`mappings.ttl`): 11,554 annotation records over 11,462 distinct correspondences (11,447 `skos:relatedMatch`,
15 `skos:closeMatch`; 92 pairs carry two records, e.g. KEV primary and secondary impact). Each record has source,
confidence and status; approved ones also approver and approval date. The approval group is applied by the build and is
not stored on the record. 120 records (low-confidence D3FEND links) remain *proposed*.

## 4. Scenario library and evidence (ABox, `data/abox/crgo-library.ttl`, 551,664 triples)

| Content | Count |
|---|---|
| Library scenarios | 1,884 = 1,811 families from the 2023 CRG rows + 67 teaching-case scenarios + 6 written (AUTH-001 to AUTH-006) |
| Framework links on scenarios (annotated) | 24,871 as counted by the build (CSF, SP 800-53, ISO 27002, Loi 25, ATT&CK, CWE…); 26,894 annotated library records in all, including theme, weakness and *refines* links |
| CRG quantities | about 1,850 per input quantity; 1,096 computed risk sets |
| EPSS estimates | 1,739 (one per KEV vulnerability) |
| VCDB sector frequency estimates | 111 |
| Evidence register entries | 17 |

## 5. Quality infrastructure

| Gate | Present |
|---|---|
| Build | `scripts/check.sh` (13 steps), all passing on `381f7f5` |
| Reasoning | HermiT and ELK on the merged modules; OWL 2 DL profile; full closure consistency |
| OWL fixtures | 6 (1 positive, 5 negative: category errors such as scenario ≠ process, library ≠ assessment) |
| SHACL | `shapes/crgo-shapes.ttl`: 48 node shapes, 60 property constraints; 8 negative SHACL fixtures; MediBec case as positive fixture |
| Competency questions | 27 SPARQL queries (`tests/cq/`) with expected-row assertions; all pass |
| Identification | `tests/identify/test_identify.py` (17 checks) |
| CRG round trip | MediBec regression: 84,491 estimated, 41,104 residual, reproduced exactly |
| Pitfalls | OOPS-style scan, no critical pitfall |
| Redirects | 35,386 IRIs simulated against the w3id rules, 0 unresolved |
| Change control | `src/approvals.tsv`, `CHANGELOG.md`, `docs/decisions.md` (prose); no machine-readable diff between releases |

## 6. Reconciliation with the specification's reported 0.8.0 inventory (§1)

| Domain | Reported | Found | Comment |
|---|---|---|---|
| Loi 25 / P-39.1 with C-1.1 | 31 | 31 | ✓ |
| A-2.1 | 18 | 18 | ✓ |
| R-22.1 with r. 1 and r. 2 | 54 | 54 | ✓ |
| PIPEDA | 13 | 13 | ✓ |
| OSFI B-13 | 3 domains, 17 principles | 20 concepts | ✓ |
| NIST CSF 2.0 | 225 | 225 | **Clarification:** 134 current elements (6 functions, 22 categories, 106 subcategories) + 91 withdrawn CSF 1.1 elements (79 subcategories, 12 categories) kept as deprecated so old links resolve |
| SP 800-53 Rev. 5 | 1,216 | 1,216 | **Clarification:** 182 withdrawn controls and enhancements kept as deprecated; 1,014 current controls and enhancements + 20 family concepts |
| ISO/IEC 27002:2022 | 93 | 97 | 93 controls + 4 themes; identifiers and titles taken from secondary public listings (licensing gate, gap G14) |
| COBIT 2019 | 40 | 45 | 40 objectives + 5 domains |
| CSA CCM 4.1 | 17 domains | 17 | ✓ domains only; the private full-CCM build has no input file |
| ATT&CK Enterprise 19.2 | 873 | 873 | **Clarification:** includes 161 deprecated or revoked; groups, software and campaigns not imported |
| CAPEC 3.9 | 559 | 559 | ✓ (deprecated patterns excluded at import) |
| CWE | 943 | 943 | **Clarification:** the CWE entries carried by D3FEND 1.6.0, not the CWE catalogue; CWE version unknown |
| D3FEND 1.6.0 | 270 | 270 | ✓ defensive techniques only |
| KEV 2026-10-08 | 1,739 | 1,739 | ✓ |
| CTID / NIST / CAPEC / CWE / KEV / CRGO mappings | listed | 11,554 | CTID mappings are for ATT&CK 16.1 while the vocabulary is 19.2 |
| FIRST EPSS 2026-10-04 | listed | 1,739 estimates | only KEV vulnerabilities; modelled as *likelihood* (gap G6) |
| VERIS frequencies 2026-09-30 | listed | 111 | ✓ derived counts only |
| Scenarios | rows, families, AUTH-001 to 006 | 1,884 | ✓ all approved |
| BFO-2020 + CCO subset | listed | present | consistent; alignment recorded per term |
| EU GDPR | "ingestion in progress" | 40 provisions, 25 correspondences | **Ingested, independently reviewed and approved 2026-10-11; approval written into the built files; not released.** No duplicate ingestion needed. |

No reported figure was contradicted. Five need the clarification noted, because a count alone overstates current content.
