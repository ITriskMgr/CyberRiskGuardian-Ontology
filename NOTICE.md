# Third-party notices

This repository includes or derives material from the following works. Their
licences apply to the files listed, not the CC BY-NC 4.0 licence of CRGO.

## Basic Formal Ontology (BFO-2020)

- File: `imports/bfo-core.ttl`
- Source: https://github.com/BFO-ontology/BFO-2020
- Standard: ISO/IEC 21838-2:2021, *Information technology — Top-level ontologies (TLO) — Part 2: Basic Formal Ontology (BFO)*
- Licence: Creative Commons Attribution 4.0 International (CC BY 4.0), https://creativecommons.org/licenses/by/4.0/
- Unmodified copy of the BFO-2020 core OWL file.

## Common Core Ontologies (CCO) 2.2

- File: `imports/cco-slice.ttl`, a module extracted with ROBOT `extract --method BOT` from `CommonCoreOntologiesMerged.ttl` (seed terms in `imports/cco-seeds.txt`).
- Source: https://github.com/CommonCoreOntology/CommonCoreOntologies
- Licence: BSD 3-Clause. Copyright (c) 2017, CUBRC, INC. Full text in `imports/CCO-LICENSE.txt`.
- The extract is a subset; no CCO axioms were changed.

## Framework vocabularies (ontology/vocab/)

- **NIST CSF 2.0 and NIST SP 800-53 Rev. 5.2.0**: built from the OSCAL catalogues in https://github.com/usnistgov/oscal-content. US Government works, not subject to copyright in the United States (17 U.S.C. 105). Credit: National Institute of Standards and Technology.
- **MITRE ATT&CK Enterprise 19.2**: built from https://github.com/mitre-attack/attack-stix-data. © The MITRE Corporation. Reproduced and distributed with the permission of The MITRE Corporation under the ATT&CK Terms of Use, https://attack.mitre.org/resources/legal-and-branding/terms-of-use/.
- **ISO/IEC 27002:2022**: control identifiers and titles only, © ISO/IEC, cited for reference and mapping. No control text is reproduced; obtain the standard from ISO or a national standards body.
- **COBIT 2019**: objective identifiers and names only, © ISACA, cited for reference and mapping.
- **CSA Cloud Controls Matrix v4.1**: domain identifiers and names only, © Cloud Security Alliance, attributed to the Cloud Security Alliance Cloud Controls Matrix Version 4.
- **Québec Law 25** and the **Act respecting health and social services information (CQLR c. R-22.1)** with its regulations: labels and definitions are CRGO paraphrases with section references; the official text is published in LégisQuébec.

## Case data

- `data/library/case_scenarios.json` quotes values from fictional teaching cases (CanaRetail, ACRB, MediBec, Chez Pierre) by Marc-André Léger, used with permission of the author; instructor annex values are calibration aids, not facts about real organisations.

## Test data

- `tests/crg/medibec30.json` is the fictional MediBec teaching case from CyberRiskGuardian (© Marc-André Léger, CC BY-NC 4.0).

## Standards cited as evidence

ISO/IEC 27005:2022, ISO 31000:2018, NIST SP 800-30 Rev. 1 and Québec's Loi 25 are
cited in `crgo:evidenceSource`
annotations by title and clause only. No text from these documents is
reproduced; definitions in CRGO are original wording.

## Sources added in 0.7.0

| Vocabulary or file | Source | Version used | Licence or terms |
|---|---|---|---|
| `ontology/vocab/cwe.ttl` | MITRE CWE, as carried by MITRE D3FEND (github.com/d3fend/d3fend-ontology) | D3FEND 1.6.0, commit 577623b (2026-10-08) | CWE Terms of Use (free use with attribution); D3FEND MIT licence (`data/raw/external/LICENSE-d3fend.md`) |
| `ontology/vocab/d3fend.ttl` | MITRE D3FEND defensive techniques | 1.6.0, commit 577623b | MIT licence |
| `ontology/vocab/capec.ttl` | MITRE CAPEC, STIX bundle in github.com/mitre/cti | commit 8543c5b (2026-08-05) | CAPEC Terms of Use (free use with attribution) |
| `ontology/vocab/kev.ttl` | CISA Known Exploited Vulnerabilities (github.com/cisagov/kev-data) | catalogue 2026.10.08 | U.S. government work |
| `ontology/vocab/mappings.ttl` (ATT&CK→SP 800-53, KEV→ATT&CK) | MITRE Center for Threat-Informed Defense, Mappings Explorer (github.com/center-for-threat-informed-defense/mappings-explorer) | commit a85e55a (2026-10-04); ATT&CK 16.1 mappings | Apache License 2.0 (`data/raw/external/LICENSE-ctid.txt`) |
| `ontology/vocab/mappings.ttl` (CAPEC→ATT&CK, CAPEC→CWE, KEV→CWE) | the references inside CAPEC and KEV | as above | as above |
| `ontology/vocab/mappings.ttl` (ATT&CK→D3FEND) | judged by Claude against D3FEND 1.6.0 | 2026-10-11 | CRGO, CC BY-NC 4.0 |

MITRE ATT&CK, CWE, CAPEC and D3FEND are trademarks of The MITRE Corporation. Labels and definitions are reproduced from these sources as published; CRGO adds no endorsement by MITRE, CISA or NIST. The raw downloads are kept in `data/raw/external/` (not versioned); `pipeline/vocab/build_external.py` rebuilds the vocabularies from them.

The VERIS schema (github.com/vz-risk/veris) is under CC BY-SA 4.0, a share-alike licence that is not compatible with CRGO's CC BY-NC 4.0 for copied text. If VERIS is used in 0.8.0, CRGO will reference VERIS identifiers without copying its descriptions, or publish the VERIS-derived file separately under CC BY-SA.

## Sources added in 0.8.0

| Content | Source | Version used | Licence or terms |
|---|---|---|---|
| EPSS estimates for the KEV vulnerabilities (`data/abox/crgo-library.ttl`) | FIRST Exploit Prediction Scoring System, file retrieved by CyberRiskGuardian | scores of 2026-10-04, model v2026.06.15 | FIRST EPSS usage terms (free use with attribution to FIRST, https://www.first.org/epss/) |
| Sector frequency estimates (`data/library/vcdb_frequencies.csv`, library estimates `VCDB-*`) | VERIS Community Database, github.com/vz-risk/VCDB | commit f6f98c0 (2026-09-30) | CC BY-SA 4.0. CRGO stores only counts and shares derived from VCDB, with this attribution; no incident text or VERIS description is copied. |
| `ontology/vocab/a21.ttl` | LégisQuébec, CQLR c. A-2.1 | current to 2026-08-12 | Labels and definitions are CRGO paraphrases of the official text |
| `ontology/vocab/pipeda.ttl` | Justice Laws Website, S.C. 2000, c. 5 | current to 2026-05-26 | CRGO paraphrases of the official text |
| `ontology/vocab/osfi-b13.ttl` | OSFI Guideline B-13 | July 2022, page modified 2024-02-20 | CRGO paraphrases; short principle names follow OSFI's headings |
| CSF 2.0 → SP 800-53 (derived) and SP 800-53 → ISO/IEC 27002 cross-references in `mappings.ttl` | NIST CPRT CSF 2.0 export, NIST CSF 1.1 to SP 800-53r5 mapping, NIST OLIR mapping of SP 800-53r5 to ISO/IEC 27001:2022 (files supplied by the project owner from csrc.nist.gov) | downloaded 2026-10-11 | U.S. government works |
| French labels of CSF 2.0 (`csf2.ttl`, `data/frameworks/csf2_fr.json`) | NIST CSWP 29, French translation | as published by NIST | NIST publication |

## Sources added in 0.9.0

| Vocabulary or file | Source | Version used | Licence or terms |
|---|---|---|---|
| `ontology/vocab/gdpr.ttl`, Loi 25 ↔ GDPR in `mappings.ttl` | Regulation (EU) 2016/679, Official Journal of the European Union L 119, 4.5.2016, p. 1 (EUR-Lex, CELEX 32016R0679), English text; French terminology from the official French version | as published 2016 (corrigenda not reviewed) | EU legislative texts may be reused (Commission Decision 2011/833/EU); labels and definitions are CRGO paraphrases; only the Official Journal text is authentic |

## Sources added in 0.9.0 (Sprint 1)

| File | Source | Version used | Licence or terms |
|---|---|---|---|
| `imports/prov-slice.ttl` | W3C PROV-O: The PROV Ontology (github.com/w3c/prov, ontology/prov-o.ttl), BOT module extracted with ROBOT | W3C Recommendation 2013-04-30 | W3C Software and Document License |
| `imports/time-slice.ttl` | W3C Time Ontology in OWL (github.com/w3c/sdw-time, rdf/time.ttl), BOT module extracted with ROBOT | edition of 2025-08-27 | CC BY 4.0 |
| `ontology/vocab/legal.ttl`, `ontology/vocab/sources.ttl` | Official texts of P-39.1, C-1.1, A-2.1 (r. 0.1, r. 3.1), R-22.1 (r. 1, r. 2) (LégisQuébec), PIPEDA (Justice Laws Website), OSFI B-13, Regulation (EU) 2016/679 (EUR-Lex): PDF snapshots saved by the project owner on 2026-10-11 | dates printed on each file (`docs/baseline/source_registry.csv`) | CRGO stores citations, dates and paraphrased conditions only; the PDFs stay in `data/raw/` and are not redistributed |

`tests/samples/` (Nordelle Market inc.) is synthetic test data written for CRGO; it describes no real organisation.

