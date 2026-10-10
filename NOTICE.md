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
- **Québec Law 25**: labels and definitions are CRGO paraphrases with section references; the official text is published in LégisQuébec.

## Test data

- `tests/crg/medibec30.json` is the fictional MediBec teaching case from CyberRiskGuardian (© Marc-André Léger, CC BY-NC 4.0).

## Standards cited as evidence

ISO/IEC 27005:2022, ISO 31000:2018, NIST SP 800-30 Rev. 1 and Québec's Loi 25 are
cited in `crgo:evidenceSource`
annotations by title and clause only. No text from these documents is
reproduced; definitions in CRGO are original wording.
