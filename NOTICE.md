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

## Standards cited as evidence

ISO/IEC 27005:2022, ISO 31000:2018, NIST SP 800-30 Rev. 1 and Québec's Loi 25 are
cited in `crgo:evidenceSource`
annotations by title and clause only. No text from these documents is
reproduced; definitions in CRGO are original wording.
