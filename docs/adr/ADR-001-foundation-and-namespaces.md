# ADR-001 Ontology foundation, namespace and version policy

Status: proposed (0.9.0), documents practice since 0.1.0. Specification sections 3, 5 (Identity), 17.

## Context
The specification asks for persistent, namespace-controlled IRIs, careful BFO/CCO reuse and no identity derived from labels.

## Decision
- **Terms** are `https://w3id.org/crgo/CRGO_nnnnnnn`, opaque and assigned once by `src/build.py` through `src/ids.tsv`. A term's IRI never changes meaning or disappears; a retired term is deprecated (`owl:deprecated`, status *deprecated*) and kept.
- **Vocabulary concepts** are `https://w3id.org/crgo/vocab/<scheme>/<official identifier>`, because the external identifier (CSF `PR.AA-05`, `CVE-2021-44228`, `GDPR Art. 33(1)`) is itself persistent and controlled by its publisher.
- **Library individuals** are `https://w3id.org/crgo/data/library/<family id>`, frozen in `data/library/family_ids.tsv`.
- **Legal instruments and source records** are `https://w3id.org/crgo/vocab/legal/<id>` and `https://w3id.org/crgo/vocab/sources/<source id>`.
- **Versions**: `owl:versionIRI https://w3id.org/crgo/<version>/<module>`, resolved by w3id.org to the release tag. Minor versions add terms or data; 1.0.0 will add a stability commitment.
- **Upper ontology**: every class is placed under BFO-2020 or a CCO 2.2 class (`imports/cco-slice.ttl`), with an OntoClean note when the choice is contested. W3C vocabularies (PROV-O, OWL-Time) are imported as ROBOT BOT slices because the published files are not OWL 2 DL.
- **Modules** (decision D2, 2026-10-11): the four 0.8.0 modules are unchanged; new content goes into new modules (`crgo-evidence`, `crgo-org`, `crgo-vuln`, `crgo-grc`, `crgo-mapping`). The specification's thirteen modules map onto them as listed in `docs/baseline/gap_analysis.md` section D.

## Alternatives
Readable IRIs (`crgo:RiskScenario`) were rejected in Phase 1: renaming a class would break every reference. Splitting the existing modules into thirteen was rejected (D2): it moves approved terms without changing their meaning.

## Counterexample and test
A label change (e.g. "control measure" to "control implementation") must not change any IRI. `scripts/check_metadata.py` checks every term has labels and governance; `scripts/check_modules.py` checks each module references only terms it declares or imports; `scripts/check_w3id.py` resolves every CRGO IRI used in the files (37,656 in 0.9.0).
