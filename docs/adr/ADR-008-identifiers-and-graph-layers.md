# ADR-008 Identifiers and graph layers; tenant separation

Status: approved (0.9.0, project owner, 2026-10-11). Remaining-gaps specification sections 5 and 10.1; decision R-c (approved by the project owner, 2026-10-11: "apply R-c as described").

## Decision
Four layers, each in its own files:

| Layer | Content | IRIs | Files |
|---|---|---|---|
| Reference TBox | classes, properties, value sets | `https://w3id.org/crgo/CRGO_nnnnnnn` (opaque, stable) | `ontology/crgo-*.ttl` |
| Reference vocabularies and source ABox | framework and legal vocabularies, legal instruments, source records, mappings, scenario library, work programmes | `https://w3id.org/crgo/vocab/...`, `https://w3id.org/crgo/data/...` | `ontology/vocab/`, `data/abox/` |
| Organisation graphs | one organisation's profile, assets, assessments, audit records, incidents, decisions | the organisation's own base, never under `https://w3id.org/crgo/` | outside the reference files (in this repository only synthetic examples in `tests/samples/`) |
| Derived analytical results | results computed by the DSS and written back | the organisation's base (`.../dss-result/...`) | the organisation's `*-dss-proposed.ttl`, which declares the same base; never its fact graph |

Rules:
1. One graph (one file or one named graph) per organisation, under its own IRI base, which the graph declares on its ontology header with `vann:preferredNamespaceUri`; tools read the declared base and never guess it from an IRI.
2. Reference files never mention an organisation IRI.
3. An organisation graph states triples only about subjects under its own base. It may point to reference IRIs as objects, but never states anything about them: an organisation's claim that a control supports an obligation is stated on its own control measure, not on the reference concepts.
4. An organisation graph refers to no other organisation's base.
5. Queries and contract documents are scoped to one organisation; records under another base are withheld and reported (`pipeline/contracts/dss.py`).
6. Deprecation: reference terms are never deleted; a replaced term is `owl:deprecated` with `dcterms:isReplacedBy` (as for the 0.8.0 EPSS stubs), and the change report lists it.

Grandfathered exception: the MediBec teaching case keeps `https://w3id.org/crgo/data/medibec/`, published since 0.4.0, because changing it would break published IRIs. It is fictional and serves as a reference example.

## Alternatives
Named graphs in one store per tenant were considered equivalent and remain allowed (rule 1). A single merged graph with an organisation property on every record was rejected: one missing property leaks a record across organisations.

## Counterexample and test
`scripts/check_tenants.py` (check step 15) fails when a reference file mentions an organisation base, when an organisation graph states something about a subject outside its base, or refers to another organisation (verified by injecting both faults). The synthetic second tenant (Boréal, `tests/samples/tenant-b.ttl`) mirrors Nordelle's conflicting assessments; CQ-GRCA-08 scoped to Nordelle never returns Boréal's records, and the contract withholds stray links to another organisation's assets, findings and obligations (`tests/contracts/test_dss_contract.py`).
