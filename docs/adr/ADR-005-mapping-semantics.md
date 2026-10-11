# ADR-005 Mapping semantics

Status: proposed (0.9.0). Decision D3 (2026-10-11). Specification sections 3, 5 (Mappings), 7, 13.

## Decision
- Each meaning has its own relation in `crgo-mapping`, a sub-property of `skos:relatedMatch` (or `skos:closeMatch` for the same obligation in another Québec regime), with the direction in its label: *technique mitigated by control*, *technique countered by defensive technique*, *attack pattern exploits weakness*, *attack pattern related to technique*, *vulnerability is an instance of weakness*, *vulnerability associated with technique*, *subcategory supported by control*, *control corresponds to control*, *principle addressed by category*, *comparable obligation*, *same obligation in another regime*.
- Every correspondence keeps its SKOS triple and its OWL axiom annotation (source, confidence, status, proposer, approver and date, comment), and gains the typed triple. SKOS consumers keep working without a reasoner.
- **Proposed correspondences are kept apart**: `ontology/vocab/mappings-proposed.ttl` and `data/abox/crgo-library-proposed.ttl` hold links whose approval group is not approved (120 D3FEND links; library links of unapproved groups). `crgo-full` does not import them; the query store loads them so that analysts can still ask for low-confidence links explicitly.

## Alternatives
A reified `MappingAssertion` individual per link (specification section 7) was rejected for the existing 11,462 vocabulary correspondences and 24,871 library links: the axiom annotations already carry the required fields, and reification would add about 200,000 triples. Reified records remain the plan for future human review records (`MappingReview`).

## Counterexample and test
A correspondence with only a SKOS triple and annotation, no typed relation, violates SHACL (`tests/shacl/neg-mapping-untyped`). An approved correspondence without approver and date violates SHACL (existing shape since 0.4.0). CQ01 to CQ27 still pass on the SKOS relations.
