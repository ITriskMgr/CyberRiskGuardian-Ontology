# ADR-002 Hypothetical scenario, observed incident, observation and estimate

Status: proposed (0.9.0). Specification sections 5 (Risk classes, Confidence), 6, 10.

## Context
A risk scenario linked to an ATT&CK technique or a CVE must never read as a confirmed incident or exposure; and a source's published value (EPSS) must not be confused with an analyst's estimate or a scenario's likelihood.

## Decision
- `risk scenario` (library or assessment) is a **description** (CCO descriptive information content entity) of a possible causal chain. `incident` is an **occurrent** (BFO process). They cannot be confused: a description is a continuant, an incident is a process, and BFO makes the two disjoint.
- `observation` (new, `crgo-evidence`) is a dated record that a stated source reported a value about an entity. `estimate` (since 0.1.0) is a value given for an assessment, with scale, confidence and rationale. **Observation and estimate are disjoint** (`owl:disjointWith`).
- `EPSS observation` (new, `crgo-vuln`) replaces the 0.8.0 EPSS *likelihood* estimates (decision D4). It records probability, percentile, the 30-day horizon, the score date, the model version and the source record. Each 0.8.0 IRI is kept as a deprecated stub with `dcterms:isReplacedBy`.
- Relations from scenarios to techniques, weaknesses and CVEs are *possibility* links (`has external reference`, `exploits`); none asserts that an organisation was attacked or is exposed. Organisation-specific exposure is planned for 0.9.5 (gap G8).

## Alternatives
Keeping EPSS as likelihood with a note was rejected by the specification (section 5, Confidence). A reified "claim" class for all statements was rejected as too heavy for the library.

## Counterexample and test
An individual typed both EPSS observation and likelihood is inconsistent: `tests/fixtures/neg-observation-is-estimate.ttl` (HermiT). An undated observation, an EPSS probability of 1.3, or two different scores for the same CVE on the same date violate SHACL (`tests/shacl/neg-observation-undated`, `neg-epss-out-of-range`, `neg-epss-contradictory`). CQ-03 returns scenarios but never an incident (`tests/spec_cq`, category guard).
