# ADR-006 Provenance, time and units

Status: proposed (0.9.0). Specification sections 3, 5 (Numeric data), 7, 13.

## Decision
- **Source records** (new class, sub-class of the CCO descriptive information content entity and of `prov:Entity`): one per row of `docs/baseline/source_registry.csv` (29), with issuer, official identifier, version, retrieval date, licence, what CRGO redistributes, SHA-256 checksums of the files used, and a verification note. `has source record` (sub-property of `prov:hadPrimarySource`) links every vocabulary, the mappings, the library, legal instruments and observations to them.
- **Governance metadata** stays on the CRGO annotation properties used since 0.1.0 (status, confidence, proposed by, approved by, approval date, evidence source); `evidence source` and `derived from` are sub-properties of `dcterms:source`. They are not re-expressed in PROV-O, to avoid rewriting the governance annotations of every approved term and link.
- **Time**: dates are `xsd:dateTime` data properties (`retrieved on`, `observed on`, `assessed on`, `published on`, `applies from`, `consolidated to`), because HermiT supports only the OWL 2 datatype map (`xsd:date` is outside it). OWL-Time is used where a *period* is the object of a claim: a legal instrument's in-force interval (`time:ProperInterval`, beginning `time:Instant` with `time:inXSDDateTimeStamp`), open-ended while the instrument is not repealed.
- **Units**: probabilities and shares are decimals on the unit-interval scale (`on scale`); EPSS horizons are stated (`observation horizon`); costs carry an ISO 4217 currency code. QUDT is deferred to 0.9.5, when monetary loss and duration quantities (BIA, Open FAIR) arrive.

## Alternatives
Full PROV-O qualification (activities, plans, agents for every import) was rejected as disproportionate for this release. Importing OWL-Time and PROV-O whole was impossible: neither published file is OWL 2 DL (undeclared annotation properties; property punning).

## Counterexample and test
A vocabulary without a source record, a source record without version, and an observation without date or source violate SHACL (shapes `VocabularySource`, `SourceRecord`, `Observation`; fixture `neg-source-record-no-version`). CQ-11 returns the source versions behind the determinations of an assessment.
