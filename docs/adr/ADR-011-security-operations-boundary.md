# ADR-011 Security monitoring and response (SIEM and SOAR): boundary and modelling

Status: proposed for 0.10.0 (decisions S1-S12 taken by Claude under the project owner's delegation of 2026-10-12; listed for review before pushing).

## Decision
- **Boundary.** CRGO holds reusable concepts, reference vocabularies (ATT&CK detection strategies, analytics and data components; OCSF categories and event classes) and selected organisation records. Event streams, alert payloads, execution histories, baselines and secrets stay in operational stores; CRGO records point to them (S7).
- **No inference authorises an action** (S6). There is no property chain or class definition from which an approval could be derived. Whether an impactful action execution relied on a granted approval valid at its start is checked by SHACL as a warning and reported by the secops/v1 contract: an audit signal, never a permission. A record of an unapproved action is a correct record of a control failure.
- **No inference to incidents or attribution** (S5). *Potentially indicates* and *matched indicator* imply nothing; an investigation's *concluded incident* counts only with an incident confirmation (warning otherwise); a threat indicator is disjoint from an incident confirmation.
- **One approval validity rule**, shared by the SHACL warning, CQ-SOAR-02 and secops/v1: outcome approved; decided and valid at the start; not denied or revoked before it; about this execution, its action or its risk class; made by a gate authority when the action's gates name one.
- **No accidental classification**: incident links and incident attributes have no OWL domain or range; SHACL checks them, so a categorised case or an early notice is never inferred to be an incident. A detection test or playbook simulation is never reported as the effectiveness of the whole control measure.
- **Reuse by subclass** (S3): detection tests and playbook simulations are control assessments; detection gaps are control gaps; threat intelligence sources are source records; approval decisions are decision records; playbook versions are directive versions; response evidence and forensic artefacts are evidence items; event records and telemetry health observations are observations.
- **Modules** (S2): `crgo-siem` (imports incident, grc) and `crgo-soar` (imports siem, audit).
- **Confidence** stated by a source is kept with its method and never read as a probability (S8). TLP 2.0 labels mark sharing restrictions.

## Alternatives
Classifying log sources as assets (rejected: it would reclassify assets); an "approved execution" class or rule (rejected: reasoning must not authorise); modelling TAXII and OpenTelemetry attributes (deferred, S11).

## Counterexample and test
Thirteen SHACL negative fixtures `tests/shacl/neg-secops-*` (six of them by warning-severity shapes: four approval cases including a retroactive and an unrelated approval, an unconfirmed conclusion, a regulator notice without submission), two OWL fixtures (indicator that is a confirmation, rule that is a strategy); 12 competency questions CQ-SIEM-01-06 and CQ-SOAR-01-06 in `tests/pca_cq/run_pca_cq.py`; read contract `contracts/secops/v1`.
