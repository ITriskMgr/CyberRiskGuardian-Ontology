# CRGO 0.10.0 — SIEM and SOAR: Phase 0 analysis and decisions

**Status:** decided by Claude under the project owner's delegation of 2026-10-12, 19:26 (`docs/decisions.md` §21). The decisions are listed again in the final review, before anything is pushed.

**Inputs:**

- *CRGO SIEM Ontology Extension Specification* v1.0 (**SIEM**)
- *CRGO SOAR Ontology Extension Specification* v1.0 (**SOAR**)

Both are dated 2026-10-12. They share sections 1, 4, 5 and 7, and their reference lists: NIST SP 800-61 Rev. 3, OCSF, OpenTelemetry logs, Sigma, MITRE ATT&CK, STIX/TAXII 2.1, CACAO 2.0, PROV-O and SHACL.

## 1. What CRGO 0.10.0 already has

The specifications ask for reuse of existing concepts:

| Concept in the specifications | Existing CRGO term |
|---|---|
| Asset, Organization, BusinessProcess, RiskScenario | `Asset`, CCO organisation, `BusinessProcess`, `RiskScenario` |
| Threat | `ThreatEventDescription`, `ThreatSourceDescription` |
| Vulnerability | `Vulnerability` |
| SecurityControl | `Control` (catalogue) and `ControlMeasure` (as implemented) |
| PolicyRequirement, ComplianceObligation | `PolicyStatement`, `LegalObligation` and provisions |
| AuditEvidence, AuditFinding | `EvidenceItem`, `AuditFinding` |
| Incident | `Incident` (core) |
| Security events, alerts and incident handling | `crgo-incident` (0.9.0): `SecurityEvent`, `SecurityAlert`, `IncidentConfirmation`, `BreachReportabilityAssessment`, `IncidentTimelineEntry`, `LessonLearned`, response phases |
| Approvals and versions | `DecisionRecord`, `DirectiveVersion` (0.10.0) |
| Testing | `ControlAssessment` (test result, assessor, evidence) |
| Gaps | `ControlGap` |
| Hypotheses | `AnalyticalHypothesis` |
| Observations | `Observation` |
| Sources and licences | `SourceRecord` |
| Regulatory notices | `RegulatorySubmission`, `ComplianceDeadline` (0.10.0) |

**ATT&CK 19.2**, which CRGO already holds as a raw bundle, contains:

- 699 detection strategies (697 neither revoked nor deprecated);
- 1,758 analytics;
- 109 data components (106 neither revoked nor deprecated).

The bundle also holds 697 *detects* relationships from detection strategies to techniques. CRGO's ATT&CK vocabulary so far used only tactics and techniques.

## 2. Reconciliation matrix

### 2.1 SIEM

| SIEM candidate | Decision | CRGO term |
|---|---|---|
| TelemetrySource | **new**: a record about the source, linked to its asset | `TelemetrySource` (a descriptive ICE, not an asset subclass, so that assets are not reclassified) |
| SecurityEventType | **reuse a vocabulary**: OCSF 1.9.0 categories and event classes, as a new SKOS vocabulary `vocab/ocsf` | `mapsToEventClass` (correspondence, not equivalence) |
| SecurityEventReference | **new** subclass | `SecurityEventRecord` ⊑ `Observation`; points to the existing `SecurityEvent` through `observationOf` |
| NormalizationProfile, ParserDefinition | **new** | `NormalizationProfile`, `ParserDefinition` (directives, versioned by `versionLabel`) |
| DetectionStrategy | **new** (the organisation's own) plus **reference** ATT&CK strategies in the new `vocab/attack-detection` | `DetectionStrategy`, `adaptsReferenceStrategy` |
| DetectionAnalytic | **reuse a vocabulary**: ATT&CK analytics in `vocab/attack-detection` | `usesAnalytic`, `analyticUsesDataComponent` |
| DetectionRule, CorrelationRule | **new** | `DetectionRule`, `CorrelationRule`, linked to the detective `ControlMeasure` it carries out (`ruleForMeasure`) |
| SecurityAlert | **reuse** `SecurityAlert` | + `hasAlertDisposition`, `generatedByRule`, `correlatedWith`, `involvesAsset`, `potentiallyIndicates` |
| ThreatIndicator | **new** | `ThreatIndicator` (with stated confidence and its method) |
| ThreatIntelligenceSource | **new** subclass | `ThreatIntelligenceSource` ⊑ `SourceRecord` |
| DetectionCoverage | **new** | `DetectionCoverage` + `CoverageStatus` |
| DetectionGap | **new** subclass | `DetectionGap` ⊑ `ControlGap`; reuses `hasControlGap` (spec: hasDetectionGap) |
| DetectionTest | **new** subclass | `DetectionTest` ⊑ `ControlAssessment` |
| TelemetryHealthObservation | **new** subclass | `TelemetryHealthObservation` ⊑ `Observation` + `TelemetryHealthState` |
| HuntingHypothesis | **new** subclass | `HuntingHypothesis` ⊑ `AnalyticalHypothesis` |
| BehavioralBaseline | **new** | `BehavioralBaseline` (metadata only) |
| Common properties | **reuse** where they exist | id → `localIdentifier`; source version → `versionLabel`/`sourceVersion`; validity → `validFrom`/`validUntil`; observed → `observedOn`, `occurredAt`; review → `hasReviewState`; evidence pointer → `evidenceLocator`; provenance → `prov:wasDerivedFrom`. **New**: `sourceSystem`, `recordedAt`, `statedConfidence`, `confidenceMethod`, and the `InformationMarking` value set (FIRST TLP 2.0) for privacy and sharing marking |

### 2.2 SOAR

| SOAR candidate | Decision | CRGO term |
|---|---|---|
| SecurityInvestigation | **new** | `SecurityInvestigation` (planned act) + `CaseStatus` |
| SecurityIncident | **reuse** `Incident` and `IncidentConfirmation` | `concludedIncident` (never a confirmation by itself) |
| IncidentClassification | **new value sets** | `IncidentCategory`, `IncidentSeverity` (CRGO's own scales; NIST SP 800-61 Rev. 3 defines none) |
| ResponsePlaybook, PlaybookVersion, PlaybookStep | **new** | `ResponsePlaybook` ⊑ `Procedure`, `PlaybookVersion` ⊑ `DirectiveVersion`, `PlaybookStep` |
| PlaybookTrigger | **new** | `PlaybookTrigger` + `TriggerKind` |
| ResponseAction, ActionRiskClass | **new** | `ResponseAction` (definition, not execution) + `ActionRiskClass`; may point to a D3FEND technique |
| ApprovalGate | **new** | `ApprovalGate` (risk classes it covers, authority, critical-asset rule) |
| ApprovalDecision | **new** subclass | `ApprovalDecision` ⊑ `DecisionRecord` + `ApprovalStatus`, with pre-authorisation |
| AutomationExecution, ActionExecution | **new** (records, not the operational history) | `AutomationExecution`, `ActionExecution` + `ExecutionStatus`, attempt identifier |
| ResponseEvidence, ForensicArtifact | **new** subclasses | `ResponseEvidence` and `ForensicArtifact` ⊑ `EvidenceItem` (custody, hash and collection date reused) |
| IncidentImpact | **new** | `IncidentImpact` (observed or estimated), kept distinct from a scenario's consequence |
| IncidentCommunication | **new** | `IncidentCommunication` + `CommunicationAudience`; a notice to a regulator is linked to its `RegulatorySubmission` |
| LessonsLearned | **reuse** `LessonLearned` | + `ledToAction` → `CorrectiveAction` |
| RecoveryVerification | **new** | `RecoveryVerification` |
| ResponseEffectiveness | **new** | `ResponseMeasurement` (a CCO measurement) + `ResponseMetric` |
| createsComplianceReview | **reuse** | `BreachReportabilityAssessment` and `ComplianceDeadline` answer CQ-SOAR-03; no new link class |
| simulation (CQ-SOAR-04) | **new** subclass | `PlaybookSimulation` ⊑ `ControlAssessment` |

**Result:**

- 32 new classes;
- 14 new value sets with 74 values;
- 73 object properties;
- 20 data properties (after review: *verified at* and *baseline period* dropped in favour of *assessed on* and the period properties; *reference version* and *revoked on* added);
- 2 reference vocabularies: ATT&CK detection objects, and OCSF categories and classes;
- 7 new source records.

## 3. Decisions

- **S1. One release.** SIEM and SOAR go into 0.10.0 with policy, compliance and audit, so that the CyberRiskGuardian application is updated once.
- **S2. Modules.**
  - `crgo-siem` imports `incident` and `grc`.
  - `crgo-soar` imports `siem` and `audit`.
  - Opaque IRIs and the single namespace are kept, as in D2 (the specifications' `crgo:{kind.lower()}` is read as a module name).
- **S3. Reuse by subclass, not by parallel classes.** A detection test and a playbook simulation are control assessments. A detection gap is a control gap. A threat intelligence source is a source record. An approval decision is a decision record. A playbook version is a directive version. Response evidence and forensic artefacts are evidence items. Event records and telemetry health observations are observations.
- **S4. Reference versus organisation content.** ATT&CK detection strategies, analytics and data components, and OCSF categories and classes, are imported as SKOS reference vocabularies, with their licences recorded. The organisation's own strategies, rules, profiles and playbooks are classes whose instances live in its own graph (ADR-008).
- **S5. No inference to incidents or attribution.**
  - *potentially indicates* and *matched indicator* never imply an incident.
  - *concluded incident* needs an incident confirmation to count.
  - An indicator is disjoint from an incident confirmation.
- **S6. Reasoning never authorises an action.**
  - There is no property chain or class definition from which an approval could be inferred.
  - SHACL checks that a containment or destructive action execution relied on an approval decision that was granted and valid at the time. That check is an audit signal; it is not a permission.
  - This is recorded in ADR-011.
- **S7. Records, not streams.** Event records, alerts, executions and baselines are pointers and metadata; payloads, execution logs and secrets stay in operational stores. The specifications' IRI ↔ application UUID mapping is `localIdentifier` (the application's UUID) on the organisation's own IRI.
- **S8. Confidence.** The confidence stated by a source is kept with its method (for example, STIX 2.1 confidence on a 0–100 scale). It is never treated as a probability.
- **S9. Own scales.** Incident category and severity are CRGO's own scales, in line with D13. The TLP 2.0 labels are FIRST's labels, cited by name.
- **S10. Read contract.** A read-only `contracts/secops/v1` and an MCP tool `crgo_secops_context`, built alongside `contracts/compliance/v1` (D11), so that the CyberRiskGuardian application can read three views:
  - detection coverage and gaps per scenario;
  - playbooks and simulation status;
  - approval requirements.

  There is no write-back: graph updates remain the application's, with provenance.
- **S11. Not modelled.**
  - TAXII collections and OpenTelemetry attributes. They are transport and attribute details with no competency question; OpenTelemetry is cited as a source only.
  - CACAO agents, targets and commands beyond what playbook steps and response actions carry.
  - Feature flags and application migrations, which belong to the application.
- **S12. Competency questions.** All 12 (CQ-SIEM-01 to 06 and CQ-SOAR-01 to 06) are implemented over synthetic Nordelle data, with positive and negative checks.

## 4. Sources added

| Source | Version used | Use in CRGO |
|---|---|---|
| NIST SP 800-61 Rev. 3 | April 2025, doi:10.6028/NIST.SP.800-61r3 | Cited; US Government work |
| MITRE ATT&CK detection objects | Enterprise 19.2 bundle already held | Identifiers, names and analytic statements, reproduced under the ATT&CK Terms of Use, as for the techniques |
| OCSF | 1.9.0 (git tag) | Category and class identifiers, captions and descriptions; Apache-2.0 |
| Sigma specification | v2.1.0 (2025-09-12) | Cited by name |
| STIX 2.1 | OASIS Standard, with Errata 01 (2025-04-02) | Cited: indicator, confidence 0–100 |
| CACAO 2.0 | Committee Specification 01 (2023-11-27) | Cited: playbook, workflow step types |
| FIRST TLP 2.0 | Authoritative from August 2022 | The four labels and AMBER+STRICT, cited |
| OpenTelemetry logs data model | As published | Cited only (S11) |

## 5. Changes after the independent review (2026-10-12)

- **Tenant separation in the contracts**: every reverse lookup (health observations, playbook versions, simulations, detection tests, assessments, closures, exemptions, mappings) keeps only the organisation's own records; others are withheld and reported. Injection tests added.
- **Dating in secops/v1**: coverage statements, tests, playbook versions, simulations, alerts and reportability assessments are taken on or before the date asked; undated ones are left out; statuses are documented as last recorded.
- **One approval validity rule** for the SHACL warning, CQ-SOAR-02 and secops/v1: outcome approved; decided and valid at the start; not denied or revoked before it; about this execution, its action or its risk class; made by a gate authority when the gates name one. New property *revoked on*; approval status and decision outcome checked for agreement.
- **No accidental incident classification**: the domains of *has incident category*, *has incident severity* and *has observed impact*, and the ranges of *concluded incident*, *communication about* and *recovery after*, were removed and replaced by SHACL checks; an investigation is disjoint from an incident.
- **A test is not a measure's effectiveness**: detection tests and playbook simulations are left out wherever a control measure's latest result is reported (dss/v1, compliance/v1, POL CQ02/04/07).
- **CQs**: CQ-SIEM-06 reads the ATT&CK version the rule was mapped against (*reference version*); CQ-SIEM-05 only current statements and approved mappings; CQ-SIEM-02 includes rules deployed for testing; CQ-SIEM-04 requires an effective test of a provider for validated coverage.
- **Reuse**: a response playbook is a procedure; *verified at* replaced by *assessed on*; behavioural baselines use the period properties.
- **Licensing**: the OCSF NOTICE is reproduced; the TLP:RED meaning is a CRGO paraphrase.
