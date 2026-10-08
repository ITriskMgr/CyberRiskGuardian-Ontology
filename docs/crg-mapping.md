# CyberRiskGuardian → CRGO mapping

`pipeline/crg/crg2rdf.py` converts a CRG assessment file (the JSON data model of
`assets/scenario-template.json`) into CRGO instance data. Risk quantities are computed by CRG's own
`crg_calc.py`, loaded from the CRG repository, so the graph reproduces CRG's numbers exactly.
`tests/crg/check_roundtrip.py` checks this on the MediBec teaching case: totals 84,491 estimated
and 41,104 residual (CRG's regression values), and all 20 stored sensitivity cases.

| CRG key | CRGO | Notes |
|---|---|---|
| `APPETITE`, `FACTOR` | RiskAssessment `hasRiskAppetite` → RiskAppetiteStatement `numericValue`; `assessmentFactor` | |
| `CASE_APPETITE`, `PERIOD`, `CURRENCY` | `caseAppetite`, `assessmentHorizon`, `currencyCode` | |
| `SOURCE` | `rdfs:comment` on the assessment | |
| `EVIDENCE` [id, title, basis, summary] | EvidenceItem `localIdentifier`, `evidenceLocator`, `hasEvidenceBasis`, `rdfs:comment` | Basis by keyword: documented → documented evidence; exercise/simulation → exercise evidence (new in 0.2.0); external, methodology, calibration → external evidence; expert → expert input; AI or analyst estimate → AI estimate; assumption → analyst inference. The original string is kept. |
| `CROWN` [id, name, purpose, owner, C, I, A, dependencies, provider] | Asset + AssetValuation (`isCrownJewel`, `purposeText`, C/I/A requirement levels) | Asset subclass is not stated in CRG, so assets are typed `Asset`. Owner, dependencies and provider stay text. |
| `SCEN[].id, name, statement, background, narrative` | AssessmentScenario `localIdentifier`, `rdfs:label`, `statement`, `background`, `narrative` | |
| `threat_source`, `threat_event`, `vulns[]` | ThreatSourceDescription, ThreatEventDescription, VulnerabilityDescription (labels) | Evidence IDs in the text become `hasEvidence`. |
| `assets` | `affectsAsset` for each crown-jewel ID mentioned (CJn); full text as comment | |
| `controls[]` | ControlMeasure, status *in place*, linked by `mitigatedBy` | CRG lists existing controls here. |
| `sequence[]` | ScenarioStep with `stepOrder` and `nextStep` | |
| `consequences{}` | ConsequenceDescription per key with ImpactDimension | "Confidentiality/privacy" → confidentiality and privacy; "Operations" → operational; "Regulatory" → legal and regulatory. |
| `params` {v, qual, rat, ev, conf} | ThreatPresence, ExploitationProbability, ExpectedDamage, MaximumDamage, Resilience, Criticality: `numericValue`, `qualitativeReading`, `rationale`, `hasEvidence`, `hasConfidence`, stage inherent | |
| `red_p`, `red_i` | ProbabilityReduction, ImpactReduction | |
| `cvss` vector, `cvss_note` | CVSSInput `cvssVector`, `cvssVersion`, `cvssSeverity`, `numericValue` (from crg_calc), `rationale` | |
| computed est, tol, mit, res, ratio, pre_ratio | EstimatedRisk, ToleratedRisk, MitigatedRisk, ResidualRisk, RiskToToleranceRatio, PreTreatmentRatio, `generatedBy` the calculation activity, `usedInput` the inputs, `inSensitivityCase` an explicit central case | Tolerance class on the ratio. |
| `SENS_IDS` | SensitivityCase lower and higher (±0.10, clamped to [0.05, 0.99] by crg_calc) with their est, res, ratio | |
| `treatment`, `horizon` | RiskTreatmentDecision (option *risk modification*) `treatmentSummary`, `treatmentHorizon` | |
| `INITIATIVES` [id, name, description, scenarios, owner, priority, initial, recurring, start, end, success, prerequisite, function] | TreatmentInitiative with `addresses`, `hasPriority`, costs, dates, `successIndicator`, `hasControlFunction` | Owner as text. |
| `KRIS` [id, name, scenarios, method, source, owner, frequency, target, warning, critical] | KeyRiskIndicator with `monitors` and the text fields | |
| `CANDIDATES` [id, name, …, disposition, rationale] | AssessmentScenario with `hasDisposition` (selected, consolidated) and `rationale`; the selected scenario `refines` its candidate | "Not selected" has no matching disposition value and is kept as text. |
| `stakeholders`, `processes`, `owner`, `ref` | `rdfs:comment` | Lossy until positions and processes are modelled (deferred L15). |
| `TOT_INITIAL`, `TOT_RECUR`, `alloc_*`, `cost_y1`, `ce` | not converted | Derivable; cost allocation per scenario is a later step. |
