# CRGO 0.10.0 — Phase 0: policy, compliance and audit management

Status: **proposed — awaiting MAL review** · Date: 2026-10-12 · Baseline: CRGO 0.9.1 (883 approved terms, 13 modules)

Inputs:

- **POL**: *Information Security Policy Governance, Compliance Traceability and Assurance*, O-ISPMS-001 v1.0.
- **CMP**: *Compliance management extension*, v1.0, dated 2026-10-12.
- **AUD**: *Audit management extension*, v1.0, dated 2026-10-12.

Nothing has been built yet. This document gives four things for review:

1. The reconciliation (merge) matrix that all three specifications ask for before any edit.
2. The improvements I propose beyond the specifications.
3. A module and version plan.
4. The decisions I need from you.

## 1. Summary

CRGO 0.9.0 already covers much of what the three specifications describe:

| Module | What it already models |
|---|---|
| `crgo-governance` | Policy, policy statement, technical standard, procedure, policy exception, compensating control, decision records, roles, delegation and independence. |
| `crgo-grc` | Legal instruments and versions, applicability, compliance determination, nonconformity and regulatory change. |
| `crgo-audit` | Audit universe through to finding closure. |
| `crgo-assurance` | Sampling, evidence sufficiency and external assurance reports. |

The three specifications propose 89 candidate classes. Several are named in more than one specification, and the matrix in section 2 groups those that share a row. Here is how the rows split:

| Specification | Matrix rows | Reuse an existing CRGO term (same meaning) | Add as new | Exclude | Your decision |
|---|---|---|---|---|---|
| POL (34 classes) | 34 | 23 | 9 | 2 | — |
| CMP (26 classes) | 24 | 11 | 11 | 1 | D5 |
| AUD (29 classes) | 23 | 14 | 7 | 1 | D7 |

Once the overlaps between specifications are merged, **27 new classes** remain, or 28 if D5(a) is chosen. Adding the value sets and properties gives an estimate of **about 150 new terms**, which would use IDs 885 to about 1035.

**No existing IRI changes meaning.** Two existing terms would get a wider definition or range (see D9). Nothing is deprecated.

The specifications also conflict with each other, and with CRGO's existing architecture decisions, in places. Section 5 lists these conflicts with a proposed resolution for each.

## 2. Reconciliation matrix

Key to the Action column:

- **reuse**: use the existing CRGO term as it is.
- **reuse+**: reuse it and add a property or a value.
- **new**: create a new term.
- **excl**: exclude it.

### 2.1 Policy management (POL)

| Proposed (POL) | Existing CRGO term | Action | Rationale |
|---|---|---|---|
| PolicyDocument | `Policy` (governance) | reuse | Same meaning: a document of formal direction. |
| PolicyFamily | none | **new** `PolicyFamily` | A grouping of related directives. Needed for POL CQ03 and CQ08. |
| PolicyVersion | none (`InstrumentVersion` exists only for legal instruments) | **new** `DirectiveVersion`, with `PolicyVersion` as a subclass | Separates the document from its frozen releases. Covers standards, procedures and the audit charter as well (improvement I3). |
| PolicyRequirement | `PolicyStatement` | reuse+ | Add the alternative label "policy requirement", plus `hasNormativeModality` and `statementInVersion`. |
| PolicyClause | none | **new** `PolicyClause` | Where a statement sits in a version (section number). Lightweight; optional in data. |
| NormativeStatement | none | **new value set** `NormativeModality` (must, should, may, must not) | Modality is better modelled as an attribute than as a superclass. A superclass would force reclassification of the existing `PolicyStatement`. |
| PolicyStandard | `TechnicalStandard` | reuse | |
| PolicyProcedure | `Procedure` | reuse | |
| PolicyGuideline | none | **new** `Guideline` | Non-mandatory guidance. Declared disjoint from `PolicyStatement` so that guidance can never be read as a binding requirement. |
| PolicyTemplate | none | excl | Authoring artefact belonging to the application (POL section 1 also puts the policy editor out of scope). |
| PolicyApproval | `DecisionRecord` + `decisionOn` a version | reuse | The approval is a decision about an exact version. |
| PolicyReview | none (`ExceptionExpiryReview` is specific to exceptions) | **new** `DirectiveReview` | A periodic or event-driven review, with `reviewTrigger`. |
| PolicyAcknowledgement | none | **new** `PolicyAcknowledgement`, under a new `Attestation` superclass | An acknowledgement concerns an exact version. It is not compliance, and the two are made disjoint (I2). |
| PolicyAssignment | `ApplicabilityAssessment` + `RoleAssignment` | reuse+ | Widen the documented scope of applicability to policy statements (D9). |
| ApplicabilityRule | `ApplicabilityCondition` | reuse+ | Shared by POL and CMP. Add `ruleVersion`. |
| OrganizationalContext | organisation profile (`crgo-org`) | excl | Already handled as organisation-profile facts used by applicability conditions. |
| PolicyException | `PolicyException` | reuse+ | Add `authorisedByRiskAcceptance` → `RiskAcceptance`. |
| CompensatingControl | `CompensatingControl` | reuse | |
| RiskAcceptanceDecision | `RiskAcceptance` | reuse | |
| PolicyChangeEvent | `RegulatoryChange` (external) + new `ReviewTrigger` value set | reuse+ | An event class adds little. A value set of trigger kinds is enough, and it links to a `RegulatoryChange`, incident or finding when there is one. |
| ControlImplementation | `ControlMeasure` | reuse | |
| ControlAssessment | `ControlAssessment` | reuse | |
| EvidenceArtifact | `EvidenceRegisterEntry` (evidence item) | reuse | Already has a locator, hash, access restriction and validity. |
| AuditFinding | `AuditFinding` | reuse | |
| RemediationAction | `CorrectiveAction` | reuse | |
| ComplianceAssessment | `ComplianceDetermination` | reuse | POL means a per-requirement result. CMP uses the same name for a campaign (see section 5). |
| RegulatoryObligation | `LegalObligation` | reuse | |
| FrameworkRequirement | `FrameworkRequirement` | reuse | |
| ExternalSourceEdition | `SourceRecord` + `InstrumentVersion` | reuse | |
| ActorRole | `GovernanceRole` | reuse | |
| AssignmentOfAccountability | `RoleAssignment` | reuse | Already temporal (valid from / valid until). |
| MappingAssertion | none (mappings are direct triples, with approval kept in `approvals.tsv`) | **new** `MappingAssertion` | Shared with CMP's ControlObligationMapping (I1). |
| TrainingRequirement | none | **new** `TrainingRequirement` (D7) | Small. Keeps learning distinct from attestation. |
| ComplianceEvidencePeriod | `periodStart` / `periodEnd` | reuse | Existing data properties. |

### 2.2 Compliance management (CMP)

| Proposed (CMP) | Existing CRGO term | Action | Rationale |
|---|---|---|---|
| ComplianceSource | `LegalInstrument`, `Framework`, `SourceRecord` | reuse+ | Add instrument kinds "contract" and "directive (EU-type)". Voluntary standards are covered by `FrameworkAdoption` (below). |
| LegalProvision | provision concepts (`vocab/loi25`, `gdpr`…) + `provisionOf` | reuse | |
| ComplianceObligation | `LegalObligation` | reuse | |
| ObligationVersion | `InstrumentVersion`, `Amendment` (versioning at instrument level) | **D5** | Options are given in D5. |
| RequirementInterpretation | none | **new** `RequirementInterpretation` | A reviewed reading of an obligation, with assumptions, legal-review state and a privilege flag. |
| ApplicabilityRule / ApplicabilityDetermination | `ApplicabilityCondition` / `ApplicabilityAssessment` | reuse+ | Add `ruleVersion`, `missingFact` and `factRelied`. "Conditional" is a property of the rule, not a state. |
| Jurisdiction | `Jurisdiction` (org) | reuse | |
| RegulatoryAuthority | `issuer` (a string on `SourceRecord`) | **new** `RegulatoryAuthority` | Needed for `issuedBy`, `enforcedBy`, submissions and exemptions. |
| ComplianceProgram | none | **new** `ComplianceProgramme` | The organisation's compliance management system and its scope (ISO 37301 clause 4.3, cited by number only). |
| ComplianceObjective | `BusinessObjective` | **new** subclass `ComplianceObjective` | |
| ComplianceAssessment (campaign) | none | **new** `ComplianceAssessmentCampaign` | Groups `ComplianceDetermination`s under one scope, period and method. |
| AssessmentResult | `ComplianceDetermination` | reuse | `ComplianceState` already holds satisfied / partially satisfied / unsatisfied / not assessed / undetermined. "Not applicable" stays with applicability (D10). |
| EvidenceArtifact / EvidenceEvaluation | `EvidenceRegisterEntry` / `EvidenceSufficiencyAssessment` | reuse+ | Add the sufficiency values "sufficient with limitations", "unavailable" and "not yet reviewed". |
| ComplianceFinding / Nonconformity | `Nonconformity` | reuse | |
| CorrectiveAction / EffectivenessVerification | `CorrectiveAction` / `FollowUpVerification` | reuse+ | Closure currently only covers audit findings. Extend it to nonconformities (D9). |
| RegulatoryChange | `RegulatoryChange` | reuse | |
| ComplianceDeadline | none (`notificationDueBy` covers incidents only) | **new** `ComplianceDeadline` | Calendar- or event-triggered, with computation metadata. |
| RegulatorySubmission | none | **new** `RegulatorySubmission` | Notice or filing, its state and the receipt evidence. Links to `BreachReportabilityAssessment`. |
| ComplianceException | none (and `PolicyException` is already barred from waiving law) | **new** `RegulatoryExemption` | Granted by an authority, with its legal basis. Internal approval cannot be modelled this way. |
| ComplianceRiskLink | `triggersObligation`, `findingAboutScenario` | reuse+ | Add the property `obligationAtStakeIn` (obligation → scenario). A link class is not needed. |
| ControlObligationMapping | none | **new** → `MappingAssertion` (I1) | |
| ThirdPartyComplianceRecord | `ExternalAssuranceReport` + `SupplierRole` | excl | Already covered. |
| ComplianceAttestation | none | **new** `ComplianceAttestation`, under `Attestation` | |
| — (CMP section 8) | — | **new** `FrameworkAdoption` | A dated decision by which an organisation adopts a voluntary framework, turning its requirements into internal commitments (I4). |

### 2.3 Audit management (AUD)

| Proposed (AUD) | Existing CRGO term | Action | Rationale |
|---|---|---|---|
| AuditFunction | `ChiefAuditExecutiveRole`, third-line role | **new** `AuditFunction` | The organisational unit, as opposed to the role. |
| AuditCharter | none | **new** `AuditCharter` | A directive, so it is versioned through `DirectiveVersion`. |
| AuditUniverse / AuditableEntity | same | reuse | |
| AuditPlan | `AuditPlan` + `supersedes` | reuse | Plan versions use the existing supersession. |
| AuditPlanEntry | none (only `plannedEngagement`) | **new** `AuditPlanEntry` | Priority rationale, state (proposed, approved, deferred, cancelled, completed), deferral and authoriser. Needed for AUD CQ-09. |
| AuditEngagement | same | reuse+ | Add value sets `EngagementType` and engagement state. |
| AuditObjective / AuditCriterion | same | reuse | |
| AuditScope | `assessmentScope` + period | excl as a class | A scope class would only hold properties that already exist. |
| AuditProgramme / AuditProcedure | `AuditWorkProgramme` / `AuditProcedure` | reuse | |
| AuditTestExecution | `ControlAssessment` + `executesProcedure` + `performedInCapacity` internal audit | reuse | Already models one execution against a population. |
| AuditPopulation / AuditSample | `Population` / `SamplingPlan`, `SampleItem` | reuse | Sampling plan already has method, size and rationale. Add `samplingSeed`. |
| AuditWorkpaper | none | **new** `AuditWorkpaper` | `preparedBy` and `reviewedBy`, plus a SHACL self-review check. |
| AuditEvidenceReference | `EvidenceRegisterEntry` + `EvidenceRequest` | reuse | The specification itself asks not to duplicate evidence. |
| AuditObservation | none | **new** `AuditObservation` (D8) | A preliminary record that is not yet a conclusion. Disjoint from `AuditFinding`, linked by `validatedAs`. |
| AuditFinding / AuditRecommendation / ManagementResponse | same (`Recommendation`) | reuse+ | Add `hasRootCauseCategory` (I5). |
| AuditActionReference | `CorrectiveAction` | reuse | A shared action, as the specification requires. |
| AuditFollowUp | `FollowUpVerification` | reuse | |
| AuditConclusion / AuditReport | same | reuse+ | Add report audience and revision. Approval goes through a `DecisionRecord`. |
| AuditQualityReview | none | **new** `AuditQualityReview` | Kinds: supervisory review, internal quality assessment, external quality assessment. |
| IndependenceDeclaration | `ConflictOfInterestDeclaration` + `IndependenceAssessment` | reuse | |
| AuditorCompetency | none | **D7** | Personal data. Proposed: exclude, or a minimal qualification record. |
| AuditMethodology | `AssessmentMethod`, `SamplingMethod`, `significanceMethod` | **new** `AuditMethodology` | A directive naming the methodology version. Engagements cite it. |
| AssuranceStatement | `AssuranceOpinion` + `evidenceLimitation` | reuse | |

### 2.4 Properties and data properties (summary)

- **POL**: about 24 object properties and 17 data properties are proposed.
  - 12 are reused, for example:
    - `derivedFromRequirement` ≈ mapsToObligation and mapsToFrameworkRequirement;
    - `exceptionTo`, `compensatedBy`, `assessedBy`, `hasEvidence`, `effectiveOn`, `versionLabel`, `localIdentifier` (= canonicalId), `evidenceLocator`, `evidenceHash`, `officialCitation`, `hasJurisdiction`.
  - The rest are new, for example:
    - `statementImplementedBy` (statement → measure);
    - `intendedToMitigate` (statement → scenario; rationale only, never a risk reduction);
    - `appliesToScope`, `requiresTraining`, `authorisedByRiskAcceptance`;
    - `retiredOn`, `reviewDueOn`, `reviewIntervalMonths`.
- **CMP**: about 17 properties.
  - 7 are reused (`provisionOf`, `complianceWith`, `hasEvidence`, `corrects`, `changeOf`, `hasJurisdiction`, `concernsOrganisation`).
  - About 12 are new: `interpretationOf`, `issuedByAuthority`, `enforcedBy`, `deadlineFor`, `deadlineTriggerKind`, `dueOffsetDays`, `submissionTo`, `receiptEvidence`, `exemptionFrom`, `grantedBy`, `legalBasis`, `adoptsFramework`.
- **AUD**: about 27 properties.
  - About 19 are reused (most of the `crgo-audit` ones).
  - About 10 are new: `entryInPlan`, `entryForEngagement`, `deferralReason`, `priorityRationale`, `workpaperFor`, `preparedBy`, `reviewedBy`, `validatedAs`, `qualityReviewOf`, `followsMethodology`.

The specifications' datatypes are adjusted to CRGO practice:

- Dates use `xsd:dateTime`, not `xsd:date` (HermiT's datatype map, ADR-006).
- Offsets use `xsd:nonNegativeInteger` days, not `xsd:duration`, which is outside the OWL 2 datatype map.
- Free-text properties have no range, so labels can be language-tagged.

## 3. Proposed improvements beyond the specifications

**I1 — `MappingAssertion` as the single qualified-crosswalk class.** It covers POL MappingAssertion and CMP ControlObligationMapping, with:

- source and target;
- `hasMappingType`, a value set of: exact, full coverage, partial coverage, broader, narrower, related, conflicting;
- the source edition, rationale, confidence (0–1) and reviewer;
- governance status and a validity interval.

This aligns with the existing direct properties in `crgo-mapping` (`broaderThan`, `narrowerThan`, `partiallyOverlaps`, `supportsComplianceWith`) through a documented correspondence, not through property chains. The 161 k approved reference mappings stay as direct triples (D6). `MappingAssertion` is meant for organisation crosswalks and for the reference mappings you choose to qualify. A SHACL rule makes a mapping of type exact or full coverage invalid without a rationale, reviewer, date, source edition and approval.

**I2 — `Attestation` superclass** for `PolicyAcknowledgement` and `ComplianceAttestation`. A disjointness axiom keeps it apart from `ComplianceDetermination` and `AuditConclusion`, which encodes the rule in all three specifications that an acknowledgement or a management attestation is not compliance and not an audit conclusion. Each attestation carries the knowledge status `KsManagementDecision`.

**I3 — Directive lifecycle, generalised.** It applies to policy, standard, procedure, guideline, charter and methodology, and consists of:

- `DirectiveVersion`;
- the value set `DirectiveLifecycleState` (draft, under review, approved, published, retired, superseded);
- `retiredOn`, `reviewDueOn` and `reviewIntervalMonths`.

It is kept strictly separate from `governanceStatus`, which is about CRGO's own terms and not about an organisation's documents.

**I4 — `FrameworkAdoption`.** CRGO can currently say what a framework requires, but not that an organisation has committed to it. Adoption is dated and scoped. It is what makes a voluntary standard's requirements apply to that organisation, and it lets compliance be queried uniformly across law, contract and voluntary standards.

**I5 — `RootCauseCategory` value set**, with CRGO's own scale (people, process, technology, governance, third party, design, resourcing). It is shared by audit findings and nonconformities and supports AUD CQ-10 and CMP CQ-9 (recurring causes). As with the 0.9.0 scales, it is an own scale, not a standard's.

**I6 — Lifecycle-aware SHACL profiles** (POL section 8). Constraints apply according to the directive lifecycle state, so that drafts are not held to publication rules. For example, a published version must have an effective date and an approval decision, and a draft need not. This is implemented with `sh:targetClass` + `sh:condition`-style SPARQL targets.

**I7 — Tenant boundary for the new records (ADR-008).** Policies, versions, exemptions, submissions, workpapers and attestations are organisation records. They live only in organisation graphs, under that organisation's declared base, and the existing `check_tenants.py` is extended to cover them. CRGO publishes only the classes, the value sets and the reference vocabularies.

**I8 — Read contract for the application.** The specifications' "lookup service" and "event exchange" belong to the application. On the ontology side, I propose a read-only, versioned JSON contract `contracts/compliance/v1` with three views, returned by one new MCP tool `crgo_compliance_context`. Its shape follows `dss/v1`, and it has no write-back. The three views are:

- obligation → policy statement → control measure → assessment → evidence, with as-of dating;
- active exceptions and exemptions;
- open findings and nonconformities.

This would make it easier for you to integrate into the CRG app afterwards. **D11** asks whether to do it now or defer it.

**I9 — Source editions to verify.** POL and CMP cite these sources:

- ISO 37301:2021/Amd 1:2024;
- ISO/IEC 27001:2022 Annex A 5.1;
- ISO/IEC 27002:2022 5.1;
- CSF 2.0 GV.PO;
- SP 800-53 Rev. 5 PL-1.

CSF GV.PO-01/02, SP 800-53 PL-1 and ISO/IEC 27002 5.1 are already in the vocabularies. The 37301 amendment is **not** in the source registry, and I have not verified it. See D12.

## 4. Modules, version and plan

**Modules.** I recommend two new modules and an extension of an existing one, keeping the file-level modularity of 0.9.0:

| Module | Imports | Contents |
|---|---|---|
| `crgo-policy` (new) | `crgo-governance` | Directive versions and lifecycle, clauses, guidelines, families, reviews, attestations and acknowledgements, training requirements. |
| `crgo-compliance` (new) | `crgo-grc`, `crgo-policy` | Programme, objectives, interpretations, authorities, adoption, campaigns, deadlines, submissions, exemptions, compliance attestations. |
| `crgo-audit` (extended) | +`crgo-policy`, `crgo-compliance` | Charter, function, plan entries, workpapers, observations, quality reviews, methodology. |
| `crgo-mapping` (extended) | | `MappingAssertion` and the mapping-type value set. |

Further details:

- **Total modules**: 15.
- **IRIs**: opaque `CRGO_nnnnnnn` as usual.
- **Prefix**: no `crgop:` or `crgoc:` (see section 5).
- **Version**: **0.10.0** (minor version: additions, plus two backward-compatible widenings).

**Sprint plan** (stopping at each checkpoint):

| Step | Content | Checkpoint |
|---|---|---|
| P0 | This document | **now** |
| P1 | `src/spec_pca.py`: all terms with EN/FR labels, definitions, examples, sources and IDs from 885. Build. HermiT and ELK consistency. Review document of the new terms, all `proposed`. | Review the term list |
| P2 | SHACL (about 25 shapes, lifecycle profiles, self-review, closure of nonconformities, exemption authority, mapping qualification). Positive and negative fixtures (POL section 12 fixture list, CMP section 13, AUD section 11). | Review the shapes |
| P3 | Synthetic data: extend Nordelle with the information-security policy (approved v2 superseding v1, a draft v3), the privileged-access requirement (matches POL section 12 and AUD section 11 and reuses AUD-PAM-001), Loi 25 obligation, an active exception escalated to risk acceptance, a stale assessment, a finding past its due date, a regulatory submission, a CAI notice deadline, and Boréal as the second tenant. The 30 specification CQs (10 + 10 + 10) as `tests/pca_cq/*.rq`, with expected results. | Review the CQ results |
| P4 | (If D11 = yes) `contracts/compliance/v1` + MCP tool + contract tests. | Review the contract |
| P5 | `check.sh` steps, docs (model guide, reuse register, migration note), CHANGELOG, independent review, then your approval → release 0.10.0 and an updated CRG brief. | Approval to release |

**Migration.** No existing published data needs migrating:

- The only organisation data are the synthetic Nordelle and Boréal fixtures and MediBec. These are regenerated, and MediBec is untouched.
- Existing `derivedFromRequirement` links stay valid. A `MappingAssertion` can be added on top to qualify them.
- Rollback means reverting to 0.9.1, because no IRI is removed or redefined.

## 5. Conflicts and their proposed resolutions

| # | Conflict | Proposed resolution |
|---|---|---|
| C1 | POL proposes the namespace `<base>/ontology/policy-management/1.0`, prefix `crgop:` and readable term names. CMP proposes `crgoc:`. | Keep ADR-001: opaque `CRGO_nnnnnnn` terms under `https://w3id.org/crgo/`, with module IRIs `crgo/crgo-policy` and `crgo/crgo-compliance`. A separate namespace would break the single-namespace contract the CRG app already relies on. |
| C2 | Human-facing IDs (POL-0001, PREQ-000001…) | These are the organisation's `localIdentifier` values in its own graph. CRGO does not mint them. |
| C3 | "ComplianceAssessment" means a per-requirement result in POL and a campaign in CMP. | Use `ComplianceDetermination` (existing) for the result and a new `ComplianceAssessmentCampaign` for the campaign. |
| C4 | `xsd:date` (reviewDueAt) and durations | Use `xsd:dateTime` and integer days (HermiT). |
| C5 | `statementText` as rdf:langString containing "exact controlled requirement text" | Allowed for an organisation's own policies, in its own graph. Never for licensed standard text (rule R-d), which is enforced by the existing licence checks. |
| C6 | POL has `mitigatesRiskScenario`. Core has `mitigatedBy` (scenario → control measure), which implies an effect. | A new, weaker `intendedToMitigate`, with the documented caveat "rationale only". It is not a sub-property of `mitigatedBy`. |
| C7 | POL `implementedBy` (requirement → implementation) vs the existing `implementedByProcedure` | Add a separate `statementImplementedBy` (→ control measure). Keep the procedure link. |
| C8 | AUD wants an AuditTestExecution class | Reuse `ControlAssessment` with `executesProcedure`, which is already the 0.9.0 pattern. Not every audit test is of a control, so D8 covers non-control tests. |

## 6. Decisions for MAL

Each decision has my recommendation in **bold**.

- **D1 Modules.** Options:
  - **(a) two new modules, `crgo-policy` and `crgo-compliance`, plus extensions to `crgo-audit` and `crgo-mapping`** (section 4);
  - (b) put everything in the existing governance, grc and audit modules.
- **D2 Namespace.** **Keep CRGO opaque IRIs and the single namespace (C1).** The specifications' prefixes would only be documentation aliases.
- **D3 Target version.** **0.10.0.**
- **D4 Policy versioning.** **A generalised `DirectiveVersion` with a `PolicyVersion` subclass (I3).** The alternative is a version class for policies only.
- **D5 Obligation versioning** (CMP Source → Edition → ProvisionVersion → ObligationVersion). Options:
  - **(a) keep instrument-level versions (`InstrumentVersion`, `Amendment`) and add `ProvisionVersion` only when an amendment changes a provision's wording, which is what reproducing historical assessments needs**;
  - (b) a full `ObligationVersion` for every obligation, which would add about 300 nodes for Loi 25, GDPR, PIPEDA and the rest without new information.
- **D6 MappingAssertion scope.** Options:
  - **(a) for organisation crosswalks, plus newly reviewed reference mappings; the 161 k approved direct mappings are not reified**;
  - (b) generate a `MappingAssertion` for every existing mapping.
- **D7 Personal-data-adjacent classes.** I recommend:
  - **`TrainingRequirement`: include.** It is generic.
  - **`AuditorCompetency`: exclude.** It is an HR record about people, and CRGO already has role assignments and independence.
  - **`PolicyAcknowledgement`: include as a class.** Instances stay in organisation graphs or the app (POL section 1 excludes employee PII).
- **D8 Observation vs finding.** **A separate `AuditObservation` class, disjoint from `AuditFinding` and linked by `validatedAs`.** This keeps the 0.9.0 rule that a finding carries `KsAuditConclusion`. The alternative is a state value on `AuditFinding`.
- **D9 Two widenings of existing terms**, which are backward compatible but change inferences:
  - (i) the range of `closesFinding` becomes audit finding **or** nonconformity, so that compliance nonconformities can be closed through the same verified-closure pattern;
  - (ii) the definitions of `ApplicabilityAssessment` and `ApplicabilityCondition` are widened from legal instruments to policy statements as well.

  **Approve both.**
- **D10 "Not applicable" as an assessment conclusion.** **Do not add it to `ComplianceState`.** Applicability stays a separate determination, and a SHACL rule forbids a compliance determination for a requirement assessed as not applicable at that date.
- **D11 Application contract.** **Yes, build `contracts/compliance/v1` and `crgo_compliance_context` in this release (P4)**, so the CRG app update has a stable read interface. The alternative is to defer it to the app phase.
- **D12 ISO 37301:2021/Amd 1:2024.** Can you confirm that this amendment exists and is relevant (I have not verified it), and should I add it to the source registry as identifier and title only? If you have no access to it, I will cite only the 2021 edition, which is already registered.
- **D13 Root-cause categories (I5) and the other new value sets.** **CRGO's own scales**, the same approach you approved for the 0.9.0 scales. The value sets are:
  - normative modality;
  - directive lifecycle;
  - review trigger;
  - mapping type;
  - engagement type;
  - plan-entry state;
  - quality-review kind;
  - legal-review state;
  - submission state;
  - deadline trigger.
- **D14 Spec CQs.** **Implement all 30 as written, adapted only in vocabulary.** POL CQ09 ("published employee answer") is reinterpreted as "which version and source were in force on date D for statement S", because CRGO has no employee answers.

After your answers I will start P1 and stop at the term-list review. Nothing will be pushed.
