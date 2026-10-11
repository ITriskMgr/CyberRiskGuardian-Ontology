# GRCA extension: Phase 0 audit and first-sprint plan

Prepared 2026-10-11 for *CRGO Governance, Risk, Compliance and Assurance (GRCA) Audit: Claude Implementation Specification* (v1.0, 11 October 2026). Baseline: the repository at commit `fc8a4e4` (0.9.0, approved, not yet released), which already contains Sprint 1 of the v0.8 → v1.0 specification. The full Stage 0 audit of that baseline is in `baseline_inventory.md`, `source_registry.csv` and `gap_analysis.md`; this document covers only what the GRCA specification adds.

## 1. Coverage matrix: GRCA specification against CRGO 0.9.0

Legend: **●** present · **◐** partly · **○** absent.

| Spec section | Required | In 0.9.0 | |
|---|---|---|---|
| §4 Governance | governing bodies, committees, Three Lines roles, CAE, compliance officer, control and risk owner roles, policy, objectives, appetite, decisions, oversight, independence, temporal role assignment; accountableFor, ownsRisk, operatesControl, oversees, reportsTo, delegatesAuthorityTo, requiresIndependenceFrom; role-conflict checks | risk owner, owner, risk appetite statement, risk treatment decision, risk acceptance (authority, expiry), business objective, *decided by*; organisations from CCO | ◐ |
| §5 Enterprise risk and RCSA | process, objective, scenario, threat event, vulnerability, predisposing condition, consequence, assessment, estimate, appetite, tolerance, control implementation, control self-assessment vs effectiveness assessment, response; inherent / current / projected residual; risk types | all core risk classes; estimates with method, horizon, evidence, assumption; inherent and residual stages; CRG tolerance; control measure; control assessment (0.9.0) | ◐ no self-assessment vs independent assessment distinction; no *current* vs *projected* residual; no risk-type distinction |
| §6 Compliance | instrument, **instrument version**, provision, requirement, obligation, obligated party, applicability, control objective, policy requirement, evaluation, determination, **nonconformity**, **regulatory change**, compliance risk, **waiver / exception**, **evidence requirement**; *supports* ≠ *proves* compliance; supersession | instrument, provisions, legal obligation, applicability conditions and assessments, compliance determination with evidence or gap, jurisdictions, dates (0.9.0) | ◐ |
| §7 Audit lifecycle | universe, auditable entity, plan, engagement, objective, scope, criteria, programme, procedure, method, evidence request, population, sampling plan, sample item, control test, test execution and result, observation, exception, finding, conclusion, report, management response, recommendation, corrective action, follow-up | control assessment (test act with procedure, scope, result, evidence); control gap finding (description only) | ○ |
| §8 Audit work-programme library | reusable programmes by domain with objective, criteria, control references, methods, evidence, population, sampling rationale, procedures, expected results, exception logic | — | ○ |
| §9 Assurance and evidence | typed evidence (documentary, configuration, transactional, operational, interview, observational, test, external assurance report, governance); custody, origin, method, date, population, boundary, hash, access, validity, limitations; explicit sufficiency assessment; SOC report scope, period, exceptions, CUECs | evidence register entry with basis (documented, external, expert, inference, AI estimate) and locator; source records with checksums (0.9.0) | ◐ |
| §10 Findings and remediation | criterion, condition, observed vs hypothesised cause, effect, severity method, scenario, owner, recommendation, response, action, due date, acceptance, verification, closure, reopening; monitoring exception ≠ audit finding | treatment initiative (dates, owner, cost); risk acceptance | ○ |
| §11 Crosswalk and epistemic rules | narrowerThan, broaderThan, partiallyOverlaps, supportsComplianceWith, fulfillsCriterion, evaluatesControl, producesEvidenceFor, mitigatesRiskScenario, justifiesRecommendation; MappingAssertion objects; knowledge status (reference fact, organisational observation, analytical hypothesis, risk estimate, audit conclusion, management decision, verified outcome) | 11 typed relations with source, confidence, status, approval (0.9.0); observation ≠ estimate ≠ assumption; AI proposals start *proposed* and are kept apart | ◐ no partial-overlap relations, no knowledge-status value set |
| §12 Integration | 800-53A bound to exact 800-53 control and version; CSF / COBIT to responsibilities; ISO 27002 to tests; scenarios to findings; ATT&CK etc. to test domains; laws as scoped obligations; EPSS/KEV as context only | 800-53 5.2.0 vocabulary; laws as scoped provisions; EPSS as observations | ◐ **800-53A is already in the installed NIST catalogue** (below) |
| §13 Competency questions | CQ-GRCA-01 to 12, each with positive, negative and unknown fixtures | specification CQ-03, 04, 05, 07, 08, 11 (0.9.0) | ○ |
| §3 Source statuses | VERIFIED / PENDING_ACCESS / LICENSE_RESTRICTED / REJECTED; extraction confidence, reviewer, import pipeline | 29 source records with version, licence, checksum, verification note | ◐ no status value |

## 2. A finding that changes the plan: SP 800-53A is already here

The OSCAL catalogue CRGO's SP 800-53 vocabulary was built from (`NIST_SP-800-53_rev5_catalog.json`, release 5.2.0, 2026-05-11) carries the SP 800-53A assessment content for every control and enhancement: **3,715 assessment objectives** (labelled in 800-53A form, e.g. `AC-02a.[01]`, each linked to the control statement it assesses) and **2,931 assessment-method parts** (examine 1,013, interview 1,012, test 906) with their assessment objects. It is a U.S. government work, already checksummed in the source registry, and exactly version-matched to the installed 800-53. The specification asked for two controls linked to 800-53A in the first sprint; the whole of 800-53A can be imported, with no licensing or version risk.

## 3. Source manifest for the GRCA sources (status to be confirmed)

| Tier | Source | Status now | Path |
|---|---|---|---|
| P0 | NIST SP 800-53A Rev. 5 (in the 800-53 5.2.0 OSCAL catalogue) | **VERIFIED** (file held, U.S. government work) | import in full |
| P0 | NIST OSCAL models (catalog, profile, SSP, assessment plan/results, POA&M) | VERIFIED (public, U.S. government work) | mapping target; export later |
| P0 | IIA Global Internal Audit Standards (2024) | PENDING_ACCESS / LICENSE_RESTRICTED (© IIA) | identifiers and short titles of domains, principles and standards with CRGO paraphrases, if you hold the PDF |
| P0 | IIA Topical Requirements (Cybersecurity; Third-Party) | PENDING_ACCESS / LICENSE_RESTRICTED | as above; effective dates to be verified on the texts |
| P0 | ISACA ITAF 4th edition | PENDING_ACCESS / LICENSE_RESTRICTED (© ISACA) | identifiers and paraphrases only |
| P0 | ISO 19011, ISO/IEC 27007, ISO/IEC TS 27008, ISO 37301, ISO 37302:2025 | LICENSE_RESTRICTED (paid) | metadata-only placeholders; clause identifiers only if you hold licensed copies |
| P1 | COSO Internal Control (2013) and ERM (2017) | LICENSE_RESTRICTED | component and principle identifiers with paraphrases, if you hold copies |
| P1 | IIA Three Lines Model (2020), ISO 37000 | PENDING_ACCESS / LICENSE_RESTRICTED | roles modelled from the published structure, no text |
| P1 | AICPA SOC 1/2/3, Trust Services Criteria | PENDING_ACCESS / LICENSE_RESTRICTED (© AICPA) | report types and criterion identifiers |
| P2 | GAO Government Auditing Standards (Yellow Book) | likely VERIFIED (U.S. government work) | later |

Nothing in this table has been downloaded or read yet except the NIST catalogue; statuses are my expectation from the publishers' usual terms and must be confirmed on each document.

## 4. Proposed first GRCA sprint

Additive, in new modules (decision D2 still applies: the existing modules are not modified).

| # | Work package | Deliverable | Acceptance test |
|---|---|---|---|
| 1 | Knowledge status | value set of the seven epistemic categories of §11, on records and assertions | SHACL: every finding, determination and estimate carries one |
| 2 | `crgo-governance` | governing body, board and audit committees, management, first/second/third-line roles, chief audit executive, compliance officer, control owner (BFO roles); temporal role assignment; policy; oversight activity; independence assessment; accountable for, oversees, reports to, delegates authority to, operates control, requires independence from | SHACL *warning* (not violation) when the same agent operates and independently assures a control (§4) |
| 3 | `crgo-audit` (includes remediation) | audit universe, auditable entity, plan, engagement, objective, scope, criterion, programme, procedure, assessment method (examine, interview, test), evidence request, population, sampling plan, sample item, test result, monitoring exception, finding (criterion, condition, observed vs hypothesised cause, effect, significance), conclusion, report, recommendation, management response, corrective action, follow-up verification, closure and reopening | finding needs criterion, condition and evidence; a monitoring exception becomes a finding only by an audit review; closure needs an independent verification |
| 4 | `crgo-assurance` | evidence subtypes; collected on, valid until, covered period and population, system boundary, integrity hash, custody, access restriction, limitations; evidence sufficiency assessment; external assurance report (SOC 1/2/3, type I/II, period, scope, opinion, exceptions, CUECs); control self-assessment vs independent assessment | stale or out-of-scope evidence flagged (CQ-GRCA-11) |
| 5 | Compliance additions (in `crgo-grc`) | instrument version and supersession, regulatory change, nonconformity, waiver / exception, evidence requirement, obligated party role; *supports compliance with* (never *proves*) | CQ-GRCA-02 |
| 6 | SP 800-53A vocabulary | 3,715 objectives and the methods and objects of every 5.2.0 control, linked to the exact control and enhancement | every objective resolves to an existing 800-53 concept |
| 7 | Mapping relations | narrower than, broader than, partially overlaps, supports compliance with, fulfils criterion, evaluates control, produces evidence for, mitigates risk scenario, justifies recommendation | typed, directional; SHACL as in 0.9.0 |
| 8 | Work-programme library | AUD-PAM-001 (privileged access) and AUD-VULN-001 (vulnerability remediation), marked illustrative, bound to 800-53A objectives (AC-2, AC-6, RA-5, SI-2 families) | each procedure cites the objectives it serves |
| 9 | Synthetic engagement | on Nordelle: a 2026 engagement over backup and recovery; the partly effective restore test becomes one finding with evidence, management response, corrective action and follow-up verification; one RCSA result that conflicts with the audit result | CQ-GRCA-08 and 09 end to end |
| 10 | Competency questions | CQ-GRCA-01, 02, 03, 04, 06, 08, 09, 11 with positive, negative and unknown fixtures | all pass |
| 11 | Source records | GRCA sources with status values (VERIFIED, PENDING_ACCESS, LICENSE_RESTRICTED, REJECTED) | no content imported from a restricted source |

Later sprints: CQ-GRCA-05, 07, 10, 12 (tolerance, SOC CUECs, regulatory change, treatment overlap), IIA and ITAF identifiers if you can supply them, COSO, OSCAL assessment-results export.

## 5. Decisions needed

| # | Decision | Recommendation |
|---|---|---|
| G1 | Release | Publish 0.9.0 now, as approved and tested, and make the GRCA sprint the next version (0.10.0), rather than enlarge 0.9.0 further |
| G2 | Modules | Three new modules (`crgo-governance`, `crgo-audit` with remediation, `crgo-assurance`); compliance additions go into `crgo-grc`; enterprise-risk additions go into these new modules, not into `crgo-core` |
| G3 | Control test | Keep the 0.9.0 *control assessment* as the test execution, and add who performed it (management self-assessment, second line, internal audit, external assurer) instead of a second test class |
| G4 | 800-53A | Import all 3,715 objectives now, not only two controls |
| G5 | Licensed sources | Tell me which of these you hold: IIA Global Internal Audit Standards and Topical Requirements, ISACA ITAF, ISO 19011 / 27007 / 27008 / 37301 / 37302, COSO, AICPA Trust Services Criteria. Without them, CRGO records metadata-only placeholders and blockers, and models the concepts from the specification without any source text |
