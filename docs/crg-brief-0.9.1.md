# Brief: update CyberRiskGuardian to use CRGO 0.9.1

**For:** Claude working in the CyberRiskGuardian (CRG) repository (`github.com/ITriskMgr/CyberRiskGuardian`).
**From:** the CRGO project. CRGO is the CyberRiskGuardian Ontology, release v0.9.1 (2026-10-12), at `github.com/ITriskMgr/CyberRiskGuardian-Ontology`. 0.9.1 is 0.9.0 plus a fix to the CRG bridge; the ontology itself is 0.9.0.
**Goal:** a new minor version of the CRG plugin (suggested 1.2.0) that uses what CRGO 0.9.x adds, without changing CRG's formulas or its evidence discipline.

Read this whole brief, then inspect the CRG repository as it is now before planning. This brief was written against CRG commit `f0cd36e` (plugin 1.1.1); if the repository has moved on, adapt. Plan first, show the plan to the project owner, and build only after approval.

---

## 1. What CRGO is, in one paragraph

CRGO is an OWL 2 ontology (BFO-2020, Common Core Ontologies) and a set of SKOS vocabularies that give a formal meaning to CRG's data: assets, threats, weaknesses, scenarios, controls, frameworks, legal obligations and the CRG v1.0c quantities. It ships with:

- a library of about 1,900 generic risk scenarios linked to MITRE ATT&CK, NIST CSF 2.0, SP 800-53 Rev. 5, ISO/IEC 27002:2022, Loi 25 and other regimes;
- a local MCP server that CRG already uses for scenario identification.

CRGO states facts, links and their review status. **It never computes risk.** All numbers still come from CRG's `crg_calc.py` and `crg-calculator` MCP tools.

## 2. What is new in CRGO 0.9.0

| Area | What CRG can now use |
|---|---|
| **Legal applicability** | Legal instruments (Loi 25/P-39.1, A-2.1, R-22.1, PIPEDA, OSFI B-13, GDPR, C-1.1) with 19 applicability conditions. An evaluator (`pipeline/grc/applicability.py`) answers *applicable*, *not applicable*, *potentially applicable* (needs qualified review) or *unknown* (a fact is missing) for an organisation profile. *Unknown* is never turned into *not applicable*. Compliance determinations are recorded with evidence or an explicit evidence gap. |
| **EPSS as observations** | EPSS scores are dated observations about a CVE (probability of exploitation in the next 30 days, plus percentile). They are **not** a scenario likelihood and must never be used as Pb(A) or Pb(ψ,A). |
| **Typed cross-references** | Each link says what it means: "technique mitigated by control", "control corresponds to control", "supports compliance with" and so on, each with a confidence and a review status. "Supports compliance with" never means "proves compliance". |
| **Control assessments** | A control test records its date, result (effective / partly / ineffective / not tested), evidence, the **assessor line** (management self-assessment, second line, internal audit, external assurer) and the **aspect** tested (design, implementation, operation). Operating-effectiveness tests also record their period, population, sample size and deviations. |
| **Governance** | Governing bodies and committees; Three Lines roles held by named people over dated periods; delegations of authority; decision records (approved / rejected / deferred / escalated, with rationale); policy exceptions (scoped, approved, compensated, expiring, and never able to waive a law). |
| **Audit and assurance** | Audit engagements, criteria, procedures, findings (criterion, condition, cause, effect, significance, evidence), recommendations, management responses, corrective actions, independent follow-up, closure and reopening. Also: evidence metadata (period, hash, custodian, validity), evidence-sufficiency judgements, SOC reports with exceptions and complementary user entity controls. |
| **Incidents (minimal)** | Security events, alerts, incident confirmation, breach-reportability assessments (Loi 25 s. 3.5, GDPR Art. 33), timelines and lessons learned. An incident **informs** a scenario's likelihood; it does not prove it. |
| **Epistemic status** | Every record can say what kind of claim it is: reference fact, organisational observation, analytical hypothesis, risk estimate, audit conclusion, management decision or verified outcome. |
| **New vocabularies** | NIST SP 800-53A (all 3,715 assessment objectives and their examine/interview/test methods, each tied to its exact SP 800-53 5.2.0 control); IIA Global Internal Audit Standards 2024 and Topical Requirements; ISACA ITAF 5th edition; AICPA 2017 Trust Services Criteria; COSO ERM 2017; the clause structure of ISO 19011, 27007, 27008, 37301 and 37302. |
| **Work programmes** | Two illustrative audit programmes, AUD-PAM-001 (privileged access) and AUD-VULN-001 (vulnerability remediation), whose procedures cite 800-53A objectives. They are illustrative, not a validated methodology. |
| **Data contract `dss/v1`** | JSON documents exchanged through two new CRGO MCP tools: `crgo_risk_context` (read) and `crgo_submit_assessment` (write back). See section 4. |
| **Tenant separation** | Each organisation's data lives in its own graph under its own IRI base, never under `https://w3id.org/crgo/`. CRGO tools never mix two organisations (ADR-008). |

Reference documents in the CRGO repository:
- `CHANGELOG.md` (0.9.0 entry);
- `docs/adr/ADR-007-crgo-dss-boundary.md`, `ADR-008-identifiers-and-graph-layers.md`, `ADR-009-governance-audit-assurance.md`;
- `contracts/dss/v1/README.md`;
- `docs/crg-integration.md`;
- `AGENTS.md`.

## 3. Connecting CRG to CRGO

CRG's `.mcp.json` (and the plugin's `.mcp.json`) should register CRGO next to `crg-calculator`. Adjust the path to where CRGO is cloned:

```json
"crgo-ontology": {
  "command": "python3",
  "args": ["../CyberRiskGuardian-Ontology/pipeline/mcp/crgo_server.py"]
}
```

- **Requirements:** `pip install "mcp>=1.2" pyoxigraph rdflib jsonschema`.
- **First call:** builds a local store (about 10 s).
- **Version:** pin to tag `v0.9.1` for reproducible assessments (v0.9.0 is not enough: it lacks the bridge fix in section 4). Record the ontology release in reports; the read document carries it as `ontologyRelease`.

**Tools (8):**

| Tool | Purpose | Status |
|---|---|---|
| `crgo_sweep` | Profile-wide scenario identification (start here) | unchanged |
| `crgo_identify` | Targeted scenario search | unchanged |
| `crgo_scenario` | Full detail of one scenario | now also returns weaknesses, D3FEND countermeasures, KEV evidence, EPSS observations and `other_regimes` (A-2.1, PIPEDA, GDPR, B-13) |
| `crgo_controls_for_technique` | Controls for an ATT&CK technique | unchanged |
| `crgo_scenarios_for_control` | Coverage of one control | unchanged |
| `crgo_list_values` | Allowed filter values | unchanged |
| `crgo_risk_context(org_graph_files, organization, scenario, as_of)` | Read the context of one organisation's scenario at a date | **new** |
| `crgo_submit_assessment(document, org_graph_files)` | Write a CRG result back, stored as *proposed* | **new** |

## 4. The data contract `dss/v1`

### Producing the organisation graph

The two contract tools work on RDF files describing one organisation. Convert a CRG assessment JSON with CRGO's bridge:

```
python3 <CRGO>/pipeline/crg/crg2rdf.py ASSESSMENT.json \
  --crg-calc plugins/cyberriskguardian/skills/cyber-risk-assessment/scripts/crg_calc.py \
  --base https://<organisation-namespace>/ --org-label "<organisation name>" --out <org>.ttl
```

- The output declares its base (`vann:preferredNamespaceUri`) and names the organisation `<base>org`.
- The bridge needs CRGO v0.9.1 or later. In v0.9.0 the output lacks the organisation and its base, and the contract tools refuse it.
- Use a base the organisation controls, or a private one (for example `urn:` or `https://example.org/<org>/` for tests). Never use `https://w3id.org/crgo/`.
- Keep these files with the client's confidential deliverables, never in either repository. CRG's data-protection rule applies.

### Read: `crgo_risk_context`

Returns a document valid against `contracts/dss/v1/risk-context.schema.json`. It contains:

- `scenario`: its IRI, label, kind and techniques. Its knowledge status is always *analytical hypothesis*.
- `relatedAssets`: assets the scenario affects, and assets they depend on.
- `candidateObligations`: for each, `applicability` (applicable, not-applicable, potentially-applicable, unknown or not-assessed), `unresolvedConditions`, `complianceState` and `evidenceGap`.
- `controlLinks`: for each control measure, `controlStatus`, `latestAssessments` (one per assessor line, with `result`, `line`, `aspect` and `assessedOn`) and `openFindings`.
- `estimates`: value, scale, confidence, `assumptions`, `distribution` and `evidenceQuality`.
- `evidenceRefs`, `ontologyRelease`, `asOf`, `caveats`.
- **No risk score.**

### Write: `crgo_submit_assessment`

Send a document valid against `contracts/dss/v1/assessment-result.schema.json`:

```json
{
  "schemaVersion": "1.0", "contract": "dss/v1",
  "organizationId": "https://<org-base>/org",
  "subjectId": "https://<org-base>/scenario-S1",
  "assessmentKind": "residual-risk",
  "modelId": "CyberRiskGuardian", "modelVersion": "<plugin version actually used>",
  "computedAt": "2026-10-12T09:00:00Z",
  "inputs": ["https://<org-base>/scenario-S1-PbA", "..."],
  "inputDocumentSha256": "<sha256 of the risk-context or CRG JSON actually used>",
  "ontologyRelease": "0.9.0",
  "result": {"value": 1234.5, "unit": "CRG risk units"},
  "status": "proposed",
  "provenance": {"producer": "CyberRiskGuardian", "tool": "crg_risk", "actor": "<analyst or service account>"}
}
```

- **`assessmentKind`** takes these values, mapped from the `crg_calc` / `crg_risk` outputs:

  | `assessmentKind` | Source |
  |---|---|
  | `estimated-risk` | `est` |
  | `tolerated-risk` | `tol` |
  | `mitigated-risk` | `mit` |
  | `residual-risk` | `res` |
  | `risk-to-tolerance-ratio` | `ratio`, with unit `ratio` |
  | `budget-target` | `budget_target`, with unit `currency` and an ISO 4217 code |
  | `sensitivity-case` | `sensitivity` |

  Send one document per quantity you want recorded.
- **`status`** must be `proposed`. CRGO stores the result as a proposed *risk estimate* in `<org>-dss-proposed.ttl`, next to the organisation file. A write-back is never an approval, a risk acceptance or a funding decision; those stay human decisions ("Management decision required").
- **`modelVersion`**: placeholders (`TBD`, `unknown`, `n/a`) are refused.
- **Errors** come back as `{"error": true, "code", "message", "details"}` with one of these codes: `SCHEMA_INVALID`, `UNKNOWN_ORGANISATION`, `UNKNOWN_SUBJECT`, `TENANT_MISMATCH`, `REFERENCE_NAMESPACE`, `STATUS_NOT_PROPOSED`, `MODEL_VERSION_MISSING`, `INPUT_UNKNOWN`. CRG should show the message to the analyst and stop, not retry with altered data.
- **Examples:** valid and invalid documents are in `contracts/dss/v1/examples/` in the CRGO repository.

## 5. Where each feature fits in CRG's 19-step workflow

These are suggestions for the `cyber-risk-assessment` skill and its agents. Keep the workflow's numbering and wording style.

| CRG step | Use of CRGO 0.9.0 |
|---|---|
| 1 Evidence register | Map CRG's evidence classes to CRGO knowledge status: verified organisational evidence → organisational observation; external/sector evidence → reference fact; assumption → assumption; analyst estimate → risk estimate. Where known, record the evidence period, validity date and custodian. Flag evidence that is out of date or out of scope (CRGO raises a warning for stale evidence). |
| 2 Context, obligations, jurisdictions | Build the organisation profile (type, establishment, markets, processing activities, data categories, transfers). Run the applicability evaluator, and say which properties the profile lists completely. Report *potentially applicable* regimes as "qualified review required", and *unknown* as "Evidence gap — organizational input required". Never present applicability as legal advice. |
| 2 Incidents and audit findings | Use confirmed incidents and open audit findings as evidence for scenarios and for control status. An incident informs a likelihood; it does not prove it. Monitoring alerts are not findings. |
| 5–7 Scenario selection | `crgo_sweep` / `crgo_identify` as today. `crgo_scenario` now gives the obligations under each regime (`other_regimes`). Use EPSS/KEV only as evidence that exploitation is happening in the wild, never as an organisational likelihood. |
| 8 Existing controls | Take control status from `crgo_risk_context.controlLinks`. Rely on independent results (second line, internal audit, external); treat management self-assessments as lower-grade evidence. When a self-assessment conflicts with an independent result, show **both** and flag the conflict (CRGO's CQ-GRCA-08). Open findings on a control lower confidence in it. |
| 9 Quantify | Carry CRGO estimates' assumptions, distributions and evidence quality into the rationale and confidence. Low or very-low evidence quality means "Analytical estimate — validation required". |
| 11 Risk indices | Unchanged: `crg_calc` / `crg_risk` compute everything. Afterwards, write chosen results back with `crgo_submit_assessment` (status proposed). |
| 12–14 Treatment | Policy exceptions with compensating controls, and their expiry dates, belong in the residual-risk discussion. An exception that has expired is no longer a mitigation. |
| 16–17 Prioritisation, decisions | Risk acceptance needs a named decision maker with delegated authority valid on the decision date (CQ-06). Keep "Management decision required" for every acceptance; CRG may draft the decision record but never marks it approved. |
| QC review (`risk-qc-reviewer`) | Add checks: every write-back has model version and inputs; no result is cited as approved unless a person approved it; obligations shown as "supported by" a control are not called "compliant"; EPSS is not used as a likelihood; client data stays out of both repositories. |
| Optional audit support | For assurance-oriented engagements, SP 800-53A objectives and the illustrative work programmes give objectives, methods and evidence to request. Label them illustrative. |

## 6. Rules that must not be broken

1. CRGO computes no risk, and CRG must not ask it to. All risk indices, CVSS scores, sensitivity cases and budget targets come from CRG's scripts or `crg-calculator`.
2. Write-backs are always `status: proposed`. Approval, acceptance and funding are human acts recorded separately.
3. Organisation IRIs use the organisation's own base, never `https://w3id.org/crgo/`. One organisation per graph file, and no links to another organisation's records.
4. "Supports compliance with" is not compliance. Only a compliance determination with evidence can say an obligation is satisfied.
5. EPSS is not a scenario likelihood. KEV presence says nothing about the organisation's own systems.
6. *Unknown* applicability stays unknown until the missing fact is supplied; *potentially applicable* needs a qualified person.
7. Licensed standards (IIA, ISACA, AICPA, COSO, ISO) appear in CRGO only as identifiers, official headings and CRGO paraphrases. CRG must not add or reproduce their text in reports or in the repository.
8. CRGO's sample companies (Nordelle, Boréal) and MediBec are fictional. They are not calibration evidence for real organisations.
9. CRG's formulas, the 1,000 factor and the MediBec regression (84,305 estimated / 41,023 residual since CRG 2.1.0 and CRGO 0.10.1; 84,491 / 41,104 before) must not change.

## 7. Suggested implementation plan for CRG 1.2.0

1. **Inventory.** Inspect the current CRG repository: `.mcp.json`, plugin `.mcp.json`, skills, agents, commands, rules, scripts, examples. Confirm the plugin version.
2. **MCP registration.** Add `crgo-ontology` to both `.mcp.json` files and document the clone path and requirements in `README.md`.
3. **Contract helper.** Add a small script, e.g. `scripts/crgo_contract.py`:
   - convert the assessment JSON to an organisation graph with CRGO's `crg2rdf.py`;
   - call `crgo_risk_context` for each selected scenario;
   - after calculation, build and submit one write-back per recorded quantity, computing `inputDocumentSha256` from the exact file used.
   - Keep everything under the git-ignored `output/` folder.
4. **Skill updates.** Change the `cyber-risk-assessment` SKILL.md (steps 1, 2, 8, 9, 11, 12–14, 16–17) as in section 5, plus `references/crg-formulas-and-workbook.md` (EPSS caution) and `scenario-selection` (`other_regimes`, applicability states).
5. **Agents.**
   - `risk-scenario-analyst`: applicability and incidents as evidence.
   - `risk-quantifier`: contract read and write; assessor lines and conflicts.
   - `risk-qc-reviewer`: the checks in section 5.
6. **Rules.** Extend `.claude/rules/evidence-discipline.md` with the knowledge-status mapping and the EPSS and "supports ≠ proves" rules.
7. **Report template.** Add a short "Legal applicability" table (state, unresolved conditions, qualified review needed) and a "Control evidence" column showing the assessor line. Cite the CRGO release.
8. **Sync and version.** Run `scripts/sync-project-config.sh`, bump to 1.2.0 in `plugin.json` and `marketplace.json`, and run `claude plugin validate` on both.
9. **Regression.**
   - Run `crg_calc.py` on MediBec: it must still give 84,305 / 41,023 (84,491 / 41,104 before CRG 2.1.0).
   - Run an end-to-end test on MediBec converted under a test base (`https://example.org/crgo-sample/medibec/`): read the context of scenario S1, compute with `crg_risk`, write back. Check that the result is stored as proposed and that the schemas validate.
   - The CRGO session ran exactly this test successfully on 2026-10-12.

## 8. Acceptance tests for the CRG update

- `crgo_risk_context` for a MediBec test scenario returns a schema-valid document; CRG uses its control results and assumptions in the scenario write-up.
- A CRG `residual-risk` write-back is accepted and stored as proposed; a write-back with `status: approved` or `modelVersion: TBD` is refused, and CRG reports the error.
- A self-assessment conflicting with an internal-audit result is shown as a conflict, not resolved silently.
- A regime with *unknown* applicability appears as an evidence gap, not as "not applicable".
- No report states compliance from a control mapping, uses EPSS as a likelihood, or reproduces text from a licensed standard.
- The MediBec regression is unchanged, and the plugin validates.

## 9. Known limits of CRGO 0.9.0

- Converted CRG assessments carry no legal obligations unless the CRG data names them. To get *candidateObligations*, link scenarios to Loi 25 provisions (CRGO notations such as `P-39.1 s. 10`) or run the applicability evaluator on a profile.
- The applicability evaluator is a Python function, not an MCP tool (`pipeline/grc/applicability.py`, `evaluate(graph, org, date, assessor, out_base)`).
- The IIA documents held by the project carry publication dates, not effective dates. COSO English titles are CRGO translations.
- IT service management, enterprise architecture objects, risk registers and the P1/P2 domain packages (supply chain, identity, OT, insurance, metrics and others) are planned for a later CRGO version.
