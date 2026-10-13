# CRGO 0.10.0 — final review before release

**Decision of the project owner (2026-10-13, 02:42): "go ahead". Groups 1–7 approved; release 0.10.0.** Prepared 2026-10-12.

## What 0.10.0 contains

- **Policy, compliance and audit management.** Decisions D1–D14 and the P1 term list were approved by the project owner on 2026-10-12. Details are in `docs/review-0.10.0-p1-terms.md`. The work produced:
  - two new modules, `crgo-policy` and `crgo-compliance`;
  - additions to `crgo-audit` and `crgo-mapping`;
  - six values added to three existing value sets;
  - eleven changes to approved terms (five under D9, six approved as P1 group 6).
- **SIEM and SOAR.** These follow decisions S1–S12, taken by Claude under the project owner's delegation of 2026-10-12. The reasoning is in `docs/baseline/siem_soar_phase0.md` and ADR-011. The work produced:
  - two new modules, `crgo-siem` and `crgo-soar`, with 32 classes, 14 value sets and 74 values, 73 object properties and 20 data properties;
  - two reference vocabularies: ATT&CK 19.2 detection strategies, analytics and data components, and OCSF 1.9.0 categories and event classes;
  - seven source records.
- **Read contracts.** `contracts/compliance/v1` and `contracts/secops/v1`, with the MCP tools `crgo_compliance_context` and `crgo_secops_context`.
- **Synthetic data and tests.**
  - Data: Nordelle policy, compliance and audit records, and Nordelle SIEM and SOAR records.
  - Competency questions: 42 specification CQs, checked by 91 checks.
  - Negative fixtures: 31 SHACL and 4 OWL.
  - Contract checks: 31.
- **Documentation.** ADR-010 and ADR-011, the CHANGELOG, README, AGENTS.md and NOTICE.md (OCSF NOTICE reproduced) are updated, and the documentation site is regenerated. A brief for the CyberRiskGuardian application is in `docs/crg-brief-0.10.0.md`.

## Groups approved on 2026-10-13

Each group has one row, dated 2026-10-13, in `src/approvals.tsv`.

| # | Group (key) | Content | Recommendation |
|---|---|---|---|
| 1 | `terms/siem` | 88 terms: telemetry, event records, normalisation, detection strategies and rules, coverage, gaps, tests, indicators, hunting, baselines; plus the detection status, alert disposition, coverage status, telemetry health and TLP marking value sets | Approve |
| 2 | `terms/soar` | 125 terms: investigations, incident category and severity, playbooks and versions, actions and risk classes, approval gates and decisions, execution records, evidence, forensics, impact, communications, recovery, measurements, simulations | Approve |
| 3 | `attack-detection/*`, `ocsf/*` | Reference vocabularies: 2,561 ATT&CK concepts with their links, and 87 OCSF concepts | Approve |
| 4 | `sources/records-secops` | 7 source records: NIST SP 800-61r3, OCSF 1.9.0, Sigma 2.1.0, STIX 2.1, CACAO 2.0, TLP 2.0, OpenTelemetry logs (cited only, pending access) | Approve |
| 5 | `adr/ADR-010-011` | Design records for policy, compliance and audit management, and for the security operations boundary | Approve |
| 6 | `contracts/compliance-v1`, `contracts/secops-v1` | Read contracts, schemas, examples, MCP tools | Approve |
| 7 | `tests/0.10.0` | Synthetic Nordelle data, the 42 CQs, negative fixtures, contract tests | Approve |

After approval, the release steps are:

1. Approval rows, rebuild and full check (CQ17 then passes).
2. Release commit and tag `v0.10.0`.
3. Push to GitHub.
4. GitHub release (created in the browser, as for 0.9.x).
5. Change report.

The w3id.org rules already cover the new modules and contract schemas (`check_w3id`: 0 unresolved), so no pull request is needed.

## Independent reviews and fixes

**First review (P1 terms):** 2 high, 10 medium and 8 low findings. All are fixed, as listed in `docs/review-0.10.0-p1-terms.md`.

**Second review (SIEM, SOAR, data, CQs, contracts):** 3 high, 6 medium and 6 low findings. All are fixed, except the points noted under "Not changed".

| Area | Findings | Fixes |
|---|---|---|
| **High: tenant leaks** | The contracts let another organisation's health observations, simulations, assessments and closures influence the output. | Every reverse lookup now keeps only the organisation's own records and reports what it withheld. Injection tests added. |
| **High: dating** | `secops/v1` ignored dates in places. | Coverage, tests, versions, simulations, alerts and reportability assessments are taken on or before the date asked; undated ones are left out. An early-date test was added. |
| **High: approval rule** | The approval audit signal could be silenced by an unrelated or retroactive approval, and three implementations disagreed. | One rule is used by the SHACL warning, CQ-SOAR-02 and `secops/v1`. It requires: outcome approved; decided and valid at the start; not denied or revoked; about this execution, its action or its risk class; made by a gate authority when the gates name one. New: *revoked on*, a consistency check between approval status and decision outcome, and tests for retroactive, unrelated, wrong-authority and revoked approvals. |
| **Medium: accidental incident classification** | Incident attributes and links could classify investigations, alerts or early notices as incidents. | Their domains and ranges were removed and replaced by SHACL checks; an investigation is now disjoint from an incident. |
| **Medium: tests read as control effectiveness** | A detection test or playbook simulation counted as the effectiveness of a whole control measure. | They are left out wherever a measure's latest result is reported: dss/v1, compliance/v1 and POL CQ02, 04 and 07. |
| **Medium: CQs** | — | CQ-SIEM-06 reads the ATT&CK version the rule was mapped against (new *reference version*). CQ-SIEM-05 keeps only current statements and approved mappings. CQ-SIEM-02 includes rules deployed for testing. CQ-SIEM-04 requires an effective test. |
| **Medium: OCSF attribution** | — | The OCSF NOTICE is reproduced in full. |
| **Medium: reuse** | — | A playbook is now a procedure. *Verified at* is replaced by *assessed on*. Behavioural baselines use the period properties. |
| **Low** | — | Corrected counts (32 classes; 697 and 106 live ATT&CK objects; warning fixtures). TLP:RED reworded as a paraphrase. French wording fixed. The kiosk alert no longer comes from the impossible-travel rule. The August approval is about the execution. Version 2 of the policy is now a version of the same policy. Malformed dates are refused. Coverage may name only an asset. A validated coverage must be tested on its own rule. |
| **Full check run** | The full check found one more problem: the class checks did not see subclasses. | Fixed by making them follow `rdfs:subClassOf`. |

**Not changed, and why:**

- **Approval status kept with the decision outcome.** The SOAR specification lists approval statuses explicitly; a SHACL check keeps the two consistent.
- **Statuses are "as last recorded".** Point-in-time history comes from dated records, and the contract caveats say so.
- **CaseStatus kept separate from IncidentPhase.** Case status describes the case, while response phase describes the incident timeline.
- **The OCSF record has no file checksum.** The source is a git tag, so its commit is recorded instead.

## Checks run

`scripts/check.sh` was run in full (`WITH_LIBRARY=1`) after the review fixes. Results:

| Area | Result |
|---|---|
| HermiT and ELK | Consistent, no unsatisfiable classes |
| OWL 2 DL profile | In profile, with imports |
| `crgo-full` | Consistent and in OWL 2 DL |
| Negative OWL fixtures | All inconsistent, as expected |
| Metadata, modules, SKOS vocabularies | Pass |
| MediBec regression | 84,491 / 41,104 |
| Pitfall scan | No critical pitfalls |
| Identification tests | Pass |
| Sample data | All Nordelle graphs and the second tenant consistent and in OWL 2 DL |
| Competency questions | Specification CQs 27/27, GRCA 57/57, 0.10.0 91/91 |
| w3id | 0 unresolved IRIs (45,656 IRIs and 7 schema ids) |
| Tenants | Separated |
| Contracts | dss/v1 29/29; compliance/v1 and secops/v1 31/31 |

Two results were expected at that checkpoint (before the go-ahead); the release check after approval is recorded in the CHANGELOG:

- **SHACL.** That run reported two violations from the subclass bug. After the fix, the data conforms with only the three deliberate warnings: two stale-evidence cases and the October kiosk isolation without a valid approval. All 31 new negative fixtures are rejected with their expected messages.
- **CQ17 ("terms not yet approved")** lists the 227 SIEM/SOAR identifiers awaiting groups 1–2. It passes once they are approved.
