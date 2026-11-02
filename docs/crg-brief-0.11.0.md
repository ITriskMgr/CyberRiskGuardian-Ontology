# Brief: CRGO 0.11.0 terms for the CyberRiskGuardian 1.9.0 "Identity, Privilege & Configuration" module

**For:** Claude working in the CyberRiskGuardian (CRG) repository on release 1.9.0 (decision record of 2026-11-02, group 4).
**From:** CRGO 0.11.0 (tag `v0.11.0`; every term **approved** by the project owner on 2026-11-02; CIS v8.1 values flagged `REVIEW:` were accepted as delivered and stay unverified).
**Rule:** CRG stores counts per population, never names or usernames; findings may *propose* Pb(ψ,A) or θ changes through the
existing propose → review → accept flow; CRGO computes no risk and no inference in CRGO approves access or accepts a risk.

The earlier briefs (`docs/crg-brief-0.9.1.md`, `docs/crg-brief-0.10.0.md`) still hold. Term IRIs are `https://w3id.org/crgo/CRGO_nnnnnnn`.

## 1. Register classes (one per CRG register) and their fields

| CRG register (decision record) | CRGO class | Fields (CRGO property) |
|---|---|---|
| 1. Account populations | account population `CRGO_0001384` (sub-class of population `CRGO_0000528`) | account type `CRGO_0001528` → value set `CRGO_0001434` (employee, contractor/vendor, service/workload, AI agent, emergency); total = population size `CRGO_0000855`; MFA count `CRGO_0001554`; phishing-resistant MFA count `CRGO_0001555`; dormant `CRGO_0001556`; without owner `CRGO_0001557`; unknown state `CRGO_0001558`; owner = has owner; last reconciled on `CRGO_0001561`; source `CRGO_0001564` |
| 2. Privileged roles by tier | privileged role holder population `CRGO_0001386`, about a privileged role `CRGO_0001346` | population of role `CRGO_0001530`; privilege tier `CRGO_0001529` → value set `CRGO_0001441` (tier 0-3); holders = population size; standing `CRGO_0001559`; just-in-time `CRGO_0001560`; MFA count; last review = reviewed on; owner |
| 3. Emergency (break-glass) accounts | emergency access account population `CRGO_0001385` (account type = emergency) | as register 1, plus protective controls = protected by measure `CRGO_0001531`; last tested on `CRGO_0001562`; last used on `CRGO_0001563`; post-use review state `CRGO_0001522` → value set `CRGO_0001447` |
| 4. Access-review campaigns | access review campaign `CRGO_0001354` | scope = assessment scope; due on; completed on; items due `CRGO_0001565`, completed `CRGO_0001566`; revocations requested `CRGO_0001567`, verified `CRGO_0001568`; reviewer conflicts `CRGO_0001569` |
| 5. Baselines | baseline version `CRGO_0001374` (directive version of a configuration baseline `CRGO_0000501`); deviation register: baseline deviation `CRGO_0001377`; exceptions: policy exception `CRGO_0000502` | version of directive; version label; lifecycle state; effective on; owner; review due on; platform applicability; source licence reference. Deviation: deviation from baseline `CRGO_0001542`; drift class `CRGO_0001545` → value set `CRGO_0001453` (six classes of spec 6.4); deviation count `CRGO_0001572`; identified on; assessed on; covered by exception `CRGO_0001546` (an expired exception never counts) |
| 6. Segregation-of-duties conflicts | segregation-of-duties conflict `CRGO_0001366`, of a rule `CRGO_0001350` | conflict of rule `CRGO_0001524`; conflict count `CRGO_0001571`; owner; mitigation = conflict mitigated by |
| 7. Configuration changes | configuration change record `CRGO_0001378` | change class `CRGO_0001548` → value set `CRGO_0001461` (standard, normal, emergency, suspected unauthorised); changes item; verified `CRGO_0001580`; ticket `CRGO_0001579`; authorised by decision |

Starter KRIs: outcome metric `CRGO_0001382` (a key risk indicator) with *has indicator kind* `CRGO_0001532` → value set
`CRGO_0001467` (the eight indicators of the decision record); each dated value is a coverage observation `CRGO_0001383` with
numerator `CRGO_0001573`, denominator `CRGO_0001574` and unknown count; zero denominator = not applicable; unknowns stay in the
denominator (SHACL). Findings: identity finding `CRGO_0001364`, privilege finding, configuration finding `CRGO_0001367` (control
gap findings, with evidence).

## 2. Questionnaire filter and CIS v8.1

`vocab/cis81` holds CIS Controls 4, 5 and 6 (and the others) by identifier, with Implementation Group membership, asset type and
CSF 2.0 function; labels are CRGO paraphrases (show the identifier and link to https://www.cisecurity.org/controls/v8-1, never CIS
text). Safeguards of controls 4, 5 and 6 (and 1.1, 2.1, 12.5, 12.8, 16.7) point (`rdfs:seeAlso`) to the crgo-iam classes that record them. Values flagged
`REVIEW:` (confidence Low) are not yet checked against the CIS workbook: display them as unverified.

## 3. Scenario patterns and applicability

Scenario pattern `CRGO_0001387` (has scenario pattern `CRGO_0001478`, from a risk scenario):

| Pattern | IRI | Theme (narrower than) |
|---|---|---|
| harvest now, decrypt later (post-quantum) | `CRGO_0001389` | cryptography |
| crypto-agility failure | `CRGO_0001390` | cryptography |
| certificate expiry outage (book ch20) | `CRGO_0001391` | cryptography; continuity |
| agentic AI misuse | `CRGO_0001392` | emerging technologies |
| prompt injection in agent workflows | `CRGO_0001393` | emerging technologies; applications |
| AI supply chain compromise (book ch18) | `CRGO_0001394` | third party; emerging technologies |

Links in `vocab/pattern-links`: *pattern involves technique* `CRGO_0001603` (ATT&CK), *pattern involves weakness* `CRGO_0001604`
(CWE), *pattern addressed by* `CRGO_0001605` (SP 800-53 Rev. 5, CIS v8.1), each approved (2026-11-02) with a confidence; ATLAS techniques by
`rdfs:seeAlso`. OWASP LLM and Agentic entries point to the patterns ('partially overlaps'). Technology in use
`CRGO_0001395` (uses technology `CRGO_0001479`) on the organisation profile lets `pipeline/grc/applicability.py` evaluate ISO/IEC
42001, the OWASP lists and ISO/IEC 27701 (at most *potentially applicable*) and the CCSPA (designated operators).
