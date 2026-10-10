# Extension plan

What comes after 0.5.0, in suggested order. Each item says why, what it would change, and who has to decide. The principles of the first five phases stay in force: reuse before creating, evidence for every element, nothing approved without the project owner, TBox, vocabularies and instance data kept apart.

## 1. Reviews waiting for the project owner

| Item | What is needed | Effort |
|---|---|---|
| Proposed links of 0.4.0 | Review the 2,292 rule-based R-22.1 links and the links of the three written scenarios (F1812–F1814). A group decision like the one for 0.3.0 is enough; a sample can be drawn first | Small |
| Loi 25 for about 176 scenarios | Decided 2026-10-10: Claude judges them against Loi 25 with the 0.3.0 method and confidence grading; links stay proposed until a group review (next draft) | Small |
| Low-confidence links (1,742) | Keep as suggestions (current), or review them in batches by scheme | Medium |

## 2. Identification quality (requirement R1)

Findings of the ACRB evaluation (`docs/identification-eval-acrb.md`), the first measurement on a case not used in tuning:

- **Other sectors.** The library comes from a healthcare generator. Add synonym groups for banking and payments (ATM, teller, card, POS, core banking, online banking, payment processor) and for other sectors as cases arrive; lower the rank of healthcare-worded scenarios when the profile has no healthcare terms.
- **Risks made of two concepts.** Vendor × remote access, insider × financial-record manipulation, API × rate limiting, BYOD × malware appear only when both are asked together. Add them as combination probes in the sweep.
- **Missing scenarios.** ATM malware or jackpotting; outage from an expired certificate; incomplete asset inventory. Same procedure as F1812–F1814: written, linked, proposed.
- **Near-duplicates across themes.** The merge works only within a theme. A cross-theme merge on name similarity would shorten the lists.
- **Evaluation protocol.** Every change to synonyms, probes or the baseline list is tuned on cases already used; recall is measured only on a case never seen before, read blind (profile only), and reported once. Each case is used for measurement once. A set of five to ten cases from different sectors is the target. The case pool is the teaching cases in Drive and new ones written for the purpose.

## 3. Calibration

- The library values are LLM estimates from 2023 for a fictitious hospital, partly recalibrated on four teaching cases. Next sources, by weight: organisational loss data where an organisation agrees to share it; public studies with stated method (for example sector breach-cost reports); expert elicitation with recorded experts.
- Record each source as an evidence item with its basis, as now, and keep "calibration aid, not organisational evidence".
- Check calibration: for cases with expert values, compare library priors with the expert values and report the error per parameter.

## 4. Ontology extensions

| Item | Origin | Proposal |
|---|---|---|
| CVE and CWE | Deferred since Phase 2 | A CWE vocabulary (SKOS, from MITRE's CWE list, about 1,000 weaknesses) linked to weakness descriptions; CVE as external references only, not a vocabulary (too large and changing). Library links to CWE judged like the ATT&CK links |
| M7 | Deferred | Clarify the meaning of `mitigatedBy` between a scenario and a control record: a record does not reduce likelihood; the control it describes does. Candidate: "recorded as mitigated by" |
| L6 | Deferred | A parent "normative requirement" for framework requirements and legal obligations, so that queries can ask for "any requirement" |
| L13 | Deferred | Type the drafting agent as `prov:SoftwareAgent` in a PROV-O bridge module, outside the DL core |
| L15 | Deferred | Owners as positions (role-based pattern) rather than people, checked with SHACL |
| L17 | Deferred | Incident → scenario link; threat-source characteristics of SP 800-30 (capability, intent, targeting, tables D-3 to D-5); a risk register as an information artifact listing assessed scenarios over time |
| DOLCE alignment | Option of Q-A | A separate alignment module mapping the BFO-based core to DOLCE, for users of DOLCE-based ontologies. Optional; only if a user needs it |
| Other frameworks | Decisions D1–D4 | CIS Controls were left out (licence); CCM v4.1 controls stay private. Revisit if licences change. COBIT 2019 stays unless a newer edition is adopted |

## 5. Release and operations

- **1.0.0.** Once the w3id.org redirects resolve and the documentation is public, the term IRIs can be promised as stable; that promise is what 1.0.0 would signal. After 1.0.0, a removed or redefined term needs deprecation and a major version.
- **Continuous checks.** Run `scripts/check.sh` in GitHub Actions on each pull request (Java for HermiT and ROBOT, Python for the rest).
- **Documentation.** Regenerate the site with each release (`scripts/make_docs.py`) and keep the dated version under `docs/<version>/` for comparison.
- **CyberRiskGuardian.** Register the MCP server in CyberRiskGuardian's configuration and use it in scenario selection (`docs/crg-integration.md`); report false positives and misses back as cases for the evaluation set.
