# Scenario-to-framework links

Each of the 1,811 library scenario families is linked to:

| Target | Attached to | Property | Max per family |
|---|---|---|---|
| MITRE ATT&CK technique or sub-technique | the family's threat event description | `hasExternalReference` | 3 |
| NIST CSF 2.0 subcategory | the scenario | `hasRelevantRequirement` | 4 |
| NIST SP 800-53 Rev. 5 base control | the scenario | `hasRelevantRequirement` | 4 |
| ISO/IEC 27002:2022 control | the scenario | `hasRelevantRequirement` | 4 |
| Loi 25 obligation | the scenario | `triggersObligation` | 3 |

Every link carries a confidence (high, medium, low), `proposedBy` Claude and status proposed, as an OWL axiom annotation.

## Method

1. `candidates.py` writes the family batches and `reference.md`, the complete list of valid targets.
2. Judgement: Claude reads each family (name, narrative, event sequence, consequences, suggested mitigations, theme) and picks the targets that a risk analyst would cite, following the rules below. It also re-checks the theme and the threat source types.
3. `validate.py` rejects any identifier not in the reference lists, merges the batches into `data/library/links.csv`, and reports coverage.
4. An independent reviewer re-judges a random sample.

## Rules given to the judge

- ATT&CK: only for scenarios with an adversary technique. Prefer a sub-technique when the scenario is that specific; otherwise the parent technique. None for pure control gaps, governance, accidents or environmental events.
- Controls (CSF, SP 800-53, ISO): those that most directly prevent, detect or limit the scenario, not generic governance controls that apply to everything (avoid GV.PO-01, PL-1, 5.1 unless the scenario is about policy).
- Loi 25: only when personal information is involved; incidents affecting confidentiality point to the incident obligations (s. 3.5, 3.7, 3.8).
- Confidence: high = direct and unambiguous; medium = relevant but partial or one of several plausible choices; low = plausible only.
