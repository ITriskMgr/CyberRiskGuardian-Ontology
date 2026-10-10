# Using CRGO from CyberRiskGuardian

CRGO answers the identification questions of a CyberRiskGuardian assessment: which risk scenarios fit this organisation, which ATT&CK techniques and weaknesses they involve, which controls (NIST CSF 2.0, SP 800-53, ISO/IEC 27002) address them, which Loi 25 obligations they can trigger, and what calibration values exist.

## Three ways to use it

| Way | For | How |
|---|---|---|
| MCP server | Claude in CyberRiskGuardian (interactive) | `pipeline/mcp/crgo_server.py`, five read-only tools |
| Python module | scripts, notebooks | `pipeline/query/identify.py` |
| JSON export | tools without a SPARQL store | `data/export/crgo-identification.json` (all 1,878 scenarios, every link with confidence and status) |

The MCP server and the module use an embedded Oxigraph store built from the repository files on first use (about 10 s, into `build/store/`). Requirements: `pip install "mcp>=1.2" pyoxigraph`.

## Registering the server in CyberRiskGuardian

Add to CyberRiskGuardian's `.mcp.json`, next to `crg-calculator` (adjust the path to where CRGO is cloned):

```json
"crgo-ontology": {
  "command": "python3",
  "args": ["../cyberriskguardian-ontology/pipeline/mcp/crgo_server.py"]
}
```

## Tools

| Tool | Use |
|---|---|
| `crgo_sweep` | Start here. Profile-wide identification: scenarios matching any element of the profile, near-duplicates merged under one representative (`see_also`), up to `per_theme` per requested theme, one representative per commonly assessed risk, gaps reported. |
| `crgo_identify` | Targeted follow-up: scenarios matching all given filters, ranked by fit. |
| `crgo_scenario` | Full detail of one scenario: techniques, weaknesses, controls per framework, obligations, estimates with their evidence. |
| `crgo_controls_for_technique` | Controls most often linked to scenarios using an ATT&CK technique; reports replacements for revoked identifiers. |
| `crgo_scenarios_for_control` | Coverage of one control requirement. |
| `crgo_list_values` | Allowed values for asset categories, themes, threat source types, impact dimensions, sectors. |

Link confidence: `min_confidence="M"` (default) returns the approved high- and medium-confidence links; `"L"` adds the low-confidence suggestions.

## Suggested place in the CRG workflow

In scenario selection (CRG `scenario-selection` skill, candidate generation):

1. Build the profile from the organisation's documents: asset categories present, themes of concern, sector, ATT&CK techniques seen in incidents or threat intelligence, keywords for notable systems and weaknesses.
2. Call `crgo_sweep`, then `crgo_identify` for anything the documents mention that the sweep did not return.
3. For each kept candidate, call `crgo_scenario` and use its techniques, controls and obligations in the scenario write-up and the treatment portfolio.
4. Keep CRG's evidence discipline: library and case values are calibration priors. Write them as "Analyst estimate - validation required" and replace them with organisational evidence. `estimated_risk` is in CRG risk units (relative), not a 0–1 score.

## Evaluation

The interface was tested blind on the MediBec case: an agent read only the organisation profile, used the tools with MediBec held out (`holdout=["MediBec-CRG","MediBec"]`), and its candidate list was compared with the 30 scenarios of the expert assessment. Recall was 0.52 in the first truly blind run; the misses came mostly from scenarios the library holds but the interface did not surface, and three risks the library lacks (cloud tenant takeover through token theft or app consent, staff pasting data into generative-AI tools, HL7/DICOM interception). After the fixes, a third run reached 0.62, but that figure is not independent: the synonym list and the list of commonly assessed risks were written after seeing which MediBec scenarios had been missed. A fair measurement was then made on ACRB, a regional bank that played no part in tuning: recall 0.76 on the 19 risks the case author expected (12 covered, 5 partly, 2 missed). Reports: `docs/identification-eval-*.md`.
