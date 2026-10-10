# Using the CyberRiskGuardian Ontology (CRGO) — brief for AI agents

CRGO is an OWL 2 ontology (BFO-2020) for cybersecurity risk assessment, aligned with CyberRiskGuardian (CRG). It holds 1,881 risk scenarios (library and teaching cases) linked to MITRE ATT&CK, NIST CSF 2.0, SP 800-53 Rev. 5, ISO/IEC 27002:2022, Québec's Loi 25 (P-39.1) and the Québec health-information act (R-22.1), with calibration estimates for the CRG v1.0c parameters. Labels and definitions in English and French.

- Home and documentation: https://itriskmgr.github.io/CyberRiskGuardian-Ontology/
- Repository: https://github.com/ITriskMgr/CyberRiskGuardian-Ontology (latest release: see Releases)
- Term IRIs: `https://w3id.org/crgo/CRGO_nnnnnnn` (opaque, stable)

## Three ways to connect

**1. Read the files (any agent with web access, no install).**
- Ontology (all classes and properties, one file): https://raw.githubusercontent.com/ITriskMgr/CyberRiskGuardian-Ontology/main/docs/doc/ontology.ttl
- Scenario export for identification (JSON, 5 MB, every scenario with its links, confidence and status): https://raw.githubusercontent.com/ITriskMgr/CyberRiskGuardian-Ontology/main/data/export/crgo-identification.json
- Integration guide: https://raw.githubusercontent.com/ITriskMgr/CyberRiskGuardian-Ontology/main/docs/crg-integration.md
Replace `main` with a release tag (for example `v0.6.0`) to pin a version.

**2. Query in code (agents that can run Python).** Clone the repository, `python3 -m pip install "mcp>=1.2" pyoxigraph`, then use `pipeline/query/identify.py`: `sweep(...)`, `identify(...)`, `scenario(id)`, `controls_for_technique(id)`, `scenarios_for_control(id)`, `list_values(kind)`. The first call builds a local index (about 10 s).

**3. MCP server (Claude Code, Claude desktop app, CyberRiskGuardian).** Register `pipeline/mcp/crgo_server.py`, run with a Python that has `mcp` and `pyoxigraph`:
```json
"crgo-ontology": { "command": "/absolute/path/to/python3", "args": ["/absolute/path/to/CyberRiskGuardian-Ontology/pipeline/mcp/crgo_server.py"] }
```
Tools: `crgo_sweep` (start here: profile-wide identification), `crgo_identify` (targeted filters), `crgo_scenario` (full detail of one scenario), `crgo_controls_for_technique`, `crgo_scenarios_for_control`, `crgo_list_values` (allowed filter values).

## Rules for using the results

- **Library values are calibration priors, not organisational evidence.** They come from a 2023 generator for a fictitious hospital, partly recalibrated on teaching cases. Label them "Analyst estimate — validation required" and replace them with the organisation's own evidence (CRG evidence discipline).
- **Risk values are CRG risk units** (relative, appetite-based), not 0–1 scores or currency.
- **Every link carries a confidence (H/M/L) and a status.** *approved* = reviewed by the project owner (high and medium links); *proposed* = suggestion (low links, R-22.1 rule equivalents, scenarios F1812–F1814). Cite low/proposed links as suggestions only. Default filter `min_confidence="M"`.
- **Sector bias.** The library is healthcare-worded; for other sectors, translate scenario names and check for missing sector risks (for example ATM malware). Combined risks (vendor × remote access, insider × fraud) may need targeted `crgo_identify` calls.
- **Privacy law.** Loi 25 links assume a private-sector organisation (P-39.1); public bodies fall under A-2.1, which is not modelled yet.
- **Never invent identifiers.** Use only ATT&CK, control and obligation IDs returned by the ontology; revoked ATT&CK IDs come back with their replacement.
- **Evaluation hygiene.** When testing identification on a known case, pass `holdout=["<case key>"]` so the case's own scenarios are not returned.

Maintainer: Marc-André Léger (GitHub @ITriskMgr). Licence CC BY-NC 4.0; framework identifiers keep their owners' terms (`NOTICE.md`). Cite with `CITATION.cff`.
