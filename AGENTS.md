# Using the CyberRiskGuardian Ontology (CRGO) — brief for AI agents

CRGO is an OWL 2 ontology (BFO-2020) for cybersecurity risk assessment, aligned with CyberRiskGuardian (CRG). It holds 1,884 risk scenarios (library and teaching cases) linked to MITRE ATT&CK, NIST CSF 2.0, SP 800-53 Rev. 5, ISO/IEC 27002:2022, Québec's Loi 25 (P-39.1) and the Québec health-information act (R-22.1), with calibration estimates for the CRG v1.0c parameters. From 0.7.0 it also carries MITRE CWE, CAPEC and D3FEND, the CISA KEV catalogue, and cross-references between them (ATT&CK→SP 800-53 from MITRE CTID). Labels and definitions in English and French. CRG's method, and CRGO's wording for it, follow the author's textbook *Introduction to Cybersecurity Governance for Business Technology Management*, 3rd ed., v2.51 (Léger, October 2026; distributed with CyberRiskGuardian in `plugins/crg-governance-textbook`).

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
Tools: `crgo_sweep` (start here: profile-wide identification), `crgo_identify` (targeted filters), `crgo_scenario` (full detail of one scenario, including CWE weaknesses, D3FEND countermeasures and KEV exploitation evidence), `crgo_controls_for_technique`, `crgo_scenarios_for_control`, `crgo_list_values` (allowed filter values); from 0.9.0, `crgo_risk_context` and `crgo_submit_assessment` implement the CyberRiskGuardian data contract `dss/v1` (`contracts/dss/v1/`): the second stores a DSS result only as a proposed risk estimate in the organisation's own graph. From 0.10.0, `crgo_compliance_context` and `crgo_secops_context` return read-only views (`contracts/compliance/v1/`, `contracts/secops/v1/`) of one organisation's obligations, policies, exceptions, deadlines and findings, and of its detection coverage, alerts, approval gates and regulatory triage; neither is a compliance claim or an authorisation.

## Rules for using the results

- **Library values are calibration priors, not organisational evidence.** They come from a 2023 generator for a fictitious hospital, partly recalibrated on teaching cases. Label them "Analytical estimate — validation required" (French: « Estimation analytique — validation requise ») and replace them with the organisation's own evidence (CRG evidence discipline). Mark missing facts "Information gap — organizational validation required" (« Lacune d'information — validation organisationnelle requise ») and decisions that belong to management "Management decision required" (« Décision de la direction requise »).
- **Risk values are CRG risk units** (relative, appetite-based), not 0–1 scores or currency. Computed CRG values (estimated, tolerated, mitigated and residual risk, the risk-to-tolerance ratio) are *risk indices* (textbook v2.51 ch06), not KRIs; key risk indicators are measured monitoring values (CRG step 19).
- **Every link carries a confidence (H/M/L) and a status.** *approved* = reviewed by the project owner (high and medium links); *proposed* = suggestion (low links, R-22.1 rule equivalents, scenarios F1812–F1814). Cite low/proposed links as suggestions only. Default filter `min_confidence="M"`.
- **Sector bias.** The library is healthcare-worded; for other sectors, translate scenario names and check for missing sector risks (for example ATM malware). Combined risks (vendor × remote access, insider × fraud) may need targeted `crgo_identify` calls.
- **Privacy law.** Scenario links are to Loi 25 (P-39.1, Québec private sector). `other_regimes` in the scenario detail gives the corresponding A-2.1 obligations (Québec public bodies), PIPEDA provisions (federal private sector, federally regulated businesses), GDPR provisions (organisations offering goods or services to people in the EU) and OSFI B-13 principles (federally regulated financial institutions). Check which regime applies to the organisation: from 0.9.0, `pipeline/grc/applicability.py` evaluates CRGO's applicability conditions over an organisation profile and answers applicable, not applicable, potentially applicable (needs qualified review) or unknown (a fact is missing). It is not legal advice, and a correspondence between obligations is never evidence of compliance.
- **Sector frequencies.** `sector_frequency` in a sweep comes from public incident records (VCDB); it shows which themes dominate disclosed incidents in a sector, not incident rates.
- **EPSS values are dated observations** (0.9.0): the FIRST probability that a vulnerability is exploited in the next 30 days, on the score date given; never use them as the likelihood of a risk scenario.
- **Exploitation evidence is not an inventory.** KEV counts show that a technique or weakness is actively exploited somewhere; they say nothing about the organisation's own systems.
- **Never invent identifiers.** Use only ATT&CK, control and obligation IDs returned by the ontology; revoked ATT&CK IDs come back with their replacement.
- **Evaluation hygiene.** When testing identification on a known case, pass `holdout=["<case key>"]` so the case's own scenarios are not returned.

Maintainer: Marc-André Léger (GitHub @ITriskMgr). Licence CC BY-NC 4.0; framework identifiers keep their owners' terms (`NOTICE.md`). Cite with `CITATION.cff`.
