#!/usr/bin/env python3
# SPDX-License-Identifier: CC-BY-NC-4.0
# Copyright (c) 2026 Marc-André Léger
"""CyberRiskGuardian Ontology - local MCP server (stdio) for threat, vulnerability and risk identification.

Tools (read-only unless stated):
  - crgo_sweep                  profile-wide identification: one representative per kind of scenario, a few per theme
  - crgo_identify               scenarios matching all given filters, ranked by fit
  - crgo_scenario               one scenario in full: threats, weaknesses, controls, obligations, estimates
  - crgo_controls_for_technique controls associated with an ATT&CK technique across the library
  - crgo_scenarios_for_control  scenarios a framework requirement addresses
  - crgo_list_values            allowed values for the filters
  - crgo_risk_context           DSS contract dss/v1, read document for one organisation and scenario (0.9.0)
  - crgo_submit_assessment      DSS contract dss/v1, write-back: stores a DSS result as PROPOSED in the organisation's
                                own proposed graph file, never in CRGO reference files (0.9.0)
  - crgo_compliance_context     contract compliance/v1 (read): obligations, policy versions, exceptions, deadlines and
                                findings of one organisation at a date (0.10.0)
  - crgo_secops_context         contract secops/v1 (read): detection coverage, telemetry, untriaged alerts, approval
                                gates, executions without valid approval, open regulatory triage (0.10.0)

Every answer carries confidence and approval status per link and a caveat: library and case values are
calibration priors, never organisational evidence (CyberRiskGuardian evidence discipline).

Requires: pip install "mcp>=1.2" pyoxigraph (mcp 1.x and 2.x both work). The store is built on first use from the repository files
(about 10 s) into build/store/.
"""
import os, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "query"))
try:  # mcp 1.x (as used by CyberRiskGuardian)
    from mcp.server.fastmcp import FastMCP as _Server
except ModuleNotFoundError:  # mcp 2.x renamed FastMCP to MCPServer
    from mcp.server.mcpserver import MCPServer as _Server
import identify as I

mcp = _Server("crgo-ontology")


@mcp.tool()
def crgo_sweep(asset_categories: list[str] = [], themes: list[str] = [], sector: str = "", techniques: list[str] = [],
               keywords: list[str] = [], per_theme: int = 3, min_confidence: str = "M", include_cases: bool = True,
               holdout: list[str] = [], max_total: int = 60) -> dict:
    """Start here for scenario identification. Give the organisation profile: asset categories present, themes of
    concern, sector, ATT&CK techniques seen in incidents or threat intelligence, and keywords for notable systems or
    weaknesses (synonyms are expanded: telehealth, HL7/DICOM, MFA, GenAI...). Returns scenarios matching ANY element,
    near-duplicates merged under one representative ('see_also'), up to per_theme representatives per theme, and the
    requested themes with no scenario ('theme_gaps'). holdout: case keys to ignore (e.g. 'MediBec-CRG') for blind tests.
    Then call crgo_scenario on the ones you keep. Treat all numbers as 'Analytical estimate — validation required'."""
    return I.sweep(asset_categories, themes, sector or None, techniques, keywords, per_theme, min_confidence, include_cases, holdout, max_total)


@mcp.tool()
def crgo_identify(asset_categories: list[str] = [], themes: list[str] = [], sector: str = "", techniques: list[str] = [],
                  keywords: list[str] = [], min_confidence: str = "M", limit: int = 15, include_cases: bool = True,
                  holdout: list[str] = []) -> dict:
    """Identify candidate risk scenarios for an organisation profile.
    asset_categories: keys or labels from crgo_list_values('asset_category') (e.g. 'CatCloud', 'OT, IoT and connected devices').
    themes: theme keys or labels (e.g. 'ThemeRansomware'). sector: substring such as 'health', 'retail', 'banking'.
    techniques: ATT&CK ids; sub-techniques are included (e.g. 'T1566'). keywords: words to find in scenario names and statements.
    Different filters combine with AND, values within one filter with OR. min_confidence: 'H', 'M' (approved links, default) or 'L'.
    Returns scenarios with ATT&CK techniques, weaknesses, CSF 2.0 / SP 800-53 / ISO 27002 controls, Loi 25 obligations,
    estimated risk and its basis. Treat all numbers as 'Analytical estimate — validation required'."""
    return I.identify(asset_categories, themes, sector or None, techniques, keywords, min_confidence, limit, include_cases, holdout)


@mcp.tool()
def crgo_scenario(scenario_id: str, min_confidence: str = "M", holdout: list[str] = []) -> dict:
    """Full detail for one scenario: id such as 'LIB-F1467' (library), 'MediBec/MED-A1' (case scenario) or an IRI.
    Includes the 2023 library estimates (low confidence), case-calibrated estimates where available (medium or low),
    risk indices (CRG computed values, not KRIs), evidence identifiers and the families or case scenarios it is related to."""
    return I.scenario(scenario_id, min_confidence, holdout=holdout)


@mcp.tool()
def crgo_controls_for_technique(technique: str, min_confidence: str = "M", top: int = 10) -> dict:
    """Controls most often linked to library scenarios whose threat event uses an ATT&CK technique (sub-techniques
    included), per framework. Revoked identifiers report their replacement (e.g. T1562 -> T1685)."""
    return I.controls_for_technique(technique, min_confidence, top)


@mcp.tool()
def crgo_scenarios_for_control(framework: str, control_id: str, min_confidence: str = "M", limit: int = 50) -> dict:
    """Library scenarios that a framework requirement addresses. framework: 'csf2', 'sp800-53r5' or 'iso27002-2022';
    control_id as in the framework (e.g. 'PR.AA-05', 'SI-4', '8.16')."""
    return I.scenarios_for_control(framework, control_id, min_confidence, limit)


@mcp.tool()
def crgo_list_values(kind: str) -> list:
    """Allowed filter values. kind: 'asset_category', 'theme', 'threat_source_type', 'impact_dimension' or 'sector'."""
    return I.list_values(kind)


sys.path.insert(0, os.path.join(HERE, "..", "contracts"))


def _org_files(org_graph_files):
    files = [os.path.abspath(f) for f in org_graph_files]
    missing = [f for f in files if not os.path.exists(f)]
    if missing:
        raise FileNotFoundError("organisation graph file(s) not found: %s" % missing)
    return files


@mcp.tool()
def crgo_risk_context(org_graph_files: list[str], organization: str, scenario: str, as_of: str) -> dict:
    """DSS contract dss/v1 (read). org_graph_files: the organisation's own RDF files (Turtle), kept outside the CRGO
    repository's reference files; organization: the organisation IRI (its own base, never https://w3id.org/crgo/);
    scenario: the organisation's assessment scenario IRI or a CRGO library scenario; as_of: yyyy-mm-dd.
    Returns a document valid against contracts/dss/v1/risk-context.schema.json, or an error document.
    CRGO returns facts, links and their status; it never computes risk (ADR-007)."""
    import dss
    return dss.risk_context(_org_files(org_graph_files), organization, scenario, as_of)


@mcp.tool()
def crgo_submit_assessment(document: dict, org_graph_files: list[str]) -> dict:
    """DSS contract dss/v1 (write-back). document: a result valid against contracts/dss/v1/assessment-result.schema.json
    with status 'proposed'. The result is stored as a proposed analytical result (knowledge status: risk estimate) in
    '<name>-dss-proposed.ttl' next to the first organisation graph file. It never becomes approved, an acceptance or a
    funding decision by being written back; approval is a separate act. Returns the stored IRI or an error document."""
    import dss
    from rdflib import Graph
    files = _org_files(org_graph_files)
    g = dss.load(files, reference=False)
    try:
        base = dss.org_base(document.get("organizationId", ""), g)
    except (ValueError, LookupError):
        return dss.error("UNKNOWN_ORGANISATION", "No organisation graph among the files declares a base for this organisation.")
    # the proposed graph sits next to the file that declares the organisation's base, never next to another tenant's file
    home = next((f for f in files if base in dss.declared_bases(Graph().parse(f))), None)
    if home is None:
        return dss.error("UNKNOWN_ORGANISATION", "No file declares the base %s." % base)
    out = os.path.join(os.path.dirname(home), os.path.splitext(os.path.basename(home))[0].split("-")[0] + "-dss-proposed.ttl")
    return dss.submit_assessment(document, files, out, g=g)


@mcp.tool()
def crgo_compliance_context(org_graph_files: list[str], organization: str, as_of: str) -> dict:
    """Contract compliance/v1 (read only). org_graph_files: the organisation's own RDF files; organization: its IRI
    (own base, never https://w3id.org/crgo/); as_of: yyyy-mm-dd. Returns a document valid against
    contracts/compliance/v1/compliance-context.schema.json, or an error document. Compliance states are the
    organisation's latest recorded determinations; a mapping, statement or attestation is never evidence of compliance."""
    import views
    return views.compliance_context(_org_files(org_graph_files), organization, as_of)


@mcp.tool()
def crgo_secops_context(org_graph_files: list[str], organization: str, as_of: str) -> dict:
    """Contract secops/v1 (read only). Same parameters as crgo_compliance_context. Returns a document valid against
    contracts/secops/v1/secops-context.schema.json, or an error document. It reports approval gaps as audit signals and
    never authorises a response action (ADR-011)."""
    import views
    return views.secops_context(_org_files(org_graph_files), organization, as_of)


if __name__ == "__main__":
    mcp.run()
