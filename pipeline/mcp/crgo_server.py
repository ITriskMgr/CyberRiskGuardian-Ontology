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
  - crgo_group_candidates       contract library-proposal/v1 (read, 0.11.2): candidate descriptors -> family proposals
                                (same near-duplicate cluster, or same theme + technique + asset category), unique
                                proposals, own scenarios and theme gaps; rule crgo-grouping/1, identical offline
  - crgo_validate_scenario      library-proposal/v1 (read, 0.11.2): findings for one scenario descriptor (match, revoked
                                techniques, CWE consistency, vocabulary), linked controls and obligations; never an error
  - crgo_propose_library_scenario  library-proposal/v1 (writes, 0.11.2): a library-scenario proposal into the
                                installation's store folder (status proposed); never parameters or organisation figures
  - crgo_list_proposals         library-proposal/v1 (read, 0.11.2): proposals in a store folder
  - crgo_approve_proposal       library-proposal/v1 (writes, 0.11.2): proposed -> approved; adds the scenario to this
                                installation's ontology (approved/crgo-local-extension.json), not to CRGO
  - crgo_reject_proposal        library-proposal/v1 (writes, 0.11.2): proposed -> rejected, with a reason
  - crgo_export_contribution    library-proposal/v1 (writes, 0.11.2): public contribution file of an approved proposal
                                for ITriskMgr/CyberRiskGuardian-Ontology, status proposed

Every answer carries confidence and approval status per link and a caveat: library and case values are
calibration priors, never organisational evidence (CyberRiskGuardian evidence discipline).

Errors (0.11.1): bad input never surfaces as a bare "Error executing tool". Every tool returns an error document
{"error": true, "code": ..., "message": ..., "details": [...]}: INVALID_ARGUMENT (value, shape or size not accepted;
the allowed values are listed), UNKNOWN_ID (an identifier CRGO does not hold), and for the contract tools the codes of
contracts/*/v1/error.schema.json. Result sizes are clamped to 1..200 and list arguments capped at 50 values.

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
sys.path.insert(0, os.path.join(HERE, "..", "contracts"))
import grouping as GR
import proposals as PR

mcp = _Server("crgo-ontology")


def _error(code, message, details=None):
    e = {"error": True, "code": code, "message": message}
    if details: e["details"] = details
    return e


def guarded(fn):
    """Turn invalid input into an error document instead of a bare 'Error executing tool' (NV-C02)."""
    import functools
    @functools.wraps(fn)
    def wrapper(*a, **k):
        try:
            return fn(*a, **k)
        except (I.CrgoError, PR.ProposalError) as e:
            return e.document()
        except (ValueError, TypeError, KeyError) as e:
            return _error("INVALID_ARGUMENT", "%s: %s" % (type(e).__name__, str(e)[:300]))
    return wrapper


@mcp.tool()
@guarded
def crgo_sweep(asset_categories: list[str] = [], themes: list[str] = [], sector: str = "", techniques: list[str] = [],
               keywords: list[str] = [], per_theme: int = 3, min_confidence: str = "M", include_cases: bool = True,
               holdout: list[str] = [], max_total: int = 60) -> dict:
    """Start here for scenario identification. Give the organisation profile: asset categories present, themes of
    concern, sector, ATT&CK techniques seen in incidents or threat intelligence, and keywords for notable systems or
    weaknesses (synonyms are expanded: telehealth, HL7/DICOM, MFA, GenAI...). Returns scenarios matching ANY element,
    near-duplicates merged under one representative ('see_also'), up to per_theme representatives per theme, and the
    requested themes with no scenario ('theme_gaps'). holdout: case keys to ignore (e.g. 'MediBec-CRG') for blind tests.
    Then call crgo_scenario on the ones you keep. Treat all numbers as 'Analytical estimate — validation required'.
    Lists take at most 50 values; per_theme and max_total are clamped to 1..200; unknown ATT&CK ids are reported in
    'unknown_techniques'; unknown categories or themes return INVALID_ARGUMENT with the allowed values."""
    return I.sweep(asset_categories, themes, sector or None, techniques, keywords, per_theme, min_confidence, include_cases, holdout, max_total)


@mcp.tool()
@guarded
def crgo_identify(asset_categories: list[str] = [], themes: list[str] = [], sector: str = "", techniques: list[str] = [],
                  keywords: list[str] = [], min_confidence: str = "M", limit: int = 15, include_cases: bool = True,
                  holdout: list[str] = []) -> dict:
    """Identify candidate risk scenarios for an organisation profile.
    asset_categories: keys or labels from crgo_list_values('asset_category') (e.g. 'CatCloud', 'OT, IoT and connected devices').
    themes: theme keys or labels (e.g. 'ThemeRansomware'). sector: substring such as 'health', 'retail', 'banking'.
    techniques: ATT&CK ids; sub-techniques are included (e.g. 'T1566'). keywords: words to find in scenario names and statements.
    Different filters combine with AND, values within one filter with OR. min_confidence: 'H', 'M' (approved links, default) or 'L'.
    Returns scenarios with ATT&CK techniques, weaknesses, CSF 2.0 / SP 800-53 / ISO 27002 controls, Loi 25 obligations,
    estimated risk and its basis. Treat all numbers as 'Analytical estimate — validation required'.
    Lists take at most 50 values; limit is clamped to 1..200; unknown ATT&CK ids are reported in 'unknown_techniques'."""
    return I.identify(asset_categories, themes, sector or None, techniques, keywords, min_confidence, limit, include_cases, holdout)


@mcp.tool()
@guarded
def crgo_scenario(scenario_id: str, min_confidence: str = "M", holdout: list[str] = [], store_dir: str = "") -> dict:
    """Full detail for one scenario: id such as 'LIB-F1467' (library), 'MediBec/MED-A1' (case scenario) or an IRI.
    Includes the 2023 library estimates (low confidence), case-calibrated estimates where available (medium or low),
    risk indices (CRG computed values, not KRIs), evidence identifiers and the families or case scenarios it is related to.
    An identifier CRGO does not hold returns an UNKNOWN_ID document. From 0.11.2, with store_dir (the installation's
    proposal store), a local addition 'LOC-xxxxxxxxxx' approved in this installation is returned as stored."""
    sid = str(scenario_id or "").strip()
    if sid.startswith("LOC-"):
        if not PR.RX_LOC.match(sid):
            return _error("INVALID_ARGUMENT", "a local scenario id is 'LOC-' followed by 10 hexadecimal digits.")
        rec = next((r for r in PR.load_local(store_dir) if r["id"] == sid), None)
        if rec is None:
            return _error("UNKNOWN_ID", "unknown local scenario: %s (approved additions are read from store_dir)." % sid)
        return dict(rec, caveat=GR.CAVEAT)
    return I.scenario(scenario_id, min_confidence, holdout=holdout)


@mcp.tool()
@guarded
def crgo_controls_for_technique(technique: str, min_confidence: str = "M", top: int = 10) -> dict:
    """Controls most often linked to library scenarios whose threat event uses an ATT&CK technique (sub-techniques
    included), per framework. Revoked identifiers report their replacement (e.g. T1562 -> T1685). Unknown identifier:
    UNKNOWN_ID; top clamped to 1..200."""
    return I.controls_for_technique(technique, min_confidence, top)


@mcp.tool()
@guarded
def crgo_scenarios_for_control(framework: str, control_id: str, min_confidence: str = "M", limit: int = 50) -> dict:
    """Library scenarios that a framework requirement addresses. framework: 'csf2', 'sp800-53r5', 'iso27002-2022' or
    'cis81' (CIS Controls v8.1, 0.11.1); control_id as in the framework (e.g. 'PR.AA-05', 'SI-4', '8.16', '6.5').
    CIS safeguards are reached through the requirements they partially overlap ('via'): suggestions by correspondence.
    Unknown framework: INVALID_ARGUMENT listing the allowed ones; unknown requirement: UNKNOWN_ID. limit clamped to 1..200."""
    return I.scenarios_for_control(framework, control_id, min_confidence, limit)


@mcp.tool()
@guarded
def crgo_list_values(kind: str) -> list | dict:
    """Allowed filter values. kind: 'asset_category', 'theme', 'threat_source_type', 'impact_dimension' or 'sector'.
    Any other kind returns an INVALID_ARGUMENT document listing the allowed kinds."""
    return I.list_values(kind)


sys.path.insert(0, os.path.join(HERE, "..", "contracts"))


class _OrgFilesError(Exception):
    def __init__(self, doc): self.doc = doc


def _org_files(org_graph_files):
    """The organisation's RDF files, resolved to real paths; missing or unparseable files are reported as INVALID_ARGUMENT
    documents (the contracts' error schemas), never as a bare tool error (NV-C02)."""
    if isinstance(org_graph_files, str): org_graph_files = [org_graph_files]
    if not org_graph_files or not all(isinstance(f, str) and f.strip() for f in org_graph_files):
        raise _OrgFilesError(_error("INVALID_ARGUMENT", "org_graph_files: a non-empty list of paths to the organisation's own Turtle files."))
    files = [os.path.realpath(f) for f in org_graph_files]
    missing = [f for f in files if not os.path.isfile(f)]
    if missing:
        raise _OrgFilesError(_error("INVALID_ARGUMENT", "organisation graph file(s) not found.", missing))
    from rdflib import Graph
    for f in files:
        try:
            Graph().parse(f, format="turtle" if os.path.splitext(f)[1].lower() in ("", ".txt") else None)
        except Exception as e:  # noqa: BLE001 (rdflib raises several parser classes)
            raise _OrgFilesError(_error("INVALID_ARGUMENT", "%s is not an RDF file CRGO can read (%s)." % (f, type(e).__name__)))
    return files


def _date(as_of):
    import datetime
    try:
        datetime.date.fromisoformat(str(as_of))
    except (TypeError, ValueError):
        raise _OrgFilesError(_error("SCHEMA_INVALID", "as_of must be a date written yyyy-mm-dd."))
    return str(as_of)


@mcp.tool()
@guarded
def crgo_risk_context(org_graph_files: list[str], organization: str, scenario: str, as_of: str) -> dict:
    """DSS contract dss/v1 (read). org_graph_files: the organisation's own RDF files (Turtle), kept outside the CRGO
    repository's reference files; organization: the organisation IRI (its own base, never https://w3id.org/crgo/);
    scenario: the organisation's assessment scenario IRI or a CRGO library scenario; as_of: yyyy-mm-dd.
    Returns a document valid against contracts/dss/v1/risk-context.schema.json, or an error document.
    CRGO returns facts, links and their status; it never computes risk (ADR-007)."""
    import dss
    try:
        files, as_of = _org_files(org_graph_files), _date(as_of)
    except _OrgFilesError as e:
        return e.doc
    for name, v in (("organization", organization), ("scenario", scenario)):
        if not isinstance(v, str) or not I.RX_IRI.match(v.strip()):
            return _error("INVALID_ARGUMENT", "%s must be an http(s) IRI." % name)
    return dss.risk_context(files, organization.strip(), scenario.strip(), as_of)


@mcp.tool()
@guarded
def crgo_submit_assessment(document: dict, org_graph_files: list[str]) -> dict:
    """DSS contract dss/v1 (write-back). document: a result valid against contracts/dss/v1/assessment-result.schema.json
    with status 'proposed'. The result is stored as a proposed analytical result (knowledge status: risk estimate) in
    '<name>-dss-proposed.ttl' next to the first organisation graph file. It never becomes approved, an acceptance or a
    funding decision by being written back; approval is a separate act. Returns the stored IRI or an error document.
    The schema is checked first; the file is written only outside the CRGO repository (or under its build/ folder):
    a path inside the repository returns REPOSITORY_PATH (0.11.1)."""
    import dss
    from rdflib import Graph
    if not isinstance(document, dict):
        return _error("SCHEMA_INVALID", "document must be a JSON object valid against assessment-result.schema.json.")
    errs = dss.validate_doc(document, "assessment-result.schema.json")   # 0.11.1: the schema is checked first (NV-C04)
    if errs:
        return dss.error(dss.schema_error_code(errs), "The write-back document does not conform to dss/v1.", errs)
    try:
        files = _org_files(org_graph_files)
    except _OrgFilesError as e:
        return e.doc
    g = dss.load(files, reference=False)
    try:
        base = dss.org_base(document.get("organizationId", ""), g)
    except ValueError:
        return dss.error("REFERENCE_NAMESPACE", "Organisation identifiers must not be under https://w3id.org/crgo/.")
    except LookupError:
        return dss.error("UNKNOWN_ORGANISATION", "No organisation graph among the files declares a base for this organisation.")
    # the proposed graph sits next to the file that declares the organisation's base, never next to another tenant's file
    home = next((f for f in files if base in dss.declared_bases(Graph().parse(f))), None)
    if home is None:
        return dss.error("UNKNOWN_ORGANISATION", "No file declares the base %s." % base)
    out = os.path.join(os.path.dirname(home), os.path.splitext(os.path.basename(home))[0].split("-")[0] + "-dss-proposed.ttl")
    return dss.submit_assessment(document, files, out, g=g)


@mcp.tool()
@guarded
def crgo_compliance_context(org_graph_files: list[str], organization: str, as_of: str) -> dict:
    """Contract compliance/v1 (read only). org_graph_files: the organisation's own RDF files; organization: its IRI
    (own base, never https://w3id.org/crgo/); as_of: yyyy-mm-dd. Returns a document valid against
    contracts/compliance/v1/compliance-context.schema.json, or an error document. Compliance states are the
    organisation's latest recorded determinations; a mapping, statement or attestation is never evidence of compliance."""
    import views
    try:
        files, as_of = _org_files(org_graph_files), _date(as_of)
    except _OrgFilesError as e:
        return e.doc
    if not isinstance(organization, str) or not I.RX_IRI.match(organization.strip()):
        return _error("INVALID_ARGUMENT", "organization must be an http(s) IRI.")
    return views.compliance_context(files, organization.strip(), as_of)


@mcp.tool()
@guarded
def crgo_secops_context(org_graph_files: list[str], organization: str, as_of: str) -> dict:
    """Contract secops/v1 (read only). Same parameters as crgo_compliance_context. Returns a document valid against
    contracts/secops/v1/secops-context.schema.json, or an error document. It reports approval gaps as audit signals and
    never authorises a response action (ADR-011)."""
    import views
    try:
        files, as_of = _org_files(org_graph_files), _date(as_of)
    except _OrgFilesError as e:
        return e.doc
    if not isinstance(organization, str) or not I.RX_IRI.match(organization.strip()):
        return _error("INVALID_ARGUMENT", "organization must be an http(s) IRI.")
    return views.secops_context(files, organization.strip(), as_of)


# ---------------------------------------------------------------- contract library-proposal/v1 (0.11.2)
def _ref():
    return GR.load_reference()


def _id_exists(framework, ident):
    """Does CRGO hold this requirement or obligation identifier? (store lookup; proposals never invent ids)"""
    return I._control_iri(framework, ident) is not None


@mcp.tool()
@guarded
def crgo_group_candidates(candidates: list[dict], store_dir: str = "", min_confidence: str = "M") -> dict:
    """Group screening candidates with the ontology (contract library-proposal/v1, rule crgo-grouping/1). candidates: at
    most 200 objects {ref, name and/or statement, techniques, cwe, asset_categories, threat_source_types, themes,
    crgo_id} in CRGO terms (keys or English labels; no parameters or organisation figures: other fields are refused).
    Candidates in the same CRGO near-duplicate cluster, or (unmatched) sharing theme + ATT&CK technique + asset category,
    form one family proposal whose starting statement is the cluster's representative; a candidate alone in its cluster
    is a unique proposal; a candidate with no match is an own scenario, with a theme gap when no CRGO scenario has its
    theme. store_dir (optional): the installation's proposal store; its approved additions take part like library
    scenarios. Deterministic: the same input gives the same output as the offline snapshot of the same release.
    Unknown vocabulary and revoked techniques are reported, never errors; bad shapes return INVALID_ARGUMENT."""
    local = PR.load_local(store_dir)
    return GR.group(candidates, _ref(), local, I._confidence(min_confidence))


@mcp.tool()
@guarded
def crgo_validate_scenario(scenario: dict, store_dir: str = "", min_confidence: str = "M") -> dict:
    """Validate one scenario descriptor against the ontology (library-proposal/v1, crgo-validation/1): same fields as a
    candidate ('ref' optional). Returns state consistent | needs_attention | outside_ontology, findings with codes
    (LIBRARY_MATCH, THEME_MATCH_ONLY, OUTSIDE_ONTOLOGY, TECHNIQUE_UNKNOWN, TECHNIQUE_REVOKED with the successor,
    TECHNIQUE_DEPRECATED, CWE_UNKNOWN, CWE_TECHNIQUE_UNLINKED, CWE_NO_REFERENCE, ASSET_CATEGORY_UNKNOWN,
    THREAT_SOURCE_TYPE_UNKNOWN, THEME_UNKNOWN, CRGO_ID_UNKNOWN) and the linked controls and obligations. Findings never
    block anything; only a bad shape returns INVALID_ARGUMENT."""
    local = PR.load_local(store_dir)
    return GR.validate(scenario, _ref(), local, I._confidence(min_confidence))


@mcp.tool()
@guarded
def crgo_propose_library_scenario(proposal: dict, store_dir: str) -> dict:
    """Propose a scenario for this installation's ontology (library-proposal/v1, writes). proposal: {name, statement,
    themes (1-3, first = primary), asset_categories, threat_source_types, impact_dimensions, weaknesses, techniques
    [[id, H|M|L]], cwe, csf2, sp80053r5, iso27002, loi25 [[id, conf]], proposed_by, proposed_on (yyyy-mm-dd),
    anonymized: true, source_refs, public}; never parameters, estimates or organisation figures (SCHEMA_INVALID).
    Identifiers CRGO does not hold, revoked techniques (with their successor) and unknown vocabulary: INVALID_ARGUMENT.
    store_dir: an existing folder outside the CRGO repository (REPOSITORY_PATH otherwise). Returns {id 'LOC-...', status
    'proposed', path}; the same content proposed twice returns the existing proposal."""
    return PR.propose(proposal, store_dir, _ref(), _id_exists)


@mcp.tool()
@guarded
def crgo_list_proposals(store_dir: str, status: str = "") -> dict:
    """Proposals in the installation's store folder, sorted by id: id, status (proposed | approved | rejected), name,
    proposed_by/on, decided_by/on, reason, public (requested | submitted | withdrawn). status filters."""
    return PR.list_proposals(store_dir, status)


@mcp.tool()
@guarded
def crgo_approve_proposal(store_dir: str, proposal_id: str, approver: str, date: str = "") -> dict:
    """Approve a proposal (proposed -> approved; STATUS_NOT_PROPOSED if already decided, UNKNOWN_ID if absent). The
    scenario joins THIS installation's ontology (approved/crgo-local-extension.json, with its cluster and primary theme),
    not CRGO. approver: the approving person's name (required; CRGO records it, the application checks the role);
    date: yyyy-mm-dd (default today)."""
    return PR.approve(store_dir, proposal_id, approver, date, _ref())


@mcp.tool()
@guarded
def crgo_reject_proposal(store_dir: str, proposal_id: str, approver: str, reason: str, date: str = "") -> dict:
    """Reject a proposal (proposed -> rejected) with a reason (required: INVALID_ARGUMENT if empty); approver and date
    are recorded. STATUS_NOT_PROPOSED if already decided."""
    return PR.reject(store_dir, proposal_id, approver, date, reason)


@mcp.tool()
@guarded
def crgo_export_contribution(store_dir: str, proposal_id: str, out_dir: str, action: str = "add", date: str = "",
                             tool: str = "") -> dict:
    """Write the public contribution file of an APPROVED proposal (STATUS_NOT_PROPOSED otherwise) to out_dir, the folder
    for ontology proposals (never inside the CRGO repository: REPOSITORY_PATH): crgo-contribution-<id>.json, one scenario
    shaped as an authored_scenarios.json entry with status 'proposed' for ITriskMgr/CyberRiskGuardian-Ontology. Nothing
    is sent anywhere. action 'withdraw' writes a withdrawal file. tool: the producing application, for the provenance."""
    return PR.export_contribution(store_dir, proposal_id, out_dir, _ref(), action, date, tool)


if __name__ == "__main__":
    mcp.run()
