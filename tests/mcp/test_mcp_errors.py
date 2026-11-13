# -*- coding: utf-8 -*-
"""Drive the CRGO stdio MCP server with empty, unknown-identifier and hostile inputs (0.11.1, NV-C01..C04, NV-C06;
0.11.2: the seven library-proposal/v1 tools, with a proposal store and a proposals folder in temporary folders).

Every call must come back as a tool result, never as a bare "Error executing tool": bad input gives an error document
with a code (INVALID_ARGUMENT, UNKNOWN_ID, SCHEMA_INVALID, REPOSITORY_PATH ...), result sizes are bounded, and a
write-back aimed inside the repository is refused and leaves the repository unchanged outside build/.

Requires the `mcp` package. Run from anywhere: python3 tests/mcp/test_mcp_errors.py
"""
import asyncio, hashlib, json, os, shutil, sys, tempfile, time
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SAMPLES = os.path.join(ROOT, "tests", "samples")
N = "https://example.org/crgo-sample/nordelle/"
ORG = tempfile.mkdtemp(prefix="crgo-mcp-org-")     # the organisation's folder, outside the repository
for f in ("nordelle.ttl", "nordelle-applicability.ttl", "nordelle-grca.ttl", "tenant-b.ttl"):
    shutil.copy(os.path.join(SAMPLES, f), ORG)
OF = [os.path.join(ORG, f) for f in ("nordelle.ttl", "nordelle-applicability.ttl", "nordelle-grca.ttl", "tenant-b.ttl")]
REPO_FILES = [os.path.join(SAMPLES, f) for f in ("nordelle.ttl", "nordelle-applicability.ttl", "nordelle-grca.ttl", "tenant-b.ttl")]
WB = json.load(open(os.path.join(ROOT, "contracts", "dss", "v1", "examples", "assessment-result.nordelle-ransomware.json")))
INJ = '"} } ; DROP ALL ; SELECT * WHERE { ?s ?p ?o } #'
BIG = ["x" * 50] * 5000
# 0.11.2, contract library-proposal/v1: the installation's proposal store and proposals folder, outside the repository
sys.path.insert(0, os.path.join(ROOT, "pipeline", "contracts"))
import proposals as _P  # noqa: E402
LP = os.path.join(ROOT, "contracts", "library-proposal", "v1", "examples")
STORE = tempfile.mkdtemp(prefix="crgo-mcp-store-")
OUTD = tempfile.mkdtemp(prefix="crgo-mcp-out-")
PROP = json.load(open(os.path.join(LP, "proposal.infusion-telemetry.json")))
PID = _P.proposal_id(PROP)
GOLD = json.load(open(os.path.join(LP, "golden-grouping.json")))
MB = next(c["input"] for c in GOLD["cases"] if c["id"] == "medibec-45")

# tool, label, args, expected: a code (error document), "ok" (a result), or "ok<=N" (a result of at most N returned items)
CASES = [
 ("crgo_list_values", "asset_category", {"kind": "asset_category"}, "ok"),
 ("crgo_list_values", "empty kind", {"kind": ""}, "INVALID_ARGUMENT"),
 ("crgo_list_values", "unknown kind", {"kind": "nope"}, "INVALID_ARGUMENT"),
 ("crgo_list_values", "injection", {"kind": INJ}, "INVALID_ARGUMENT"),
 ("crgo_sweep", "health ransomware", {"asset_categories": ["CatCloud"], "themes": ["ThemeRansomware"], "sector": "health"}, "ok"),
 ("crgo_sweep", "unknown cat/theme", {"asset_categories": ["CatNope"], "themes": ["ThemeNope"]}, "INVALID_ARGUMENT"),
 ("crgo_sweep", "injection keyword/sector", {"keywords": [INJ], "sector": INJ}, "INVALID_ARGUMENT"),
 ("crgo_sweep", "negative/huge bounds", {"themes": ["ThemeRansomware"], "per_theme": -5, "max_total": 10**9}, "ok<=200"),
 ("crgo_sweep", "5000 keywords", {"keywords": BIG}, "INVALID_ARGUMENT"),
 ("crgo_sweep", "bad confidence", {"themes": ["ThemeRansomware"], "min_confidence": "Z"}, "INVALID_ARGUMENT"),
 ("crgo_identify", "phishing T1566", {"techniques": ["T1566"], "limit": 5}, "ok<=5"),
 ("crgo_identify", "limit -1", {"techniques": ["T1566"], "limit": -1}, "ok<=1"),
 ("crgo_identify", "limit 10^9", {"techniques": ["T1566"], "limit": 10**9}, "ok<=200"),
 ("crgo_identify", "injection", {"keywords": [INJ], "techniques": [INJ]}, "INVALID_ARGUMENT"),
 ("crgo_identify", "crafted technique", {"techniques": ['T1566" "T1059']}, "INVALID_ARGUMENT"),
 ("crgo_scenario", "LIB-F1467", {"scenario_id": "LIB-F1467"}, "ok"),
 ("crgo_scenario", "empty", {"scenario_id": ""}, "INVALID_ARGUMENT"),
 ("crgo_scenario", "unknown", {"scenario_id": "LIB-F999999"}, "UNKNOWN_ID"),
 ("crgo_scenario", "injection", {"scenario_id": INJ}, "INVALID_ARGUMENT"),
 ("crgo_scenario", "file IRI", {"scenario_id": "file:///etc/passwd"}, "INVALID_ARGUMENT"),
 ("crgo_scenario", "IRI with >", {"scenario_id": "https://w3id.org/crgo/data/library/F0001> } UNION { ?s ?p ?o"}, "INVALID_ARGUMENT"),
 ("crgo_scenario", "unknown IRI", {"scenario_id": "https://w3id.org/crgo/data/library/F999999"}, "UNKNOWN_ID"),
 ("crgo_controls_for_technique", "T1566", {"technique": "T1566"}, "ok"),
 ("crgo_controls_for_technique", "injection", {"technique": INJ}, "INVALID_ARGUMENT"),
 ("crgo_controls_for_technique", "unknown", {"technique": "T9999"}, "UNKNOWN_ID"),
 ("crgo_scenarios_for_control", "cis81 6.5", {"framework": "cis81", "control_id": "6.5"}, "ok"),
 ("crgo_scenarios_for_control", "cis-v8.1 (wrong name)", {"framework": "cis-v8.1", "control_id": "6.5"}, "INVALID_ARGUMENT"),
 ("crgo_scenarios_for_control", "unknown requirement", {"framework": "csf2", "control_id": "ZZ.ZZ-99"}, "UNKNOWN_ID"),
 ("crgo_scenarios_for_control", "injection", {"framework": "csf2", "control_id": INJ}, "INVALID_ARGUMENT"),
 ("crgo_risk_context", "nordelle ransomware", {"org_graph_files": OF, "organization": N + "org", "scenario": N + "scenario/ransomware", "as_of": "2026-10-11"}, "ok"),
 ("crgo_risk_context", "bad date", {"org_graph_files": OF, "organization": N + "org", "scenario": N + "scenario/ransomware", "as_of": "11/10/2026"}, "SCHEMA_INVALID"),
 ("crgo_risk_context", "/etc/passwd as graph", {"org_graph_files": ["/etc/passwd"], "organization": N + "org", "scenario": N + "scenario/ransomware", "as_of": "2026-10-11"}, "INVALID_ARGUMENT"),
 ("crgo_risk_context", "missing file", {"org_graph_files": [os.path.join(ORG, "nope.ttl")], "organization": N + "org", "scenario": N + "scenario/ransomware", "as_of": "2026-10-11"}, "INVALID_ARGUMENT"),
 ("crgo_risk_context", "no files", {"org_graph_files": [], "organization": N + "org", "scenario": N + "scenario/ransomware", "as_of": "2026-10-11"}, "INVALID_ARGUMENT"),
 ("crgo_compliance_context", "bad date", {"org_graph_files": OF, "organization": N + "org", "as_of": "yesterday"}, "SCHEMA_INVALID"),
 ("crgo_compliance_context", "/etc/hostname", {"org_graph_files": ["/etc/hostname"], "organization": N + "org", "as_of": "2026-10-11"}, "INVALID_ARGUMENT"),
 ("crgo_secops_context", "nordelle", {"org_graph_files": OF, "organization": N + "org", "as_of": "2026-10-11"}, "ok"),
 ("crgo_submit_assessment", "valid -> org dir", {"document": WB, "org_graph_files": OF}, "ok"),
 ("crgo_submit_assessment", "empty doc", {"document": {}, "org_graph_files": OF}, "SCHEMA_INVALID"),
 ("crgo_submit_assessment", "status approved", {"document": dict(WB, status="approved"), "org_graph_files": OF}, "STATUS_NOT_PROPOSED"),
 ("crgo_submit_assessment", "org under w3id crgo", {"document": dict(WB, organizationId="https://w3id.org/crgo/org"), "org_graph_files": OF}, "REFERENCE_NAMESPACE"),
 ("crgo_submit_assessment", "org files inside repo tests/samples", {"document": WB, "org_graph_files": REPO_FILES}, "REPOSITORY_PATH"),
 ("crgo_submit_assessment", "/etc/passwd graph", {"document": WB, "org_graph_files": ["/etc/passwd"]}, "INVALID_ARGUMENT"),
 # 0.11.2: contract library-proposal/v1
 ("crgo_group_candidates", "MediBec 45 candidates", {"candidates": MB}, "ok"),
 ("crgo_group_candidates", "empty list", {"candidates": []}, "INVALID_ARGUMENT"),
 ("crgo_group_candidates", "201 candidates", {"candidates": [{"ref": "C%d" % i, "name": "x"} for i in range(201)]}, "INVALID_ARGUMENT"),
 ("crgo_group_candidates", "injection in ref", {"candidates": [{"ref": INJ, "name": "x"}]}, "INVALID_ARGUMENT"),
 ("crgo_group_candidates", "injection in technique (finding)", {"candidates": [{"ref": "A", "name": "x", "techniques": [INJ[:90]]}]}, "ok"),
 ("crgo_group_candidates", "parameters in a candidate", {"candidates": [{"ref": "A", "name": "x", "PbA": 0.4}]}, "INVALID_ARGUMENT"),
 ("crgo_group_candidates", "bad confidence", {"candidates": [{"ref": "A", "name": "x"}], "min_confidence": "Z"}, "INVALID_ARGUMENT"),
 ("crgo_group_candidates", "store inside repo", {"candidates": [{"ref": "A", "name": "x"}], "store_dir": os.path.join(ROOT, "data")}, "REPOSITORY_PATH"),
 ("crgo_group_candidates", "relative store", {"candidates": [{"ref": "A", "name": "x"}], "store_dir": "crgo-local"}, "INVALID_ARGUMENT"),
 ("crgo_validate_scenario", "revoked + unknown vocab", {"scenario": {"name": "x", "techniques": ["T1562", "T9999"], "asset_categories": ["CatNope"]}}, "ok"),
 ("crgo_validate_scenario", "estimates in scenario", {"scenario": {"name": "x", "estimates": {"PbA": 0.4}}}, "INVALID_ARGUMENT"),
 ("crgo_validate_scenario", "no name or statement", {"scenario": {"ref": "A"}}, "INVALID_ARGUMENT"),
 ("crgo_propose_library_scenario", "empty proposal", {"proposal": {}, "store_dir": STORE}, "SCHEMA_INVALID"),
 ("crgo_propose_library_scenario", "with estimates", {"proposal": dict(PROP, estimates={"PbA": 0.4}), "store_dir": STORE}, "SCHEMA_INVALID"),
 ("crgo_propose_library_scenario", "revoked technique", {"proposal": dict(PROP, techniques=[["T1562", "M"]]), "store_dir": STORE}, "INVALID_ARGUMENT"),
 ("crgo_propose_library_scenario", "unknown control", {"proposal": dict(PROP, sp80053r5=[["ZZ-99", "M"]]), "store_dir": STORE}, "INVALID_ARGUMENT"),
 ("crgo_propose_library_scenario", "empty store_dir", {"proposal": PROP, "store_dir": ""}, "INVALID_ARGUMENT"),
 ("crgo_propose_library_scenario", "store inside repo", {"proposal": PROP, "store_dir": os.path.join(ROOT, "tests")}, "REPOSITORY_PATH"),
 ("crgo_propose_library_scenario", "store under build/", {"proposal": PROP, "store_dir": os.path.join(ROOT, "build")}, "REPOSITORY_PATH"),
 ("crgo_propose_library_scenario", "valid", {"proposal": PROP, "store_dir": STORE}, "ok"),
 ("crgo_list_proposals", "store", {"store_dir": STORE}, "ok"),
 ("crgo_list_proposals", "empty store_dir", {"store_dir": ""}, "INVALID_ARGUMENT"),
 ("crgo_list_proposals", "bad status", {"store_dir": STORE, "status": INJ}, "INVALID_ARGUMENT"),
 ("crgo_export_contribution", "before approval", {"store_dir": STORE, "proposal_id": PID, "out_dir": OUTD}, "STATUS_NOT_PROPOSED"),
 ("crgo_approve_proposal", "unknown id", {"store_dir": STORE, "proposal_id": "LOC-0000000000", "approver": "Admin"}, "UNKNOWN_ID"),
 ("crgo_approve_proposal", "injection id", {"store_dir": STORE, "proposal_id": INJ, "approver": "Admin"}, "INVALID_ARGUMENT"),
 ("crgo_approve_proposal", "no approver", {"store_dir": STORE, "proposal_id": PID, "approver": ""}, "INVALID_ARGUMENT"),
 ("crgo_approve_proposal", "valid", {"store_dir": STORE, "proposal_id": PID, "approver": "Admin", "date": "2026-11-12"}, "ok"),
 ("crgo_approve_proposal", "twice", {"store_dir": STORE, "proposal_id": PID, "approver": "Admin", "date": "2026-11-12"}, "STATUS_NOT_PROPOSED"),
 ("crgo_reject_proposal", "after approval", {"store_dir": STORE, "proposal_id": PID, "approver": "Admin", "reason": "no"}, "STATUS_NOT_PROPOSED"),
 ("crgo_reject_proposal", "no reason", {"store_dir": STORE, "proposal_id": PID, "approver": "Admin", "reason": ""}, "INVALID_ARGUMENT"),
 ("crgo_reject_proposal", "unknown id", {"store_dir": STORE, "proposal_id": "LOC-0000000000", "approver": "Admin", "reason": "no"}, "UNKNOWN_ID"),
 ("crgo_scenario", "local addition with store", {"scenario_id": PID, "store_dir": STORE}, "ok"),
 ("crgo_scenario", "local addition without store", {"scenario_id": PID}, "UNKNOWN_ID"),
 ("crgo_group_candidates", "with the local store", {"candidates": [{"ref": "Z", "name": PROP["name"], "themes": ["ThemeMedicalIoT"]}], "store_dir": STORE}, "ok"),
 ("crgo_export_contribution", "out_dir inside repo", {"store_dir": STORE, "proposal_id": PID, "out_dir": os.path.join(ROOT, "build")}, "REPOSITORY_PATH"),
 ("crgo_export_contribution", "valid", {"store_dir": STORE, "proposal_id": PID, "out_dir": OUTD, "date": "2026-11-12"}, "ok"),
]

def tree(root):
    out = {}
    for d, _, fs in os.walk(root):
        if os.path.relpath(d, root).split(os.sep)[0] in ("build", ".git"): continue
        for f in fs:
            p = os.path.join(d, f)
            if "__pycache__" in p: continue
            out[os.path.relpath(p, root)] = hashlib.sha256(open(p, "rb").read()).hexdigest()
    return out

async def main():
    before = tree(ROOT)
    fails = []
    params = StdioServerParameters(command=sys.executable, args=[os.path.join(ROOT, "pipeline", "mcp", "crgo_server.py")], cwd=tempfile.gettempdir())
    async with stdio_client(params) as (r, w):
        async with ClientSession(r, w) as s:
            await s.initialize()
            for tool, label, args, expect in CASES:
                t0 = time.time()
                res = await asyncio.wait_for(s.call_tool(tool, args), 300)
                txt = "".join(getattr(c, "text", "") for c in (res.content or []))
                is_err = bool(getattr(res, "isError", False))
                dt = time.time() - t0
                try:   # a list result is sent as one text content per item
                    docs = [json.loads(getattr(c, "text", "")) for c in (res.content or [])]
                    doc = docs[0] if len(docs) == 1 else docs
                except ValueError:
                    doc = None
                ok = not is_err and doc is not None and dt < 60 and len(txt) < 2_500_000   # 200 brief scenarios at most
                if expect.startswith("ok"):
                    ok = ok and not (isinstance(doc, dict) and doc.get("error"))
                    if ok and "<=" in expect and isinstance(doc, dict):
                        ok = doc.get("returned", 0) <= int(expect.split("<=")[1])
                else:
                    ok = ok and isinstance(doc, dict) and doc.get("error") is True and doc.get("code") == expect and bool(doc.get("message"))
                got = (doc.get("code") if isinstance(doc, dict) and doc.get("error") else ("tool error" if is_err else "result")) if doc is not None or is_err else "not JSON"
                print("   %-27s %-36s %-20s %-20s %5.1fs %8dB %s" % (tool, label, "expected " + expect, "got " + str(got), dt, len(txt), "ok" if ok else "FAIL"))
                if not ok: fails.append((tool, label, txt[:200]))
    after = tree(ROOT)
    changed = sorted(k for k in set(before) | set(after) if before.get(k) != after.get(k))
    print("   repository files changed outside build/: %s" % (changed or "none"))
    if changed: fails.append(("repository", "changed", str(changed)))
    stored = [f for f in os.listdir(ORG) if f.endswith("-dss-proposed.ttl")]
    print("   proposed graph stored next to the organisation's files: %s" % (stored or "NONE"))
    if not stored: fails.append(("submit", "not stored", ""))
    contrib = [f for f in os.listdir(OUTD) if f.startswith("crgo-contribution-")]
    print("   contribution file written to the proposals folder: %s" % (contrib or "NONE"))
    if contrib != ["crgo-contribution-%s.json" % PID]: fails.append(("export_contribution", "not written", str(contrib)))
    ext = os.path.join(STORE, "approved", "crgo-local-extension.json")
    print("   local extension in the store: %s" % ("present" if os.path.isfile(ext) else "MISSING"))
    if not os.path.isfile(ext): fails.append(("approve", "no local extension", ""))
    shutil.rmtree(ORG, ignore_errors=True); shutil.rmtree(STORE, ignore_errors=True); shutil.rmtree(OUTD, ignore_errors=True)
    print("   MCP error-handling tests: %s" % ("all passed" if not fails else "%d FAILED" % len(fails)))
    for f in fails: print("     ", f)
    sys.exit(1 if fails else 0)

asyncio.run(main())
