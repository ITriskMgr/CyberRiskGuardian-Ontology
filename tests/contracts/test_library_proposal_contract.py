# -*- coding: utf-8 -*-
"""Contract library-proposal/v1 (0.11.2): schemas and examples, the store guard, and the flows
propose -> list -> approve -> group/validate with the local addition -> export contribution, and propose -> reject.
Writes only to temporary folders outside the repository; the repository must be unchanged afterwards.
Prints ok/FAIL per check; exits non-zero on any failure. Run: python3 tests/contracts/test_library_proposal_contract.py"""
import copy, glob, hashlib, json, os, shutil, sys, tempfile
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "pipeline", "query"))
sys.path.insert(0, os.path.join(ROOT, "pipeline", "contracts"))
import grouping as G  # noqa: E402
import proposals as P  # noqa: E402
import dss  # noqa: E402

V1 = os.path.join(ROOT, "contracts", "library-proposal", "v1")
EX = os.path.join(V1, "examples")
res = []
def check(label, cond, detail=""):
    res.append(bool(cond)); print("   %-96s %s %s" % (label, "ok" if cond else "FAIL", "" if cond else str(detail)[:300]))

def tree(root):
    out = {}
    for d, _, fs in os.walk(root):
        if os.path.relpath(d, root).split(os.sep)[0] in ("build", ".git") or "__pycache__" in d: continue
        for f in fs:
            p = os.path.join(d, f); out[os.path.relpath(p, root)] = hashlib.sha256(open(p, "rb").read()).hexdigest()
    return out

def code(fn):
    try:
        fn(); return None
    except P.ProposalError as e:
        doc = e.document()
        assert not dss.validate_doc(doc, "error.schema.json", V1), doc
        return e.code

before = tree(ROOT)
ref = G.load_reference()
try:
    import identify as I
    id_exists = lambda fw, i: I._control_iri(fw, i) is not None
except Exception:  # noqa: BLE001 (no store: identifier checks of requirements are skipped)
    id_exists = None
    print("   (no SPARQL store: requirement identifiers not checked)")

# 1. schemas and examples
import jsonschema
for f in sorted(glob.glob(os.path.join(V1, "*.schema.json"))):
    s = json.load(open(f, encoding="utf-8"))
    jsonschema.Draft202012Validator.check_schema(s)
    check("schema: %s is a valid JSON Schema 2020-12" % os.path.basename(f), True)
prop = json.load(open(os.path.join(EX, "proposal.infusion-telemetry.json"), encoding="utf-8"))
cand = json.load(open(os.path.join(EX, "candidate.medibec-C23.json"), encoding="utf-8"))
check("example: proposal conforms", not dss.validate_doc(prop, "proposal.schema.json", V1))
check("example: candidate conforms (schema and the port's shape check)", not dss.validate_doc(cand, "candidate.schema.json", V1) and not G.check_candidate(cand))
golden = json.load(open(os.path.join(EX, "golden-grouping.json"), encoding="utf-8"))
check("example: golden local extension conforms to local-extension.schema.json", not dss.validate_doc(golden["local_extension"], "local-extension.schema.json", V1),
      dss.validate_doc(golden["local_extension"], "local-extension.schema.json", V1))
check("example: every golden candidate conforms to candidate.schema.json",
      all(not dss.validate_doc(c, "candidate.schema.json", V1) for case in golden["cases"] if case["tool"] == "crgo_group_candidates" for c in case["input"]))
bad_cand = json.load(open(os.path.join(EX, "invalid", "candidate-with-figures.json"), encoding="utf-8"))
check("invalid: candidate with a figure rejected by the schema and the shape check", dss.validate_doc(bad_cand, "candidate.schema.json", V1) and G.check_candidate(bad_cand))
EXPECT = {"proposal-with-estimates.json": "SCHEMA_INVALID", "proposal-with-parameters.json": "SCHEMA_INVALID", "proposal-not-anonymized.json": "SCHEMA_INVALID",
          "proposal-revoked-technique.json": "INVALID_ARGUMENT", "proposal-unknown-theme.json": "INVALID_ARGUMENT",
          "proposal-unknown-control.json": "INVALID_ARGUMENT" if id_exists else None}
tmp = tempfile.mkdtemp(prefix="crgo-proposals-")
store = os.path.join(tmp, "crgo-local"); os.makedirs(store)
for f, exp in EXPECT.items():
    if exp is None: continue
    doc = json.load(open(os.path.join(EX, "invalid", f), encoding="utf-8"))
    check("invalid: %s -> %s" % (f, exp), code(lambda: P.propose(doc, store, ref, id_exists)) == exp)
e = None
try:
    P.propose(json.load(open(os.path.join(EX, "invalid", "proposal-revoked-technique.json"))), store, ref, id_exists)
except P.ProposalError as x:
    e = x
check("invalid: a revoked technique is refused with its successor in the details", e and any("T1685" in d for d in e.details), e and e.details)
check("invalid: nothing was stored by refused proposals", not os.path.isdir(os.path.join(store, "proposals")) or not os.listdir(os.path.join(store, "proposals")))

# 2. store guard
check("guard: store inside the repository -> REPOSITORY_PATH", code(lambda: P.propose(prop, os.path.join(ROOT, "tests"), ref)) == "REPOSITORY_PATH")
check("guard: store under build/ -> REPOSITORY_PATH (no build/ exception)", code(lambda: P.list_proposals(os.path.join(ROOT, "build"))) == "REPOSITORY_PATH")
link = os.path.join(tmp, "link-into-repo"); os.symlink(os.path.join(ROOT, "data"), link)
check("guard: a symlink into the repository -> REPOSITORY_PATH", code(lambda: P.propose(prop, link, ref)) == "REPOSITORY_PATH")
check("guard: empty store_dir for a write tool -> INVALID_ARGUMENT", code(lambda: P.propose(prop, "", ref)) == "INVALID_ARGUMENT")
check("guard: relative store_dir -> INVALID_ARGUMENT", code(lambda: P.propose(prop, "crgo-local", ref)) == "INVALID_ARGUMENT")
check("guard: missing store folder -> INVALID_ARGUMENT", code(lambda: P.propose(prop, os.path.join(tmp, "nope"), ref)) == "INVALID_ARGUMENT")
check("guard: read tools work without a store (library only)", P.load_local("") == [])

# 3. propose -> list -> approve -> grouping uses it -> export
r1 = P.propose(prop, store, ref, id_exists)
r2 = P.propose(copy.deepcopy(dict(prop, proposed_by="Someone else")), store, ref, id_exists)
check("propose: status proposed, id LOC-<10 hex>, file in proposals/", r1["status"] == "proposed" and P.RX_LOC.match(r1["id"]) and os.path.isfile(r1["path"]))
check("propose: the same content twice is idempotent (same id, existing)", r2["id"] == r1["id"] and r2["existing"] and r2["status"] == "proposed")
check("propose: the id is the documented hash of the content", r1["id"] == "LOC-" + hashlib.sha256(G.canonical({k: prop[k] for k in P.CONTENT_KEYS if k in prop}).encode()).hexdigest()[:10])
lst = P.list_proposals(store)
check("list: one proposal, proposed, public requested", lst["count"] == 1 and lst["proposals"][0]["status"] == "proposed" and lst["proposals"][0]["public"] == "requested", lst)
check("list: unknown status filter -> INVALID_ARGUMENT", code(lambda: P.list_proposals(store, "maybe")) == "INVALID_ARGUMENT")
out = os.path.join(tmp, "proposals-folder"); os.makedirs(out)
check("export: before approval -> STATUS_NOT_PROPOSED", code(lambda: P.export_contribution(store, r1["id"], out, ref)) == "STATUS_NOT_PROPOSED")
check("approve: unknown id -> UNKNOWN_ID", code(lambda: P.approve(store, "LOC-0000000000", "Admin", "2026-11-12", ref)) == "UNKNOWN_ID")
check("approve: malformed id -> INVALID_ARGUMENT", code(lambda: P.approve(store, "LIB-F0001", "Admin", "2026-11-12", ref)) == "INVALID_ARGUMENT")
check("approve: empty approver -> INVALID_ARGUMENT", code(lambda: P.approve(store, r1["id"], " ", "2026-11-12", ref)) == "INVALID_ARGUMENT")
check("approve: bad date -> INVALID_ARGUMENT", code(lambda: P.approve(store, r1["id"], "Admin", "12/11/2026", ref)) == "INVALID_ARGUMENT")
cand_z = {"ref": "Z", "name": prop["name"], "themes": ["ThemeMedicalIoT"]}
g0 = G.group([cand_z], ref, P.load_local(store))
a = P.approve(store, r1["id"], "Admin", "2026-11-12", ref)
check("approve: status approved, local extension written with cluster and primary theme", a["status"] == "approved" and os.path.isfile(a["local_extension"]) and a["primary_theme"] == "ThemeMedicalIoT")
ext = json.load(open(a["local_extension"], encoding="utf-8"))
check("approve: the local extension conforms to its schema", not dss.validate_doc(ext, "local-extension.schema.json", V1), dss.validate_doc(ext, "local-extension.schema.json", V1))
check("approve: the local record holds no estimates or parameters", "estimates" not in json.dumps(ext) and all("PbA" not in json.dumps(s) for s in ext["scenarios"]))
check("approve: links of the local record are 'proposed' (not reviewed by the CRGO owner)", all(x["status"] == "proposed" for s in ext["scenarios"] for x in s["attack_techniques"]))
check("approve twice -> STATUS_NOT_PROPOSED", code(lambda: P.approve(store, r1["id"], "Admin", "2026-11-12", ref)) == "STATUS_NOT_PROPOSED")
check("reject after approval -> STATUS_NOT_PROPOSED", code(lambda: P.reject(store, r1["id"], "Admin", "2026-11-12", "late")) == "STATUS_NOT_PROPOSED")
g1 = G.group([cand_z], ref, P.load_local(store))
m0, m1 = g0["groups"][0]["members"][0]["match"], g1["groups"][0]["members"][0]["match"]
check("grouping: the approved addition is matched after approval", m1 and m1["id"] == r1["id"] and (m0 is None or m0["id"] != r1["id"]), (m0, m1))
check("grouping: the local count and sha256 change with the extension", g0["local"]["count"] == 0 and g1["local"]["count"] == 1 and g0["local"]["sha256"] != g1["local"]["sha256"])
v = G.validate(dict(cand_z, techniques=["T1557"], asset_categories=["CatOTIoT"]), ref, P.load_local(store))
check("validation: matches the local addition, theme gap cleared", v["match"] and v["match"]["id"] == r1["id"] and v["theme_gap"] is None, v["match"])
check("export: out_dir inside the repository -> REPOSITORY_PATH", code(lambda: P.export_contribution(store, r1["id"], os.path.join(ROOT, "build"), ref)) == "REPOSITORY_PATH")
check("export: bad action -> INVALID_ARGUMENT", code(lambda: P.export_contribution(store, r1["id"], out, ref, action="push")) == "INVALID_ARGUMENT")
x = P.export_contribution(store, r1["id"], out, ref, date="2026-11-12", tool="CyberRiskGuardian Desktop 1.9.3")
c = json.load(open(x["path"], encoding="utf-8"))
check("export: contribution file written to the proposals folder, named crgo-contribution-<id>.json", os.path.basename(x["path"]) == "crgo-contribution-%s.json" % r1["id"])
check("export: conforms to contribution.schema.json, status proposed, action add", not dss.validate_doc(c, "contribution.schema.json", V1) and c["status"] == "proposed" and c["action"] == "add")
check("export: authored_scenarios.json keys (+ cwe) only, theme = first theme", set(c["scenario"]) == {"name", "statement", "theme", "asset_categories", "threat_source_types",
      "impact_dimensions", "weaknesses", "attack", "csf2", "sp80053r5", "iso27002", "loi25", "cwe"} and c["scenario"]["theme"] == "ThemeMedicalIoT")
check("export: no figures, parameters, proposer names or source refs", not any(k in json.dumps(c) for k in ("PbA", "estimate", "Analyst", "C09", "proposed_by")))
check("export: the stored example equals this contribution", c == json.load(open(os.path.join(EX, "contribution.infusion-telemetry.json"), encoding="utf-8"))
      if os.path.isfile(os.path.join(EX, "contribution.infusion-telemetry.json")) else False)
check("list: public submitted after export", P.list_proposals(store)["proposals"][0]["public"] == "submitted")
w = P.export_contribution(store, r1["id"], out, ref, action="withdraw", date="2026-11-13", tool="CyberRiskGuardian Desktop 1.9.3")
check("withdraw: a new file with action withdraw; list says withdrawn", json.load(open(w["path"]))["action"] == "withdraw" and P.list_proposals(store)["proposals"][0]["public"] == "withdrawn")
bad = copy.deepcopy(c); bad["scenario"]["estimates"] = {"PbA": 0.4}
check("contribution schema: an extra field (estimates) is refused", dss.validate_doc(bad, "contribution.schema.json", V1))
bad = copy.deepcopy(c); bad["status"] = "approved"
check("contribution schema: status other than proposed is refused", dss.validate_doc(bad, "contribution.schema.json", V1))

# 4. propose -> reject
p2 = dict(prop, name="Badge readers of the pharmacy cloned", statement="An intruder clones staff badges at the pharmacy door and enters the drug store room.",
          themes=["ThemePhysical"], techniques=[], cwe=[], csf2=[], sp80053r5=[], iso27002=[])
r3 = P.propose(p2, store, ref, id_exists)
check("reject: without a reason -> INVALID_ARGUMENT", code(lambda: P.reject(store, r3["id"], "Admin", "2026-11-12", "  ")) == "INVALID_ARGUMENT")
j = P.reject(store, r3["id"], "Admin", "2026-11-12", "Covered by LIB-F0300")
lst = {s["id"]: s for s in P.list_proposals(store)["proposals"]}
check("reject: status rejected with approver, date and reason", j["status"] == "rejected" and lst[r3["id"]]["decided_by"] == "Admin" and lst[r3["id"]]["reason"] == "Covered by LIB-F0300")
check("reject: not added to the local extension", r3["id"] not in json.dumps(P.load_local(store)))
check("reject: export -> STATUS_NOT_PROPOSED; approve after reject -> STATUS_NOT_PROPOSED",
      code(lambda: P.export_contribution(store, r3["id"], out, ref)) == "STATUS_NOT_PROPOSED" and code(lambda: P.approve(store, r3["id"], "A", "", ref)) == "STATUS_NOT_PROPOSED")
check("list: status filter", [s["id"] for s in P.list_proposals(store, "rejected")["proposals"]] == [r3["id"]])

if "--write-example" in sys.argv:
    json.dump(c, open(os.path.join(EX, "contribution.infusion-telemetry.json"), "w", encoding="utf-8"), indent=1, ensure_ascii=False); print("   example written")
shutil.rmtree(tmp, ignore_errors=True)
after = tree(ROOT)
changed = sorted(k for k in set(before) | set(after) if before.get(k) != after.get(k) and not k.endswith("contribution.infusion-telemetry.json"))
check("repository unchanged outside build/", not changed, changed)
print("   library-proposal contract tests: %d of %d passed" % (sum(res), len(res)))
sys.exit(0 if all(res) else 1)
