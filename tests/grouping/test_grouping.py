# -*- coding: utf-8 -*-
"""Candidate grouping and scenario validation (contract library-proposal/v1, rules crgo-grouping/1 and crgo-validation/1).
Golden replay, determinism (input order, PYTHONHASHSEED), static clusters, revoked techniques, CWE consistency, unknown
vocabulary, theme gaps and approved local additions. Store-free: reads only the committed export.
Prints ok/FAIL per check; exits non-zero on any failure. Run: python3 tests/grouping/test_grouping.py"""
import copy, json, os, random, subprocess, sys
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "pipeline", "query"))
sys.path.insert(0, os.path.join(ROOT, "pipeline", "library"))
import grouping as G  # noqa: E402

GOLDEN = os.path.join(ROOT, "contracts", "library-proposal", "v1", "examples", "golden-grouping.json")
res = []
def check(label, cond, detail=""):
    res.append(bool(cond)); print("   %-96s %s %s" % (label, "ok" if cond else "FAIL", "" if cond else str(detail)[:300]))

ref = G.load_reference()
gold = json.load(open(GOLDEN, encoding="utf-8"))
local = gold["local_extension"]["scenarios"]

def run(case, inp=None):
    inp = case["input"] if inp is None else inp
    L = local if case["local"] else []
    f = G.group if case["tool"] == "crgo_group_candidates" else G.validate
    return f(inp, ref, L, case["min_confidence"])

# 1. golden replay
check("golden: release and algorithms match the export", gold["release"] == ref.release and gold["algorithms"] == [G.ALGORITHM_GROUP, G.ALGORITHM_VALID])
for c in gold["cases"]:
    out = run(c)
    check("golden: %s" % c["id"], out == c["expected"], json.dumps(out)[:200])
r = subprocess.run([sys.executable, os.path.join(ROOT, "tests", "grouping", "make_golden.py")], capture_output=True, text=True)
check("golden: the committed file is what make_golden.py builds (inputs, mapping, local extension)", r.returncode == 0, r.stdout + r.stderr)

# 2. input-order independence (shuffled candidates and shuffled list values)
for c in gold["cases"]:
    if c["tool"] != "crgo_group_candidates": continue
    rnd = random.Random(7)
    for k in range(3):
        inp = copy.deepcopy(c["input"]); rnd.shuffle(inp)
        for x in inp:
            for f in ("techniques", "asset_categories", "threat_source_types", "cwe"):
                if f in x: rnd.shuffle(x[f])
        check("order: %s, shuffle %d gives the same output" % (c["id"], k + 1), run(c, inp) == c["expected"])

# 3. PYTHONHASHSEED independence (fresh interpreters)
code = ("import sys, json; sys.path.insert(0, %r); import grouping as G; g = json.load(open(%r)); R = G.load_reference(); "
        "print(G.canonical([G.group(c['input'], R, g['local_extension']['scenarios'] if c['local'] else [], c['min_confidence']) "
        "if c['tool'] == 'crgo_group_candidates' else G.validate(c['input'], R, g['local_extension']['scenarios'] if c['local'] else [], c['min_confidence']) "
        "for c in g['cases']]))") % (os.path.join(ROOT, "pipeline", "query"), GOLDEN)
outs = [subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, env=dict(os.environ, PYTHONHASHSEED=s)).stdout for s in ("0", "1", "4242")]
check("hash seed: identical results under PYTHONHASHSEED=0, 1 and 4242", outs[0] and outs[0] == outs[1] == outs[2])
check("hash seed: and identical to the golden expectations", outs[0].strip() == G.canonical([c["expected"] for c in gold["cases"]]))

# 4. static clusters
doc = json.load(open(os.path.join(ROOT, "data", "export", "crgo-identification.json"), encoding="utf-8"))
lib = [s for s in doc["scenarios"] if s["kind"] == "library scenario"]
prim = {s["id"]: s["primary_theme"] for s in lib}
cl1 = G.static_clusters(lib, prim); cl2 = G.static_clusters(list(reversed(lib)), prim)
check("clusters: recomputed clusters equal the exported ones, whatever the record order", cl1 == cl2 == {s["id"]: s["cluster"] for s in lib})
check("clusters: every library scenario has a primary theme among its themes", all(s["primary_theme"] in [t["key"] for t in s["themes"]] for s in lib))
reps = {s["id"] for s in lib if s["cluster"] == s["id"]}
check("clusters: a cluster id is its representative's id, itself a library scenario", all(s["cluster"] in reps for s in lib), len(reps))
check("clusters: case scenarios take the cluster of their first family", all(s["cluster"] == (cl1[sorted(x["id"] for x in s["refines"])[0]] if s.get("refines") else None)
                                                                             for s in doc["scenarios"] if s["kind"] == "case scenario"))
g = doc["grouping"]
check("export: grouping block (ATT&CK, CWE, references, theme rules)", g["attack"]["replaced"].get("T1562") == "T1685" and "CWE-79" in g["cwe_ids"]
      and len(g["theme_rules"]) == 23 and g["theme_rules"][0][0] == g["event_first"][0])

# 5. rules, one by one
def grp(cands, L=()):
    return G.group(cands, ref, list(L))
def val(s, L=()):
    return G.validate(s, ref, list(L))
o = grp([{"ref": "A", "name": "Attackers disable endpoint security tools", "techniques": ["T1562"]}])
check("revoked: T1562 is replaced by T1685 and reported per member", o["groups"][0]["members"][0]["replaced_techniques"] == {"T1562": "T1685"})
v = val({"name": "Attackers disable endpoint security tools", "techniques": ["T1562"]})
f = [x for x in v["findings"] if x["code"] == "TECHNIQUE_REVOKED"]
check("revoked: validation finding with the successor as suggestion", f and f[0]["suggestion"] == "T1685" and f[0]["severity"] == "attention")
v = val({"name": "Phishing of clinic staff credentials", "techniques": ["T1566"], "cwe": ["CWE-89"]})
check("CWE: CWE-89 with T1566 -> CWE_TECHNIQUE_UNLINKED (attention)", any(x["code"] == "CWE_TECHNIQUE_UNLINKED" for x in v["findings"]) and v["state"] == "needs_attention")
v = val({"name": "Cross-site scripting in the patient portal", "techniques": ["T1190"], "cwe": ["CWE-79"], "asset_categories": ["CatApplication"]})
check("CWE: CWE-79 with T1190 -> consistent", v["state"] == "consistent" and not [x for x in v["findings"] if x["code"].startswith("CWE")], v["findings"])
v = val({"name": "Cross-site scripting in the patient portal", "techniques": ["T1190"], "cwe": ["CWE-1037"]})
check("CWE: no reference for the CWE or its parents -> CWE_NO_REFERENCE (info only)", [x["severity"] for x in v["findings"] if x["code"] == "CWE_NO_REFERENCE"] == ["info"])
v = val({"name": "Ransomware encrypts servers", "asset_categories": ["CatNope"], "threat_source_types": ["SrcMartian"], "themes": ["ThemeNope"], "techniques": ["T9999"], "cwe": ["CWE-0"]})
codes = {x["code"] for x in v["findings"]}
check("vocabulary: unknown values are findings, not errors", {"ASSET_CATEGORY_UNKNOWN", "THREAT_SOURCE_TYPE_UNKNOWN", "THEME_UNKNOWN", "TECHNIQUE_UNKNOWN", "CWE_UNKNOWN"} <= codes, codes)
o = grp([{"ref": "A", "name": "Ransomware encrypts servers", "asset_categories": ["CatNope"], "techniques": ["T9999"]}])
check("vocabulary: grouping reports unknown values and techniques", o["unknown_techniques"] == ["T9999"] and o["unknown_values"] == {"asset_categories": ["CatNope"]})
check("labels: an English label is accepted for a key", ref.key_of("asset_category", "Identity and access systems") == "CatIdentity" and ref.key_of("theme", "phishing and social engineering") == "ThemeSocialEng")
o = grp([{"ref": "A", "name": "Phishing email harvests staff credentials"}])
check("theme: empty themes -> inferred by the theme rules (event first)", o["groups"][0]["members"][0]["primary_theme"] == "ThemeSocialEng" and o["groups"][0]["members"][0]["theme_inferred"])
o = grp([{"ref": "A", "name": "Wibble wobble glorp"}])
check("no match: own scenario with a theme gap", o["groups"][0]["kind"] == "own" and o["groups"][0]["theme_gap"] == "ThemeOther" and o["theme_gaps"] == ["ThemeOther"])
check("no match: validation says outside the ontology", val({"name": "Wibble wobble glorp"})["state"] == "outside_ontology")
o = grp([{"ref": "B", "name": "Wibble wobble glorp"}, {"ref": "A", "name": "Wibble wobble glorp"}])
check("no match: two own candidates without a shared technique and asset stay apart", [x["kind"] for x in o["groups"]] == ["own", "own"])
o = grp([{"ref": "B", "name": "Glorp one", "themes": ["ThemeOther"], "techniques": ["T1001"], "asset_categories": ["CatPeople"]},
         {"ref": "A", "name": "Glorp two", "themes": ["ThemeOther"], "techniques": ["T1001.002"], "asset_categories": ["CatPeople"]}])
check("no match: same theme + base technique + asset category -> one family, no representative, hashed id",
      len(o["groups"]) == 1 and o["groups"][0]["kind"] == "family" and o["groups"][0]["representative"] is None
      and o["groups"][0]["cluster_id"] == "GRP-" + G.sha10("A\nB"), o["groups"])
o = grp([{"ref": "A", "name": "x", "crgo_id": "LIB-F1353"}, {"ref": "B", "name": "y", "crgo_id": "LIB-F1371"}])
check("kept: CRGO ids already present are kept; same cluster -> family led by the representative",
      all(m["match"]["rule"] == "kept" for gg in o["groups"] for m in gg["members"]), o["groups"])
o = grp([{"ref": "A", "name": "Phishing attack on healthcare staff"}])
check("unique: a candidate alone in its cluster is a unique proposal with the cluster representative",
      o["groups"][0]["kind"] == "unique" and o["groups"][0]["representative"]["id"] == o["groups"][0]["cluster_id"])
o1 = grp([{"ref": "A", "name": "Café phishing attack on healthcare staff"}]); o2 = grp([{"ref": "A", "name": "Café PHISHING attack on  healthcare staff"}])
check("text: NFC, case and whitespace do not change the result", o1["groups"] == o2["groups"])
# local additions
z = {"ref": "Z", "name": "Quillon ledger forged by a payroll robot", "themes": ["ThemeIntegrity"]}
check("local: before approval the candidate is an own scenario with a theme gap", grp([z])["groups"][0]["kind"] == "own")
o = grp([z], local)
check("local: approved addition takes part; gap clears; tie broken by the smaller id", o["groups"][0]["members"][0]["match"]["id"] == "LOC-9e352c2fc1"
      and o["groups"][0]["theme_gap"] is None and o["groups"][0]["representative"]["source"] == "local", o["groups"])
check("local: result carries the extension's count and sha256", o["local"]["count"] == 3 and len(o["local"]["sha256"]) == 64)
# shapes
def err(fn):
    try:
        fn(); return None
    except ValueError as e:
        return str(e)
check("shape: an extra field (parameters) is refused", "not allowed" in (err(lambda: grp([{"ref": "A", "name": "x", "PbA": 0.4}])) or ""))
check("shape: estimates refused in validation too", "not allowed" in (err(lambda: val({"name": "x", "estimates": {}})) or ""))
check("shape: duplicate refs are refused", "duplicate" in (err(lambda: grp([{"ref": "A", "name": "x"}, {"ref": "A", "name": "y"}])) or ""))
check("shape: 201 candidates are refused, 200 accepted", err(lambda: grp([{"ref": "C%d" % i, "name": "x"} for i in range(201)])) and
      not err(lambda: grp([{"ref": "C%d" % i, "name": "phishing %d" % i} for i in range(200)])))
check("shape: name or statement required; empty list refused", err(lambda: grp([{"ref": "A"}])) and err(lambda: grp([])))

print("   grouping tests: %d of %d passed" % (sum(res), len(res)))
sys.exit(0 if all(res) else 1)
