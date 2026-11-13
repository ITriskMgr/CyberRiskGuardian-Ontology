# -*- coding: utf-8 -*-
"""Smoke tests of the identification interface (pipeline/query/identify.py), as CyberRiskGuardian would call it."""
import os, sys
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "pipeline", "query"))
import identify as I

fails = []
def check(name, cond):
    print("   %-62s %s" % (name, "ok" if cond else "FAIL")); cond or fails.append(name)

r = I.identify(asset_categories=["CatOTIoT"], sector="health", limit=5)
check("OT/IoT in healthcare returns scenarios", r["matches"] >= 20 and r["returned"] == 5)
check("every returned scenario has controls", all(any(s["controls"].values()) or s.get("refines") for s in r["scenarios"]))
check("default filter returns approved links only", all(x["status"] == "approved" for s in r["scenarios"] for x in s["attack_techniques"]))
r = I.identify(techniques=["T1566"], limit=50)
check("phishing technique (with sub-techniques) finds >= 20 scenarios", r["matches"] >= 20)
r = I.identify(themes=["ThemeRansomware"], keywords=["backup"], limit=10)
check("theme + keyword filter combines with AND", r["matches"] >= 1 and all(any(t["key"] == "ThemeRansomware" for t in s["themes"]) for s in r["scenarios"]))
s = I.scenario("MediBec/MED-A8")
check("unmatched case scenario has its own links", any(x["id"] == "T1574.001" for x in s["attack_techniques"]))
s = I.scenario("LIB-F0283")
check("library scenario carries 2023 and case-calibrated estimates", {"library_2023", "case_calibrated"} <= set(s["estimates"]))
check("caveat present", "validation required" in s["caveat"])
c = I.controls_for_technique("T1562")
check("revoked technique reports its replacement", c["replaced_by"] == "T1685")
c = I.controls_for_technique("T1486")
check("ransomware encryption maps to backup control PR.DS-11", any(x["id"] == "PR.DS-11" for x in c["controls"].get("csf2", [])))
c = I.scenarios_for_control("iso27002-2022", "8.13")
check("ISO 8.13 (backup) addresses scenarios", c["matches"] >= 5)
check("filter values listed", len(I.list_values("asset_category")) == 10 and len(I.list_values("theme")) == 23)
r = I.sweep(asset_categories=["CatOTIoT", "CatCloud"], themes=["ThemeRansomware"], sector="health", keywords=["backup", "telehealth"], holdout=["MediBec-CRG", "MediBec"])
check("sweep merges near-duplicates and covers several themes", r["distinct"] < r["candidates"] and len(r["themes_covered"]) >= 5)
check("holdout hides the held-out case everywhere", not any(s_["kind"] != "library scenario" and s_["kind"] != "case scenario" for s_ in r["scenarios"])
      and not any(s_["id"].startswith(("MediBec-CRG/", "MediBec/")) for s_ in r["scenarios"]))
r2 = I.identify(themes=["ThemeRansomware"], holdout=["MediBec-CRG"], limit=100)
check("assessment scenarios are never returned as candidates", all(s_["kind"] != "assessment scenario" for s_ in r2["scenarios"]))
check("sweep returns baseline risks", any(s_["selected_because"].startswith("commonly assessed") for s_ in r["scenarios"]))
r = I.identify(keywords=["telehealth"])
check("synonyms: 'telehealth' finds telemedicine scenarios", any("telemedicine" in s_["name"].lower() for s_ in r["scenarios"]))
# 0.11.1: input validation and bounded results (NV-C01, NV-C02, NV-C03, NV-C06)
def code(fn, *a, **k):
    try:
        fn(*a, **k); return None
    except I.CrgoError as e:
        return e.code
check("injection through a technique id is refused, not executed", code(I.identify, techniques=['T1566" "T1059']) == "INVALID_ARGUMENT")
check("injection through a scenario id is refused", code(I.scenario, '"} } ; DROP ALL ; SELECT * WHERE { ?s ?p ?o } #') == "INVALID_ARGUMENT")
check("injection through a control id is refused", code(I.scenarios_for_control, "csf2", 'PR.AA-05" } UNION { ?s ?p ?o') == "INVALID_ARGUMENT")
check("an IRI with '>' is refused", code(I.scenario, "https://w3id.org/crgo/data/library/F0001> } UNION { ?s ?p ?o") == "INVALID_ARGUMENT")
check("unknown scenario id -> UNKNOWN_ID", code(I.scenario, "LIB-F999999") == "UNKNOWN_ID" and code(I.scenario, "") == "INVALID_ARGUMENT")
check("unknown list_values kind -> INVALID_ARGUMENT", code(I.list_values, "nope") == "INVALID_ARGUMENT" and code(I.list_values, "") == "INVALID_ARGUMENT")
check("unknown asset category or theme -> INVALID_ARGUMENT", code(I.sweep, asset_categories=["CatNope"]) == "INVALID_ARGUMENT" and code(I.identify, themes=["ThemeNope"]) == "INVALID_ARGUMENT")
check("bad min_confidence -> INVALID_ARGUMENT", code(I.sweep, min_confidence="Z") == "INVALID_ARGUMENT")
check("unknown technique is reported, not silently ignored", I.identify(techniques=["T9999"]).get("unknown_techniques") == ["T9999"] and code(I.controls_for_technique, "T9999") == "UNKNOWN_ID")
r = I.identify(techniques=["T1566"], limit=-1)
check("limit is clamped to 1..200 (limit -1 returns 1)", r["returned"] == 1)
check("limit 10^9 is clamped to 200", I.identify(techniques=["T1566"], limit=10**9)["returned"] <= 200)
check("list arguments are capped at 50 values", code(I.sweep, keywords=["x%d" % i for i in range(51)]) == "INVALID_ARGUMENT")
check("sweep per_theme and max_total are clamped", I.sweep(themes=["ThemeRansomware"], per_theme=0, max_total=-5)["returned"] == 1)
check("unknown framework -> INVALID_ARGUMENT listing the allowed ones", code(I.scenarios_for_control, "cis-v8.1", "6.5") == "INVALID_ARGUMENT")
check("unknown requirement -> UNKNOWN_ID", code(I.scenarios_for_control, "csf2", "ZZ.ZZ-99") == "UNKNOWN_ID")
c = I.scenarios_for_control("cis81", "6.5")
check("CIS v8.1 safeguard reaches scenarios through its correspondences ('via')", c["matches"] >= 1 and c["via"] and all(s_["via"] for s_ in c["scenarios"]))
# 0.11.2: ties are broken by IRI, so a sweep no longer depends on the string-hash seed
import subprocess
_code = ("import sys, json; sys.path.insert(0, %r); import identify as I; print(json.dumps(I.sweep(asset_categories=['CatCloud'], "
         "themes=['ThemeRansomware', 'ThemeSocialEng'], sector='health', techniques=['T1566']), sort_keys=True))") % os.path.join(ROOT, "pipeline", "query")
_outs = [subprocess.run([sys.executable, "-c", _code], capture_output=True, text=True, env=dict(os.environ, PYTHONHASHSEED=h)).stdout for h in ("0", "1")]
check("sweep is identical under PYTHONHASHSEED=0 and 1 (tie-break by IRI)", _outs[0] and _outs[0] == _outs[1])
print("   identification tests: %s" % ("all passed" if not fails else "%d FAILED" % len(fails)))
sys.exit(1 if fails else 0)
