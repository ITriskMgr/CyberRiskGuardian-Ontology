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
print("   identification tests: %s" % ("all passed" if not fails else "%d FAILED" % len(fails)))
sys.exit(1 if fails else 0)
