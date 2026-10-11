# -*- coding: utf-8 -*-
"""0.8.0: sector frequency evidence from the VERIS Community Database (VCDB, github.com/vz-risk/VCDB, commit f6f98c0,
2026-09-30; CC BY-SA 4.0). Only counts derived from VCDB are stored, with attribution; no incident text is copied.

For each sector (NAICS two-digit group of the victim) the share of confirmed security incidents of 2015-2025 that
involve each CRGO theme or threat-source type, by rules on the VERIS fields (an incident can count under several):
  ThemeRansomware  action.malware.variety contains Ransomware
  ThemeSocialEng   action.social present
  ThemeInsider     action.misuse present
  ThemePhysical    action.physical present, or action.error.variety Loss
  ThemeAccess      action.hacking.variety Use of stolen creds, Brute force or Password dumping
  ThemeVulnMgmt    action.hacking.variety Exploit vuln
  ThemeDoS         action.hacking.variety DoS
  ThemeThirdParty  actor.partner present
  ThemeDataBreach  attribute.confidentiality.data_disclosure Yes
  SrcAccidental    action.error present;  SrcEnvironmental  action.environmental present
  SrcAdversarial   any of hacking, malware, social, misuse or physical
Mass campaigns are counted once per sector: incidents that share a VCDB campaign_id, or whose summary names one of the
known supply-chain compromises below (each coded in VCDB once per victim; the 2023 MOVEit breach alone accounts for 613 of
the 842 education incidents of the period).
VCDB is built from public reports (news, regulators' breach lists), so it over-represents disclosed breaches and sectors
with mandatory reporting (healthcare, public sector); shares are relative frequencies in that record, not incident rates.
Writes data/library/vcdb_frequencies.csv."""
import csv, json, os, zipfile, collections

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SECTORS = [("all", "All sectors", None), ("healthcare", "Health care (NAICS 62)", ("62",)), ("public", "Public administration (NAICS 92)", ("92",)),
           ("education", "Education (NAICS 61)", ("61",)), ("finance", "Finance and insurance (NAICS 52)", ("52",)),
           ("information", "Information (NAICS 51)", ("51",)), ("professional", "Professional services (NAICS 54)", ("54",)),
           ("retail", "Retail (NAICS 44-45)", ("44", "45")), ("manufacturing", "Manufacturing (NAICS 31-33)", ("31", "32", "33")),
           ("accommodation", "Accommodation and food (NAICS 72)", ("72",))]


CAMPAIGNS = ("moveit", "blackbaud", "accellion", "kaseya", "solarwinds")


def campaign(x):
    cid = x.get("campaign_id") or x.get("plus", {}).get("campaign_id")
    if cid:
        return cid
    s = (x.get("summary") or "").lower()
    return next((c for c in CAMPAIGNS if c in s), None)


def dedupe(inc):
    seen, out = set(), []
    for x in inc:
        c = campaign(x)
        if c is None:
            out.append(x)
        elif c not in seen:
            seen.add(c); out.append(x)
    return out


def tags(x):
    a, out = x.get("action", {}), set()
    if "Ransomware" in a.get("malware", {}).get("variety", []):
        out.add("ThemeRansomware")
    if "social" in a:
        out.add("ThemeSocialEng")
    if "misuse" in a:
        out.add("ThemeInsider")
    if "physical" in a or "Loss" in a.get("error", {}).get("variety", []):
        out.add("ThemePhysical")
    hv = set(a.get("hacking", {}).get("variety", []))
    if hv & {"Use of stolen creds", "Brute force", "Password dumping"}:
        out.add("ThemeAccess")
    if "Exploit vuln" in hv:
        out.add("ThemeVulnMgmt")
    if "DoS" in hv:
        out.add("ThemeDoS")
    if "partner" in x.get("actor", {}):
        out.add("ThemeThirdParty")
    if x.get("attribute", {}).get("confidentiality", {}).get("data_disclosure") == "Yes":
        out.add("ThemeDataBreach")
    if "error" in a:
        out.add("SrcAccidental")
    if "environmental" in a:
        out.add("SrcEnvironmental")
    if {"hacking", "malware", "social", "misuse", "physical"} & set(a):
        out.add("SrcAdversarial")
    return out


def main():
    z = zipfile.ZipFile(os.path.join(ROOT, "data", "raw", "external", "vcdb.json.zip"))
    data = json.loads(z.read([n for n in z.namelist() if n.endswith(".json")][0]))
    rows = []
    for key, label, naics in SECTORS:
        inc = [x for x in data if x.get("security_incident") == "Confirmed"
               and 2015 <= (x.get("timeline", {}).get("incident", {}).get("year") or 0) <= 2025
               and (naics is None or (x.get("victim", {}).get("industry") or "")[:2] in naics)]
        inc = dedupe(inc)
        c = collections.Counter(t for x in inc for t in tags(x))
        for t, k in sorted(c.items()):
            rows.append((key, label, t, len(inc), k, round(k / len(inc), 4)))
        print("%-14s n=%5d  %s" % (key, len(inc), ", ".join("%s %.0f%%" % (t.replace("Theme", "").replace("Src", "src:"), 100 * k / len(inc))
                                                          for t, k in c.most_common(7))))
    with open(os.path.join(ROOT, "data", "library", "vcdb_frequencies.csv"), "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["sector", "sector_label", "category", "incidents", "count", "share"])
        w.writerows(rows)


if __name__ == "__main__":
    main()
