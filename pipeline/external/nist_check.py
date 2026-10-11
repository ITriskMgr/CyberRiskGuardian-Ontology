# -*- coding: utf-8 -*-
"""0.8.0: corroborate the scenarios' CSF 2.0 and ISO/IEC 27002 links with the NIST crosswalks (nist_crosswalks.py).
A CSF (ISO) link of a scenario is corroborated when one of the scenario's own SP 800-53 links (any confidence, judged)
maps to that CSF subcategory (ISO control) in NIST's data. Scope: only links whose CSF subcategory (ISO control) appears
in the NIST crosswalk at all. Writes data/library/nist_corroboration.csv and prints agreement by confidence."""
import csv, os, collections
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
L = os.path.join(ROOT, "data", "library")
c2s = collections.defaultdict(set); s2c = collections.defaultdict(set)
for r in csv.DictReader(open(os.path.join(L, "nist_csf2_80053.csv"))): s2c[r["sp80053r5"]].add(r["csf2"]); c2s[r["csf2"]].add(r["sp80053r5"])
s2i = collections.defaultdict(set); i2s = collections.defaultdict(set)
for r in csv.DictReader(open(os.path.join(L, "nist_80053_iso27002.csv"))): s2i[r["sp80053r5"]].add(r["iso27002"]); i2s[r["iso27002"]].add(r["sp80053r5"])
links = list(csv.DictReader(open(os.path.join(L, "links.csv"))))
ctl = collections.defaultdict(set)
for l in links:
    if l["scheme"] == "sp80053r5" and not l["basis"].startswith("CTID"): ctl[l["family"]].add(l["id"])
rows, st = [], collections.Counter()
for l in links:
    f = l["family"]
    if l["scheme"] == "csf2" and l["id"] in c2s:
        via = sorted(ctl[f] & c2s[l["id"]]); ok = bool(via)
        rows.append((f, "csf2", l["id"], l["confidence"], "yes" if ok else "no", " ".join(via))); st[("csf2", l["confidence"], ok)] += 1
    if l["scheme"] == "iso27002" and l["id"] in i2s:
        via = sorted(ctl[f] & i2s[l["id"]]); ok = bool(via)
        rows.append((f, "iso27002", l["id"], l["confidence"], "yes" if ok else "no", " ".join(via))); st[("iso27002", l["confidence"], ok)] += 1
with open(os.path.join(L, "nist_corroboration.csv"), "w", newline="") as fh:
    w = csv.writer(fh); w.writerow(["family", "scheme", "id", "confidence", "corroborated", "via_controls"]); w.writerows(rows)
for sch in ("csf2", "iso27002"):
    tot = sum(v for k, v in st.items() if k[0] == sch)
    print(sch, "links checkable:", tot, "of", sum(1 for l in links if l["scheme"] == sch))
    for c in "HML":
        y, n = st[(sch, c, True)], st[(sch, c, False)]
        if y + n: print("   %s: %d of %d corroborated (%.0f%%)" % (c, y, y + n, 100 * y / (y + n)))
