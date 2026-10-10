# -*- coding: utf-8 -*-
"""Step 3 of linking: validate and merge the judged batches.

- every identifier must be in the reference lists (valid_ids.json); invalid ones are dropped and reported;
- ISO links of the first eight batches that used an identifier made ambiguous by a parsing bug (5.10 shown as
  "5.1" and so on) are replaced by the re-judged links in isofix_out_*.jsonl;
- Loi 25 identifiers written in the earlier long form are converted to the current notation.
Writes data/library/links.csv (family, scheme, id, confidence) and data/library/family_review.csv
(theme and threat source types re-checked during judgement), and prints coverage.
"""
import csv, glob, json, os, re, sys
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
W = os.path.join(ROOT, "data", "work", "linking")
sys.path.insert(0, os.path.join(ROOT, "pipeline", "vocab")); sys.path.insert(0, os.path.join(ROOT, "pipeline", "library"))
from ids_loi25 import loi25_notation  # noqa: E402
import themes as T  # noqa: E402

valid = json.load(open(os.path.join(W, "valid_ids.json")))
valid = {k: set(v) for k, v in valid.items()}
SCHEME = {"attack": "attack", "csf": "csf2", "sp80053": "sp80053r5", "iso": "iso27002", "loi25": "loi25"}
loi_rows = list(csv.DictReader(open(os.path.join(ROOT, "data", "frameworks", "loi25.tsv"), encoding="utf-8"), delimiter="\t"))
old_loi = {}
for r in loi_rows:
    old = ("%s s. %s" % (r["act"], r["section"])) + (" (notification)" if r["key"] == "Loi25IncidentNotification" else "")
    old_loi[old] = loi25_notation(r["act"], r["section"])
isofix = {}
for f in glob.glob(os.path.join(W, "isofix_out_*.jsonl")):
    for l in open(f, encoding="utf-8"):
        x = json.loads(l); isofix[x["family"]] = x["iso"]
themes = {t[0] for t in T.THEMES}
SRC = {"SrcAdversarial", "SrcAccidental", "SrcStructural", "SrcEnvironmental"}

links, review, dropped, seen = [], [], Counter(), set()
for f in sorted(glob.glob(os.path.join(W, "out_*.jsonl"))):
    first_wave = int(re.search(r"out_(\d+)", f).group(1)) <= 8
    for l in open(f, encoding="utf-8"):
        x = json.loads(l); fam = x["family"]
        if fam in seen:
            dropped["duplicate family line"] += 1; continue
        seen.add(fam)
        if first_wave and fam in isofix:
            x["iso"] = isofix[fam]
        for key, scheme in SCHEME.items():
            for item in x.get(key, []):
                i = item["id"].strip()
                if key == "loi25":
                    i = old_loi.get(i, i)
                if i not in valid[key]:
                    dropped["invalid %s id" % key] += 1; continue
                c = item.get("c", "M") if item.get("c") in ("H", "M", "L") else "M"
                links.append((fam, scheme, i, c, "judged"))
        th = x.get("theme") if x.get("theme") in themes else ""
        src = " ".join(s for s in x.get("src", []) if s in SRC)
        review.append((fam, th, src))
# rule: every family that involves personal information also engages P-39.1 s. 10 (security measures proportionate to
# sensitivity), the preventive duty; the judges could not choose it because it was added to the reference afterwards.
import pandas as pd
fam_df = pd.read_csv(os.path.join(ROOT, "data", "library", "families.csv"))
privacy = set(fam_df[fam_df.impact_dimensions.fillna("").str.contains("DimPrivacy")].family) | {l[0] for l in links if l[1] == "loi25"}
links += [(f_, "loi25", "P-39.1 s. 10", "M", "rule: personal information involved") for f_ in privacy]
links = sorted(set(links))
with open(os.path.join(ROOT, "data", "library", "links.csv"), "w", newline="", encoding="utf-8") as fh:
    w = csv.writer(fh); w.writerow(["family", "scheme", "id", "confidence", "basis"]); w.writerows(links)
with open(os.path.join(ROOT, "data", "library", "family_review.csv"), "w", newline="", encoding="utf-8") as fh:
    w = csv.writer(fh); w.writerow(["family", "theme", "threat_source_types"]); w.writerows(review)
fams = {l[0] for l in links}
print("families judged %d; with at least one link %d" % (len(seen), len(fams)))
by = Counter(l[1] for l in links); conf = Counter((l[1], l[3]) for l in links)
for s in SCHEME.values():
    n_f = len({l[0] for l in links if l[1] == s})
    print("  %-10s %5d links on %4d families  (H %d, M %d, L %d)" % (s, by[s], n_f, conf[(s, "H")], conf[(s, "M")], conf[(s, "L")]))
print("dropped:", dict(dropped) or "none")
