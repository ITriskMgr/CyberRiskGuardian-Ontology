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
SCHEMES_ALL = list(SCHEME.values()) + ["lrsss", "cwe"]
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
# Loi 25 pass 2 (2026-10-10, decided by the project owner): families tagged with a privacy impact that had no judged
# Loi 25 obligation were judged again for Loi 25 only (prompt: data/library/loi25_pass2_prompt.md; up to 4 links).
PASS2 = "judged, Loi 25 pass 2026-10-10"
judged_loi = {l[0] for l in links if l[1] == "loi25"}
pass2_nopi = []
for l in open(os.path.join(ROOT, "data", "library", "loi25_pass2.jsonl"), encoding="utf-8"):
    x = json.loads(l)
    if x["family"] in judged_loi:
        dropped["pass 2 family already judged"] += 1; continue
    if not x["pi"]:
        pass2_nopi.append(x["family"])
    for item in x["loi25"]:
        if item["id"] not in valid["loi25"]:
            dropped["invalid loi25 id (pass 2)"] += 1; continue
        links.append((x["family"], "loi25", item["id"], item["c"], PASS2))
# 0.7.0 CWE pass: families with a weakness, application-security, vulnerability-management or cryptography theme judged
# against MITRE CWE (prompt data/library/cwe_pass_prompt.md, results data/library/cwe_pass.jsonl). Rule applied after an
# independent review: CWE-1104 (unmaintained component) is replaced by CWE-1395 (vulnerable component) unless the
# scenario says the software is unsupported, end-of-life, legacy or obsolete.
CWEPASS = "judged, CWE pass 2026-10-11"
fam_text = {}
import pandas as _pd
for _r in _pd.read_csv(os.path.join(ROOT, "data", "library", "families.csv")).itertuples():
    fam_text[_r.family] = "%s %s" % (_r.name, _r.narrative if isinstance(_r.narrative, str) else "")
EOL = re.compile(r"(?i)end[- ]of[- ]life|unsupported|legacy|obsolete|unmaintained|out[- ]of[- ]support|outdated")
cwe_valid = {l.split(" | ")[0] for l in open(os.path.join(ROOT, "data", "library", "cwe_reference.md"), encoding="utf-8") if l.startswith("CWE-")}
for l in open(os.path.join(ROOT, "data", "library", "cwe_pass.jsonl"), encoding="utf-8"):
    x = json.loads(l); got = set()
    for item in x["cwe"]:
        i = item["id"]
        if i == "CWE-1104" and not EOL.search(fam_text.get(x["family"], "")):
            i = "CWE-1395"
        if i not in cwe_valid or i in got:
            dropped["cwe duplicate or invalid"] += 1; continue
        got.add(i)
        c = item["c"]
        if i in ("CWE-311", "CWE-312") and c == "H" and not re.search(r"(?i)encrypt", fam_text.get(x["family"], "")):
            c = "M"  # rule: missing encryption is only implied, not stated, by device-theft scenarios that do not mention it
        links.append((x["family"], "cwe", i, c, CWEPASS + (" (CWE-1104 replaced by rule)" if i != item["id"] else "")))
# 0.7.0 controls proposed from the MITRE CTID mapping (pipeline/external/ctid_check.py)
for _r in csv.DictReader(open(os.path.join(ROOT, "data", "library", "ctid_proposals.csv"), encoding="utf-8")):
    links.append((_r["family"], "sp80053r5", _r["control"], _r["confidence"], "CTID mapping 2026-10-11: " + _r["basis"]))
# rule: every family that involves personal information also engages P-39.1 s. 10 (security measures proportionate to
# sensitivity), the preventive duty; the judges could not choose it because it was added to the reference afterwards.
import pandas as pd
fam_df = pd.read_csv(os.path.join(ROOT, "data", "library", "families.csv"))
privacy = set(fam_df[fam_df.impact_dimensions.fillna("").str.contains("DimPrivacy")].family) | {l[0] for l in links if l[1] == "loi25"}
links += [(f_, "loi25", "P-39.1 s. 10", "M", "rule: personal information involved") for f_ in privacy]
# rule: for health information held by a health body, R-22.1 replaces the corresponding P-39.1 duties (P-39.1 s. 3,
# para. 3); library families that carry a Loi 25 obligation and concern health information get the R-22.1 equivalents.
LRSSS_EQ = {"P-39.1 s. 10": ["R-22.1 s. 99"], "P-39.1 s. 3.5 (1st para.)": ["R-22.1 s. 108"],
            "P-39.1 s. 3.5 (2nd para.)": ["R-22.1 s. 108", "R-22.1, r. 1 s. 11", "R-22.1, r. 1 s. 13"], "P-39.1 s. 3.7": ["R-22.1 s. 109"],
            "P-39.1 s. 3.8": ["R-22.1 s. 110"], "P-39.1 s. 3.1": ["R-22.1 s. 100"], "P-39.1 s. 3.2": ["R-22.1 s. 105"],
            "P-39.1 s. 3.3": ["R-22.1 s. 106"], "P-39.1 s. 17": ["R-22.1 s. 73"], "P-39.1 s. 18.3": ["R-22.1 s. 77"], "P-39.1 s. 23": ["R-22.1 s. 111"]}
HEALTH = re.compile(r"(?i)patient|medical|health|clinic|ehr\b|emr\b|hospital|prescription|diagnos|imaging|laborator|pharmac|nurs|physician|care\b")
text = {r.family: "%s %s" % (r.name, r.narrative if isinstance(r.narrative, str) else "") for r in fam_df.itertuples()}
lrsss = []
for f_, sch, i, c, basis in links:
    if sch == "loi25" and HEALTH.search(text.get(f_, "")):
        lrsss += [(f_, "lrsss", j, "M", "rule: R-22.1 equivalent of %s for health information" % i) for j in LRSSS_EQ.get(i, [])]
links += lrsss
links = sorted(set(links))
with open(os.path.join(ROOT, "data", "library", "links.csv"), "w", newline="", encoding="utf-8") as fh:
    w = csv.writer(fh); w.writerow(["family", "scheme", "id", "confidence", "basis"]); w.writerows(links)
with open(os.path.join(ROOT, "data", "library", "family_review.csv"), "w", newline="", encoding="utf-8") as fh:
    w = csv.writer(fh); w.writerow(["family", "theme", "threat_source_types"]); w.writerows(review)
fams = {l[0] for l in links}
print("families judged %d; with at least one link %d" % (len(seen), len(fams)))
by = Counter(l[1] for l in links); conf = Counter((l[1], l[3]) for l in links)
for s in SCHEMES_ALL:
    n_f = len({l[0] for l in links if l[1] == s})
    print("  %-10s %5d links on %4d families  (H %d, M %d, L %d)" % (s, by[s], n_f, conf[(s, "H")], conf[(s, "M")], conf[(s, "L")]))
print("dropped:", dict(dropped) or "none")
print("Loi 25 pass 2: %d links; judged as not involving personal information: %s" % (sum(1 for l in links if l[4] == PASS2), " ".join(pass2_nopi)))
