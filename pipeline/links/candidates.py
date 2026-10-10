# -*- coding: utf-8 -*-
"""Step 1 of scenario-to-framework linking: prepare the reference lists and the family batches.

The reference file lists every valid target (ATT&CK Enterprise techniques and sub-techniques, SP 800-53 Rev. 5 base
controls, CSF 2.0 subcategories, ISO/IEC 27002:2022 controls, Loi 25 obligations), so that the judgement step can
only choose real identifiers. TF-IDF candidates were tried and dropped: their ranking was too noisy to help.
Step 2 (judgement) is described in pipeline/links/README.md.
Writes data/work/linking/reference.md and batch_NN.jsonl.
"""
import json, os, re, sys
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import linear_kernel

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(ROOT, "pipeline", "library"))
import themes as T  # noqa: E402
OUT = os.path.join(ROOT, "data", "work", "linking"); os.makedirs(OUT, exist_ok=True)
BATCH = int(os.environ.get("BATCH", "115"))
TOPK = 20

def clean(t):
    t = re.sub(r"\(Citation:[^)]*\)", "", t or "")
    t = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", t)
    return re.sub(r"\s+", " ", t).strip()

# --- ATT&CK
bundle = json.load(open(os.path.join(ROOT, "data", "raw", "enterprise-attack.json"), encoding="utf-8"))
att = []
for o in bundle["objects"]:
    if o["type"] == "attack-pattern" and not o.get("revoked") and not o.get("x_mitre_deprecated"):
        e = next(r for r in o["external_references"] if r.get("source_name") == "mitre-attack")
        att.append((e["external_id"], o["name"], clean(o.get("description", ""))[:1200]))
# --- SP 800-53 base controls (not withdrawn)
cat = json.load(open(os.path.join(ROOT, "data", "raw", "NIST_SP-800-53_rev5_catalog.json"), encoding="utf-8"))["catalog"]
def prose(parts):
    out = []
    for p in parts or []:
        if p.get("prose"): out.append(p["prose"])
        out += prose(p.get("parts"))
    return out
nist = []
for g in cat["groups"]:
    for c in g["controls"]:
        props = {p["name"]: p["value"] for p in c.get("props", []) if "class" not in p}
        if props.get("status") == "withdrawn":
            continue
        st = " ".join(prose([p for p in c.get("parts", []) if p["name"] == "statement"]))
        st = re.sub(r"\{\{[^}]*\}\}", "", st)
        nist.append((props.get("label", c["id"].upper()), c["title"], (g["title"] + ". " + c["title"] + ". " + st)[:1200]))
# --- CSF 2.0 active subcategories, ISO, Loi 25 (full lists)
csf = json.load(open(os.path.join(ROOT, "data", "raw", "NIST_CSF_v2.0_catalog.json"), encoding="utf-8"))["catalog"]
csf_rows = []
for f in csf["groups"]:
    for c in f["controls"]:
        for s in c.get("controls", []):
            if any(p["name"] == "status" and p["value"] == "withdrawn" for p in s.get("props", [])):
                continue
            st = next(p["prose"] for p in s["parts"] if p["name"] == "statement")
            csf_rows.append((s["id"], st))
iso = pd.read_csv(os.path.join(ROOT, "data", "frameworks", "iso27002_2022.tsv"), sep="\t", dtype=str)
loi = pd.read_csv(os.path.join(ROOT, "data", "frameworks", "loi25.tsv"), sep="\t", dtype=str)
sys.path.insert(0, os.path.join(ROOT, "pipeline", "vocab"))
from ids_loi25 import loi25_notation  # noqa: E402
loi_ids = [loi25_notation(r.act, r.section) for r in loi.itertuples()]

with open(os.path.join(OUT, "reference.md"), "w", encoding="utf-8") as f:
    f.write("# Reference lists (choose IDs exactly as written)\n\n## NIST CSF 2.0 subcategories\n")
    for i, s in csf_rows: f.write("%s | %s\n" % (i, s))
    f.write("\n## ISO/IEC 27002:2022 controls\n")
    for r in iso.itertuples(): f.write("%s | %s\n" % (r.id, r.title_en))
    f.write("\n## Loi 25 obligations (use only when personal information is involved)\n")
    for i, r in zip(loi_ids, loi.itertuples()): f.write("%s | %s\n" % (i, r.label_en))
    tac = {}
    for o in bundle["objects"]:
        if o["type"] == "attack-pattern" and not o.get("revoked") and not o.get("x_mitre_deprecated"):
            e = next(r for r in o["external_references"] if r.get("source_name") == "mitre-attack")
            tac[e["external_id"]] = ",".join(p["phase_name"] for p in o.get("kill_chain_phases", []) if p["kill_chain_name"] == "mitre-attack")
    f.write("\n## MITRE ATT&CK Enterprise 19.2 techniques (ID | name | tactics)\n")
    for i, n, _ in sorted(att): f.write("%s | %s | %s\n" % (i, n, tac.get(i, "")))
    f.write("\n## NIST SP 800-53 Rev. 5 base controls (ID | title)\n")
    for i, n, _ in nist: f.write("%s | %s\n" % (i, n))
    f.write("\n## Scenario themes\n")
    for k, en, *_ in T.THEMES: f.write("%s | %s\n" % (k, en))

# --- families
fam = pd.read_csv(os.path.join(ROOT, "data", "library", "families.csv"))
rows = {json.loads(l)["row"]: json.loads(l) for l in open(os.path.join(ROOT, "data", "library", "rows.jsonl"), encoding="utf-8")}
def section(text, start, stops):
    m = re.search(r"(?is)(?:" + start + r")\s*:?(.*?)(?=" + "|".join(stops) + r"|$)", text)
    return m.group(1) if m else ""
docs, ctx = [], []
theme_label = {k: en for k, en, *_ in T.THEMES}
for r in fam.itertuples():
    first = rows[r.rows.split()[0]]
    seq = section(first["text"], r"event sequence", [r"consequences", r"historical data"])[:600]
    cons = section(first["text"], r"consequences", [r"historical data", r"threat (?:estimate|probability)"])[:400]
    mit = r.mitigations if isinstance(r.mitigations, str) else ""
    narr = r.narrative if isinstance(r.narrative, str) else ""
    docs.append(" ".join([r.name] * 3 + [narr, seq, cons, mit, theme_label[r.theme]]))
    ctx.append(dict(family=r.family, name=r.name, theme=r.theme, narrative=narr[:500], events=re.sub(r"\s+", " ", seq)[:400],
                    consequences=re.sub(r"\s+", " ", cons)[:300], mitigations=mit[:500],
                    threat_source_types=r.threat_source_types if isinstance(r.threat_source_types, str) else "",
                    impact_dimensions=r.impact_dimensions if isinstance(r.impact_dimensions, str) else ""))

def topk(concepts, k):
    vec = TfidfVectorizer(stop_words="english", sublinear_tf=True, ngram_range=(1, 2), min_df=1, max_df=0.5)
    m = vec.fit_transform([c[2] for c in concepts] + docs)
    sim = linear_kernel(m[len(concepts):], m[:len(concepts)])
    return [[(concepts[j][0], concepts[j][1]) for j in sim[i].argsort()[::-1][:k]] for i in range(len(docs))]

for b in range(0, len(ctx), BATCH):
    with open(os.path.join(OUT, "batch_%02d.jsonl" % (b // BATCH + 1)), "w", encoding="utf-8") as f:
        for c in ctx[b:b + BATCH]:
            f.write(json.dumps(c, ensure_ascii=False) + "\n")
json.dump(dict(attack=[a[0] for a in att], sp80053=[n[0] for n in nist], csf=[c[0] for c in csf_rows],
               iso=list(iso.id.astype(str)), loi25=loi_ids), open(os.path.join(OUT, "valid_ids.json"), "w"))
print("families %d, batches %d, ATT&CK %d, SP 800-53 base controls %d, CSF %d" % (len(ctx), -(-len(ctx) // BATCH), len(att), len(nist), len(csf_rows)))
