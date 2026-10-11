# -*- coding: utf-8 -*-
"""Cross-check the scenario-to-SP 800-53 links against the MITRE CTID mapping ATT&CK -> NIST SP 800-53 Rev. 5
(Mappings Explorer, ATT&CK 16.1, Apache 2.0; data/raw/external/ctid_nist_800_53-rev5_attack-16.1.json).

For a family whose threat event uses ATT&CK techniques T1..Tn, the CTID support of the family is the set of controls
that CTID maps as mitigating at least one Ti. An existing SP 800-53 link is "corroborated" when its control is in that
set. Missing controls are proposed only when they mitigate every technique of the family that has a high or medium
link, at most two per family, preferring the controls CTID maps to the fewest techniques overall (the most specific).
ATT&CK identifiers revoked between 16.1 and 19.2 are translated with the vocabulary's dcterms:isReplacedBy.
Writes data/library/ctid_corroboration.csv and data/library/ctid_proposals.csv and prints the agreement rates."""
import csv, json, math, os, re, collections
import rdflib
from rdflib.namespace import DCTERMS, SKOS
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
g = rdflib.Graph(); g.parse(os.path.join(ROOT, "ontology", "vocab", "attack.ttl"))
rep = {str(g.value(s, SKOS.notation)): str(g.value(o, SKOS.notation)) for s, o in g.subject_objects(DCTERMS.isReplacedBy)}
valid800 = {str(o) for o in rdflib.Graph().parse(os.path.join(ROOT, "ontology", "vocab", "sp800-53r5.ttl")).objects(None, SKOS.notation)}
norm_ctl = lambda c: re.sub(r"-0*(\d+)", r"-\1", c)
def norm_t(t):
    seen = set()
    while t in rep and t not in seen:
        seen.add(t); t = rep[t]
    return t
ctid = json.load(open(os.path.join(ROOT, "data", "raw", "external", "ctid_nist_800_53-rev5_attack-16.1.json")))
M = collections.defaultdict(set)
for x in ctid["mapping_objects"]:
    if x["mapping_type"] == "mitigates":
        M[norm_t(x["attack_object_id"])].add(norm_ctl(x["capability_id"]))
# a technique without its own mapping inherits its parent's (sub-techniques of mapped parents)
def mit(t):
    return M.get(t) or M.get(t.split(".")[0], set())
ntech = collections.Counter(c for cs in M.values() for c in cs)
idf = {c: math.log(len(M) / n) for c, n in ntech.items()}
links = list(csv.DictReader(open(os.path.join(ROOT, "data", "library", "links.csv"))))
att = collections.defaultdict(dict); ctl = collections.defaultdict(dict)
for l in links:
    if l["scheme"] == "attack": att[l["family"]][l["id"]] = l["confidence"]
    elif l["scheme"] == "sp80053r5": ctl[l["family"]][l["id"]] = l["confidence"]
SCOPE = set(ctid["metadata"]["capability_groups"])
usual = collections.defaultdict(collections.Counter); uses = collections.Counter()
for f, ts in att.items():
    for t, cf in ts.items():
        if cf in "HM":
            uses[t] += 1
            for c, cc in ctl.get(f, {}).items():
                if cc in "HM": usual[t][c] += 1
corr, props, stats = [], [], collections.Counter()
for f, ts in att.items():
    support = set().union(*[mit(t) for t in ts]) if ts else set()
    mapped = [t for t in ts if mit(t)]
    if not mapped:
        stats["families without CTID-mapped technique"] += 1; continue
    stats["families checked"] += 1
    for c, conf in ctl.get(f, {}).items():
        ok = c in support
        corr.append((f, c, conf, "yes" if ok else "no", " ".join(sorted(t for t in ts if c in mit(t)))))
        if c.split("-")[0] in SCOPE: stats[(conf, ok)] += 1
        else: stats["out of CTID scope"] += 1
    core = [t for t, cf in ts.items() if cf in "HM" and mit(t)] or mapped
    common = set.intersection(*[mit(t) for t in core]) - set(ctl.get(f, {}))
    common = {c for c in common if c in valid800}
    def score(c):  # share of other families with the same technique that link c
        return min((usual[t][c] - (1 if c in ctl.get(f, {}) else 0)) / max(uses[t] - 1, 1) for t in core)
    common = {c for c in common if score(c) >= 0.3}
    for c in sorted(common, key=lambda c: -score(c))[:2]:
        props.append((f, c, "M" if len(core) > 1 else "L", "CTID: mitigates %s" % " ".join(sorted(core))))
with open(os.path.join(ROOT, "data", "library", "ctid_corroboration.csv"), "w", newline="") as fh:
    w = csv.writer(fh); w.writerow(["family", "control", "confidence", "corroborated", "via_techniques"]); w.writerows(corr)
with open(os.path.join(ROOT, "data", "library", "ctid_proposals.csv"), "w", newline="") as fh:
    w = csv.writer(fh); w.writerow(["family", "control", "confidence", "basis"]); w.writerows(props)
print("families checked:", stats["families checked"], "; without a CTID-mapped technique:", stats["families without CTID-mapped technique"])
for conf in "HML":
    y, n = stats[(conf, True)], stats[(conf, False)]
    if y + n: print("  existing %s links: %d of %d corroborated (%.0f%%)" % (conf, y, y + n, 100 * y / (y + n)))
print("  links outside CTID's control families (not checkable):", stats["out of CTID scope"])
print("proposed missing controls:", len(props), collections.Counter(p[2] for p in props), "top:", collections.Counter(p[1] for p in props).most_common(8))
