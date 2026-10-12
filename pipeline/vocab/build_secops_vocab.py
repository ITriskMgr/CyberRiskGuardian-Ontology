# -*- coding: utf-8 -*-
"""0.10.0 SIEM and SOAR (decision S4): reference vocabularies for detection engineering.

Writes ontology/vocab/
  attack-detection.ttl  MITRE ATT&CK Enterprise 19.2 detection strategies (DET), analytics (AN) and data components (DC),
                        from the STIX bundle already held (data/raw/enterprise-attack.json); ATT&CK 'detects' relationships
                        become 'targets technique' links to vocab/attack, a strategy's analytics 'uses analytic', and an
                        analytic's log sources 'analytic uses data component' (the log source name and channel in a note).
  ocsf.ttl              OCSF 1.9.0 categories and event classes (data/raw/external/ocsf-1.9.0, git tag 1.9.0, Apache-2.0):
                        notation = category uid or class uid (category uid x 1000 + class uid), caption, description.
Run after build_vocab.py (scripts order: build_vocab, build_grca_vocab, build_secops_vocab, build_external, build_legal).
"""
import glob, json, os, sys
from rdflib import Literal, URIRef
from rdflib.namespace import SKOS, OWL
HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, HERE)
import build_vocab as BV  # noqa: E402  (re-running it rewrites the 0.2.0-0.9.0 vocabularies identically)
INTRO = "0.10.0"
ATTACK_RIGHTS = "(c) The MITRE Corporation. Reproduced under the ATT&CK Terms of Use (https://attack.mitre.org/resources/legal-and-branding/terms-of-use/)."
report = []

# ---------------------------------------------------------------- ATT&CK detection strategies, analytics, data components
bundle = json.load(open(os.path.join(BV.RAW, "enterprise-attack.json"), encoding="utf-8"))
objs = bundle["objects"]; byid = {o["id"]: o for o in objs}
coll = next(o for o in objs if o["type"] == "x-mitre-collection")
ext = lambda o: next((r for r in o.get("external_references", []) if r.get("source_name") == "mitre-attack"), None)
live = lambda o: not (o.get("revoked") or o.get("x_mitre_deprecated"))
s = BV.Scheme("attack-detection", "MITRE ATT&CK Enterprise detection strategies, analytics and data components",
              "Stratégies de détection, analytiques et composantes de données MITRE ATT&CK Enterprise",
              coll.get("x_mitre_version"), "https://github.com/mitre-attack/attack-stix-data (enterprise-attack.json)", None,
              ATTACK_RIGHTS, "The MITRE Corporation",
              "Reference detection content of ATT&CK %s: detection strategies (DET), the analytics they use (AN, narrower than their "
              "strategy) and data components (DC). Links: strategy 'targets technique' (ATT&CK 'detects'), strategy 'uses analytic', "
              "analytic 'analytic uses data component'. An organisation's own strategies and rules are separate records that may "
              "adapt these (crgo-siem)." % coll.get("x_mitre_version"))
T = BV.C
ATT = "https://w3id.org/crgo/vocab/attack/"
src = "MITRE ATT&CK Enterprise %s STIX bundle" % coll.get("x_mitre_version")
n = {"DET": 0, "AN": 0, "DC": 0, "detects": 0, "uses": 0, "dc": 0}
dc_of = {}
for o in sorted([o for o in objs if o["type"] == "x-mitre-data-component" and live(o)], key=lambda o: ext(o)["external_id"]):
    e = ext(o); dc_of[o["id"]] = e["external_id"]
    s.concept(e["external_id"], o["name"], definition_en=(o.get("description") or "").strip() or None, source=src,
              see_also=e.get("url"), introduced=INTRO); n["DC"] += 1
analytic_parent = {}
strategies = sorted([o for o in objs if o["type"] == "x-mitre-detection-strategy" and live(o)], key=lambda o: ext(o)["external_id"])
for o in strategies:
    for a in o.get("x_mitre_analytic_refs", []):
        analytic_parent.setdefault(a, ext(o)["external_id"])
for o in strategies:
    e = ext(o)
    c = s.concept(e["external_id"], o["name"], definition_en=(o.get("description") or "").strip() or None, source=src, see_also=e.get("url"), introduced=INTRO)
    n["DET"] += 1
detects = [r for r in objs if r["type"] == "relationship" and r["relationship_type"] == "detects" and not r.get("revoked")]
for r in detects:
    d, t = byid.get(r["source_ref"]), byid.get(r["target_ref"])
    if not (d and t and live(d) and ext(t)):
        continue
    s.g.add((s.ns[BV.safe(ext(d)["external_id"])], T("targetsTechnique"), URIRef(ATT + BV.safe(ext(t)["external_id"])))); n["detects"] += 1
for o in sorted([o for o in objs if o["type"] == "x-mitre-analytic" and live(o)], key=lambda o: ext(o)["external_id"]):
    e = ext(o); parent = analytic_parent.get(o["id"])
    plats = ", ".join(o.get("x_mitre_platforms", []))
    label = "%s (%s)" % (o["name"], plats) if plats else o["name"]
    srcs = o.get("x_mitre_log_source_references", [])
    note = "Log sources: " + "; ".join("%s [%s]" % (x.get("name"), x.get("channel")) for x in srcs) if srcs else None
    c = s.concept(e["external_id"], label, broader=parent, definition_en=(o.get("description") or "").strip() or None, source=src,
                  see_also=e.get("url"), note=note, introduced=INTRO)
    n["AN"] += 1
    if parent:
        s.g.add((s.ns[BV.safe(parent)], T("usesAnalytic"), c)); n["uses"] += 1
    for x in srcs:
        dc = dc_of.get(x.get("x_mitre_data_component_ref"))
        if dc and (c, T("analyticUsesDataComponent"), s.ns[BV.safe(dc)]) not in s.g:
            s.g.add((c, T("analyticUsesDataComponent"), s.ns[BV.safe(dc)])); n["dc"] += 1
s.g.add((s.s, OWL.imports, URIRef("https://w3id.org/crgo/vocab/attack")))
report.append(("attack-detection", s.save()))
print("attack-detection: %(DET)d strategies, %(AN)d analytics, %(DC)d data components; %(detects)d 'targets technique', %(uses)d 'uses analytic', %(dc)d 'uses data component'" % n)

# ---------------------------------------------------------------- OCSF 1.9.0
OC = os.path.join(BV.RAW, "external", "ocsf-1.9.0")
ver = json.load(open(os.path.join(OC, "version.json")))["version"]
s = BV.Scheme("ocsf", "Open Cybersecurity Schema Framework (OCSF) categories and event classes",
              "Catégories et classes d'événements de l'Open Cybersecurity Schema Framework (OCSF)", ver,
              "https://github.com/ocsf/ocsf-schema (git tag %s)" % ver, "https://www.apache.org/licenses/LICENSE-2.0",
              "OCSF schema (c) OCSF contributors, Apache License 2.0; captions and descriptions reproduced with attribution.", "OCSF project",
              "Event categories and event classes of OCSF %s (no attributes or profiles). Notation: category uid, or class uid = category uid x 1000 "
              "+ class uid. Linking a normalisation profile or rule to a class states a correspondence, not an equivalence of taxonomies." % ver)
cats = json.load(open(os.path.join(OC, "categories.json"), encoding="utf-8"))["attributes"]
cat_uid = {}
for name, c in sorted(cats.items(), key=lambda kv: kv[1]["uid"]):
    cat_uid[name] = c["uid"]
    s.concept(str(c["uid"]), c["caption"], definition_en=c.get("description"), source="OCSF %s categories.json" % ver, introduced=INTRO,
              note="OCSF category name: %s" % name)
nc = 0
for f in sorted(glob.glob(os.path.join(OC, "events", "**", "*.json"), recursive=True)):
    d = json.load(open(f, encoding="utf-8"))
    cat = os.path.relpath(f, os.path.join(OC, "events")).split(os.sep)[0]
    if "uid" not in d or cat not in cat_uid:
        continue
    uid = cat_uid[cat] * 1000 + d["uid"]
    desc = (d.get("description") or "").replace("<code>", "").replace("</code>", "").strip() or None
    s.concept(str(uid), d["caption"], broader=str(cat_uid[cat]), definition_en=desc, source="OCSF %s %s" % (ver, os.path.relpath(f, OC)),
              introduced=INTRO, note="OCSF class name: %s" % d.get("name")); nc += 1
report.append(("ocsf", s.save()))
print("ocsf %s: %d categories, %d event classes" % (ver, len(cat_uid), nc))
