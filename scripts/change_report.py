# -*- coding: utf-8 -*-
"""Change report between a release tag and the working tree (specification sections 2 and 15, gap G16).

Compares terms (added, deprecated, label, definition, parent, domain and range, status changes), vocabularies
(concepts added and removed), cross-references (SKOS and typed relations, status changes) and the scenario library
(individuals by type). Writes releases/<version>/change-report.json and change-report.md.

Usage: python3 scripts/change_report.py v0.8.0 0.9.0
"""
import json, os, subprocess, sys, tempfile, collections, glob
from rdflib import Graph, URIRef, Literal
from rdflib.namespace import RDF, RDFS, OWL, SKOS

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
tag, version = sys.argv[1], sys.argv[2]
BASE = "https://w3id.org/crgo/"
ids = dict(l.rstrip("\n").split("\t") for l in open(os.path.join(ROOT, "src", "ids.tsv"), encoding="utf-8"))
T = lambda k: URIRef(BASE + "CRGO_%07d" % int(ids[k]))

def at_tag(path):
    r = subprocess.run(["git", "show", "%s:%s" % (tag, path)], cwd=ROOT, capture_output=True)
    return r.stdout if r.returncode == 0 else None

def files_at_tag(pattern_dir, suffix=".ttl"):
    r = subprocess.run(["git", "ls-tree", "--name-only", tag, pattern_dir + "/"], cwd=ROOT, capture_output=True, text=True)
    return [p for p in r.stdout.split() if p.endswith(suffix)]

def load(paths, old):
    g = Graph()
    for p in paths:
        if old:
            data = at_tag(p)
            if data: g.parse(data=data.decode("utf-8"), format="turtle")
        elif os.path.exists(os.path.join(ROOT, p)):
            g.parse(os.path.join(ROOT, p))
    return g

old_mods = [p for p in files_at_tag("ontology") if os.path.basename(p).startswith("crgo-") and "full" not in p]
new_mods = sorted(os.path.relpath(p, ROOT) for p in glob.glob(os.path.join(ROOT, "ontology", "crgo-*.ttl")) if "full" not in p)
og, ng = load(old_mods, True), load(new_mods, False)
terms = lambda g: {s for s in g.subjects(RDF.type, None) if str(s).startswith(BASE + "CRGO_")}
ot, nt = terms(og), terms(ng)
lab = lambda g, s: next((str(o) for o in g.objects(s, RDFS.label) if getattr(o, "language", None) == "en"), "")
def props(g, s, p): return sorted(str(o) for o in g.objects(s, p))
report = {"from": tag, "to": version, "terms": {}, "vocabularies": {}, "mappings": {}, "library": {}}
R = report["terms"]
R["added"] = sorted(("%s %s" % (str(s).rsplit("/", 1)[1], lab(ng, s))) for s in nt - ot)
R["removed"] = sorted(("%s %s" % (str(s).rsplit("/", 1)[1], lab(og, s))) for s in ot - nt)
R["newly_deprecated"] = sorted(str(s).rsplit("/", 1)[1] for s in ot & nt if (s, OWL.deprecated, Literal(True)) in ng and (s, OWL.deprecated, Literal(True)) not in og)
for name, p in (("label_changed", RDFS.label), ("definition_changed", SKOS.definition), ("parent_changed", RDFS.subClassOf),
                ("domain_changed", RDFS.domain), ("range_changed", RDFS.range), ("status_changed", T("governanceStatus"))):
    R[name] = sorted("%s %s" % (str(s).rsplit("/", 1)[1], lab(ng, s)) for s in ot & nt if props(og, s, p) != props(ng, s, p))
R["counts"] = {"before": len(ot), "after": len(nt)}

# vocabularies
old_v = {os.path.basename(p)[:-4]: p for p in files_at_tag("ontology/vocab")}
new_v = {os.path.basename(p)[:-4]: os.path.relpath(p, ROOT) for p in glob.glob(os.path.join(ROOT, "ontology", "vocab", "*.ttl"))}
skip = {"mappings", "mappings-proposed"}
for k in sorted(set(old_v) | set(new_v)):
    if k in skip: continue
    a = load([old_v[k]], True) if k in old_v else Graph(); b = load([new_v[k]], False) if k in new_v else Graph()
    ca, cb = set(a.subjects(SKOS.inScheme, None)), set(b.subjects(SKOS.inScheme, None))
    other_a, other_b = len(set(a.subjects())), len(set(b.subjects()))
    report["vocabularies"][k] = {"status": "new" if k not in old_v else ("removed" if k not in new_v else "kept"),
                                 "concepts_before": len(ca), "concepts_after": len(cb), "concepts_added": len(cb - ca), "concepts_removed": len(ca - cb),
                                 "subjects_before": other_a, "subjects_after": other_b}

# cross-references
def maps(g):
    out = {}
    for ax in g.subjects(RDF.type, OWL.Axiom):
        p = g.value(ax, OWL.annotatedProperty)
        if p in (SKOS.relatedMatch, SKOS.closeMatch):
            out[(str(g.value(ax, OWL.annotatedSource)), str(p), str(g.value(ax, OWL.annotatedTarget)))] = str(g.value(ax, T("governanceStatus"))).rsplit("/", 1)[1]
    return out
om = maps(load(["ontology/vocab/mappings.ttl"], True))
nmg = load(["ontology/vocab/mappings.ttl", "ontology/vocab/mappings-proposed.ttl"], False); nm = maps(nmg)
typed = collections.Counter(str(p) for s, p, o in nmg if str(p).startswith(BASE + "CRGO_"))
M = report["mappings"]
M["before"] = len(om); M["after"] = len(nm); M["added"] = len(set(nm) - set(om)); M["removed"] = len(set(om) - set(nm))
M["status_changed"] = sum(1 for k in set(om) & set(nm) if om[k] != nm[k])
M["moved_to_proposal_file"] = len(set(maps(load(["ontology/vocab/mappings-proposed.ttl"], False))))
mapping_rels = {str(p) for p, o in ng.subject_objects(RDFS.subPropertyOf) if o in (SKOS.relatedMatch, SKOS.closeMatch)}
M["typed_relations"] = {lab(ng, URIRef(p)): n for p, n in typed.items() if p in mapping_rels}
M["added_examples"] = sorted("%s %s %s" % (s.rsplit("/", 2)[-2] + "/" + s.rsplit("/", 1)[1], p.rsplit("#", 1)[1], o.rsplit("/", 2)[-2] + "/" + o.rsplit("/", 1)[1]) for s, p, o in set(nm) - set(om))[:40]

# library: individuals by type, deprecations
def lib(g):
    c = collections.Counter(str(t).rsplit("/", 1)[1] for s, t in g.subject_objects(RDF.type) if str(s).startswith(BASE + "data/library/"))
    return c, {str(s) for s in g.subjects(OWL.deprecated, Literal(True))}
ol, od = lib(load(["data/abox/crgo-library.ttl"], True))
nl, nd = lib(load(["data/abox/crgo-library.ttl", "data/abox/crgo-library-proposed.ttl"], False))
L = report["library"]
L["types"] = {lab(ng, URIRef(BASE + k)) or k: {"before": ol.get(k, 0), "after": nl.get(k, 0)} for k in sorted(set(ol) | set(nl)) if ol.get(k, 0) != nl.get(k, 0)}
L["newly_deprecated_individuals"] = len(nd - od)

out = os.path.join(ROOT, "releases", version); os.makedirs(out, exist_ok=True)
json.dump(report, open(os.path.join(out, "change-report.json"), "w"), indent=1, ensure_ascii=False)
md = ["# CRGO change report: %s → %s" % (tag, version), "", "Generated by `scripts/change_report.py %s %s` from the repository files." % (tag, version), "",
      "## Terms", "", "| | Count |", "|---|---|"]
for k in ("added", "removed", "newly_deprecated", "label_changed", "definition_changed", "parent_changed", "domain_changed", "range_changed", "status_changed"):
    md.append("| %s | %d |" % (k.replace("_", " "), len(R[k])))
md += ["", "Terms before: %d; after: %d." % (R["counts"]["before"], R["counts"]["after"]), ""]
for k in ("removed", "newly_deprecated", "label_changed", "definition_changed", "parent_changed", "domain_changed", "range_changed", "status_changed"):
    if R[k]: md += ["**%s**: %s" % (k.replace("_", " "), "; ".join(R[k])), ""]
md += ["<details><summary>Added terms</summary>", "", "\n".join("- " + x for x in R["added"]), "", "</details>", "", "## Vocabularies", "",
       "| Vocabulary | Status | Concepts before | after | added | removed |", "|---|---|---|---|---|---|"]
for k, v in report["vocabularies"].items():
    md.append("| %s | %s | %d | %d | %d | %d |" % (k, v["status"], v["concepts_before"], v["concepts_after"], v["concepts_added"], v["concepts_removed"]))
md += ["", "## Cross-references", "", "Before: %(before)d; after: %(after)d (approved file plus proposal file); added: %(added)d; removed: %(removed)d; status changed: %(status_changed)d; in the proposal file: %(moved_to_proposal_file)d." % M, "",
       "Typed relations (0.9.0), distinct concept pairs per relation:", ""] + ["- %s: %d" % (k, v) for k, v in sorted(M["typed_relations"].items())]
md += ["", "## Scenario library", "", "| Type | Before | After |", "|---|---|---|"] + ["| %s | %d | %d |" % (k, v["before"], v["after"]) for k, v in L["types"].items()]
md += ["", "Individuals newly deprecated: %d." % L["newly_deprecated_individuals"], ""]
open(os.path.join(out, "change-report.md"), "w").write("\n".join(md))
print("terms +%d -%d deprecated %d changed(status) %d; mappings +%d -%d status %d; library deprecated %d" % (
    len(R["added"]), len(R["removed"]), len(R["newly_deprecated"]), len(R["status_changed"]), M["added"], M["removed"], M["status_changed"], L["newly_deprecated_individuals"]))
