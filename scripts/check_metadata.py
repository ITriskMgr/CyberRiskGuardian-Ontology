# -*- coding: utf-8 -*-
"""Check that every crgo term carries the governance metadata the project requires:
en and fr labels, en and fr definitions, a status, a confidence and at least one source;
and that labels are unique per language."""
import os, sys
from collections import Counter
import rdflib
from rdflib import RDFS
from rdflib.namespace import SKOS

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ids = dict(l.rstrip("\n").split("\t") for l in open(os.path.join(ROOT, "src", "ids.tsv"), encoding="utf-8"))
A = lambda k: rdflib.URIRef("https://w3id.org/crgo/CRGO_%07d" % int(ids[k]))
g = rdflib.Graph()
for m in ["gov", "core", "measure", "crg", "evidence", "org", "vuln", "grc", "mapping"]:
    g.parse(os.path.join(ROOT, "ontology", "crgo-%s.ttl" % m))
terms = {s for s in g.subjects() if str(s).startswith("https://w3id.org/crgo/CRGO_")}
lang = lambda s, p, l: any(getattr(o, "language", None) == l for o in g.objects(s, p))
checks = {
    "label@en": lambda s: lang(s, RDFS.label, "en"), "label@fr": lambda s: lang(s, RDFS.label, "fr"),
    "definition@en": lambda s: lang(s, SKOS.definition, "en"), "definition@fr": lambda s: lang(s, SKOS.definition, "fr"),
    "status": lambda s: (s, A("governanceStatus"), None) in g, "confidence": lambda s: (s, A("confidence"), None) in g,
    "source": lambda s: (s, A("evidenceSource"), None) in g,
}
fail = False
for name, f in checks.items():
    missing = [str(s) for s in terms if not f(s)]
    if missing:
        fail = True
        print("   missing %s: %d, e.g. %s" % (name, len(missing), missing[:3]))
approved = [s for s in terms if (s, A("governanceStatus"), A("StatusApproved")) in g]
bad = [str(s) for s in approved if (s, A("approvedBy"), None) not in g or (s, A("approvalDate"), None) not in g]
if bad:
    fail = True
    print("   approved without approvedBy/approvalDate: %d, e.g. %s" % (len(bad), bad[:3]))
print("   approved: %d of %d terms" % (len(approved), len(terms)))
for l in ("en", "fr"):
    c = Counter(str(o).lower() for s in terms for o in g.objects(s, RDFS.label) if getattr(o, "language", None) == l)
    d = [k for k, v in c.items() if v > 1]
    if d:
        fail = True
        print("   duplicate %s labels: %s" % (l, d))
print("   %d terms: %s" % (len(terms), "metadata complete, labels unique" if not fail else "problems above"))
sys.exit(1 if fail else 0)
