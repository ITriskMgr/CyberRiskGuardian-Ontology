# -*- coding: utf-8 -*-
"""Each module may reference only crgo terms declared in itself or in the modules it imports."""
import os, sys, rdflib
from rdflib import RDF
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
order = ["gov", "core", "measure", "crg"]
decl, graphs, fail = {}, {}, False
for m in order:
    g = rdflib.Graph(); g.parse(os.path.join(ROOT, "ontology", "crgo-%s.ttl" % m)); graphs[m] = g
    decl[m] = {s for s in g.subjects(RDF.type, None) if str(s).startswith("https://w3id.org/crgo/CRGO_")}
for i, m in enumerate(order):
    closure = set().union(*[decl[x] for x in order[:i + 1]])
    bad = {o for s, p, o in graphs[m] if isinstance(o, rdflib.URIRef) and str(o).startswith("https://w3id.org/crgo/CRGO_")} - closure
    if bad:
        fail = True; print("   %s references terms it does not import: %s" % (m, sorted(map(str, bad))))
print("   module references: %s" % ("clean" if not fail else "problems above"))
sys.exit(1 if fail else 0)
