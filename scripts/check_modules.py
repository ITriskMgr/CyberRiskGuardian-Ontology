# -*- coding: utf-8 -*-
"""Each module may reference only crgo terms declared in itself or in the modules it imports."""
import os, sys, rdflib
from rdflib import RDF
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# each module and the modules it imports directly (src/build.py MODULES)
DEPS = {"gov": [], "core": ["gov"], "measure": ["core"], "crg": ["measure"], "evidence": ["measure"], "org": ["core"],
        "vuln": ["evidence"], "grc": ["evidence", "org"], "mapping": ["gov"]}
order = list(DEPS)
def closure_of(m):
    out = {m}
    for d in DEPS[m]: out |= closure_of(d)
    return out
decl, graphs, fail = {}, {}, False
for m in order:
    g = rdflib.Graph(); g.parse(os.path.join(ROOT, "ontology", "crgo-%s.ttl" % m)); graphs[m] = g
    decl[m] = {s for s in g.subjects(RDF.type, None) if str(s).startswith("https://w3id.org/crgo/CRGO_")}
for i, m in enumerate(order):
    closure = set().union(*[decl[x] for x in closure_of(m)])
    bad = {o for s, p, o in graphs[m] if isinstance(o, rdflib.URIRef) and str(o).startswith("https://w3id.org/crgo/CRGO_")} - closure
    if bad:
        fail = True; print("   %s references terms it does not import: %s" % (m, sorted(map(str, bad))))
print("   module references: %s" % ("clean" if not fail else "problems above"))
sys.exit(1 if fail else 0)
