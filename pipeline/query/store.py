# -*- coding: utf-8 -*-
"""Embedded SPARQL store for CRGO (Oxigraph).

build(): loads the repository files (BFO and CCO imports, core modules, vocabularies, private vocabularies if
present, scenario library and the MediBec example assessment) and materialises RDFS-style inferences that queries need:
  - rdf:type closure over rdfs:subClassOf (so ?x a crgo:Estimate finds every CRG parameter estimate),
  - rdfs:subPropertyOf closure for asserted property values.
The store is written to build/store/ and reopened read-only by queries, the MCP server and the tests.
"""
import glob, os, sys, time
import pyoxigraph as ox

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
STORE = os.path.join(ROOT, "build", "store")
RDF_TYPE = ox.NamedNode("http://www.w3.org/1999/02/22-rdf-syntax-ns#type")
SUBCLASS = "http://www.w3.org/2000/01/rdf-schema#subClassOf"
SUBPROP = "http://www.w3.org/2000/01/rdf-schema#subPropertyOf"

SOURCES = ["imports/bfo-core.ttl", "imports/cco-slice.ttl", "ontology/crgo-*.ttl", "ontology/vocab/*.ttl",
           "ontology/vocab-private/*.ttl", "data/abox/crgo-library.ttl", "tests/crg/medibec30.ttl"]

def build(src=None, path=STORE):
    """Load the repository files directly (the union of the crgo-full import closure, the private vocabularies if
    present and the MediBec example). No ROBOT merge is needed."""
    t0 = time.time()
    files = [src] if src else [f for pat in SOURCES for f in sorted(glob.glob(os.path.join(ROOT, pat)))]
    if os.path.exists(path):
        import shutil; shutil.rmtree(path)
    st = ox.Store(path)
    for f in files:
        st.bulk_load(path=f, format=ox.RdfFormat.TURTLE)
    n0 = len(st)
    # subclass closure (named classes only)
    sup = {}
    for s in st.query("SELECT ?c ?d WHERE { ?c <%s> ?d FILTER(isIRI(?c) && isIRI(?d)) }" % SUBCLASS):
        sup.setdefault(s["c"].value, set()).add(s["d"].value)
    def ancestors(c, seen=None):
        seen = seen if seen is not None else set()
        for d in sup.get(c, ()):
            if d not in seen:
                seen.add(d); ancestors(d, seen)
        return seen
    closure = {c: ancestors(c) for c in sup}
    add = []
    for s in st.query("SELECT ?x ?c WHERE { ?x a ?c FILTER(isIRI(?c)) }"):
        for d in closure.get(s["c"].value, ()):
            add.append(ox.Quad(s["x"], RDF_TYPE, ox.NamedNode(d)))
    # subproperty closure
    psup = {}
    for s in st.query("SELECT ?p ?q WHERE { ?p <%s> ?q FILTER(isIRI(?p) && isIRI(?q)) }" % SUBPROP):
        psup.setdefault(s["p"].value, set()).add(s["q"].value)
    for p, qs in psup.items():
        for s in st.query("SELECT ?s ?o WHERE { ?s <%s> ?o }" % p):
            for q in qs:
                add.append(ox.Quad(s["s"], ox.NamedNode(q), s["o"]))
    st.extend(add)
    st.flush(); st.optimize()
    print("store: %d asserted + %d inferred triples in %.1f s -> %s" % (n0, len(st) - n0, time.time() - t0, path))
    return st

def open_store(path=STORE):
    if not os.path.exists(path):
        return build(path=path)
    return ox.Store.read_only(path)

if __name__ == "__main__":
    build()
