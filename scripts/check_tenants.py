# -*- coding: utf-8 -*-
"""Tenant separation (decision R-c, ADR-008).
1. Reference files (ontology/, ontology/vocab/, data/abox/, shapes/) contain no IRI under an organisation base.
2. Each organisation graph (tests/samples/*.ttl, tests/crg/*.ttl) states triples only about subjects under its own base,
   which is never https://w3id.org/crgo/ (except the grandfathered MediBec teaching case), and refers to no other
   organisation's base.
Each organisation graph declares its base on its ontology header with vann:preferredNamespaceUri."""
import glob, os, sys
from rdflib import Graph, URIRef, BNode
from rdflib.namespace import RDF, OWL
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GRANDFATHERED = {"https://w3id.org/crgo/data/medibec/"}  # MediBec teaching case, published under CRGO since 0.4.0
ORG_FILES = sorted(glob.glob(os.path.join(ROOT, "tests", "samples", "*.ttl")) + glob.glob(os.path.join(ROOT, "tests", "crg", "*.ttl")))
REF_FILES = sorted(glob.glob(os.path.join(ROOT, "ontology", "*.ttl")) + glob.glob(os.path.join(ROOT, "ontology", "vocab", "*.ttl")) +
                   glob.glob(os.path.join(ROOT, "data", "abox", "*.ttl")) + glob.glob(os.path.join(ROOT, "shapes", "*.ttl")))
fail = False
bases = {}
VANN = URIRef("http://purl.org/vocab/vann/preferredNamespaceUri")
for f in ORG_FILES:
    g = Graph().parse(f)
    heads = [o for o in g.subjects(RDF.type, OWL.Ontology)]
    if not heads:
        print("   %s: no ontology header" % os.path.relpath(f, ROOT)); fail = True; continue
    h = str(heads[0])
    declared = [str(b) for b in g.objects(heads[0], VANN)]
    if declared:
        b = declared[0]
    elif any(h.startswith(x.rstrip("/")) for x in GRANDFATHERED):
        b = next(x for x in GRANDFATHERED if h.startswith(x.rstrip("/")))
    else:  # the base must be declared, not guessed (independent review, 2026-10-11)
        print("   %s: organisation graph does not declare its base (vann:preferredNamespaceUri)" % os.path.relpath(f, ROOT)); fail = True; continue
    if b.startswith("https://w3id.org/crgo/") and b not in GRANDFATHERED:
        print("   %s: organisation base under https://w3id.org/crgo/" % os.path.relpath(f, ROOT)); fail = True
    bases[f] = (b, g, h)
all_bases = {b for b, _, _ in bases.values()}
for f, (b, g, h) in bases.items():
    others = all_bases - {b}
    bad_subj = {str(s) for s in g.subjects() if isinstance(s, URIRef) and not str(s).startswith(b) and not str(s).startswith(h.rstrip("/"))}
    bad_ref = {str(x) for t in g for x in t if isinstance(x, URIRef) and any(str(x).startswith(o) for o in others)}
    if bad_subj:
        fail = True; print("   %s: %d subject(s) outside its base %s, e.g. %s" % (os.path.relpath(f, ROOT), len(bad_subj), b, sorted(bad_subj)[:2]))
    if bad_ref:
        fail = True; print("   %s: refers to another organisation: %s" % (os.path.relpath(f, ROOT), sorted(bad_ref)[:2]))
n_ref = 0
for f in REF_FILES:
    txt = open(f, encoding="utf-8").read()
    hit = [b for b in all_bases | {"https://example.org/"} if b in txt and b not in GRANDFATHERED]
    n_ref += 1
    if hit:
        fail = True; print("   %s: reference file mentions organisation base(s) %s" % (os.path.relpath(f, ROOT), hit))
print("   tenants: %d organisation graphs (%d bases), %d reference files: %s" % (len(bases), len(all_bases), n_ref, "separated" if not fail else "PROBLEMS ABOVE"))
sys.exit(1 if fail else 0)
