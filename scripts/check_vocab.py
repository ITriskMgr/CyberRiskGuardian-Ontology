# -*- coding: utf-8 -*-
"""Check the SKOS vocabularies: every concept has a notation, an English prefLabel, a scheme, a source and a
governance status; notations are unique per scheme; every broader concept exists; no concept has two prefLabels in one language."""
import glob, os, sys
from collections import Counter
import rdflib
from rdflib.namespace import RDF, SKOS
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ids = dict(l.rstrip("\n").split("\t") for l in open(os.path.join(ROOT, "src", "ids.tsv"), encoding="utf-8"))
A = lambda k: rdflib.URIRef("https://w3id.org/crgo/CRGO_%07d" % int(ids[k]))
fail = False
for f in sorted(glob.glob(os.path.join(ROOT, "ontology", "vocab", "*.ttl"))):
    g = rdflib.Graph(); g.parse(f)
    cs = set(g.subjects(RDF.type, SKOS.Concept)); probs = []
    for c in cs:
        if not any(l.language == "en" for l in g.objects(c, SKOS.prefLabel)): probs.append("no en label")
        if Counter(l.language for l in g.objects(c, SKOS.prefLabel)).most_common(1)[0][1] > 1: probs.append("two labels in one language")
        for p, name in [(SKOS.notation, "notation"), (SKOS.inScheme, "scheme"), (A("evidenceSource"), "source"), (A("governanceStatus"), "status")]:
            if (c, p, None) not in g: probs.append("no " + name)
    if len(cs) != len({g.value(c, SKOS.notation) for c in cs}): probs.append("duplicate notations")
    probs += ["broader missing" for b in g.objects(None, SKOS.broader) if b not in cs]
    fail |= bool(probs)
    print("   %-18s %5d concepts %s" % (os.path.basename(f), len(cs), "ok" if not probs else Counter(probs)))
sys.exit(1 if fail else 0)
