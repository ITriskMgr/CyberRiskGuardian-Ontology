# -*- coding: utf-8 -*-
"""Validate CRGO data against shapes/crgo-shapes.ttl with pySHACL.
Data: the merged full ontology (build/crgo-full-merged.ttl), the MediBec example and the test fixture.
Writes build/shacl-report.txt; exits non-zero on any violation."""
import os, sys, time
from collections import Counter
import rdflib
from pyshacl import validate
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
t0 = time.time()
data = rdflib.Graph()
for f in ["build/crgo-full-merged.ttl", "tests/crg/medibec30.ttl", "tests/fixtures/crg-template-s1.ttl"]:
    data.parse(os.path.join(ROOT, f))
shapes = rdflib.Graph().parse(os.path.join(ROOT, "shapes", "crgo-shapes.ttl"))
conforms, rep_g, rep_t = validate(data, shacl_graph=shapes, inference="none", advanced=True, allow_warnings=True)
open(os.path.join(ROOT, "build", "shacl-report.txt"), "w").write(rep_t)
SH = rdflib.Namespace("http://www.w3.org/ns/shacl#")
msgs = Counter(str(m) for r in rep_g.subjects(rdflib.RDF.type, SH.ValidationResult) for m in rep_g.objects(r, SH.resultMessage))
print("   SHACL: %s, %d results in %.0f s" % ("conforms" if conforms else "VIOLATIONS", sum(msgs.values()), time.time() - t0))
for m, n in msgs.most_common(10):
    print("     %5d  %s" % (n, m))
# negative tests: each small graph must violate the shapes (TBox modules give the class hierarchy)
import glob
tbox = rdflib.Graph()
for m in ["gov", "core", "measure", "crg"]:
    tbox.parse(os.path.join(ROOT, "ontology", "crgo-%s.ttl" % m))
neg_ok = True
for f in sorted(glob.glob(os.path.join(ROOT, "tests", "shacl", "neg-*.ttl"))):
    d = rdflib.Graph(); d += tbox; d.parse(f)
    c, _, _ = validate(d, shacl_graph=shapes, inference="none", advanced=True)
    neg_ok &= not c
    print("   %-34s %s" % (os.path.basename(f)[:-4], "violates, as expected" if not c else "SHOULD VIOLATE"))
sys.exit(0 if conforms and neg_ok else 1)
