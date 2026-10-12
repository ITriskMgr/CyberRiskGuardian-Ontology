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
for f in ["build/crgo-full-merged.ttl", "tests/crg/medibec30.ttl", "tests/fixtures/crg-template-s1.ttl",
          "ontology/vocab/mappings-proposed.ttl", "data/abox/crgo-library-proposed.ttl", "tests/samples/nordelle.ttl", "tests/samples/nordelle-applicability.ttl",
          "tests/samples/nordelle-grca.ttl", "data/abox/crgo-workprogrammes.ttl"]:
    data.parse(os.path.join(ROOT, f))
shapes = rdflib.Graph().parse(os.path.join(ROOT, "shapes", "crgo-shapes.ttl"))
conforms, rep_g, rep_t = validate(data, shacl_graph=shapes, inference="none", advanced=True, allow_warnings=True)
open(os.path.join(ROOT, "build", "shacl-report.txt"), "w").write(rep_t)
SH = rdflib.Namespace("http://www.w3.org/ns/shacl#")
msgs = Counter(("[warning] " if (r, SH.resultSeverity, SH.Warning) in rep_g else "") + str(m)
               for r in rep_g.subjects(rdflib.RDF.type, SH.ValidationResult) for m in rep_g.objects(r, SH.resultMessage))
print("   SHACL: %s, %d results in %.0f s" % ("conforms" if conforms else "VIOLATIONS", sum(msgs.values()), time.time() - t0))
for m, n in msgs.most_common(10):
    print("     %5d  %s" % (n, m))
# negative tests: each small graph must violate the shapes (TBox modules give the class hierarchy)
import glob
tbox = rdflib.Graph()
for m in ["gov", "core", "measure", "crg", "evidence", "org", "vuln", "grc", "mapping", "governance", "assurance", "audit", "incident", "policy", "compliance", "siem", "soar"]:
    tbox.parse(os.path.join(ROOT, "ontology", "crgo-%s.ttl" % m))
neg_ok = True
for f in sorted(glob.glob(os.path.join(ROOT, "tests", "shacl", "neg-*.ttl"))):
    d = rdflib.Graph(); d += tbox; d.parse(f)
    c, rg, _ = validate(d, shacl_graph=shapes, inference="none", advanced=True)
    # 0.9.0 fixtures name the message they must trigger (skos:note "expect: ..."), so a fixture cannot pass for another reason
    exp = [str(n)[8:] for n in d.objects(None, rdflib.URIRef("http://www.w3.org/2004/02/skos/core#note")) if str(n).startswith("expect: ")]
    got = [str(m) for r in rg.subjects(rdflib.RDF.type, SH.ValidationResult) for m in rg.objects(r, SH.resultMessage)]
    hit = all(any(e in m for m in got) for e in exp)
    ok = (not c) and hit
    neg_ok &= ok
    print("   %-34s %s" % (os.path.basename(f)[:-4], ("violates, as expected" + (" (expected message)" if exp else "")) if ok else ("SHOULD VIOLATE" if c else "violates, but not with the expected message")))
sys.exit(0 if conforms and neg_ok else 1)
