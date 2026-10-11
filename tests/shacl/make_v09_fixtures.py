# -*- coding: utf-8 -*-
"""Write the 0.9.0 negative fixtures: SHACL graphs that must violate shapes/crgo-shapes.ttl (tests/shacl/neg-*.ttl)
and one OWL graph that must be inconsistent (tests/fixtures/neg-observation-is-estimate.ttl)."""
import os
from rdflib import Graph, URIRef, Literal, BNode, Namespace
from rdflib.namespace import RDF, RDFS, OWL, XSD, SKOS

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
ids = dict(l.rstrip("\n").split("\t") for l in open(os.path.join(ROOT, "src", "ids.tsv"), encoding="utf-8"))
T = lambda k: URIRef("https://w3id.org/crgo/CRGO_%07d" % int(ids[k]))
X = Namespace("https://example.org/crgo-test/")
CVE = URIRef("https://w3id.org/crgo/vocab/kev/CVE-2021-44228")
dt = lambda d: Literal(d + "T00:00:00", datatype=XSD.dateTime)
dec = lambda v: Literal(str(v), datatype=XSD.decimal)

def write(name, triples, folder="shacl", imports=None):
    g = Graph(); g.bind("crgo", "https://w3id.org/crgo/"); g.bind("x", X)
    o = X["fixture/" + name]; g.add((o, RDF.type, OWL.Ontology))
    for i in imports or []: g.add((o, OWL.imports, URIRef(i)))
    g.add((o, RDFS.comment, Literal("Negative fixture (0.9.0): must be rejected.", lang="en")))
    g.add((CVE, RDF.type, SKOS.Concept))
    for t in triples: g.add(t)
    g.serialize(os.path.join(ROOT, "tests", folder, name + ".ttl"), format="turtle")

def epss(o, value, date="2026-10-04"):
    return [(o, RDF.type, T("EPSSObservation")), (o, T("observationOf"), CVE), (o, T("observedOn"), dt(date)),
            (o, T("numericValue"), dec(value)), (o, T("hasSourceRecord"), X.src)]

write("neg-epss-out-of-range", epss(X.o1, 1.3))
write("neg-epss-contradictory", epss(X.o1, 0.97) + epss(X.o2, 0.42))
write("neg-observation-undated", [(X.o1, RDF.type, T("Observation")), (X.o1, T("observationOf"), CVE), (X.o1, T("hasSourceRecord"), X.src)])
org, who = X.org, X.who
write("neg-determination-no-evidence", [(X.d, RDF.type, T("ComplianceDetermination")), (X.d, T("concernsOrganisation"), org),
      (X.d, T("complianceWith"), X.provision), (X.d, T("hasComplianceState"), T("CompSatisfied")), (X.d, T("hasJurisdiction"), T("JurQuebec")),
      (X.d, T("assessedOn"), dt("2026-10-01")), (X.d, T("assessedBy"), who)])
write("neg-applicability-no-state", [(X.a, RDF.type, T("ApplicabilityAssessment")), (X.a, T("applicabilityOf"), X.inst),
      (X.a, T("concernsOrganisation"), org), (X.a, T("assessedOn"), dt("2026-10-01")), (X.a, T("assessedBy"), who)])
write("neg-control-test-no-evidence", [(X.c, RDF.type, T("ControlAssessment")), (X.c, T("evaluatesControlMeasure"), X.m),
      (X.c, T("assessedOn"), dt("2026-09-15")), (X.c, T("hasTestResult"), T("TestEffective")), (X.c, T("assessedBy"), who)])
write("neg-measure-sameas-control", [(X.m, RDF.type, T("ControlMeasure")), (X.ctl, RDF.type, T("Control")), (X.m, OWL.sameAs, X.ctl)])
ax = BNode(); s, o = URIRef("https://w3id.org/crgo/vocab/attack/T1078"), URIRef("https://w3id.org/crgo/vocab/sp800-53r5/AC-2")
write("neg-mapping-untyped", [(s, SKOS.relatedMatch, o), (ax, RDF.type, OWL.Axiom), (ax, OWL.annotatedSource, s), (ax, OWL.annotatedProperty, SKOS.relatedMatch),
      (ax, OWL.annotatedTarget, o), (ax, T("confidence"), T("ConfHigh")), (ax, T("governanceStatus"), T("StatusProposed")), (ax, T("proposedBy"), T("AgentClaude"))])
write("neg-source-record-no-version", [(X.src2, RDF.type, T("SourceRecord")), (X.src2, T("localIdentifier"), Literal("x")), (X.src2, RDFS.label, Literal("x")),
      (X.src2, T("issuerName"), Literal("x")), (X.src2, T("licenceTerms"), Literal("x"))])
# OWL: an observation that is also an estimate contradicts the disjointness of observation and estimate
write("neg-observation-is-estimate", [(X.o1, RDF.type, OWL.NamedIndividual), (X.o1, RDF.type, T("EPSSObservation")), (X.o1, RDF.type, T("Likelihood"))],
      folder="fixtures", imports=["https://w3id.org/crgo/crgo"])
print("0.9.0 negative fixtures written")
