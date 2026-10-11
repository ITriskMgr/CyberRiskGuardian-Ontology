# -*- coding: utf-8 -*-
"""A second SYNTHETIC organisation, Boréal Outillage ltée (fictional hardware wholesaler), in its own graph under its
own IRI base, for the tenant fixtures of the remaining-gaps specification (section 10.1) and ADR-008.

It deliberately mirrors parts of Nordelle (a backup control, a self-assessment and an internal audit test that
disagree) so that a query scoped to one organisation can be checked not to return the other's records.
Writes tests/samples/tenant-b.ttl."""
import os
from rdflib import Graph, Namespace, URIRef, Literal
from rdflib.namespace import RDF, RDFS, OWL, XSD, DCTERMS

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
BASE = "https://w3id.org/crgo/"
ids = dict(l.rstrip("\n").split("\t") for l in open(os.path.join(ROOT, "src", "ids.tsv"), encoding="utf-8"))
T = lambda k: URIRef(BASE + "CRGO_%07d" % int(ids[k]))
B = Namespace("https://example.org/crgo-sample/boreal/")
CCO = Namespace("https://www.commoncoreontologies.org/")
dt = lambda d: Literal(d + "T00:00:00", datatype=XSD.dateTime)
g = Graph(); g.bind("crgo", BASE); g.bind("boreal", B)
o = URIRef("https://example.org/crgo-sample/boreal")
g.add((o, RDF.type, OWL.Ontology)); g.add((o, OWL.imports, URIRef(BASE + "crgo")))
g.add((o, URIRef("http://purl.org/vocab/vann/preferredNamespaceUri"), Literal(str(B))))  # organisation base, declared (ADR-008)
g.add((o, RDFS.label, Literal("Boréal Outillage ltée - SYNTHETIC second tenant for CRGO 0.9.0 tenant tests", lang="en")))
def ind(s, cls, label):
    g.add((s, RDF.type, OWL.NamedIndividual)); g.add((s, RDF.type, cls)); g.add((s, RDFS.label, Literal(label, lang="en")))
    g.add((s, DCTERMS.type, Literal("synthetic test data"))); return s
org = ind(B.org, CCO.ont00001180, "Boréal Outillage ltée (fictional)")
ops = ind(B["person/ops"], CCO.ont00001262, "Boréal operations lead (fictional)")
aud = ind(B["person/auditor"], CCO.ont00001262, "Boréal internal auditor (fictional)")
m = ind(B["control/backups"], T("ControlMeasure"), "Weekly tape backups (fictional)")
ev = ind(B["evidence/tape-log"], T("EvidenceItem"), "Tape rotation log (fictional)"); g.add((ev, T("localIdentifier"), Literal("tape-log")))
for key, who, line, res, date in (("rcsa", ops, "LineSelfAssessment", "TestEffective", "2026-08-01"), ("audit", aud, "LineInternalAudit", "TestIneffective", "2026-08-20")):
    a = ind(B["control-assessment/" + key], T("ControlAssessment"), "Boréal backup assessment (%s)" % key)
    for p, v in (("evaluatesControlMeasure", m), ("assessedOn", dt(date)), ("hasTestResult", T(res)), ("assessedBy", who),
                 ("performedInCapacity", T(line)), ("hasEvidence", ev), ("concernsOrganisation", org)):
        g.add((a, T(p), v))
g.serialize(os.path.join(ROOT, "tests", "samples", "tenant-b.ttl"), format="turtle")
print("tenant-b: %d triples" % len(g))
