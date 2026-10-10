# -*- coding: utf-8 -*-
"""Generate shapes/crgo-shapes.ttl (SHACL) from readable keys.

Covers what OWL 2 does not check on open-world data:
- the 'functional' object properties of the specification (max 1 value), deferred from Phase 2;
- estimates: exactly one numeric value, value ranges per kind (unit interval, CVSS 0-10, non-negative risk);
- library and assessment scenarios: label, theme, threat event, links to requirements or a refined family;
- link annotations (OWL axioms): confidence, status and proposer; approver and date when approved;
- evidence items, tolerance classification, calculation provenance.
"""
import os, sys
from rdflib import Graph, Namespace, Literal, URIRef, BNode
from rdflib.collection import Collection
from rdflib.namespace import RDF, RDFS, OWL, XSD, SKOS

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))
from spec_props import OBJECT_PROPERTIES  # noqa: E402
ids = dict(l.rstrip("\n").split("\t") for l in open(os.path.join(ROOT, "src", "ids.tsv"), encoding="utf-8"))
C = lambda k: URIRef("https://w3id.org/crgo/CRGO_%07d" % int(ids[k]))
SH = Namespace("http://www.w3.org/ns/shacl#")
S = Namespace("https://w3id.org/crgo/shapes/")
g = Graph(); g.bind("sh", SH); g.bind("crgo", "https://w3id.org/crgo/"); g.bind("shape", S); g.bind("xsd", XSD); g.bind("skos", SKOS)
o = URIRef("https://w3id.org/crgo/shapes")
g.add((o, RDF.type, OWL.Ontology)); g.add((o, RDFS.label, Literal("CRGO SHACL shapes", lang="en"))); g.add((o, OWL.versionInfo, Literal("0.5.0")))

def shape(name, target, msg_en):
    s = S[name]
    g.add((s, RDF.type, SH.NodeShape))
    kind, t = target
    g.add((s, {"class": SH.targetClass, "subjectsOf": SH.targetSubjectsOf, "node": SH.targetNode}[kind], t))
    g.add((s, RDFS.comment, Literal(msg_en, lang="en")))
    return s

def prop(s, path, msg, **k):
    p = BNode(); g.add((s, SH.property, p)); g.add((p, SH.path, path)); g.add((p, SH.message, Literal(msg, lang="en")))
    for key, v in k.items():
        g.add((p, SH[key], v if isinstance(v, (URIRef, Literal, BNode)) else Literal(v)))
    return p

# 1. functional object properties of the specification
n_func = 0
for key, mod, en, fr, den, dfr, dom, rng, srcs, conf, rat, chars, sup in OBJECT_PROPERTIES:
    if "functional" in chars:
        target = ("class", C(dom)) if dom and not dom.startswith(("bfo:", "cco:")) else ("subjectsOf", C(key))
        s = shape("Functional_" + key, target, "At most one '%s' value (functional in the CRGO specification)." % en)
        prop(s, C(key), "'%s' takes at most one value." % en, maxCount=1)
        n_func += 1

# 2. estimates
s = shape("Estimate", ("class", C("Estimate")), "Every estimate has exactly one numeric value and is about something.")
prop(s, C("numericValue"), "An estimate needs exactly one numeric value.", minCount=1, maxCount=1)
prop(s, C("estimateOf"), "An estimate must say what it is an estimate of.", minCount=1)
for cls in ["ThreatPresence", "ExploitationProbability", "ExpectedDamage", "MaximumDamage", "Criticality", "ProbabilityReduction", "ImpactReduction"]:
    s = shape("Range_" + cls, ("class", C(cls)), "Values on the unit interval.")
    prop(s, C("numericValue"), "Value must be between 0 and 1.", minInclusive=Literal(0, datatype=XSD.decimal), maxInclusive=Literal(1, datatype=XSD.decimal))
s = shape("Range_Resilience", ("class", C("Resilience")), "Resilience is in (0, 1]: CRG divides by it.")
prop(s, C("numericValue"), "Resilience must be greater than 0 and at most 1.", minExclusive=Literal(0, datatype=XSD.decimal), maxInclusive=Literal(1, datatype=XSD.decimal))
s = shape("Range_CVSS", ("class", C("CVSSInput")), "CVSS base scores are between 0 and 10.")
prop(s, C("numericValue"), "CVSS score must be between 0 and 10.", minInclusive=Literal(0, datatype=XSD.decimal), maxInclusive=Literal(10, datatype=XSD.decimal))
for cls in ["EstimatedRisk", "ToleratedRisk", "MitigatedRisk", "ResidualRisk", "RiskToToleranceRatio", "PreTreatmentRatio"]:
    s = shape("Range_" + cls, ("class", C(cls)), "Computed risk quantities are non-negative and come from a calculation.")
    prop(s, C("numericValue"), "Value must be non-negative.", minInclusive=Literal(0, datatype=XSD.decimal))
    prop(s, C("generatedBy"), "A computed quantity must record the calculation that produced it.", minCount=1, maxCount=1)
s = shape("ToleranceClass", ("class", C("RiskToToleranceRatio")), "A ratio carries its tolerance class.")
prop(s, C("hasToleranceClassification"), "A risk-to-tolerance ratio needs exactly one tolerance class.", minCount=1, maxCount=1)

# 3. scenarios
s = shape("RiskScenario", ("class", C("RiskScenario")), "Scenarios are named.")
prop(s, RDFS.label, "A scenario needs a label.", minCount=1)
s = shape("LibraryScenario", ("class", C("LibraryScenario")), "Library scenarios are themed or refine a family, and point to requirements or to the family they refine.")
alt = BNode(); g.add((s, SH["or"], alt))
a1, a2 = BNode(), BNode()
for b, path in ((a1, C("hasRelevantRequirement")), (a2, C("refines"))):
    pp = BNode(); g.add((b, SH.property, pp)); g.add((pp, SH.path, path)); g.add((pp, SH.minCount, Literal(1)))
Collection(g, alt, [a1, a2])
g.add((s, SH.message, Literal("A library scenario needs at least one relevant requirement, or must refine a library family.", lang="en")))
s = shape("LibraryFamily", ("subjectsOf", C("hasRelevantRequirement")), "Linked scenarios have a theme and a threat event.")
prop(s, C("hasScenarioCategory"), "A linked library scenario needs a theme.", minCount=1)
prop(s, C("hasThreatEvent"), "A linked library scenario needs a threat event description.", minCount=1)
for path, msg in ((C("hasRelevantRequirement"), "Relevant requirements are framework concepts."), (C("triggersObligation"), "Obligations are concepts of the Loi 25 vocabulary.")):
    s = shape("Target_" + str(path).rsplit("_", 1)[1], ("subjectsOf", path), msg)
    prop(s, path, msg, **{"class": SKOS.Concept})
s = shape("ScenarioStep", ("class", C("ScenarioStep")), "Steps are ordered.")
prop(s, C("stepOrder"), "A scenario step needs exactly one positive order number.", minCount=1, maxCount=1, minInclusive=Literal(1))

# 4. link annotations (OWL 2 axiom annotations)
s = shape("LinkAnnotation", ("class", OWL.Axiom), "Every annotated link records its confidence, status and proposer.")
prop(s, C("confidence"), "A link needs exactly one confidence level.", minCount=1, maxCount=1)
prop(s, C("governanceStatus"), "A link needs exactly one governance status.", minCount=1, maxCount=1)
prop(s, C("proposedBy"), "A link must record who proposed it.", minCount=1)
# approved => approver and date (SPARQL constraint)
sp = BNode(); g.add((s, SH.sparql, sp))
g.add((sp, SH.message, Literal("An approved link must record its approver and approval date.", lang="en")))
g.add((sp, SH.select, Literal("""SELECT $this WHERE {
  $this <%s> <%s> .
  FILTER NOT EXISTS { $this <%s> ?who . $this <%s> ?when . }
}""" % (C("governanceStatus"), C("StatusApproved"), C("approvedBy"), C("approvalDate")))))

# 5. evidence and calculation
s = shape("EvidenceItem", ("class", C("EvidenceItem")), "Evidence items are identified and typed.")
prop(s, C("localIdentifier"), "An evidence item needs an identifier.", minCount=1)
prop(s, C("hasEvidenceBasis"), "An evidence item has at most one evidence basis.", maxCount=1)
s = shape("CalculationActivity", ("class", C("CalculationActivity")), "Calculations name their method.")
prop(s, C("usesMethod"), "A calculation needs exactly one method.", minCount=1, maxCount=1)
s = shape("RiskAssessment", ("class", C("RiskAssessment")), "Assessments that compute tolerance state their appetite once.")
prop(s, C("hasRiskAppetite"), "An assessment has at most one risk appetite statement.", maxCount=1)

os.makedirs(os.path.join(ROOT, "shapes"), exist_ok=True)
g.serialize(os.path.join(ROOT, "shapes", "crgo-shapes.ttl"), format="turtle")
print("shapes: %d node shapes (%d for functional properties)" % (len(set(g.subjects(RDF.type, SH.NodeShape))), n_func))
