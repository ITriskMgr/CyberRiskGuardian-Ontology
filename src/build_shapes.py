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
import spec_v09 as V9  # noqa: E402
import spec_grca as VG  # noqa: E402
OBJECT_PROPERTIES = OBJECT_PROPERTIES + V9.OBJECT_PROPERTIES_09 + VG.OBJECT_PROPERTIES_GRCA
ids = dict(l.rstrip("\n").split("\t") for l in open(os.path.join(ROOT, "src", "ids.tsv"), encoding="utf-8"))
C = lambda k: URIRef("https://w3id.org/crgo/CRGO_%07d" % int(ids[k]))
SH = Namespace("http://www.w3.org/ns/shacl#")
S = Namespace("https://w3id.org/crgo/shapes/")
g = Graph(); g.bind("sh", SH); g.bind("crgo", "https://w3id.org/crgo/"); g.bind("shape", S); g.bind("xsd", XSD); g.bind("skos", SKOS)
o = URIRef("https://w3id.org/crgo/shapes")
g.add((o, RDF.type, OWL.Ontology)); g.add((o, RDFS.label, Literal("CRGO SHACL shapes", lang="en"))); g.add((o, OWL.versionInfo, Literal("0.9.0")))

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
s = S["LinkAnnotation"]; g.add((s, RDF.type, SH.NodeShape))
g.add((s, RDFS.comment, Literal("Every annotated CRGO link records its confidence, status and proposer (axioms of imported W3C slices are not CRGO links).", lang="en")))
tg = BNode(); g.add((s, SH.target, tg)); g.add((tg, RDF.type, SH.SPARQLTarget))
g.add((tg, SH.select, Literal("""SELECT ?this WHERE { ?this a <http://www.w3.org/2002/07/owl#Axiom> ; <http://www.w3.org/2002/07/owl#annotatedSource> ?s . FILTER(STRSTARTS(STR(?s), "https://w3id.org/crgo/")) }""")))
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

# 6. 0.9.0: sources, observations, legal applicability, compliance, control assessment, typed mappings (specification section 13)
def sparql(s, msg, select):
    sp = BNode(); g.add((s, SH.sparql, sp)); g.add((sp, SH.message, Literal(msg, lang="en"))); g.add((sp, SH.select, Literal(select)))
D01 = dict(minInclusive=Literal(0, datatype=XSD.decimal), maxInclusive=Literal(1, datatype=XSD.decimal))
s = shape("SourceRecord", ("class", C("SourceRecord")), "Source records carry the fields of specification section 7.")
prop(s, C("localIdentifier"), "A source record needs exactly one identifier.", minCount=1, maxCount=1)
prop(s, RDFS.label, "A source record needs a title.", minCount=1)
prop(s, C("issuerName"), "A source record must name its issuer.", minCount=1)
prop(s, C("sourceVersion"), "A source record needs exactly one version.", minCount=1, maxCount=1)
prop(s, C("licenceTerms"), "A source record must state its licence or terms.", minCount=1)
prop(s, C("retrievedOn"), "A source record has at most one retrieval date.", maxCount=1)
s = shape("Observation", ("class", C("Observation")), "Observations are dated and about one thing.")
prop(s, C("observationOf"), "An observation is about exactly one entity.", minCount=1, maxCount=1)
prop(s, C("observedOn"), "An observation needs exactly one date.", minCount=1, maxCount=1)
prop(s, C("hasSourceRecord"), "An observation must name its source record.", minCount=1)
s = shape("EPSSObservation", ("class", C("EPSSObservation")), "EPSS observations: one CVE, one date, one probability in 0..1, publisher, model version.")
prop(s, C("numericValue"), "An EPSS observation needs exactly one probability between 0 and 1.", minCount=1, maxCount=1, **D01)
prop(s, C("epssPercentile"), "An EPSS percentile is between 0 and 1.", maxCount=1, **D01)
prop(s, C("observationOf"), "An EPSS observation is about a vulnerability concept.", **{"class": SKOS.Concept})
prop(s, C("sourceModelVersion"), "An EPSS observation has at most one model version.", maxCount=1)
sparql(s, "Contradictory EPSS observations: two different scores for the same vulnerability on the same date.", """SELECT $this WHERE {
  $this <%(of)s> ?v ; <%(on)s> ?d ; <%(val)s> ?x .
  ?other a <%(cls)s> ; <%(of)s> ?v ; <%(on)s> ?d ; <%(val)s> ?y . FILTER(?other != $this && ?x != ?y)
}""" % {"of": C("observationOf"), "on": C("observedOn"), "val": C("numericValue"), "cls": C("EPSSObservation")})
s = shape("VocabularySource", ("class", SKOS.ConceptScheme), "Every imported vocabulary names its source record.")
sparql(s, "A CRGO vocabulary must name its source record (has source record).", """SELECT $this WHERE {
  FILTER(STRSTARTS(STR($this), "https://w3id.org/crgo/vocab/") && STR($this) != "https://w3id.org/crgo/vocab/theme")
  FILTER NOT EXISTS { $this <%s> ?src }
}""" % C("hasSourceRecord"))
s = shape("LegalInstrument", ("class", C("LegalInstrument")), "Legal instruments are cited, placed in a jurisdiction and sourced.")
prop(s, C("officialCitation"), "A legal instrument needs exactly one official citation.", minCount=1, maxCount=1)
prop(s, C("hasJurisdiction"), "A legal instrument needs a jurisdiction.", minCount=1)
prop(s, C("hasInstrumentKind"), "A legal instrument needs exactly one kind.", minCount=1, maxCount=1)
prop(s, C("hasSourceRecord"), "A legal instrument must name its source record.", minCount=1)
s = shape("ApplicabilityCondition", ("class", C("ApplicabilityCondition")), "Conditions belong to an instrument and have one test.")
prop(s, C("conditionOf"), "A condition must say what it is a condition of.", minCount=1)
prop(s, C("conditionTest"), "A condition needs exactly one machine-readable test.", minCount=1, maxCount=1, pattern=Literal("^(required|anyof|exception)\\|[^|]+\\|(plain|interpretive)$"))
prop(s, C("hasConditionKind"), "A condition needs exactly one kind.", minCount=1, maxCount=1)
s = shape("ApplicabilityAssessment", ("class", C("ApplicabilityAssessment")), "Applicability assessments: what, for whom, when, by whom, with what result.")
for k, m in (("applicabilityOf", "the instrument or provision assessed"), ("concernsOrganisation", "the organisation"), ("hasApplicabilityState", "the state reached"), ("assessedOn", "the date")):
    prop(s, C(k), "An applicability assessment needs exactly one value for %s." % m, minCount=1, maxCount=1)
prop(s, C("assessedBy"), "An applicability assessment must name who made it.", minCount=1)
s = shape("ComplianceDetermination", ("class", C("ComplianceDetermination")), "Compliance determinations: section 13 fields, and evidence or an explicit evidence gap.")
for k, m in (("concernsOrganisation", "the organisation"), ("complianceWith", "the provision"), ("hasComplianceState", "the state"), ("assessedOn", "the date")):
    prop(s, C(k), "A compliance determination needs exactly one value for %s." % m, minCount=1, maxCount=1)
prop(s, C("hasJurisdiction"), "A compliance determination needs its jurisdictional scope.", minCount=1)
prop(s, C("assessedBy"), "A compliance determination must name its assessor.", minCount=1)
alt = BNode(); g.add((s, SH["or"], alt)); b1, b2 = BNode(), BNode()
for b, path in ((b1, C("hasEvidence")), (b2, C("evidenceGap"))):
    pp = BNode(); g.add((b, SH.property, pp)); g.add((pp, SH.path, path)); g.add((pp, SH.minCount, Literal(1)))
Collection(g, alt, [b1, b2])
g.add((s, SH.message, Literal("A compliance determination needs evidence, or an explicit statement of the missing evidence.", lang="en")))
sparql(s, "A satisfied or partially satisfied compliance determination must cite evidence; an evidence gap alone is not enough.", """SELECT $this WHERE {
  $this <%s> ?st . FILTER(?st IN (<%s>, <%s>)) FILTER NOT EXISTS { $this <%s> ?e }
}""" % (C("hasComplianceState"), C("CompSatisfied"), C("CompPartial"), C("hasEvidence")))
for key, target in (("establishedIn", ("subjectsOf", C("establishedIn"))), ("offersServicesIn", ("subjectsOf", C("offersServicesIn"))),
                    ("monitorsBehaviourIn", ("subjectsOf", C("monitorsBehaviourIn"))), ("dataSubjectsIn", ("subjectsOf", C("dataSubjectsIn"))),
                    ("transfersDataTo", ("subjectsOf", C("transfersDataTo")))):
    s = shape("Place_" + key, target, "Places are provinces, territories or countries, not the federal legal order.")
    sparql(s, "Use a province or territory, not 'Canada (federal legal order)', as the value of '%s'." % key, """SELECT $this WHERE { $this <%s> <%s> }""" % (C(key), C("JurCanada")))
s = shape("ControlAssessment", ("class", C("ControlAssessment")), "Control assessments: measure, date, result, assessor; evidence unless not tested.")
for k, m in (("evaluatesControlMeasure", "the control measure"), ("assessedOn", "the date"), ("hasTestResult", "the result")):
    prop(s, C(k), "A control assessment needs exactly one value for %s." % m, minCount=1, maxCount=1)
prop(s, C("assessedBy"), "A control assessment must name its assessor.", minCount=1)
sparql(s, "A tested control assessment must link the evidence gathered.", """SELECT $this WHERE {
  $this <%s> ?r . FILTER(?r != <%s>) FILTER NOT EXISTS { $this <%s> ?e }
}""" % (C("hasTestResult"), C("TestNotTested"), C("hasEvidence")))
s = shape("ControlMeasureNotControl", ("class", C("ControlMeasure")), "An implementation is never the same individual as an abstract control.")
sparql(s, "A control measure must not be owl:sameAs a control.", """SELECT $this WHERE {
  { $this <http://www.w3.org/2002/07/owl#sameAs> ?c } UNION { ?c <http://www.w3.org/2002/07/owl#sameAs> $this }
  ?c a <%s> .
}""" % C("Control"))
s = shape("TypedMapping", ("class", OWL.Axiom), "Every correspondence between vocabulary concepts has a typed relation (decision D3).")
sparql(s, "A correspondence needs a typed relation (a CRGO sub-property of the SKOS mapping relation) between the same concepts.", """SELECT $this WHERE {
  $this <http://www.w3.org/2002/07/owl#annotatedProperty> ?p ; <http://www.w3.org/2002/07/owl#annotatedSource> ?s ; <http://www.w3.org/2002/07/owl#annotatedTarget> ?o .
  FILTER(?p IN (<http://www.w3.org/2004/02/skos/core#relatedMatch>, <http://www.w3.org/2004/02/skos/core#closeMatch>))
  FILTER NOT EXISTS { ?s ?tp ?o . ?tp <http://www.w3.org/2000/01/rdf-schema#subPropertyOf> ?p . FILTER(?tp != ?p) }
}""")

# 7. 0.9.0 GRCA sprint and packages R4-R8 (specification acceptance tests; GRCA sections 4, 6, 9, 10, 11)
def req(s, key, what, cls_name, one=True):
    prop(s, C(key), "%s needs %s %s." % (cls_name, "exactly one value for" if one else "at least one value for", what), minCount=1, **({"maxCount": 1} if one else {}))
def warn(s):
    g.add((s, SH.severity, SH.Warning))
P = lambda k: "<%s>" % C(k)
s = shape("SourceAccess", ("class", C("SourceRecord")), "Source records state whether CRGO holds and may use the source (GRCA section 3).")
req(s, "hasAccessStatus", "the access status", "A source record")
for cls in ("AuditFinding", "ComplianceDetermination", "AnalyticalResult"):
    s = shape("KnowledgeStatus_" + cls, ("class", C(cls)), "Findings, determinations and analytical results state their epistemic category (GRCA section 11).")
    req(s, "hasKnowledgeStatus", "the knowledge status", "A %s record" % cls)
s = shape("AnalyticalResult", ("class", C("AnalyticalResult")), "Results computed by an external model are traceable and stay risk estimates (ADR-007).")
for k, w in (("modelName", "the model name"), ("modelVersion", "the model version"), ("computedAt", "the computation time"), ("inputDocumentHash", "the input document checksum")):
    req(s, k, w, "An analytical result")
req(s, "resultFor", "what it is computed for", "An analytical result", one=False)
prop(s, C("governanceStatus"), "An analytical result needs exactly one governance status (proposed until a person approves it).", minCount=1, maxCount=1)
sparql(s, "An approved analytical result must name the person who approved it and when; a write-back alone never approves it.", """SELECT $this WHERE {
  $this %s %s . FILTER NOT EXISTS { $this %s ?who ; %s ?d } }""" % (P("governanceStatus"), P("StatusApproved"), P("approvedBy"), P("approvalDate")))
sparql(s, "An analytical result computed outside CRGO is a risk estimate, never a fact, conclusion or decision.", """SELECT $this WHERE {
  $this %s ?k . FILTER(?k != %s) }""" % (P("hasKnowledgeStatus"), P("KsRiskEstimate")))
s = shape("AuditFinding", ("class", C("AuditFinding")), "A finding needs criterion, condition and evidence, within an engagement (GRCA WP3).")
req(s, "withinEngagement", "the engagement it was raised in", "An audit finding")
req(s, "usesCriterion", "the criterion", "An audit finding", one=False)
req(s, "findingCondition", "the condition found", "An audit finding", one=False)
req(s, "hasEvidence", "the evidence relied on", "An audit finding", one=False)
req(s, "hasFindingSignificance", "the significance", "An audit finding")
req(s, "raisedOn", "the date raised", "An audit finding")
sparql(s, "An audit finding cannot have the knowledge status of a reference fact or a verified outcome.", """SELECT $this WHERE {
  $this %s ?k . FILTER(?k IN (%s, %s)) }""" % (P("hasKnowledgeStatus"), P("KsReferenceFact"), P("KsVerifiedOutcome")))
s = shape("CorrectiveAction", ("class", C("CorrectiveAction")), "Corrective actions have an owner, a due date and what they correct.")
req(s, "correctsFinding", "what it corrects", "A corrective action", one=False)
req(s, "hasOwner", "its owner", "A corrective action", one=False)
req(s, "dueOn", "the due date", "A corrective action")
s = shape("ManagementResponse", ("class", C("ManagementResponse")), "Management responses name the finding, the stance and who responded.")
req(s, "responseTo", "the finding or recommendation answered", "A management response", one=False)
req(s, "hasResponseStance", "the stance", "A management response")
req(s, "respondedBy", "who responded", "A management response", one=False)
s = shape("FollowUpVerification", ("class", C("FollowUpVerification")), "Follow-up verifications: action, result, assessor, date.")
req(s, "verifiesAction", "the action verified", "A follow-up verification")
req(s, "hasVerificationResult", "the result", "A follow-up verification")
req(s, "assessedBy", "the assessor", "A follow-up verification", one=False)
req(s, "assessedOn", "the date", "A follow-up verification")
s = shape("FindingClosure", ("class", C("FindingClosure")), "Closure needs an independent verification found effective, or a recorded risk acceptance (GRCA WP3).")
req(s, "closesFinding", "the finding closed", "A finding closure")
req(s, "closedOn", "the closure date", "A finding closure")
req(s, "closureBasedOn", "the verification or risk acceptance it relies on", "A finding closure", one=False)
sparql(s, "A finding can be closed only on a follow-up verification found effective, or on a recorded risk acceptance.", """SELECT $this WHERE {
  FILTER NOT EXISTS { $this %s ?v . { ?v %s %s } UNION { ?v a %s } }
}""" % (P("closureBasedOn"), P("hasVerificationResult"), P("VerifEffective"), P("RiskAcceptance")))
sparql(s, "Closure needs an independent verification: the verifier must not own, be accountable for, or have committed to the corrective action, nor own the control the finding is about.", """SELECT $this WHERE {
  $this %(cb)s ?v . ?v %(va)s ?a ; %(by)s ?who .
  { ?a %(own)s ?who } UNION { ?who %(acc)s ?a } UNION { ?r %(commit)s ?a ; %(resp)s ?who }
  UNION { $this %(closes)s ?f . ?f %(onc)s ?m . ?role %(rolefor)s ?m ; a %(cor)s . ?asg %(aor)s ?role ; %(at)s ?who }
}""" % {"cb": P("closureBasedOn"), "va": P("verifiesAction"), "by": P("assessedBy"), "own": P("hasOwner"), "acc": P("accountableFor"),
        "commit": P("commitsToAction"), "resp": P("respondedBy"), "closes": P("closesFinding"), "onc": P("findingOnControl"),
        "rolefor": P("roleFor"), "cor": P("ControlOwnerRole"), "aor": P("assignmentOfRole"), "at": P("assignedTo")})
s = shape("PolicyException", ("class", C("PolicyException")), "Exceptions are scoped, justified, approved by an authority and expire (GAPS D01).")
for k, w, one in (("exceptionTo", "what it deviates from", False), ("exceptionScope", "its scope", False), ("approvingAuthority", "its approving authority", False),
                  ("validFrom", "its start date", True), ("validUntil", "its expiry date", True), ("exceptionJustification", "its justification", False)):
    req(s, k, w, "A policy exception", one=one)
sparql(s, "A policy exception cannot waive a legal provision; only internal rules and controls can be excepted.", """SELECT $this WHERE {
  $this %s ?t . { ?t %s ?i } UNION { ?t a %s } UNION { ?t a %s } }""" % (P("exceptionTo"), P("provisionOf"), P("LegalObligation"), P("LegalInstrument")))
sparql(s, "A policy exception expires after it starts.", """SELECT $this WHERE { $this %s ?a ; %s ?b . FILTER(?b <= ?a) }""" % (P("validFrom"), P("validUntil")))
s = shape("RoleAssignment", ("class", C("RoleAssignment")), "Role assignments: role, agent and period (GRCA section 4).")
req(s, "assignmentOfRole", "the role", "A role assignment")
req(s, "assignedTo", "the agent", "A role assignment")
req(s, "validFrom", "the start date", "A role assignment")
sparql(s, "A role assignment ends after it starts.", """SELECT $this WHERE { $this %s ?a ; %s ?b . FILTER(?b <= ?a) }""" % (P("validFrom"), P("validUntil")))
s = shape("RoleConflict", ("class", C("ControlAssessment")), "Warning, not violation: the same agent operates a control and assesses it as an independent line (GRCA section 4).")
warn(s)
sparql(s, "Possible role conflict: the assessor also operates the control it assesses as second line, internal audit or external assurer.", """SELECT $this WHERE {
  $this %s ?m ; %s ?who ; %s ?line . FILTER(?line IN (%s, %s, %s)) ?who %s ?m .
}""" % (P("evaluatesControlMeasure"), P("assessedBy"), P("performedInCapacity"), P("LineSecond"), P("LineInternalAudit"), P("LineExternal"), P("operatesControl")))
s = shape("StaleEvidence", ("class", C("ControlAssessment")), "Warning: evidence relied on is out of date or does not cover the period assessed (CQ-GRCA-11).")
warn(s)
sparql(s, "Evidence relied on had expired, or its period ended before the period assessed began.", """SELECT $this WHERE {
  $this %s ?e .
  { $this %s ?on . ?e %s ?until . FILTER(?until < ?on) } UNION { $this %s ?ps . ?e %s ?pe . FILTER(?pe < ?ps) }
}""" % (P("hasEvidence"), P("assessedOn"), P("validUntil"), P("periodStart"), P("periodEnd")))
s = shape("OperatingEffectiveness", ("class", C("OperatingEffectivenessAssessment")), "Operating effectiveness is tested over a period and a population or sample (GAPS D05).")
req(s, "periodStart", "the start of the period tested", "An operating effectiveness assessment")
req(s, "periodEnd", "the end of the period tested", "An operating effectiveness assessment")
req(s, "itemsTested", "the number of items tested", "An operating effectiveness assessment")
sparql(s, "Deviations found cannot exceed the items tested, and the period must end after it starts.", """SELECT $this WHERE {
  { $this %s ?n ; %s ?d . FILTER(?d > ?n) } UNION { $this %s ?a ; %s ?b . FILTER(?b <= ?a) } }""" % (P("itemsTested"), P("deviationsFound"), P("periodStart"), P("periodEnd")))
s = shape("ControlDeficiency", ("class", C("ControlDeficiency")), "Deficiencies: control measure, assessment, aspect, severity.")
for k, w, one in (("deficiencyOf", "the control measure", True), ("identifiedBy", "the assessment that found it", False), ("deficiencyAspect", "the aspect", True), ("hasDeficiencySeverity", "the severity", True)):
    req(s, k, w, "A control deficiency", one=one)
s = shape("EvidenceSufficiency", ("class", C("EvidenceSufficiencyAssessment")), "Sufficiency assessments are explicit (GRCA section 9).")
for k, w, one in (("sufficiencyOf", "the evidence judged", False), ("sufficiencyFor", "the objective", False), ("hasSufficiencyConclusion", "the conclusion", True), ("assessedBy", "the assessor", False), ("assessedOn", "the date", True)):
    req(s, k, w, "An evidence sufficiency assessment", one=one)
s = shape("ExternalAssuranceReport", ("class", C("ExternalAssuranceReport")), "External assurance reports: type, assurer, service, and a period for type 2 reports.")
req(s, "hasAssuranceReportType", "the report type", "An external assurance report")
req(s, "issuedByAssurer", "the assurer", "An external assurance report", one=False)
req(s, "reportOnServiceOf", "the organisation covered", "An external assurance report", one=False)
sparql(s, "A type 2 report covers a period: it needs a period start and end.", """SELECT $this WHERE {
  $this %s ?t . FILTER(?t IN (%s, %s)) FILTER NOT EXISTS { $this %s ?a ; %s ?b } }""" % (P("hasAssuranceReportType"), P("ReportSOC1Type2"), P("ReportSOC2Type2"), P("periodStart"), P("periodEnd")))
s = shape("DecisionRecord", ("class", C("DecisionRecord")), "Decision records: subject, decision maker, outcome, date; reasons when rejected or deferred (GAPS D07).")
for k, w, one in (("decisionOn", "the subject", False), ("decisionMadeBy", "the decision maker", False), ("hasDecisionOutcome", "the outcome", True), ("decidedOn", "the date", True)):
    req(s, k, w, "A decision record", one=one)
sparql(s, "A rejected or deferred decision must state its rationale.", """SELECT $this WHERE {
  $this %s ?o . FILTER(?o IN (%s, %s)) FILTER NOT EXISTS { $this %s ?r } }""" % (P("hasDecisionOutcome"), P("DecRejected"), P("DecDeferred"), P("decisionRationale")))
s = shape("SamplingPlan", ("class", C("SamplingPlan")), "Sampling plans: population, size, method, rationale.")
for k, w in (("testedPopulation", "the population"), ("plannedSampleSize", "the sample size"), ("hasSamplingMethod", "the method")):
    req(s, k, w, "A sampling plan")
req(s, "samplingRationale", "the rationale", "A sampling plan", one=False)
s = shape("SampleItem", ("class", C("SampleItem")), "Sample items: plan and result.")
req(s, "sampleOf", "the sampling plan", "A sample item"); req(s, "hasSampleResult", "the result", "A sample item")
s = shape("AuditProcedure", ("class", C("AuditProcedure")), "Each procedure states its method and cites the objectives it serves (GRCA section 8).")
req(s, "usesAssessmentMethod", "the assessment method", "An audit procedure", one=False)
req(s, "servesObjective", "an objective it serves", "An audit procedure", one=False)
s = shape("AuditProgramme", ("class", C("AuditProgramme")), "Work programmes contain procedures.")
req(s, "hasProcedure", "a procedure", "An audit work programme", one=False)
s = shape("IncidentConfirmation", ("class", C("IncidentConfirmation")), "Incident confirmations: incident, date, who confirmed.")
req(s, "confirmsIncident", "the incident", "An incident confirmation"); req(s, "confirmedOn", "the date", "An incident confirmation")
req(s, "assessedBy", "who confirmed it", "An incident confirmation", one=False)
s = shape("BreachReportability", ("class", C("BreachReportabilityAssessment")), "Reportability assessments: incident, provision, state, date, assessor.")
for k, w, one in (("reportabilityOf", "the incident", True), ("reportableUnder", "the provision", False), ("hasReportabilityState", "the state", True), ("assessedOn", "the date", True), ("assessedBy", "the assessor", False)):
    req(s, k, w, "A breach reportability assessment", one=one)
s = shape("Nonconformity", ("class", C("Nonconformity")), "Nonconformities: requirement, organisation, date.")
req(s, "nonconformityWith", "the requirement", "A nonconformity", one=False); req(s, "concernsOrganisation", "the organisation", "A nonconformity")
req(s, "identifiedOn", "the date identified", "A nonconformity")
s = shape("RegulatoryChange", ("class", C("RegulatoryChange")), "Regulatory changes: what changed, how, when identified.")
req(s, "changeOf", "what changed", "A regulatory change", one=False); req(s, "hasChangeType", "the change type", "A regulatory change")
req(s, "identifiedOn", "the date identified", "A regulatory change")
s = shape("ReassessmentTrigger", ("class", C("ReassessmentTrigger")), "Triggers name their cause and what must be reviewed.")
req(s, "triggeredBy", "the cause", "A reassessment trigger", one=False); req(s, "requiresReviewOf", "what must be reviewed", "A reassessment trigger", one=False)

os.makedirs(os.path.join(ROOT, "shapes"), exist_ok=True)
g.serialize(os.path.join(ROOT, "shapes", "crgo-shapes.ttl"), format="turtle")
print("shapes: %d node shapes (%d for functional properties)" % (len(set(g.subjects(RDF.type, SH.NodeShape))), n_func))
