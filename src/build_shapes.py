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
import spec_pca as VP  # noqa: E402
import spec_secops as VS  # noqa: E402
OBJECT_PROPERTIES = OBJECT_PROPERTIES + V9.OBJECT_PROPERTIES_09 + VG.OBJECT_PROPERTIES_GRCA + VP.OBJECT_PROPERTIES_PCA + VS.OBJECT_PROPERTIES_SECOPS
ids = dict(l.rstrip("\n").split("\t") for l in open(os.path.join(ROOT, "src", "ids.tsv"), encoding="utf-8"))
C = lambda k: URIRef("https://w3id.org/crgo/CRGO_%07d" % int(ids[k]))
SH = Namespace("http://www.w3.org/ns/shacl#")
S = Namespace("https://w3id.org/crgo/shapes/")
g = Graph(); g.bind("sh", SH); g.bind("crgo", "https://w3id.org/crgo/"); g.bind("shape", S); g.bind("xsd", XSD); g.bind("skos", SKOS)
o = URIRef("https://w3id.org/crgo/shapes")
g.add((o, RDF.type, OWL.Ontology)); g.add((o, RDFS.label, Literal("CRGO SHACL shapes", lang="en"))); g.add((o, OWL.versionInfo, Literal("0.10.0")))

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
prop(s, C("assessedBy"), "A compliance determination must name its assessor.", minCount=1)
# 0.10.0: the jurisdiction is required when the determination is about a legal provision or obligation (frameworks and contracts may have none)
sparql(s, "A compliance determination about a legal provision or obligation needs its jurisdictional scope.", """SELECT $this WHERE {
  $this <%s> ?t . { ?t <%s> ?i } UNION { ?t a <%s> } FILTER NOT EXISTS { $this <%s> ?j } }""" % (C("complianceWith"), C("provisionOf"), C("LegalObligation"), C("hasJurisdiction")))
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

# 8. 0.10.0: policy, compliance and audit management (decisions D1-D14) and SIEM/SOAR (decisions S1-S12)
def one_of(s, key, allowed, msg):
    sparql(s, msg, """SELECT $this WHERE { $this %s ?v . FILTER NOT EXISTS { ?v a ?c . FILTER(?c IN (%s)) } }""" % (P(key), ", ".join(P(a) for a in allowed)))
# One validity rule for an approval relied on by an action execution ($this, action ?act, start ?t), shared by SHACL,
# the CQ-SOAR-02 query and the secops/v1 contract: outcome approved, decided and valid at the start, not denied or
# revoked before it, corresponding to this execution, its action or its risk class, and made by a gate authority when the
# action's gates name one.
APPROVAL_VARS = {"pa": P("performsAction"), "start": P("executionStartedAt"), "rc": P("hasActionRiskClass"), "cont": P("RiskContainment"),
                 "destr": P("RiskDestructive"), "ra": P("requiresApproval")}
VALID_APPROVAL = """$this %(auth)s ?d . ?d %(out)s %(approved)s ; %(don)s ?dd ; %(vf)s ?from . FILTER(?dd <= ?t && ?from <= ?t)
    FILTER NOT EXISTS { ?d %(vu)s ?until . FILTER(?until < ?t) } FILTER NOT EXISTS { ?d %(rev)s ?ro . FILTER(?ro <= ?t) }
    FILTER NOT EXISTS { ?d %(as)s %(denied)s }
    FILTER (EXISTS { ?d %(on)s $this } || EXISTS { ?d %(on)s ?act } || EXISTS { ?d %(pre)s ?act } || EXISTS { ?d %(pre)s ?rcl . ?act %(rc)s ?rcl })
    FILTER (NOT EXISTS { ?act %(ra)s ?g1 . ?g1 %(ga)s ?a1 } || EXISTS { ?act %(ra)s ?g2 . ?g2 %(ga)s ?who . ?d %(by)s ?who })""" % {
    "auth": P("authorizedBy"), "out": P("hasDecisionOutcome"), "approved": P("DecApproved"), "don": P("decidedOn"), "vf": P("validFrom"),
    "vu": P("validUntil"), "rev": P("revokedOn"), "as": P("hasApprovalStatus"), "denied": P("ApprDenied"), "on": P("decisionOn"),
    "pre": P("preauthorisesAction"), "rc": P("hasActionRiskClass"), "ra": P("requiresApproval"), "ga": P("gateAuthority"), "by": P("decisionMadeBy")}
def ordered(s, a, b, msg):
    sparql(s, msg, """SELECT $this WHERE { $this %s ?a ; %s ?b . FILTER(?b < ?a) }""" % (P(a), P(b)))
# --- D9: closure and reopening apply to audit findings and nonconformities
for name, key in (("FindingClosure", "closesFinding"), ("FindingReopening", "reopensFinding")):
    s = shape("Target_%s_0100" % name, ("subjectsOf", C(key)), "A closure or reopening concerns an audit finding or a nonconformity (decision D9).")
    one_of(s, key, ["AuditFinding", "Nonconformity"], "A finding closure or reopening must concern an audit finding or a nonconformity.")
s = shape("FindingClosureNonconformity", ("class", C("FindingClosure")), "Independence of closure also covers nonconformities raised from a control assessment.")
sparql(s, "Closure of a nonconformity needs an independent verification: the verifier must not own the control whose assessment raised it.", """SELECT $this WHERE {
  $this %(cb)s ?v ; %(closes)s ?f . ?v %(by)s ?who . ?f a %(nc)s ; %(rf)s ?ca . ?ca %(ecm)s ?m .
  { ?m %(own)s ?who } UNION { ?who %(op)s ?m } UNION { ?role %(rolefor)s ?m ; a %(cor)s . ?asg %(aor)s ?role ; %(at)s ?who }
}""" % {"cb": P("closureBasedOn"), "closes": P("closesFinding"), "by": P("assessedBy"), "nc": P("Nonconformity"), "rf": P("raisedFrom"),
        "ecm": P("evaluatesControlMeasure"), "own": P("hasOwner"), "op": P("operatesControl"), "rolefor": P("roleFor"), "cor": P("ControlOwnerRole"),
        "aor": P("assignmentOfRole"), "at": P("assignedTo")})
# --- policy
s = shape("DirectiveVersion", ("class", C("DirectiveVersion")), "Directive versions: the directive, the lifecycle state, a version label (POL section 8).")
req(s, "versionOfDirective", "the directive it is a version of", "A directive version")
req(s, "hasLifecycleState", "the lifecycle state", "A directive version")
req(s, "versionLabel", "the version label", "A directive version")
sparql(s, "An approved or published directive version needs its effective date and an approval decision about this exact version.", """SELECT $this WHERE {
  $this %s ?st . FILTER(?st IN (%s, %s))
  FILTER (NOT EXISTS { $this %s ?eff } || NOT EXISTS { ?d %s $this ; %s %s }) }""" % (P("hasLifecycleState"), P("LifeApproved"), P("LifePublished"),
  P("effectiveOn"), P("decisionOn"), P("hasDecisionOutcome"), P("DecApproved")))
sparql(s, "A retired or superseded directive version needs its retirement date, after its effective date.", """SELECT $this WHERE {
  $this %s ?st . FILTER(?st IN (%s, %s))
  FILTER (NOT EXISTS { $this %s ?r } || EXISTS { $this %s ?r2 ; %s ?e . FILTER(?r2 <= ?e) }) }""" % (P("hasLifecycleState"), P("LifeRetired"), P("LifeSuperseded"),
  P("retiredOn"), P("retiredOn"), P("effectiveOn")))
s = shape("PolicyStatementVersioned", ("class", C("PolicyStatement")), "Policy statements belong to an exact version and state how binding they are (POL section 8).")
req(s, "statementInVersion", "the directive version it belongs to", "A policy statement")
req(s, "hasNormativeModality", "the normative modality", "A policy statement")
s = shape("PolicyAcknowledgement", ("class", C("PolicyAcknowledgement")), "Acknowledgements name who, when and the exact policy version (POL section 4).")
req(s, "attestedBy", "who made it", "A policy acknowledgement", one=False)
req(s, "attestedOn", "the date", "A policy acknowledgement")
req(s, "attestationAbout", "the policy version acknowledged", "A policy acknowledgement", one=False)
one_of(s, "attestationAbout", ["DirectiveVersion"], "A policy acknowledgement must be about an exact directive version, not a policy in general.")
s = shape("Attestation", ("class", C("Attestation")), "Attestations are management declarations (improvement I2).")
sparql(s, "An attestation records a management declaration: its knowledge status, if stated, is a management decision.", """SELECT $this WHERE {
  $this %s ?k . FILTER(?k != %s) }""" % (P("hasKnowledgeStatus"), P("KsManagementDecision")))
s = shape("ComplianceAttestation", ("class", C("ComplianceAttestation")), "Compliance attestations: signatory, date, subject and scope.")
req(s, "attestedBy", "the signatory", "A compliance attestation", one=False); req(s, "attestedOn", "the date", "A compliance attestation")
req(s, "attestationAbout", "what is attested", "A compliance attestation", one=False); req(s, "attestationScope", "the scope and basis", "A compliance attestation", one=False)
s = shape("DirectiveReview", ("class", C("DirectiveReview")), "Directive reviews: what, why and when.")
req(s, "reviewOf", "what is reviewed", "A directive review", one=False); req(s, "hasReviewTrigger", "the trigger", "A directive review", one=False)
req(s, "assessedOn", "the review date", "A directive review")
s = shape("Guideline", ("class", C("Guideline")), "Guidelines are not binding (POL section 4).")
sparql(s, "A guideline cannot carry a 'must' or 'must not' modality; a binding rule is a policy statement.", """SELECT $this WHERE {
  $this %s ?m . FILTER(?m IN (%s, %s)) }""" % (P("hasNormativeModality"), P("ModalityMust"), P("ModalityMustNot")))
# --- mapping assertions (I1)
s = shape("MappingAssertion", ("class", C("MappingAssertion")), "Mapping assertions: source, target, type, review state and rationale (POL section 8, CMP section 10).")
for k, w in (("mappingSource", "the source"), ("mappingTarget", "the target"), ("hasMappingType", "the mapping type"), ("hasReviewState", "the review state")):
    req(s, k, w, "A mapping assertion")
req(s, "rationale", "the rationale", "A mapping assertion", one=False)
prop(s, C("mappingConfidence"), "Mapping confidence is between 0 and 1.", maxCount=1, minInclusive=Literal(0, datatype=XSD.decimal), maxInclusive=Literal(1, datatype=XSD.decimal))
sparql(s, "An exact or full-coverage mapping needs a reviewer, a review date, the editions mapped and an approved review state.", """SELECT $this WHERE {
  $this %s ?t . FILTER(?t IN (%s, %s))
  FILTER (NOT EXISTS { $this %s ?r } || NOT EXISTS { $this %s ?d } || NOT EXISTS { $this %s ?e } || NOT EXISTS { $this %s %s }) }""" % (
  P("hasMappingType"), P("MapExact"), P("MapFullCoverage"), P("reviewedBy"), P("reviewedOn"), P("mappedEdition"), P("hasReviewState"), P("RevApproved")))
# --- compliance
s = shape("RequirementInterpretation", ("class", C("RequirementInterpretation")), "Interpretations: what they interpret and their legal review state.")
req(s, "interpretationOf", "what it interprets", "A requirement interpretation", one=False); req(s, "hasLegalReviewState", "the legal review state", "A requirement interpretation")
s = shape("RegulatoryExemption", ("class", C("RegulatoryExemption")), "Exemptions come from an authority, on a legal basis, for an organisation and a period (CMP section 10).")
for k, w, one in (("exemptionFrom", "what it relieves from", False), ("grantedBy", "the granting authority", True), ("legalBasis", "the legal basis", False),
                  ("concernsOrganisation", "the organisation", False), ("validFrom", "the start date", True)):
    req(s, k, w, "A regulatory exemption", one=one)
one_of(s, "grantedBy", ["RegulatoryAuthority"], "A regulatory exemption must be granted by a regulatory authority, not by an internal approver.")
ordered(s, "validFrom", "validUntil", "A regulatory exemption ends after it starts.")
s = shape("ComplianceDeadline", ("class", C("ComplianceDeadline")), "Deadlines: what sets them and how they are computed (CMP section 8).")
req(s, "deadlineFor", "the obligation or provision", "A compliance deadline", one=False); req(s, "hasDeadlineTriggerKind", "the trigger kind", "A compliance deadline")
sparql(s, "An event-triggered deadline needs its offset in hours; a calendar deadline needs its due date.", """SELECT $this WHERE {
  { $this %s %s FILTER NOT EXISTS { $this %s ?h } } UNION { $this %s %s FILTER NOT EXISTS { $this %s ?d } } }""" % (
  P("hasDeadlineTriggerKind"), P("DeadlineEvent"), P("dueOffsetHours"), P("hasDeadlineTriggerKind"), P("DeadlineCalendar"), P("dueOn")))
s = shape("RegulatorySubmission", ("class", C("RegulatorySubmission")), "Submissions: authority, obligation, state; date once sent; receipt once acknowledged (CMP section 10).")
req(s, "submissionTo", "the authority", "A regulatory submission"); req(s, "submissionUnder", "the obligation or provision", "A regulatory submission", one=False)
req(s, "hasSubmissionState", "the state", "A regulatory submission")
sparql(s, "A submitted or acknowledged submission needs its submission date; an acknowledged one needs its receipt evidence.", """SELECT $this WHERE {
  { $this %s ?st . FILTER(?st IN (%s, %s, %s)) FILTER NOT EXISTS { $this %s ?d } } UNION { $this %s %s FILTER NOT EXISTS { $this %s ?e } } }""" % (
  P("hasSubmissionState"), P("SubSubmitted"), P("SubAcknowledged"), P("SubRejected"), P("submittedOn"), P("hasSubmissionState"), P("SubAcknowledged"), P("receiptEvidence")))
s = shape("FrameworkAdoption", ("class", C("FrameworkAdoption")), "Adoptions: what is adopted and by whom.")
req(s, "adoptsFramework", "what is adopted", "A framework adoption", one=False); req(s, "concernsOrganisation", "the organisation", "A framework adoption")
s = shape("ProvisionVersion", ("class", C("ProvisionVersion")), "Provision versions: the provision and the start of the wording.")
req(s, "provisionVersionOf", "the provision", "A provision version"); req(s, "validFrom", "when the wording took effect", "A provision version")
ordered(s, "validFrom", "validUntil", "A provision version ends after it starts.")
s = shape("NotApplicableNotAssessed", ("class", C("ComplianceDetermination")), "Decision D10: no compliance determination for a requirement assessed as not applicable at that date.")
sparql(s, "A compliance determination concerns a requirement that an applicability assessment for the same organisation found not applicable on or before this date.", """SELECT $this WHERE {
  $this %(cw)s ?req ; %(org)s ?o ; %(on)s ?d .
  ?a %(ao)s ?req ; %(org)s ?o ; %(st)s %(na)s ; %(on)s ?ad . FILTER(?ad <= ?d)
  FILTER NOT EXISTS { ?a2 %(ao)s ?req ; %(org)s ?o ; %(st)s ?s2 ; %(on)s ?ad2 . FILTER(?ad2 > ?ad && ?ad2 <= ?d && ?s2 != %(na)s) } }""" % {
  "cw": P("complianceWith"), "org": P("concernsOrganisation"), "on": P("assessedOn"), "ao": P("applicabilityOf"), "st": P("hasApplicabilityState"), "na": P("AppNotApplicable")})
# --- audit
s = shape("AuditPlanEntry", ("class", C("AuditPlanEntry")), "Plan entries: plan, state; reason and authoriser when deferred or cancelled (AUD section 7).")
req(s, "entryInPlan", "the plan", "An audit plan entry"); req(s, "hasPlanEntryState", "the state", "An audit plan entry")
sparql(s, "A deferred or cancelled plan entry needs its reason and who authorised it.", """SELECT $this WHERE {
  $this %s ?st . FILTER(?st IN (%s, %s)) FILTER (NOT EXISTS { $this %s ?r } || NOT EXISTS { $this %s ?a }) }""" % (
  P("hasPlanEntryState"), P("EntryDeferred"), P("EntryCancelled"), P("deferralReason"), P("approvingAuthority")))
s = shape("AuditWorkpaper", ("class", C("AuditWorkpaper")), "Workpapers: what they document, preparer, date; no sole self-review (AUD section 9).")
req(s, "workpaperFor", "what it documents", "An audit workpaper", one=False); req(s, "preparedBy", "the preparer", "An audit workpaper", one=False)
req(s, "preparedOn", "the preparation date", "An audit workpaper")
sparql(s, "Self-review: the only reviewer of a workpaper is its preparer.", """SELECT $this WHERE {
  $this %s ?r . FILTER NOT EXISTS { $this %s ?r2 . FILTER NOT EXISTS { $this %s ?r2 } } }""" % (P("reviewedBy"), P("reviewedBy"), P("preparedBy")))
s = shape("AuditObservation", ("class", C("AuditObservation")), "Observations belong to an engagement and carry no audit conclusion (decision D8).")
req(s, "withinEngagement", "the engagement", "An audit observation")
sparql(s, "An audit observation is preliminary: it cannot have the knowledge status of an audit conclusion, a reference fact or a verified outcome.", """SELECT $this WHERE {
  $this %s ?k . FILTER(?k IN (%s, %s, %s)) }""" % (P("hasKnowledgeStatus"), P("KsAuditConclusion"), P("KsReferenceFact"), P("KsVerifiedOutcome")))
s = shape("AuditQualityReview", ("class", C("AuditQualityReview")), "Quality reviews: subject, kind, reviewer, date.")
req(s, "qualityReviewOf", "what is reviewed", "An audit quality review", one=False); req(s, "hasQualityReviewKind", "the kind", "An audit quality review")
req(s, "assessedBy", "the reviewer", "An audit quality review", one=False); req(s, "assessedOn", "the date", "An audit quality review")
s = shape("AuditCharter", ("class", C("AuditCharter")), "Charters govern an audit function.")
req(s, "charterOf", "the audit function", "An audit charter")
s = shape("EngagementType", ("subjectsOf", C("hasEngagementType")), "An engagement has one nature (assurance or advisory) and at most one focus (compliance or follow-up).")
sparql(s, "An engagement can be either an assurance or an advisory engagement, not both, and has at most one focus.", """SELECT $this WHERE {
  { $this %s %s , %s } UNION { $this %s %s , %s } }""" % (P("hasEngagementType"), P("EngAssurance"), P("EngAdvisory"), P("hasEngagementType"), P("EngCompliance"), P("EngFollowUp")))
# --- SIEM
s = shape("TelemetrySource", ("class", C("TelemetrySource")), "Telemetry sources name the asset they report from.")
req(s, "sourceAsset", "the asset", "A telemetry source", one=False)
s = shape("SecurityEventRecord", ("class", C("SecurityEventRecord")), "Event records: emitting source and the time recorded, apart from the time observed (SIEM section 1).")
req(s, "emittedBy", "the emitting source", "A security event record"); req(s, "recordedAt", "the time recorded", "A security event record")
s = shape("DetectionRule", ("class", C("DetectionRule")), "Detection rules: status and version; enabled rules declare their telemetry (SIEM section 5).")
req(s, "hasDetectionStatus", "the detection status", "A detection rule"); req(s, "versionLabel", "the version", "A detection rule")
sparql(s, "An enabled detection rule must declare the telemetry sources or data components it needs.", """SELECT $this WHERE {
  $this %s %s FILTER NOT EXISTS { $this %s ?src } }""" % (P("hasDetectionStatus"), P("DetEnabled"), P("requiresSource")))
s = shape("DetectionCoverage", ("class", C("DetectionCoverage")), "Coverage needs a strategy or rule, a scenario or technique, and its status (SIEM section 5).")
req(s, "coverageBy", "the strategy or rule", "A detection coverage statement", one=False); req(s, "hasCoverageStatus", "the coverage status", "A detection coverage statement")
sparql(s, "A detection coverage statement must say what it covers: a risk scenario, a technique or an asset.", """SELECT $this WHERE {
  FILTER NOT EXISTS { $this %s ?x } FILTER NOT EXISTS { $this %s ?y } FILTER NOT EXISTS { $this %s ?z } }""" % (P("coversScenario"), P("coversTechnique"), P("coversAsset")))
sparql(s, "Validated coverage needs a supporting detection test, found effective, of a strategy or rule that provides the coverage.", """SELECT $this WHERE {
  $this %s %s FILTER NOT EXISTS { $this %s ?t ; %s ?r . ?t %s %s ; %s ?r } }""" % (P("hasCoverageStatus"), P("CovValidated"), P("supportedByTest"), P("coverageBy"),
  P("hasTestResult"), P("TestEffective"), P("testedRule")))
s = shape("DetectionTest", ("class", C("DetectionTest")), "Detection tests name the rule or strategy exercised.")
req(s, "testedRule", "the rule or strategy tested", "A detection test", one=False)
s = shape("ThreatIndicator", ("class", C("ThreatIndicator")), "Indicators: pattern, language, source, validity; confidence with its method (SIEM sections 2 and 4).")
for k, w, one in (("indicatorPattern", "the pattern", False), ("patternLanguage", "the pattern language", True), ("indicatorFromSource", "the source", False), ("validFrom", "the start of validity", True)):
    req(s, k, w, "A threat indicator", one=one)
sparql(s, "A stated confidence needs its method (how it is defined and on which scale).", """SELECT $this WHERE {
  $this %s ?c . FILTER NOT EXISTS { $this %s ?m } }""" % (P("statedConfidence"), P("confidenceMethod")))
ordered(s, "validFrom", "validUntil", "A threat indicator's validity ends after it starts.")
s = shape("TelemetryHealthObservation", ("class", C("TelemetryHealthObservation")), "Health observations give a state.")
req(s, "hasTelemetryHealthState", "the health state", "A telemetry health observation")
s = shape("Target_openedInvestigation", ("subjectsOf", C("openedInvestigation")), "Alerts open security investigations.")
one_of(s, "openedInvestigation", ["SecurityInvestigation"], "'opened investigation' must point to a security investigation.")
# --- SOAR
s = shape("SecurityInvestigation", ("class", C("SecurityInvestigation")), "Investigations: case status and opening time.")
req(s, "hasCaseStatus", "the case status", "A security investigation"); req(s, "investigationOpenedAt", "the opening time", "A security investigation")
s = shape("ConcludedIncidentConfirmed", ("class", C("SecurityInvestigation")), "Warning: an investigation's conclusion counts only with an incident confirmation (decision S5).")
warn(s)
sparql(s, "The incident this investigation concluded has no incident confirmation yet.", """SELECT $this WHERE {
  $this %s ?i . FILTER NOT EXISTS { ?c %s ?i } }""" % (P("concludedIncident"), P("confirmsIncident")))
s = shape("PlaybookVersion", ("class", C("PlaybookVersion")), "Playbook versions contain steps.")
req(s, "includesStep", "a step", "A playbook version", one=False)
s = shape("ResponseAction", ("class", C("ResponseAction")), "Response actions state their risk class.")
req(s, "hasActionRiskClass", "the risk class", "A response action")
s = shape("ApprovalDecision", ("class", C("ApprovalDecision")), "Approval decisions state their approval status.")
req(s, "hasApprovalStatus", "the approval status", "An approval decision")
s = shape("AutomationExecution", ("class", C("AutomationExecution")), "Executions cite the exact playbook version and an attempt identifier (SOAR section 5).")
for k, w in (("usesPlaybookVersion", "the playbook version"), ("hasExecutionStatus", "the execution status"), ("executionStartedAt", "the start time"), ("attemptIdentifier", "the attempt identifier")):
    req(s, k, w, "An automation execution record")
ordered(s, "executionStartedAt", "executionEndedAt", "An execution ends after it starts.")
s = shape("ActionExecution", ("class", C("ActionExecution")), "Action executions: action, target, status, start, attempt identifier; impactful actions need a valid approval (SOAR section 5).")
for k, w, one in (("performsAction", "the action", True), ("actionTarget", "the target", False), ("hasExecutionStatus", "the execution status", True),
                  ("executionStartedAt", "the start time", True), ("attemptIdentifier", "the attempt identifier", True)):
    req(s, k, w, "An action execution record", one=one)
ordered(s, "executionStartedAt", "executionEndedAt", "An execution ends after it starts.")
s = shape("ActionApproval", ("class", C("ActionExecution")), "Warning (audit signal): impactful actions need a granted approval valid when they started (SOAR section 5, decision S6). A record of an unapproved action is a correct record of a control failure, so this is a warning, not a violation.")
warn(s)
sparql(s, "A containment or destructive action, or one behind an approval gate, was executed without a corresponding approval that was granted and valid when it started (an audit signal, never an authorisation).", """SELECT $this WHERE {
  $this %(pa)s ?act ; %(start)s ?t .
  { ?act %(rc)s ?c . FILTER(?c IN (%(cont)s, %(destr)s)) } UNION { ?act %(ra)s ?gate }
  FILTER NOT EXISTS { %(valid)s } }""" % dict(APPROVAL_VARS, valid=VALID_APPROVAL))
s = shape("ApprovalDecisionConsistent", ("class", C("ApprovalDecision")), "Approval status and decision outcome agree.")
sparql(s, "An approval granted must have the outcome 'approved'; an approval denied must have the outcome 'rejected'.", """SELECT $this WHERE {
  { $this %s %s FILTER NOT EXISTS { $this %s %s } } UNION { $this %s %s FILTER NOT EXISTS { $this %s %s } } }""" % (
  P("hasApprovalStatus"), P("ApprGranted"), P("hasDecisionOutcome"), P("DecApproved"), P("hasApprovalStatus"), P("ApprDenied"), P("hasDecisionOutcome"), P("DecRejected")))
for key in ("concludedIncident", "communicationAbout", "recoveryAfter"):
    s = shape("Target_%s" % key, ("subjectsOf", C(key)), "Incident links point to incidents (ranges are left open to avoid classifying records as incidents).")
    one_of(s, key, ["Incident"], "'%s' must point to an incident." % key)
for key in ("hasIncidentCategory", "hasIncidentSeverity", "hasObservedImpact"):
    s = shape("Subject_%s" % key, ("subjectsOf", C(key)), "Only incidents are categorised, rated or given impacts (domains are left open to avoid classifying cases as incidents).")
    sparql(s, "Only an incident can carry '%s'; categorise the incident, not the investigation or alert." % key, """SELECT $this WHERE { FILTER NOT EXISTS { $this a %s } }""" % P("Incident"))
s = shape("ForensicArtifact", ("class", C("ForensicArtifact")), "Forensic artefacts: custodian, integrity hash, collection date.")
req(s, "custodian", "the custodian", "A forensic artefact", one=False); req(s, "evidenceHash", "the integrity hash", "A forensic artefact"); req(s, "collectedOn", "the collection date", "A forensic artefact")
s = shape("IncidentCommunication", ("class", C("IncidentCommunication")), "Communications: incident, audience, date.")
req(s, "communicationAbout", "the incident", "An incident communication"); req(s, "hasAudience", "the audience", "An incident communication", one=False)
req(s, "sentAt", "the time sent", "An incident communication")
s = shape("RegulatorCommunication", ("class", C("IncidentCommunication")), "Warning: a notice to a regulator should also be recorded as a regulatory submission.")
warn(s)
sparql(s, "A communication to a regulator is not linked to a regulatory submission.", """SELECT $this WHERE {
  $this %s %s FILTER NOT EXISTS { $this %s ?sub } }""" % (P("hasAudience"), P("AudRegulator"), P("recordedAsSubmission")))
s = shape("RecoveryVerification", ("class", C("RecoveryVerification")), "Recovery verifications: what, when, by whom, on what evidence.")
for k, w, one in (("verifiesRecoveryOf", "what was restored", False), ("assessedOn", "the time", True), ("assessedBy", "who verified", False), ("hasEvidence", "the evidence", False)):
    req(s, k, w, "A recovery verification", one=one)
s = shape("ResponseMeasurement", ("class", C("ResponseMeasurement")), "Response measurements: metric, value in hours, method and what was measured (SOAR section 2).")
req(s, "measuresMetric", "the metric", "A response effectiveness measurement"); req(s, "metricMethod", "the method", "A response effectiveness measurement", one=False)
req(s, "measurementOf", "what was measured", "A response effectiveness measurement", one=False)
prop(s, C("valueHours"), "A response effectiveness measurement needs exactly one non-negative value in hours.", minCount=1, maxCount=1, minInclusive=Literal(0, datatype=XSD.decimal))
s = shape("PlaybookSimulation", ("class", C("PlaybookSimulation")), "Simulations name the playbook version run.")
req(s, "simulatedPlaybook", "the playbook version", "A playbook simulation")

os.makedirs(os.path.join(ROOT, "shapes"), exist_ok=True)
g.serialize(os.path.join(ROOT, "shapes", "crgo-shapes.ttl"), format="turtle")
print("shapes: %d node shapes (%d for functional properties)" % (len(set(g.subjects(RDF.type, SH.NodeShape))), n_func))
