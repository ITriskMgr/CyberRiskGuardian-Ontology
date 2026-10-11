# -*- coding: utf-8 -*-
"""Write the negative fixtures of the 0.9.0 GRCA sprint and packages R4-R8: SHACL graphs that must be rejected by
shapes/crgo-shapes.ttl (tests/shacl/neg-grca-*.ttl, two of them by a warning) and OWL graphs that must be inconsistent
(tests/fixtures/neg-grca-*.ttl). Each SHACL fixture names the message it must trigger (skos:note "expect: ...")."""
import os
from rdflib import Graph, URIRef, Literal, Namespace
from rdflib.namespace import RDF, RDFS, OWL, XSD, SKOS

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
ids = dict(l.rstrip("\n").split("\t") for l in open(os.path.join(ROOT, "src", "ids.tsv"), encoding="utf-8"))
T = lambda k: URIRef("https://w3id.org/crgo/CRGO_%07d" % int(ids[k]))
X = Namespace("https://example.org/crgo-test/")
dt = lambda d: Literal(d + "T00:00:00", datatype=XSD.dateTime)
nni = lambda n: Literal(n, datatype=XSD.nonNegativeInteger)
PROVISION = URIRef("https://w3id.org/crgo/vocab/loi25/P-39.1_s._10")
INSTRUMENT = URIRef("https://w3id.org/crgo/vocab/legal/P-39.1")

def write(name, triples, folder="shacl", imports=None, expect=None):
    g = Graph(); g.bind("crgo", "https://w3id.org/crgo/"); g.bind("x", X)
    o = X["fixture/" + name]; g.add((o, RDF.type, OWL.Ontology))
    for i in imports or []: g.add((o, OWL.imports, URIRef(i)))
    g.add((o, RDFS.comment, Literal("Negative fixture (0.9.0 GRCA): must be rejected.", lang="en")))
    if expect: g.add((o, SKOS.note, Literal("expect: " + expect)))
    for t in triples: g.add(t)
    g.serialize(os.path.join(ROOT, "tests", folder, name + ".ttl"), format="turtle")

def finding(f, without=()):
    t = {"type": (f, RDF.type, T("AuditFinding")), "eng": (f, T("withinEngagement"), X.eng), "crit": (f, T("usesCriterion"), X.crit),
         "cond": (f, T("findingCondition"), Literal("condition")), "ev": (f, T("hasEvidence"), X.ev), "sig": (f, T("hasFindingSignificance"), T("SigHigh")),
         "on": (f, T("raisedOn"), dt("2026-05-20")), "ks": (f, T("hasKnowledgeStatus"), T("KsAuditConclusion"))}
    return [v for k, v in t.items() if k not in without]

def closure_on(verif_result, verifier, owner):
    return [(X.a, RDF.type, T("CorrectiveAction")), (X.a, T("correctsFinding"), X.f), (X.a, T("hasOwner"), owner), (X.a, T("dueOn"), dt("2026-07-31")),
            (X.v, RDF.type, T("FollowUpVerification")), (X.v, T("verifiesAction"), X.a), (X.v, T("hasVerificationResult"), T(verif_result)),
            (X.v, T("assessedBy"), verifier), (X.v, T("assessedOn"), dt("2026-08-25")),
            (X.c, RDF.type, T("FindingClosure")), (X.c, T("closesFinding"), X.f), (X.c, T("closureBasedOn"), X.v), (X.c, T("closedOn"), dt("2026-08-26"))]

def exception(without=(), extra=()):
    t = {"type": (X.e, RDF.type, T("PolicyException")), "to": (X.e, T("exceptionTo"), X.stmt), "scope": (X.e, T("exceptionScope"), X.asset),
         "auth": (X.e, T("approvingAuthority"), X.ceo), "from": (X.e, T("validFrom"), dt("2026-07-01")), "until": (X.e, T("validUntil"), dt("2026-12-31")),
         "why": (X.e, T("exceptionJustification"), Literal("why"))}
    return [v for k, v in t.items() if k not in without] + list(extra)

def assessment(a, measure, who, line, result="TestEffective", extra=()):
    return [(a, RDF.type, T("ControlAssessment")), (a, T("evaluatesControlMeasure"), measure), (a, T("assessedOn"), dt("2026-09-01")),
            (a, T("hasTestResult"), T(result)), (a, T("assessedBy"), who), (a, T("performedInCapacity"), T(line)), (a, T("hasEvidence"), X.ev)] + list(extra)

def result(without=(), ks="KsRiskEstimate"):
    t = {"type": (X.r, RDF.type, T("AnalyticalResult")), "for": (X.r, T("resultFor"), X.scen), "name": (X.r, T("modelName"), Literal("CyberRiskGuardian")),
         "ver": (X.r, T("modelVersion"), Literal("1.1.0")), "at": (X.r, T("computedAt"), dt("2026-10-02")),
         "hash": (X.r, T("inputDocumentHash"), Literal("0" * 64)), "ks": (X.r, T("hasKnowledgeStatus"), T(ks))}
    return [v for k, v in t.items() if k not in without]

write("neg-grca-finding-no-criterion", finding(X.f, without=("crit",)), expect="at least one value for the criterion")
write("neg-grca-finding-no-evidence", finding(X.f, without=("ev",)), expect="the evidence relied on")
write("neg-grca-finding-as-verified-outcome", finding(X.f, without=("ks",)) + [(X.f, T("hasKnowledgeStatus"), T("KsVerifiedOutcome"))], expect="cannot have the knowledge status")
write("neg-grca-closure-not-effective", closure_on("VerifPartlyEffective", X.auditor, X.owner), expect="can be closed only")
write("neg-grca-closure-self-verified", closure_on("VerifEffective", X.owner, X.owner), expect="must not own")
write("neg-grca-exception-no-expiry", exception(without=("until",)), expect="its expiry date")
write("neg-grca-exception-waives-law", exception(without=("to",), extra=[(X.e, T("exceptionTo"), PROVISION), (PROVISION, T("provisionOf"), INSTRUMENT)]),
      expect="cannot waive a legal provision")
write("neg-grca-exception-backwards", exception(without=("until",), extra=[(X.e, T("validUntil"), dt("2026-06-30"))]), expect="expires after it starts")
write("neg-grca-role-conflict-warning", assessment(X.ca, X.m, X.bob, "LineInternalAudit") + [(X.bob, T("operatesControl"), X.m)], expect="Possible role conflict")
write("neg-grca-stale-evidence-warning", assessment(X.ca, X.m, X.bob, "LineSecond") + [(X.ev, T("validUntil"), dt("2025-12-31"))], expect="had expired")
write("neg-grca-dss-result-as-fact", result(ks="KsReferenceFact") + [(X.r, T("governanceStatus"), T("StatusProposed"))], expect="is a risk estimate")
write("neg-grca-dss-result-untraceable", result(without=("ver",)) + [(X.r, T("governanceStatus"), T("StatusProposed"))], expect="the model version")
write("neg-grca-oe-deviations-exceed", assessment(X.ca, X.m, X.bob, "LineInternalAudit", "TestPartlyEffective") +
      [(X.ca, RDF.type, T("OperatingEffectivenessAssessment")), (X.ca, T("periodStart"), dt("2026-01-01")), (X.ca, T("periodEnd"), dt("2026-04-30")),
       (X.ca, T("itemsTested"), nni(25)), (X.ca, T("deviationsFound"), nni(30))], expect="cannot exceed")
write("neg-grca-decision-rejected-no-rationale", [(X.d, RDF.type, T("DecisionRecord")), (X.d, T("decisionOn"), X.e), (X.d, T("decisionMadeBy"), X.ceo),
      (X.d, T("hasDecisionOutcome"), T("DecRejected")), (X.d, T("decidedOn"), dt("2026-09-10"))], expect="must state its rationale")
write("neg-grca-source-no-access-status", [(X.s, RDF.type, T("SourceRecord")), (X.s, T("localIdentifier"), Literal("x")), (X.s, RDFS.label, Literal("x")),
      (X.s, T("issuerName"), Literal("x")), (X.s, T("sourceVersion"), Literal("1")), (X.s, T("licenceTerms"), Literal("x"))], expect="the access status")
write("neg-grca-soc2-type2-no-period", [(X.rep, RDF.type, T("ExternalAssuranceReport")), (X.rep, T("hasAssuranceReportType"), T("ReportSOC2Type2")),
      (X.rep, T("issuedByAssurer"), X.cpa), (X.rep, T("reportOnServiceOf"), X.vendor), (X.rep, T("localIdentifier"), Literal("soc2"))], expect="covers a period")
write("neg-grca-role-assignment-backwards", [(X.ra, RDF.type, T("RoleAssignment")), (X.ra, T("assignmentOfRole"), X.role), (X.ra, T("assignedTo"), X.bob),
      (X.ra, T("validFrom"), dt("2026-06-01")), (X.ra, T("validUntil"), dt("2026-01-01"))], expect="ends after it starts")
write("neg-grca-procedure-no-objective", [(X.p, RDF.type, T("AuditProcedure")), (X.p, T("usesAssessmentMethod"), T("MethodTest"))], expect="an objective it serves")
write("neg-grca-exception-waives-instrument", exception(without=("to",), extra=[(X.e, T("exceptionTo"), INSTRUMENT), (INSTRUMENT, RDF.type, T("LegalInstrument"))]),
      expect="cannot waive a legal provision")
write("neg-grca-closure-by-control-owner", closure_on("VerifEffective", X.ctlowner, X.owner) + [(X.f, T("findingOnControl"), X.m), (X.role, RDF.type, T("ControlOwnerRole")),
      (X.role, T("roleFor"), X.m), (X.asg, T("assignmentOfRole"), X.role), (X.asg, T("assignedTo"), X.ctlowner)], expect="nor own the control")
write("neg-grca-dss-result-no-status", result(), expect="exactly one governance status")
# OWL: disjointness the GRCA sprint adds
I = OWL.NamedIndividual
write("neg-grca-exception-is-finding", [(X.x, RDF.type, I), (X.x, RDF.type, T("MonitoringException")), (X.x, RDF.type, T("AuditFinding"))],
      folder="fixtures", imports=["https://w3id.org/crgo/crgo"])
write("neg-grca-hypothesis-is-assumption", [(X.x, RDF.type, I), (X.x, RDF.type, T("AnalyticalHypothesis")), (X.x, RDF.type, T("Assumption"))],
      folder="fixtures", imports=["https://w3id.org/crgo/crgo"])
write("neg-grca-first-and-third-line", [(X.x, RDF.type, I), (X.x, RDF.type, T("ControlOwnerRole")), (X.x, RDF.type, T("ChiefAuditExecutiveRole"))],
      folder="fixtures", imports=["https://w3id.org/crgo/crgo"])
print("GRCA negative fixtures written")
