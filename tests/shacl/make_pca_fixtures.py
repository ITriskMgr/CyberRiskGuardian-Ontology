# -*- coding: utf-8 -*-
"""Negative fixtures of 0.10.0 (policy, compliance and audit management; SIEM and SOAR): SHACL graphs that must be
rejected by shapes/crgo-shapes.ttl (tests/shacl/neg-pca-*.ttl and neg-secops-*.ttl; six of them by warning-severity shapes) and OWL
graphs that must be inconsistent (tests/fixtures/neg-pca-*.ttl, neg-secops-*.ttl). Each SHACL fixture names the message
it must trigger (skos:note "expect: ...")."""
import os
from rdflib import Graph, URIRef, Literal, Namespace
from rdflib.namespace import RDF, RDFS, OWL, XSD, SKOS

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
ids = dict(l.rstrip("\n").split("\t") for l in open(os.path.join(ROOT, "src", "ids.tsv"), encoding="utf-8"))
T = lambda k: URIRef("https://w3id.org/crgo/CRGO_%07d" % int(ids[k]))
X = Namespace("https://example.org/crgo-test/")
dt = lambda d: Literal(d + ("" if "T" in d else "T00:00:00"), datatype=XSD.dateTime)
dec = lambda x: Literal(str(x), datatype=XSD.decimal)
nni = lambda n: Literal(n, datatype=XSD.nonNegativeInteger)
PROVISION = URIRef("https://w3id.org/crgo/vocab/loi25/P-39.1_s._10")
INSTRUMENT = URIRef("https://w3id.org/crgo/vocab/legal/P-39.1")

def write(name, triples, folder="shacl", imports=None, expect=None):
    g = Graph(); g.bind("crgo", "https://w3id.org/crgo/"); g.bind("x", X)
    o = X["fixture/" + name]; g.add((o, RDF.type, OWL.Ontology))
    for i in imports or []: g.add((o, OWL.imports, URIRef(i)))
    g.add((o, RDFS.comment, Literal("Negative fixture (0.10.0): must be rejected.", lang="en")))
    if expect: g.add((o, SKOS.note, Literal("expect: " + expect)))
    for t in triples: g.add(t)
    g.serialize(os.path.join(ROOT, "tests", folder, name + ".ttl"), format="turtle")

def version(v=X.v, state="LifePublished", approve=True, extra=()):
    t = [(v, RDF.type, T("PolicyVersion")), (v, T("versionOfDirective"), X.pol), (v, T("hasLifecycleState"), T(state)), (v, T("versionLabel"), Literal("1")),
         (v, T("effectiveOn"), dt("2026-01-01"))]
    if approve:
        t += [(X.d, RDF.type, T("DecisionRecord")), (X.d, T("decisionOn"), v), (X.d, T("decisionMadeBy"), X.board), (X.d, T("hasDecisionOutcome"), T("DecApproved")),
              (X.d, T("decidedOn"), dt("2025-12-15"))]
    return t + list(extra)

def mapping(mtype="MapPartialCoverage", state="RevApproved", conf=0.8, reviewed=True):
    t = [(X.m, RDF.type, T("MappingAssertion")), (X.m, T("mappingSource"), X.stmt), (X.m, T("mappingTarget"), PROVISION), (X.m, T("hasMappingType"), T(mtype)),
         (X.m, T("hasReviewState"), T(state)), (X.m, T("rationale"), Literal("why")), (X.m, T("mappingConfidence"), dec(conf))]
    if reviewed: t += [(X.m, T("reviewedBy"), X.rev), (X.m, T("reviewedOn"), dt("2026-03-01")), (X.m, T("mappedEdition"), X.edition)]
    return t

def action_exec(risk="RiskDestructive", auth=None, start="2026-10-10T14:00:00"):
    t = [(X.act, RDF.type, T("ResponseAction")), (X.act, T("hasActionRiskClass"), T(risk)),
         (X.x, RDF.type, T("ActionExecution")), (X.x, T("performsAction"), X.act), (X.x, T("actionTarget"), X.host), (X.x, T("hasExecutionStatus"), T("ExecSucceeded")),
         (X.x, T("executionStartedAt"), dt(start)), (X.x, T("attemptIdentifier"), Literal("a-1"))]
    if auth:
        status, outcome, frm, until = auth
        t += [(X.x, T("authorizedBy"), X.ap), (X.ap, RDF.type, T("ApprovalDecision")), (X.ap, T("hasApprovalStatus"), T(status)), (X.ap, T("decisionOn"), X.act),
              (X.ap, T("decisionMadeBy"), X.lead), (X.ap, T("hasDecisionOutcome"), T(outcome)), (X.ap, T("decidedOn"), dt(frm)), (X.ap, T("validFrom"), dt(frm))]
        if until: t.append((X.ap, T("validUntil"), dt(until)))
    return t

# ---------------------------------------------------------------- policy
write("neg-pca-published-no-approval", version(approve=False), expect="approval decision about this exact version")
write("neg-pca-statement-no-version", [(X.stmt, RDF.type, T("PolicyStatement")), (X.stmt, T("hasNormativeModality"), T("ModalityMust"))],
      expect="the directive version it belongs to")
write("neg-pca-ack-not-version", [(X.a, RDF.type, T("PolicyAcknowledgement")), (X.a, T("attestedBy"), X.bob), (X.a, T("attestedOn"), dt("2026-02-01")),
      (X.a, T("attestationAbout"), X.pol), (X.pol, RDF.type, T("Policy"))], expect="exact directive version")
write("neg-pca-attestation-as-conclusion", [(X.a, RDF.type, T("ComplianceAttestation")), (X.a, T("attestedBy"), X.cfo), (X.a, T("attestedOn"), dt("2026-02-01")),
      (X.a, T("attestationAbout"), PROVISION), (X.a, T("attestationScope"), Literal("all stores, 2026")), (X.a, T("hasKnowledgeStatus"), T("KsAuditConclusion"))],
      expect="management decision")
write("neg-pca-exact-mapping-unreviewed", mapping("MapExact", "RevDraft", reviewed=False), expect="exact or full-coverage mapping")
write("neg-pca-mapping-confidence-range", mapping(conf=1.5), expect="between 0 and 1")
write("neg-pca-retired-no-date", version(state="LifeRetired", approve=False), expect="retirement date")
# ---------------------------------------------------------------- compliance
write("neg-pca-exemption-internal", [(X.e, RDF.type, T("RegulatoryExemption")), (X.e, T("exemptionFrom"), PROVISION), (X.e, T("grantedBy"), X.ceo),
      (X.ceo, RDF.type, URIRef("https://www.commoncoreontologies.org/ont00001262")), (X.e, T("legalBasis"), Literal("none")), (X.e, T("concernsOrganisation"), X.org),
      (X.e, T("validFrom"), dt("2026-01-01"))], expect="granted by a regulatory authority")
write("neg-pca-event-deadline-no-offset", [(X.dl, RDF.type, T("ComplianceDeadline")), (X.dl, T("deadlineFor"), PROVISION), (X.dl, T("hasDeadlineTriggerKind"), T("DeadlineEvent"))],
      expect="offset in hours")
write("neg-pca-ack-submission-no-receipt", [(X.s, RDF.type, T("RegulatorySubmission")), (X.s, T("submissionTo"), X.auth), (X.auth, RDF.type, T("RegulatoryAuthority")),
      (X.s, T("submissionUnder"), PROVISION), (X.s, T("hasSubmissionState"), T("SubAcknowledged")), (X.s, T("submittedOn"), dt("2026-08-06"))], expect="receipt evidence")
write("neg-pca-determination-not-applicable", [
      (X.a, RDF.type, T("ApplicabilityAssessment")), (X.a, T("applicabilityOf"), PROVISION), (X.a, T("concernsOrganisation"), X.org), (X.a, T("hasApplicabilityState"), T("AppNotApplicable")),
      (X.a, T("assessedOn"), dt("2026-09-01")), (X.a, T("assessedBy"), X.bob),
      (X.c, RDF.type, T("ComplianceDetermination")), (X.c, T("complianceWith"), PROVISION), (X.c, T("concernsOrganisation"), X.org), (X.c, T("hasComplianceState"), T("CompSatisfied")),
      (X.c, T("assessedOn"), dt("2026-10-01")), (X.c, T("assessedBy"), X.bob), (X.c, T("hasEvidence"), X.ev), (X.c, T("hasJurisdiction"), T("JurQuebec"))],
      expect="found not applicable")
write("neg-pca-jurisdiction-missing-legal", [
      (X.c, RDF.type, T("ComplianceDetermination")), (X.c, T("complianceWith"), PROVISION), (PROVISION, T("provisionOf"), INSTRUMENT), (X.c, T("concernsOrganisation"), X.org),
      (X.c, T("hasComplianceState"), T("CompSatisfied")), (X.c, T("assessedOn"), dt("2026-10-01")), (X.c, T("assessedBy"), X.bob), (X.c, T("hasEvidence"), X.ev)],
      expect="needs its jurisdictional scope")
# ---------------------------------------------------------------- audit
write("neg-pca-plan-deferral-no-reason", [(X.e, RDF.type, T("AuditPlanEntry")), (X.e, T("entryInPlan"), X.plan), (X.e, T("hasPlanEntryState"), T("EntryDeferred"))],
      expect="reason and who authorised")
write("neg-pca-workpaper-self-review", [(X.w, RDF.type, T("AuditWorkpaper")), (X.w, T("workpaperFor"), X.eng), (X.w, T("preparedBy"), X.bob), (X.w, T("preparedOn"), dt("2026-07-01")),
      (X.w, T("reviewedBy"), X.bob)], expect="Self-review")
write("neg-pca-observation-as-conclusion", [(X.o, RDF.type, T("AuditObservation")), (X.o, T("withinEngagement"), X.eng), (X.o, T("hasKnowledgeStatus"), T("KsAuditConclusion"))],
      expect="preliminary")
write("neg-pca-closure-of-plan", [(X.c, RDF.type, T("FindingClosure")), (X.c, T("closesFinding"), X.plan), (X.plan, RDF.type, T("AuditPlan")), (X.c, T("closedOn"), dt("2026-08-01")),
      (X.c, T("closureBasedOn"), X.ra), (X.ra, RDF.type, T("RiskAcceptance"))], expect="must concern an audit finding or a nonconformity")
write("neg-pca-engagement-two-natures", [(X.eng, RDF.type, T("AuditEngagement")), (X.eng, T("hasEngagementType"), T("EngAssurance")), (X.eng, T("hasEngagementType"), T("EngAdvisory"))],
      expect="either an assurance or an advisory")
write("neg-pca-nc-closure-by-control-owner", [
      (X.nc, RDF.type, T("Nonconformity")), (X.nc, T("raisedFrom"), X.ca), (X.ca, T("evaluatesControlMeasure"), X.m), (X.m, T("hasOwner"), X.bob),
      (X.act, RDF.type, T("CorrectiveAction")), (X.act, T("correctsFinding"), X.nc), (X.act, T("hasOwner"), X.alice), (X.act, T("dueOn"), dt("2026-08-01")),
      (X.v, RDF.type, T("FollowUpVerification")), (X.v, T("verifiesAction"), X.act), (X.v, T("hasVerificationResult"), T("VerifEffective")), (X.v, T("assessedBy"), X.bob),
      (X.v, T("assessedOn"), dt("2026-08-20")),
      (X.c, RDF.type, T("FindingClosure")), (X.c, T("closesFinding"), X.nc), (X.c, T("closureBasedOn"), X.v), (X.c, T("closedOn"), dt("2026-08-21"))],
      expect="must not own the control whose assessment raised it")
# ---------------------------------------------------------------- SIEM
write("neg-secops-enabled-rule-no-source", [(X.r, RDF.type, T("DetectionRule")), (X.r, T("hasDetectionStatus"), T("DetEnabled")), (X.r, T("versionLabel"), Literal("1"))],
      expect="declare the telemetry")
write("neg-secops-validated-coverage-untested", [(X.cov, RDF.type, T("DetectionCoverage")), (X.cov, T("coverageBy"), X.r), (X.cov, T("coversScenario"), X.scen),
      (X.cov, T("hasCoverageStatus"), T("CovValidated"))], expect="found effective")
write("neg-secops-coverage-nothing", [(X.cov, RDF.type, T("DetectionCoverage")), (X.cov, T("coverageBy"), X.r), (X.cov, T("hasCoverageStatus"), T("CovUntested"))],
      expect="what it covers")
write("neg-secops-indicator-confidence-no-method", [(X.i, RDF.type, T("ThreatIndicator")), (X.i, T("indicatorPattern"), Literal("[ipv4-addr:value = '198.51.100.7']")),
      (X.i, T("patternLanguage"), Literal("stix")), (X.i, T("indicatorFromSource"), X.feed), (X.i, T("validFrom"), dt("2026-10-01")), (X.i, T("statedConfidence"), dec(80))],
      expect="needs its method")
write("neg-secops-destructive-no-approval", action_exec(), expect="executed without a corresponding approval")
write("neg-secops-expired-approval", action_exec("RiskContainment", ("ApprGranted", "DecApproved", "2026-07-01T00:00:00", "2026-09-30T00:00:00")),
      expect="executed without a corresponding approval")
write("neg-secops-retroactive-approval", action_exec("RiskContainment", ("ApprGranted", "DecApproved", "2026-10-11T00:00:00", None)), expect="executed without a corresponding approval")
write("neg-secops-unrelated-approval", [t for t in action_exec("RiskContainment", ("ApprGranted", "DecApproved", "2026-10-01T00:00:00", None)) if t[1] != T("decisionOn")]
      + [(X.ap, T("decisionOn"), X.otheraction)], expect="executed without a corresponding approval")
write("neg-secops-category-on-investigation", [(X.inv, RDF.type, T("SecurityInvestigation")), (X.inv, T("hasCaseStatus"), T("CaseNew")),
      (X.inv, T("investigationOpenedAt"), dt("2026-10-10T10:00:00")), (X.inv, T("hasIncidentCategory"), T("CatMalware"))], expect="Only an incident can carry")
write("neg-secops-validated-by-other-rule", [(X.cov, RDF.type, T("DetectionCoverage")), (X.cov, T("coverageBy"), X.r), (X.cov, T("coversScenario"), X.scen),
      (X.cov, T("hasCoverageStatus"), T("CovValidated")), (X.cov, T("supportedByTest"), X.t), (X.t, T("hasTestResult"), T("TestEffective")), (X.t, T("testedRule"), X.otherrule)],
      expect="of a strategy or rule that provides the coverage")
write("neg-secops-execution-no-version", [(X.r, RDF.type, T("AutomationExecution")), (X.r, T("hasExecutionStatus"), T("ExecRunning")),
      (X.r, T("executionStartedAt"), dt("2026-10-10T14:00:00")), (X.r, T("attemptIdentifier"), Literal("r-1"))], expect="the playbook version")
write("neg-secops-concluded-unconfirmed-warning", [(X.inv, RDF.type, T("SecurityInvestigation")), (X.inv, T("hasCaseStatus"), T("CaseInvestigating")),
      (X.inv, T("investigationOpenedAt"), dt("2026-10-10T10:00:00")), (X.inv, T("concludedIncident"), X.inc)], expect="no incident confirmation")
write("neg-secops-regulator-comm-warning", [(X.cm, RDF.type, T("IncidentCommunication")), (X.cm, T("communicationAbout"), X.inc), (X.cm, T("hasAudience"), T("AudRegulator")),
      (X.cm, T("sentAt"), dt("2026-08-06"))], expect="not linked to a regulatory submission")
# OWL: disjointness of 0.10.0
I = OWL.NamedIndividual
for name, a, b in (("neg-pca-guideline-is-statement", "Guideline", "PolicyStatement"), ("neg-pca-observation-is-finding", "AuditObservation", "AuditFinding"),
                   ("neg-secops-indicator-is-confirmation", "ThreatIndicator", "IncidentConfirmation"), ("neg-secops-rule-is-strategy", "DetectionRule", "DetectionStrategy")):
    write(name, [(X.x, RDF.type, I), (X.x, RDF.type, T(a)), (X.x, RDF.type, T(b))], folder="fixtures", imports=["https://w3id.org/crgo/crgo"])
print("0.10.0 negative fixtures written")
