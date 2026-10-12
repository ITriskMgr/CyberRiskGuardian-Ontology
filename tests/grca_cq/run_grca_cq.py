# -*- coding: utf-8 -*-
"""Competency questions of the GRCA specification (CQ-GRCA-01, 02, 03, 04, 06, 08, 09, 11; section 13) and of the
remaining-gaps specification (CQ-01, 04, 05, 06, 07, 08, 16, 17, 18; section 10), on the SYNTHETIC Nordelle data,
the second synthetic tenant (Boréal) and the illustrative work programmes.

Every CQ has a positive, a negative and an unknown/ambiguous fixture; the suite also covers the fixture kinds of the
remaining-gaps specification section 10.1: temporal, tenant, conflict, DSS-proposed and quality. Fixtures are
variants of the base graph made in code, so each states what it changes. Expected results are written in this file
next to each check (machine-readable as Python sets). Prints PASS/FAIL; exits non-zero on any failure."""
import copy, os, re, sys
from rdflib import Graph, URIRef, Literal, Namespace
from rdflib.namespace import RDF, RDFS, OWL, XSD, SKOS, DCTERMS

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
HERE = os.path.dirname(os.path.abspath(__file__))
ids = dict(l.rstrip("\n").split("\t") for l in open(os.path.join(ROOT, "src", "ids.tsv"), encoding="utf-8"))
T = lambda k: URIRef("https://w3id.org/crgo/CRGO_%07d" % int(ids[k]))
N = Namespace("https://example.org/crgo-sample/nordelle/")
B = Namespace("https://example.org/crgo-sample/boreal/")
W = Namespace("https://w3id.org/crgo/data/workprogrammes/")
dt = lambda d: Literal(d + "T00:00:00", datatype=XSD.dateTime)
_voc = {}
def concept(scheme, notation):
    if scheme not in _voc:
        _voc[scheme] = {str(n): s for s, n in Graph().parse(os.path.join(ROOT, "ontology", "vocab", scheme + ".ttl")).subject_objects(SKOS.notation)}
    return _voc[scheme][notation]

base = Graph()
for m in ("gov", "core", "measure", "crg", "evidence", "org", "vuln", "grc", "mapping", "governance", "assurance", "audit", "incident", "policy", "compliance"):
    base.parse(os.path.join(ROOT, "ontology", "crgo-%s.ttl" % m))
base.parse(os.path.join(ROOT, "ontology", "crgo.ttl"))
for v in ("legal", "sources", "loi25", "gdpr", "sp800-53r5", "sp800-53a"):
    base.parse(os.path.join(ROOT, "ontology", "vocab", v + ".ttl"))
for f in ("tests/samples/nordelle.ttl", "tests/samples/nordelle-applicability.ttl", "tests/samples/nordelle-grca.ttl",
          "tests/samples/tenant-b.ttl", "data/abox/crgo-workprogrammes.ttl"):
    base.parse(os.path.join(ROOT, f))

def q(name, g, **params):
    txt = open(os.path.join(HERE, name + ".rq"), encoding="utf-8").read()
    txt = re.sub(r"\{\{(\w+)\}\}", lambda m: "<%s>" % T(m.group(1)), txt)
    return list(g.query(txt, initNs={"rdfs": RDFS, "owl": OWL, "xsd": XSD}, initBindings=params))

results = []
def check(label, cond, detail=""):
    results.append(bool(cond)); print("%s  %-86s %s" % ("PASS" if cond else "FAIL", label, detail))
def variant(*remove, add=()):
    g = copy.deepcopy(base)
    for t in remove: g.remove(t)
    for t in add: g.add(t)
    return g

TODAY = dt("2026-10-11")
# ---------------------------------------------------------------- CQ-GRCA-01 ownership and oversight (temporal)
rows = q("CQ-GRCA-01", base, asOf=TODAY)
got = {(r.measure, r.owner, r.body) for r in rows if r.measure == N["control/backups"]}
check("CQ-GRCA-01 positive: backups owned by IT operations today, risk overseen by the board", got == {(N["control/backups"], N["person/itops"], N["gov/board"])}, str(len(rows)))
rows = q("CQ-GRCA-01", base, asOf=dt("2024-06-01"))
check("CQ-GRCA-01 temporal: in June 2024 the backup owner was the CISO (former assignment)", {r.owner for r in rows if r.measure == N["control/backups"]} == {N["person/ciso"]})
check("CQ-GRCA-01 unknown: EDR has no owner role assigned, so its owner is unbound, not guessed",
      any(r.measure == N["control/edr"] and r.owner is None for r in q("CQ-GRCA-01", base, asOf=TODAY)))
g = variant((N["gov/board"], T("oversees"), N["scenario/ransomware"]))
rows = [r for r in q("CQ-GRCA-01", g, asOf=TODAY) if r.scenario == N["scenario/ransomware"]]
check("CQ-GRCA-01 negative: without the oversight statement no body is returned for the ransomware risk", rows and all(r.body is None for r in rows))
# ---------------------------------------------------------------- CQ-GRCA-02 supported obligations, applicability
s10, art32 = concept("loi25", "P-39.1 s. 10"), concept("gdpr", "GDPR Art. 32(1)")
rows = q("CQ-GRCA-02", base, measure=N["control/mfa"], org=N.org)
got = {(r.provision, r.state) for r in rows}
check("CQ-GRCA-02 positive: MFA supports Loi 25 s. 10 (applicable) and GDPR Art. 32(1) (potentially applicable)",
      got == {(s10, T("AppApplicable")), (art32, T("AppPotentiallyApplicable"))}, str(got))
check("CQ-GRCA-02 negative: the EDR measure supports no obligation (no statement either way)", q("CQ-GRCA-02", base, measure=N["control/edr"], org=N.org) == [])
g = copy.deepcopy(base)
for a in list(g.subjects(T("applicabilityOf"), URIRef("https://w3id.org/crgo/vocab/legal/GDPR"))):
    g.remove((a, None, None))
rows = q("CQ-GRCA-02", g, measure=N["control/mfa"], org=N.org)
check("CQ-GRCA-02 unknown: without a GDPR applicability assessment the state is unbound (unevaluated), not 'not applicable'",
      any(r.provision == art32 and r.state is None for r in rows))
# ---------------------------------------------------------------- CQ-GRCA-03 no operating-effectiveness test in period
rows = {r.measure for r in q("CQ-GRCA-03", base, start=dt("2026-01-01"), end=dt("2026-12-31"))}
check("CQ-GRCA-03 positive: MFA and EDR have no 2026 operating-effectiveness test", rows == {N["control/mfa"], N["control/edr"]}, str(len(rows)))
check("CQ-GRCA-03 negative: backups were tested for operation in May 2026, so they are not listed", N["control/backups"] not in rows)
rows = {r.measure for r in q("CQ-GRCA-03", base, start=dt("2026-06-01"), end=dt("2026-12-31"))}
check("CQ-GRCA-03 ambiguity: a design-only test (CISO, September) does not count; backups listed for June-December", N["control/backups"] in rows)
# ---------------------------------------------------------------- CQ-GRCA-04 what an IAM / vulnerability engagement needs
rows = q("CQ-GRCA-04", base, programme=W["AUD-PAM-001"])
objs = {r.objective for r in rows}
check("CQ-GRCA-04 positive: AUD-PAM-001 needs 6 procedures, both criteria and 800-53A objectives incl. AC-02j.",
      len({r.procedure for r in rows}) == 6 and len({r.criterion for r in rows}) == 2 and concept("sp800-53a", "AC-02j.") in objs)
check("CQ-GRCA-04 positive: every procedure of AUD-VULN-001 states a sampling rationale and expected result",
      all(r.sampling is not None and r.expected is not None for r in q("CQ-GRCA-04", base, programme=W["AUD-VULN-001"])))
check("CQ-GRCA-04 negative: an unknown programme returns nothing", q("CQ-GRCA-04", base, programme=W["AUD-NONE-999"]) == [])
A53 = Graph().parse(os.path.join(ROOT, "ontology", "vocab", "sp800-53a.ttl"))
for _f in ("mappings.ttl", "mappings-proposed.ttl"):
    A53.parse(os.path.join(ROOT, "ontology", "vocab", _f))
def top_of(o):
    while A53.value(o, SKOS.broader) is not None: o = A53.value(o, SKOS.broader)
    return o
check("CQ-GRCA-04 binding: every objective cited is an SP 800-53A objective whose top objective 'evaluates' an SP 800-53 control",
      objs and all((o, SKOS.inScheme, URIRef("https://w3id.org/crgo/vocab/sp800-53a")) in A53 and
                   any(str(c).startswith("https://w3id.org/crgo/vocab/sp800-53r5/") for c in A53.objects(top_of(o), T("evaluatesControl"))) for o in objs))
# ---------------------------------------------------------------- CQ-GRCA-06 late, reopened, disputed, unverified findings
F = N["finding/F-2026-03-01"]
rows = {(r.finding, str(r.reason)) for r in q("CQ-GRCA-06", base, asOf=TODAY)}
check("CQ-GRCA-06 positive: F-2026-03-01 is reopened today (not late: the new action is due 30 November)", rows == {(F, "reopened")}, str(rows))
rows = {str(r.reason) for r in q("CQ-GRCA-06", base, asOf=dt("2026-12-15"))}
check("CQ-GRCA-06 temporal: on 15 December the second action is late as well", rows == {"reopened", "late"}, str(rows))
check("CQ-GRCA-06 negative: on 1 September (after closure, before reopening) nothing is listed", q("CQ-GRCA-06", base, asOf=dt("2026-09-01")) == [])
g = variant((N["action/CA-2026-03-01a/verification"], T("assessedBy"), N["person/cae"]),
            add=[(N["action/CA-2026-03-01a/verification"], T("assessedBy"), N["person/itops"])])
check("CQ-GRCA-06 quality: a verification by the action owner is not independent, so the finding lacks a verified action",
      "no independently verified action" in {str(r.reason) for r in q("CQ-GRCA-06", g, asOf=dt("2026-09-01"))})
g = variant(add=[(N["finding/F-2026-03-01/response"], T("hasResponseStance"), T("StanceDisagree"))])
g.remove((N["finding/F-2026-03-01/response"], T("hasResponseStance"), T("StanceAgree")))
check("CQ-GRCA-06 ambiguity: a disagreeing management response marks the finding as disputed", "disputed" in {str(r.reason) for r in q("CQ-GRCA-06", g, asOf=TODAY)})
# ---------------------------------------------------------------- CQ-GRCA-08 RCSA vs independent results (conflict, tenant)
rows = q("CQ-GRCA-08", base, org=N.org)
got = {(r.self, r.indep) for r in rows}
check("CQ-GRCA-08 conflict: the September self-assessment (effective) conflicts with the audit and CISO results; both kept",
      got == {(N["control-assessment/backups-rcsa-2026-09"], N["control-assessment/backups-audit-2026-05"]),
              (N["control-assessment/backups-rcsa-2026-09"], N["control-assessment/backups-audit-oe-2026"]),
              (N["control-assessment/backups-rcsa-2026-09"], N["control-assessment/backups-2026-09"])}, "%d rows" % len(rows))
check("CQ-GRCA-08 tenant: Boréal's own conflicting assessments never appear in Nordelle's answer", all(not str(r.measure).startswith(str(B)) for r in rows))
check("CQ-GRCA-08 tenant: scoped to Boréal, only Boréal's records come back", {r.measure for r in q("CQ-GRCA-08", base, org=B.org)} == {B["control/backups"]})
g = variant((N["control-assessment/backups-rcsa-2026-09"], T("hasTestResult"), T("TestEffective")),
            add=[(N["control-assessment/backups-rcsa-2026-09"], T("hasTestResult"), T("TestPartlyEffective"))])
check("CQ-GRCA-08 negative: when the self-assessment agrees there is no conflict", q("CQ-GRCA-08", g, org=N.org) == [])
# ---------------------------------------------------------------- CQ-GRCA-09 reconstruct the audit trail
rows = q("CQ-GRCA-09", base, finding=F)
check("CQ-GRCA-09 positive: criterion, evidence, recommendation, response, action, effective verification and closure all present",
      any(all(getattr(r, k) is not None for k in ("criterion", "evidence", "recommendation", "response", "action", "verification", "closure")) and r.result == T("VerifEffective") for r in rows))
g = variant(*[(N["finding/F-2026-03-01/closure"], p, o) for p, o in base.predicate_objects(N["finding/F-2026-03-01/closure"])])
rows = q("CQ-GRCA-09", g, finding=F)
check("CQ-GRCA-09 negative: without the closure record the chain shows the closure step missing", rows and all(r.closure is None for r in rows))
check("CQ-GRCA-09 unknown: for a record that is not a finding nothing is reconstructed", q("CQ-GRCA-09", base, finding=N["monitoring/backup-job-failure-2026-09-18"]) == [])
# ---------------------------------------------------------------- CQ-GRCA-11 stale, unverified, out-of-scope evidence
rows = {(r.evidence, str(r.reason)) for r in q("CQ-GRCA-11", base)}
check("CQ-GRCA-11 positive: the 2023 restore procedure is flagged as expired when relied on and judged out of date",
      {(N["evidence/restore-procedure-2023"], "expired when relied on"), (N["evidence/restore-procedure-2023"], "judged out of date")} <= rows)
check("CQ-GRCA-11 negative: the hashed January-April job logs are not flagged", not any(e == N["evidence/backup-job-logs-2026q1"] for e, _ in rows))
check("CQ-GRCA-11 unverified: evidence without an integrity hash is reported as unverified, not as valid",
      (N["evidence/rcsa-questionnaire-2026-09"], "unverified (no integrity hash)") in rows)
# ---------------------------------------------------------------- CQ-01 policy statements for an obligation, valid exceptions
rows = q("CQ-01", base, provision=s10, asOf=TODAY)
check("CQ-01 positive: Loi 25 s. 10 is implemented by the restore-test and EDR statements; the EDR exception is valid today",
      {r.statement for r in rows} == {N["policy/infosec/restore-tests"], N["policy/infosec/edr"]} and {r.exception for r in rows} - {None} == {N["exception/edr-legacy-pos"]})
check("CQ-01 temporal/quality: on 15 January 2027 the exception has expired and is not returned",
      {r.exception for r in q("CQ-01", base, provision=s10, asOf=dt("2027-01-15"))} == {None})
check("CQ-01 negative: an obligation no policy statement cites returns nothing", q("CQ-01", base, provision=concept("loi25", "P-39.1 s. 3.3"), asOf=TODAY) == [])
# ---------------------------------------------------------------- CQ-04 latest independent operating effectiveness result
rows = q("CQ-04", base, asset=N["asset/backups"], asOf=TODAY)
check("CQ-04 positive: for the backups asset the latest independent operating test is internal audit's (partly effective)",
      [(r.assessment, r.result) for r in rows] == [(N["control-assessment/backups-audit-oe-2026"], T("TestPartlyEffective"))])
check("CQ-04 temporal: before 20 May 2026 there was no independent operating test", q("CQ-04", base, asset=N["asset/backups"], asOf=dt("2026-05-01")) == [])
check("CQ-04 unknown: an asset no control protects has no result (unknown, not effective)", q("CQ-04", base, asset=N["asset/kiosk"], asOf=TODAY) == [])
# ---------------------------------------------------------------- CQ-05 confirmed incidents, scenarios remain hypotheses
rows = q("CQ-05", base)
check("CQ-05 positive: the phishing incident is confirmed and informs the credential-compromise scenario, which stays a hypothesis",
      {(r.incident, r.confirmed.toPython(), r.scenario) for r in rows} == {(N["incident/2026-08-phishing"], True, N["scenario/credential-compromise"])})
check("CQ-05 negative: the security event is never returned as an incident", all(r.incident != N["event/2026-08-03-phish"] for r in rows))
g = variant(add=[(N["incident/suspected"], RDF.type, T("Incident"))])
check("CQ-05 unknown: an incident with no confirmation is reported as not confirmed", any(r.incident == N["incident/suspected"] and not r.confirmed.toPython() for r in q("CQ-05", g)))
# ---------------------------------------------------------------- CQ-06 authority to accept a risk on the decision date
rows = q("CQ-06", base)
check("CQ-06 positive: the CEO accepted the legacy-server risk on 25 June 2026 under a valid delegation",
      {(r.acceptance, r.maker, r.authorised.toPython()) for r in rows} == {(N["risk-acceptance/legacy-pos-2026"], N["person/ceo"], True)})
g = variant((N["decision/accept-legacy-risk"], T("decidedOn"), dt("2026-06-25")), add=[(N["decision/accept-legacy-risk"], T("decidedOn"), dt("2025-12-15"))])
check("CQ-06 temporal/negative: a decision dated December 2025, before the delegation began, had no delegated authority",
      {r.authorised.toPython() for r in q("CQ-06", g)} == {False})
g = variant(*[(N["gov/delegation-risk-acceptance"], p, o) for p, o in base.predicate_objects(N["gov/delegation-risk-acceptance"])])
check("CQ-06 unknown: with no delegation recorded, authority is not shown as held", {r.authorised.toPython() for r in q("CQ-06", g)} == {False})
# ---------------------------------------------------------------- CQ-07 assumptions behind a risk result
rows = q("CQ-07", base, result=N["dss-result/ransomware-2026-10-02"])
check("CQ-07 positive: the ransomware result rests on the restore-time assumption (contradicted by finding F-2026-03-01)",
      N["assumption/restore-time"] in {r.assumption for r in rows})
rows = q("CQ-07", variant(add=[(N["dss-result/ransomware-2026-10-02"], T("computedFromInput"), N["estimate/likelihood-cc"])]), result=N["dss-result/ransomware-2026-10-02"])
check("CQ-07 material: an input with low evidence quality and a triangular distribution is marked material",
      any(r.input == N["estimate/likelihood-cc"] and r.family == T("DistTriangular") and r.material.toPython() for r in rows))
rows = q("CQ-07", base, result=N["dss-result/ransomware-2026-10-02"])
check("CQ-07 unknown: inputs with no stated evidence quality are not marked material (unknown, not low)", rows and all(not r.material.toPython() for r in rows))
# ---------------------------------------------------------------- CQ-08 legal changes calling for review
rows = {(r.record, str(r.how)) for r in q("CQ-08", base)}
check("CQ-08 positive: the hypothetical guidance flags the Loi 25 security determination (trigger) and the incident reportability assessment",
      (N["compliance/loi25-security"], "named by a trigger") in rows and (N["incident/2026-08-phishing/reportability-loi25"], "concerns the changed provision") in rows, str(len(rows)))
g = variant(add=[(N["incident/2026-08-phishing/reportability-loi25-oct"], T("reportableUnder"), concept("loi25", "P-39.1 s. 3.5 (2nd para.)")),
                 (N["incident/2026-08-phishing/reportability-loi25-oct"], T("assessedOn"), dt("2026-10-08"))])
rows = {(r.record, str(r.how)) for r in q("CQ-08", g)}
check("CQ-08 temporal: a reassessment made after the change was identified is not flagged, the earlier one still is",
      (N["incident/2026-08-phishing/reportability-loi25"], "concerns the changed provision") in rows and
      not any(rec == N["incident/2026-08-phishing/reportability-loi25-oct"] for rec, _ in rows))
g = variant(add=[(N["reg/later"], RDF.type, T("RegulatoryChange")), (N["reg/later"], T("identifiedOn"), dt("2026-01-01")),
                 (N["reg/later"], T("changeOf"), concept("loi25", "P-39.1 s. 3.5 (2nd para.)"))])
check("CQ-08 negative: a change identified before an assessment was made does not flag that assessment",
      (N["incident/2026-08-phishing/reportability-loi25"], "concerns the changed provision") not in {(r.record, str(r.how)) for r in q("CQ-08", g) if r.change == N["reg/later"]})
# ---------------------------------------------------------------- CQ-16 DSS results proposed, never treated as decisions
rows = q("CQ-16", base)
check("CQ-16 DSS: the CyberRiskGuardian result is proposed and not used as the subject of an acceptance or decision",
      [(r.result, r.status, r.misused.toPython()) for r in rows] == [(N["dss-result/ransomware-2026-10-02"], T("StatusProposed"), False)])
g = variant(add=[(N["decision/x"], T("decisionOn"), N["dss-result/ransomware-2026-10-02"])])
check("CQ-16 DSS negative: deciding on the proposed result itself is detected as misuse", any(r.misused.toPython() for r in q("CQ-16", g)))
g = variant((N["dss-result/ransomware-2026-10-02"], T("governanceStatus"), T("StatusProposed")))
rows = q("CQ-16", g)
check("CQ-16 unknown: a result with no status is reported without one (not as approved)", rows and all(r.status is None for r in rows))
# ---------------------------------------------------------------- CQ-17 reconstruct a decision
rows = q("CQ-17", base, decision=N["decision/reject-edr-delay"])
_release = str(next(Graph().parse(os.path.join(ROOT, "ontology", "crgo.ttl")).objects(URIRef("https://w3id.org/crgo/crgo"), OWL.versionInfo)))
check("CQ-17 positive: the board's rejection is reconstructed with CyberRiskGuardian 1.1.0, contract dss/v1, the finding and the current release (%s)" % _release,
      any(r.model is not None and str(r.version) == "1.1.0" and str(r.contract) == "dss/v1" and str(r.release) == _release for r in rows)
      and N["finding/F-2026-03-01"] in {r.input for r in rows} and all(r.maker == N["gov/board"] for r in rows))
rows = q("CQ-17", base, decision=N["decision/defer-dlp"])
check("CQ-17 negative: a decision informed by no analytical result shows no model", rows and all(r.model is None for r in rows))
check("CQ-17 unknown: an unrecorded decision cannot be reconstructed", q("CQ-17", base, decision=N["decision/none"]) == [])
# ---------------------------------------------------------------- CQ-18 which constraints fail on contradictory data
try:
    from pyshacl import validate
    shapes = Graph().parse(os.path.join(ROOT, "shapes", "crgo-shapes.ttl"))
    SH = Namespace("http://www.w3.org/ns/shacl#")
    def failing(extra, remove=()):
        g = variant(*remove, add=extra)
        c, rg, _ = validate(g, shacl_graph=shapes, inference="none", advanced=True, allow_warnings=True)
        return {str(m) for r in rg.subjects(RDF.type, SH.ValidationResult) if (r, SH.resultSeverity, SH.Violation) in rg for m in rg.objects(r, SH.resultMessage)}
    base_fail = failing([])
    check("CQ-18 baseline: the synthetic data raise no violation (warnings allowed)", not base_fail, str(sorted(base_fail))[:200])
    oe = N["control-assessment/backups-audit-oe-2026"]
    f1 = failing([(oe, T("deviationsFound"), Literal(40, datatype=XSD.nonNegativeInteger))], [(oe, T("deviationsFound"), Literal(1, datatype=XSD.nonNegativeInteger))])
    check("CQ-18 quality: 40 deviations in 25 items is caught", any("cannot exceed" in m for m in f1))
    f2 = failing([(N["exception/edr-legacy-pos"], T("validUntil"), dt("2026-06-01"))], [(N["exception/edr-legacy-pos"], T("validUntil"), dt("2026-12-31"))])
    check("CQ-18 quality: an exception that ends before it starts is caught", any("expires after it starts" in m for m in f2))
    f3 = failing([(N["dss-result/ransomware-2026-10-02"], T("hasKnowledgeStatus"), T("KsVerifiedOutcome"))], [(N["dss-result/ransomware-2026-10-02"], T("hasKnowledgeStatus"), T("KsRiskEstimate"))])
    check("CQ-18 DSS: a write-back result relabelled as a verified outcome is caught", any("is a risk estimate" in m for m in f3))
except ImportError:
    check("CQ-18 needs pySHACL", False)

print("%d of %d checks passed" % (sum(results), len(results)))
sys.exit(0 if all(results) else 1)
