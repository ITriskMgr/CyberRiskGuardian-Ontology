# -*- coding: utf-8 -*-
"""Negative fixtures of 0.11.0 (identity, privilege and configuration registers; technology context): SHACL graphs that
must be rejected by shapes/crgo-shapes.ttl (tests/shacl/neg-iam-*.ttl, neg-context-*.ttl) and OWL graphs that must be
inconsistent (tests/fixtures/neg-iam-*.ttl). Each SHACL fixture names the message it must trigger (skos:note "expect: ...")."""
import os
from rdflib import Graph, URIRef, Literal, Namespace
from rdflib.namespace import RDF, RDFS, OWL, XSD, SKOS

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
ids = dict(l.rstrip("\n").split("\t") for l in open(os.path.join(ROOT, "src", "ids.tsv"), encoding="utf-8"))
T = lambda k: URIRef("https://w3id.org/crgo/CRGO_%07d" % int(ids[k]))
X = Namespace("https://example.org/crgo-test/")
dt = lambda d: Literal(d + ("" if "T" in d else "T00:00:00"), datatype=XSD.dateTime)
nni = lambda n: Literal(n, datatype=XSD.nonNegativeInteger)

def write(name, triples, folder="shacl", imports=None, expect=None):
    g = Graph(); g.bind("crgo", "https://w3id.org/crgo/"); g.bind("x", X)
    o = X["fixture/" + name]; g.add((o, RDF.type, OWL.Ontology))
    for i in imports or []: g.add((o, OWL.imports, URIRef(i)))
    g.add((o, RDFS.comment, Literal("Negative fixture (0.11.0): must be rejected.", lang="en")))
    if expect: g.add((o, SKOS.note, Literal("expect: " + expect)))
    for t in triples: g.add(t)
    g.serialize(os.path.join(ROOT, "tests", folder, name + ".ttl"), format="turtle")

def pop(p=X.pop, cls="AccountPopulation", size=10, **counts):
    t = [(p, RDF.type, T(cls)), (p, T("hasAccountType"), T("AcctEmployee")), (p, T("populationSize"), nni(size)), (p, T("hasOwner"), X.owner),
         (p, T("registerSource"), Literal("directory export"))]
    return t + [(p, T(k), nni(v)) for k, v in counts.items()]

write("neg-iam-population-count-exceeds", pop(mfaCount=12), expect="cannot exceed its total (mfaCount)")
write("neg-iam-population-phishing-resistant-exceeds-mfa", pop(mfaCount=4, phishingResistantMfaCount=6), expect="Phishing-resistant MFA is a kind of MFA")
write("neg-iam-population-names-accounts", pop() + [(X.acct, RDF.type, T("Account")), (X.acct, T("memberOfGroup"), X.pop)],
      expect="must not list individual accounts")
def emergency(tested=True, used=None, state="EmergReviewed"):
    t = [(X.ep, RDF.type, T("EmergencyAccessPopulation")), (X.ep, T("hasAccountType"), T("AcctEmergency")), (X.ep, T("populationSize"), nni(2)),
         (X.ep, T("hasOwner"), X.owner), (X.ep, T("registerSource"), Literal("vault report")), (X.ep, T("protectedByMeasure"), X.ctl),
         (X.ep, T("hasEmergencyReviewState"), T(state))]
    if tested: t.append((X.ep, T("lastTestedOn"), dt("2026-04-15")))
    if used: t.append((X.ep, T("lastUsedOn"), dt(used)))
    return t
write("neg-iam-emergency-never-tested", emergency(tested=False), expect="the date of the last test")
write("neg-iam-emergency-used-not-reviewed", emergency(used="2026-09-02", state="EmergNotUsed"), expect="Emergency access used since the last review")
write("neg-iam-emergency-wrong-type", [t for t in emergency() if t[1] != T("hasAccountType")] + [(X.ep, T("hasAccountType"), T("AcctService"))],
      expect="must have the account type 'emergency access accounts'")
write("neg-iam-standing-plus-jit-exceeds", [(X.rp, RDF.type, T("PrivilegedRolePopulation")), (X.rp, T("populationOfRole"), X.role), (X.rp, T("hasPrivilegeTier"), T("Tier0")),
      (X.rp, T("populationSize"), nni(4)), (X.rp, T("standingCount"), nni(4)), (X.rp, T("justInTimeCount"), nni(2)), (X.rp, T("hasOwner"), X.owner)],
      expect="Standing and just-in-time holders together cannot exceed")
write("neg-iam-review-completed-exceeds-due", [(X.c, RDF.type, T("AccessReviewCampaign")), (X.c, T("assessmentScope"), Literal("all")), (X.c, T("dueOn"), dt("2026-09-30")),
      (X.c, T("itemsDue"), nni(10)), (X.c, T("itemsCompleted"), nni(12))], expect="cannot complete more items than were due")
write("neg-iam-sod-rule-one-entitlement", [(X.r, RDF.type, T("SegregationOfDutiesRule")), (X.r, T("prohibitsCombination"), X.e1)],
      expect="must name at least two entitlements or roles")
def deviation(cls="DriftCompensated", exc=None, until=None):
    t = [(X.d, RDF.type, T("BaselineDeviation")), (X.d, T("deviationFromBaseline"), X.v), (X.d, T("hasDriftClass"), T(cls)),
         (X.d, T("identifiedOn"), dt("2026-07-01")), (X.d, T("assessedOn"), dt("2026-10-28")), (X.d, T("deviationAffects"), X.ci)]
    if exc: t += [(X.d, T("coveredByException"), X.exc), (X.exc, RDF.type, T("PolicyException")), (X.exc, T("validUntil"), dt(until))]
    return t
write("neg-iam-compensated-without-exception", deviation(), expect="A compensated deviation must be covered by a policy exception")
write("neg-iam-compensated-expired-exception", deviation(exc=True, until="2026-06-30"), expect="An expired exception never counts")
write("neg-iam-change-without-ticket", [(X.ch, RDF.type, T("ConfigurationChangeRecord")), (X.ch, T("hasChangeClass"), T("ChangeNormal")), (X.ch, T("changesItem"), X.ci),
      (X.ch, T("changeVerified"), Literal(True))], expect="must name its ticket or the decision")
write("neg-iam-lease-without-expiry", [(X.l, RDF.type, T("PrivilegeLease")), (X.l, T("elevatesAccount"), X.acct)], expect="an absolute expiry")
write("neg-iam-coverage-drops-unknown", [(X.o, RDF.type, T("CoverageObservation")), (X.o, T("observationOf"), X.kri), (X.o, T("observedOn"), dt("2026-10-30")),
      (X.o, T("hasSourceRecord"), X.src), (X.o, T("numeratorCount"), nni(9)), (X.o, T("denominatorCount"), nni(10)), (X.o, T("unknownStateCount"), nni(3))],
      expect="unknown items must not be dropped")
write("neg-iam-finding-without-evidence", [(X.f, RDF.type, T("IdentityFinding")), (X.f, RDFS.label, Literal("ownerless accounts"))], expect="An identity finding needs at least one value for its evidence")
write("neg-iam-baseline-version-of-policy", [(X.v, RDF.type, T("BaselineVersion")), (X.v, T("versionOfDirective"), X.pol), (X.pol, RDF.type, T("Policy")),
      (X.v, T("hasOwner"), X.owner), (X.v, T("platformApplicability"), Literal("Linux")), (X.v, T("reviewDueOn"), dt("2027-01-01"))],
      expect="must be a version of a configuration baseline")
write("neg-context-certificate-without-expiry", [(X.cert, RDF.type, T("DigitalCertificate"))], expect="A digital certificate needs exactly one value for its expiry")
write("neg-context-crypto-without-status", [(X.cu, RDF.type, T("CryptographicUseRecord")), (X.cu, T("cryptoUsedBy"), X.app), (X.cu, T("algorithmName"), Literal("RSA-2048"))],
      expect="the quantum vulnerability status")
# OWL: disjoint classes of 0.11.0
I = OWL.NamedIndividual
for name, a, b in (("neg-iam-identity-is-account", "DigitalIdentity", "Account"), ("neg-iam-human-and-non-human", "HumanIdentity", "AIAgentIdentity"),
                   ("neg-iam-deviation-is-change", "BaselineDeviation", "ConfigurationChangeRecord")):
    write(name, [(X.x, RDF.type, I), (X.x, RDF.type, T(a)), (X.x, RDF.type, T(b))], folder="fixtures", imports=["https://w3id.org/crgo/crgo"])
print("0.11.0 fixtures written")
