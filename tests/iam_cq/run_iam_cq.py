# -*- coding: utf-8 -*-
"""Competency questions of 0.11.0 on the SYNTHETIC Nordelle data (tests/samples/nordelle-iam.ttl): the identity, privilege
and configuration registers of the CyberRiskGuardian module (decision record 1.9.0), the shared relationship questions of
spec v1.1 section 9.4 that a posture register can answer, the applicability of the recognised standards and the CIS v8.1
vocabulary. Each CQ has a positive check with its expected result and a negative or variant check.
Prints PASS/FAIL; exits non-zero on any failure."""
import copy, os, sys
from rdflib import Graph, URIRef, Literal, Namespace
from rdflib.namespace import RDF, RDFS, OWL, XSD, SKOS

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "pipeline", "grc"))
import applicability as A  # noqa: E402
ids = dict(l.rstrip("\n").split("\t") for l in open(os.path.join(ROOT, "src", "ids.tsv"), encoding="utf-8"))
T = lambda k: URIRef("https://w3id.org/crgo/CRGO_%07d" % int(ids[k]))
P = lambda k: "<%s>" % T(k)
N = Namespace("https://example.org/crgo-sample/nordelle/")
LEG = Namespace("https://w3id.org/crgo/vocab/legal/")
dt = lambda d: Literal(d + ("" if "T" in d else "T00:00:00"), datatype=XSD.dateTime)
nni = lambda n: Literal(n, datatype=XSD.nonNegativeInteger)
base = Graph()
for m in ("gov", "core", "measure", "crg", "evidence", "org", "vuln", "grc", "mapping", "governance", "assurance", "audit", "incident", "policy", "compliance", "siem", "soar", "context", "iam"):
    base.parse(os.path.join(ROOT, "ontology", "crgo-%s.ttl" % m))
for v in ("legal", "cis81", "csf2", "pattern-links", "sp800-53r5", "attack", "cwe"):
    base.parse(os.path.join(ROOT, "ontology", "vocab", v + ".ttl"))
for f in ("nordelle", "nordelle-grca", "nordelle-iam"):
    base.parse(os.path.join(ROOT, "tests", "samples", f + ".ttl"))
results = []
def check(label, cond, detail=""):
    results.append(bool(cond)); print("%s  %-100s %s" % ("PASS" if cond else "FAIL", label, detail))
def variant(*remove, add=()):
    g = copy.deepcopy(base)
    for t in remove: g.remove(t)
    for t in add: g.add(t)
    return g
short = lambda xs: sorted(str(x).rsplit("/", 1)[-1] for x in xs)
SUB = "<http://www.w3.org/2000/01/rdf-schema#subClassOf>*"
def sel(g, query):
    return list(g.query(query))

# IAM-01 (spec 9.4 Q1-2, register 2): which tier 0 privileged roles have standing holders, and how many?
Q1 = "SELECT ?role ?n WHERE { ?p a %s ; %s ?role ; %s %s ; %s ?n . FILTER(?n > 0) }" % (P("PrivilegedRolePopulation"), P("populationOfRole"), P("hasPrivilegeTier"), P("Tier0"), P("standingCount"))
rows = sel(base, Q1)
check("IAM-01 positive: the identity-provider global administrator role (tier 0) has 3 standing holders", [(r.role, int(r.n)) for r in rows] == [(N["role/idp-global-admin"], 3)])
g = variant((N["population/role-idp-global-admin"], T("standingCount"), nni(3)), add=[(N["population/role-idp-global-admin"], T("standingCount"), nni(0))])
check("IAM-01 variant: with all holders just in time, no tier 0 role has standing holders", sel(g, Q1) == [])
# IAM-02 (register 1, KRI identity ownership coverage): which account populations have accounts without an owner?
Q2 = "SELECT ?p ?n WHERE { ?p a/%s %s ; %s ?n . FILTER(?n > 0) }" % (SUB, P("AccountPopulation"), P("ownerlessCount"))
rows = {r.p: int(r.n) for r in sel(base, Q2)}
check("IAM-02 positive: employee (3), contractor (2) and service (9) populations have ownerless accounts",
      rows == {N["population/employees"]: 3, N["population/contractors"]: 2, N["population/service"]: 9}, str(short(rows)))
check("IAM-02 negative: the emergency account population has none", N["population/emergency"] not in rows)
# IAM-03 (spec 6.4, 9.4 Q3): which deviations are not counted as compliant (degradation, functional, strengthening, unknown)?
Q3 = "SELECT ?d WHERE { ?d a %s ; %s ?c . FILTER(?c IN (%s, %s, %s, %s)) }" % (P("BaselineDeviation"), P("hasDriftClass"), P("DriftDegradation"), P("DriftFunctional"), P("DriftStrengthening"), P("DriftUnknown"))
rows = {r.d for r in sel(base, Q3)}
check("IAM-03 positive: the SSH degradation and the seven stale kiosks count against the baseline", rows == {N["deviation/ssh-passwords"], N["deviation/kiosks-stale"]}, str(short(rows)))
check("IAM-03 negative: the legacy server deviation is compensated by an unexpired exception", N["deviation/legacy-pos-edr"] not in rows)
# IAM-04 (spec 9.4 Q4; decision record: an expired exception never counts): compensated deviations whose exception has expired at a date
Q4 = "SELECT ?d WHERE { ?d %s %s ; %s ?e . ?e %s ?u . FILTER(?u < ?asof) }" % (P("hasDriftClass"), P("DriftCompensated"), P("coveredByException"), P("validUntil"))
asof = lambda d: list(base.query(Q4, initBindings={"asof": dt(d)}))
check("IAM-04 positive: on 2027-01-10 the legacy server deviation relies on an expired exception", {r.d for r in asof("2027-01-10")} == {N["deviation/legacy-pos-edr"]})
check("IAM-04 negative: on 2026-10-30 the exception is still valid", asof("2026-10-30") == [])
# IAM-05 (decision record KRIs): coverage with its denominator; unknown items stay in it
Q5 = "SELECT ?k ?n ?d ?u WHERE { ?o a %s ; %s ?k ; %s ?n ; %s ?d ; %s ?u }" % (P("CoverageObservation"), P("observationOf"), P("numeratorCount"), P("denominatorCount"), P("unknownStateCount"))
rows = {r.k: (int(r.n), int(r.d), int(r.u)) for r in sel(base, Q5)}
check("IAM-05 positive: privileged MFA 9 of 10; known configuration 15 of 22 with 7 unknown (68 %, not 100 %)",
      rows == {N["kri/privileged-mfa"]: (9, 10, 0), N["kri/known-configuration"]: (15, 22, 7)}, str(rows))
check("IAM-05 negative: excluding unknowns would wrongly give 15 of 15", rows[N["kri/known-configuration"]][0] / rows[N["kri/known-configuration"]][1] < 1)
# IAM-06 (register 3): emergency access used after its last test and not yet reviewed
Q6 = "SELECT ?p WHERE { ?p a %s ; %s ?used ; %s ?tested ; %s ?st . FILTER(?used > ?tested && ?st IN (%s, %s)) }" % (
    P("EmergencyAccessPopulation"), P("lastUsedOn"), P("lastTestedOn"), P("hasEmergencyReviewState"), P("EmergReviewPending"), P("EmergReviewOverdue"))
check("IAM-06 positive: the emergency accounts were used on 2 September and the review is pending", {r.p for r in sel(base, Q6)} == {N["population/emergency"]})
g = variant((N["population/emergency"], T("hasEmergencyReviewState"), T("EmergReviewPending")), add=[(N["population/emergency"], T("hasEmergencyReviewState"), T("EmergReviewed"))])
check("IAM-06 variant: once reviewed, nothing is reported", sel(g, Q6) == [])
# IAM-07 (register 7): configuration changes not verified or suspected unauthorised
Q7 = "SELECT ?c WHERE { ?c a %s . { ?c %s false } UNION { ?c %s %s } }" % (P("ConfigurationChangeRecord"), P("changeVerified"), P("hasChangeClass"), P("ChangeUnauthorisedSuspected"))
rows = {r.c for r in sel(base, Q7)}
check("IAM-07 positive: the firewall change without a ticket", rows == {N["change/fw-2026-10-27"]}, str(short(rows)))
check("IAM-07 negative: CHG-1042 was verified", N["change/CHG-1042"] not in rows)
# IAM-08 (spec 9.4 Q5): which services may be disrupted if the order application's database credential changes?
Q8 = "SELECT ?svc WHERE { ?dep %s ?cred ; %s ?svc . ?cred %s ?acct }" % (P("dependencyOnCredential"), P("credentialUsedByService"), P("credentialOfAccount"))
check("IAM-08 positive: rotating the service account's credential affects the order application", {r.svc for r in sel(base, Q8)} == {N["asset/order-app"]})
check("IAM-08 negative: no credential value is stored, only the vault reference",
      not any(str(p).endswith(("password", "secret")) for p in base.predicates(N["credential/svc-orders-db"], None)))
# IAM-09: applicability of the recognised standards and the CCSPA (pipeline/grc/applicability.py, usesTechnology)
out, res = A.evaluate(base, N.org, "2026-10-30", N["person/compliance"], str(N))
exp = {"ISO-IEC-42001-2023": "AppPotentiallyApplicable", "OWASP-TOP10-2025": "AppPotentiallyApplicable", "OWASP-LLM-2025": "AppPotentiallyApplicable",
       "OWASP-AGENTIC-2026": "AppNotApplicable", "ISO-IEC-27701-2025": "AppPotentiallyApplicable"}
check("IAM-09 positive: 42001, OWASP Top 10, OWASP LLM and 27701 potentially applicable (voluntary); agentic not applicable (no agents, profile complete)",
      all(res.get(k) == v for k, v in exp.items()), str({k: res.get(k, "")[3:] for k in exp}))
g = variant((N.org, T("profileCompleteFor"), Literal("usesTechnology")))
_, res2 = A.evaluate(g, N.org, "2026-10-30", N["person/compliance"], str(N))
check("IAM-09 variant: without a complete technology profile, the agentic guidance is unknown, not 'not applicable'", res2.get("OWASP-AGENTIC-2026") == "AppUnknown", res2.get("OWASP-AGENTIC-2026", ""))
check("IAM-09 CCSPA: Nordelle is not a designated operator", res.get("CCSPA") in ("AppNotApplicable", "AppUnknown"), res.get("CCSPA", ""))
# IAM-10: CIS v8.1 vocabulary (153 safeguards; IG1 = 56, IG2 = 130, IG3 = 153)
CIS = URIRef("https://w3id.org/crgo/vocab/cis81")
sg = [c for c in base.subjects(SKOS.inScheme, CIS) if "." in str(base.value(c, SKOS.notation))]
ig = lambda n: sum(1 for c in sg if (c, T("inImplementationGroup"), T("IG%d" % n)) in base)
check("IAM-10 positive: 18 controls and 153 safeguards; IG1 56, IG2 130, IG3 153", (len(set(base.subjects(SKOS.inScheme, CIS))) - len(sg), len(sg), ig(1), ig(2), ig(3)) == (18, 153, 56, 130, 153),
      str((len(sg), ig(1), ig(2), ig(3))))
check("IAM-10 negative: every safeguard has exactly one asset type and one security function",
      all(len(list(base.objects(c, T("hasSafeguardAssetType")))) == 1 and len(list(base.objects(c, T("hasSecurityFunction")))) == 1 for c in sg))
# PAT-01..03: scenario patterns (vocab/pattern-links) and the scenarios that instantiate them
SP = lambda n: URIRef("https://w3id.org/crgo/vocab/sp800-53r5/" + n)
pats = [T(k) for k in ("PatQuantumHarvest", "PatCryptoAgility", "PatCertificateExpiry", "PatAgenticMisuse", "PatPromptInjection", "PatAISupplyChain")]
check("PAT-01 positive: every scenario pattern has a control, a theme and a technique or weakness",
      all(list(base.objects(p, T("patternAddressedBy"))) and list(base.objects(p, T("narrowerThan"))) and
          (list(base.objects(p, T("patternInvolvesTechnique"))) or list(base.objects(p, T("patternInvolvesWeakness")))) for p in pats))
ctl = {o for o in base.objects(T("PatPromptInjection"), T("patternAddressedBy"))}
check("PAT-02 positive: prompt injection is addressed by SP 800-53 SI-10, AC-6 and SI-4", {SP("SI-10"), SP("AC-6"), SP("SI-4")} <= ctl, str(short(ctl)))
check("PAT-02 negative: certificate expiry involves no ATT&CK technique (an outage, not an attack)", list(base.objects(T("PatCertificateExpiry"), T("patternInvolvesTechnique"))) == [])
Q9 = "SELECT ?s WHERE { ?s %s ?p . ?p %s %s }" % (P("hasScenarioPattern"), P("patternAddressedBy"), "<%s>" % SP("SC-17"))
check("PAT-03 positive: the shop certificate scenario is found through its pattern's control SC-17", {r.s for r in sel(base, Q9)} == {N["scenario/shop-certificate-expiry"]})
print("%d of %d checks passed" % (sum(results), len(results)))
sys.exit(0 if all(results) else 1)
