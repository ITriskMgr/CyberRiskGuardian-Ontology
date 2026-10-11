# -*- coding: utf-8 -*-
"""Build the fictional test company of the specification's acceptance demonstration (section 22; decision D7).

Nordelle Market inc. is SYNTHETIC: a fictional Québec online grocery that sells to customers in Québec, other
Canadian provinces and the European Union, through a cloud-hosted ordering application, a payment provider, an
identity provider and a delivery partner. Every value below is invented for testing; nothing describes a real
organisation, and no estimate here is empirically validated.

Writes tests/samples/nordelle.ttl (profile, assets, suppliers, processing, assessment, two hypothetical scenarios,
estimates, assumptions, control measures and assessments, compliance determinations) and runs the applicability
evaluator into tests/samples/nordelle-applicability.ttl.
"""
import os, sys
from rdflib import Graph, Namespace, URIRef, Literal, BNode
from rdflib.namespace import RDF, RDFS, OWL, XSD, SKOS, DCTERMS

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "pipeline", "grc"))
import applicability  # noqa: E402
BASE = "https://w3id.org/crgo/"; VOC = BASE + "vocab/"
ids = dict(l.rstrip("\n").split("\t") for l in open(os.path.join(ROOT, "src", "ids.tsv"), encoding="utf-8"))
T = lambda k: URIRef(BASE + "CRGO_%07d" % int(ids[k]))
N = Namespace("https://example.org/crgo-sample/nordelle/")
CCO = Namespace("https://www.commoncoreontologies.org/"); BFO = Namespace("http://purl.obolibrary.org/obo/")
ORG_CLASS = CCO.ont00001180; PERSON = CCO.ont00001262

def concept(scheme, notation):
    g = Graph().parse(os.path.join(ROOT, "ontology", "vocab", scheme + ".ttl"))
    for c in g.subjects(SKOS.notation, Literal(notation)):
        return c
    raise KeyError((scheme, notation))

g = Graph(); g.bind("crgo", BASE); g.bind("nordelle", N); g.bind("dcterms", DCTERMS)
o = URIRef("https://example.org/crgo-sample/nordelle")
g.add((o, RDF.type, OWL.Ontology)); g.add((o, OWL.imports, URIRef(BASE + "crgo")))
g.add((o, RDFS.label, Literal("Nordelle Market inc. - SYNTHETIC test data for CRGO 0.9.0", lang="en")))
g.add((o, DCTERMS.type, Literal("synthetic test data")))
g.add((o, RDFS.comment, Literal("Fictional organisation for the CRGO acceptance demonstration (specification section 22). "
                                "All facts and values are invented; estimates are not empirically validated.", lang="en")))
def ind(s, *types, label=None):
    g.add((s, RDF.type, OWL.NamedIndividual))
    for t in types: g.add((s, RDF.type, t))
    if label: g.add((s, RDFS.label, Literal(label, lang="en")))
    g.add((s, DCTERMS.type, Literal("synthetic test data")))
    return s
dt = lambda d: Literal(d + "T00:00:00", datatype=XSD.dateTime)
dec = lambda x: Literal(str(x), datatype=XSD.decimal)

# organisation profile
org = ind(N.org, ORG_CLASS, label="Nordelle Market inc. (fictional)")
g.add((org, T("hasOrganisationType"), T("OrgEnterprise"))); g.add((org, T("establishedIn"), T("JurQuebec")))
for j in ("JurQuebec", "JurCanadaOtherProvince", "JurEU"): g.add((org, T("offersServicesIn"), T(j)))
assessor = ind(N["person/ciso"], PERSON, label="Nordelle information security lead (fictional)")
# suppliers (role borne by the supplier, toward Nordelle)
sup = {}
for key, name in (("cloudco", "Cumulus Hosting Ltd. (fictional cloud provider)"), ("payco", "Paysage Payments Corp. (fictional payment provider)"),
                  ("idco", "Clef Identity Services (fictional identity provider)"), ("delivco", "Rapide Livraison (fictional delivery partner)")):
    s = ind(N["org/" + key], ORG_CLASS, label=name); r = ind(N["role/" + key + "-supplier"], T("SupplierRole"), label="supplier role of " + name)
    g.add((s, BFO.BFO_0000196, r)); g.add((r, T("supplierTo"), org)); sup[key] = s
# assets, process, objective
app = ind(N["asset/order-app"], T("SoftwareAsset"), label="online ordering application")
host = ind(N["asset/cloud-hosting"], T("ServiceAsset"), label="cloud hosting of the ordering application")
pay = ind(N["asset/payment-service"], T("ServiceAsset"), label="card payment service")
idp = ind(N["asset/identity-service"], T("ServiceAsset"), label="customer and staff identity service")
db = ind(N["asset/customer-db"], T("InformationAsset"), label="customer and order database")
backup = ind(N["asset/backups"], T("InformationAsset"), label="nightly backups of the order database")
proc = ind(N["process/online-ordering"], T("BusinessProcess"), label="online ordering and fulfilment")
obj = ind(N["objective/online-revenue"], T("BusinessObjective"), label="grow online revenue while keeping customer trust")
unused = ind(N["asset/kiosk"], T("HardwareAsset"), label="in-store price kiosk (no scenario affects it)")
for a in (app, host, pay, idp, db): g.add((a, T("supportsProcess"), proc))
g.add((proc, T("supportsObjective"), obj))
g.add((app, T("dependsOn"), host)); g.add((app, T("dependsOn"), idp)); g.add((app, T("dependsOn"), pay)); g.add((app, T("dependsOn"), db))
g.add((host, T("providedBy"), sup["cloudco"])); g.add((pay, T("providedBy"), sup["payco"])); g.add((idp, T("providedBy"), sup["idco"]))
# processing activity
pa = ind(N["processing/customer-orders"], T("ProcessingActivity"), label="processing of customer orders")
g.add((pa, T("carriedOutBy"), org)); g.add((pa, T("hasProcessingRole"), T("RoleController")))
for c in ("DataIdentityContact", "DataFinancial", "DataOnlineId"): g.add((pa, T("processesDataCategory"), T(c)))
for j in ("JurQuebec", "JurCanadaOtherProvince", "JurEU"): g.add((pa, T("dataSubjectsIn"), T(j)))
# risk assessment, two hypothetical scenarios
ra = ind(N["assessment/2026"], T("RiskAssessment"), label="Nordelle cybersecurity risk assessment 2026 (fictional)")
g.add((ra, T("assessesOrganization"), org)); g.add((ra, T("assessmentHorizon"), Literal("next 12 months")))
S = {}
for key, name, assets, tech, cons in (
        ("credential-compromise", "Compromise of an administrator account of the ordering application", (app, db, idp), "T1078", "Customer data disclosed and orders manipulated"),
        ("ransomware", "Ransomware encrypts the ordering application and its database", (app, db, host), "T1486", "Online sales stopped for several days")):
    s = ind(N["scenario/" + key], T("AssessmentScenario"), label=name + " (hypothetical)"); S[key] = s
    g.add((ra, T("includesScenario"), s)); g.add((s, T("affectsProcess"), proc))
    for a in assets: g.add((s, T("affectsAsset"), a))
    ev = ind(N["scenario/" + key + "/event"], T("ThreatEventDescription"), label=name)
    g.add((s, T("hasThreatEvent"), ev)); g.add((ev, T("hasExternalReference"), concept("attack", tech)))
    cd = ind(N["scenario/" + key + "/consequence"], T("ConsequenceDescription"), label=cons); g.add((s, T("hasConsequence"), cd))
    g.add((s, T("triggersObligation"), concept("loi25", "P-39.1 s. 3.5 (2nd para.)")))
# assumptions and estimates
A1 = ind(N["assumption/admin-targeting"], T("Assumption"), label="Attackers try stolen administrator passwords against small online retailers at least once a year")
A2 = ind(N["assumption/restore-time"], T("Assumption"), label="A full restore from backup takes about two days")
A3 = ind(N["assumption/no-eu-establishment"], T("Assumption"), label="Nordelle has no establishment in the European Union")
for key, cls, val, asm, scen in (("likelihood-cc", "Likelihood", 0.30, A1, "credential-compromise"), ("impact-cc", "ImpactEstimate", 0.60, A1, "credential-compromise"),
                                 ("likelihood-rw", "Likelihood", 0.15, A2, "ransomware"), ("impact-rw", "ImpactEstimate", 0.80, A2, "ransomware")):
    e = ind(N["estimate/" + key], T(cls), label="%s of %s (fictional)" % (cls, scen))
    g.add((e, T("estimateOf"), S[scen])); g.add((e, T("assessedIn"), ra)); g.add((e, T("numericValue"), dec(val)))
    g.add((e, T("onScale"), T("ScaleUnitInterval"))); g.add((e, T("hasConfidence"), T("ConfMedium"))); g.add((e, T("dependsOnAssumption"), asm))
    g.add((e, T("rationale"), Literal("Synthetic value for testing; not empirically validated.", lang="en")))
stray = ind(N["estimate/unrelated"], T("Likelihood"), label="Likelihood from an older assessment (not in the 2026 assessment)")
g.add((stray, T("estimateOf"), S["ransomware"])); g.add((stray, T("numericValue"), dec(0.5))); g.add((stray, T("onScale"), T("ScaleUnitInterval")))
g.add((stray, T("dependsOnAssumption"), ind(N["assumption/old"], T("Assumption"), label="Superseded assumption from 2024")))
# control measures, control assessments, evidence
def evidence(key, label, locator, date):
    e = ind(N["evidence/" + key], T("EvidenceItem"), label=label)
    g.add((e, T("localIdentifier"), Literal(key))); g.add((e, T("evidenceLocator"), Literal(locator)))
    g.add((e, T("hasEvidenceBasis"), T("EvDocumented"))); g.add((e, DCTERMS.date, Literal(date + "T00:00:00", datatype=XSD.dateTime)))
    return e
E1 = evidence("mfa-config", "Identity service policy export showing MFA enforced for administrators", "exports/idp-policy-2026-09-15.json (fictional)", "2026-09-15")
E2 = evidence("restore-test", "Restore test report: database restored in 41 hours, application configuration missing", "reports/restore-test-2026-09-20.pdf (fictional)", "2026-09-20")
E3 = evidence("incident-register", "Extract of the confidentiality incident register", "registers/incidents-2026.xlsx (fictional)", "2026-09-30")
M = {}
for key, name, status, scen in (("mfa", "Multi-factor authentication for administrator accounts", "CtlInPlace", "credential-compromise"),
                                ("backups", "Nightly offline backups of the order database", "CtlInPlace", "ransomware"),
                                ("edr", "Endpoint detection and response on servers", "CtlPlanned", "ransomware")):
    m = ind(N["control/" + key], T("ControlMeasure"), label=name); M[key] = m
    g.add((m, T("hasControlStatus"), T(status))); g.add((S[scen], T("mitigatedBy"), m))
g.add((M["backups"], T("protectsAsset"), backup))
CA = {}
for key, meas, date, result, ev, proc_ in (("mfa-2026-09", "mfa", "2026-09-15", "TestEffective", E1, "Inspection of the enforced policy and a sample of 10 administrator sign-ins"),
                                         ("backups-2026-09", "backups", "2026-09-20", "TestPartlyEffective", E2, "Full restore test into an isolated environment"),
                                         ("edr-2026-09", "edr", "2026-09-30", "TestNotTested", None, "Not deployed yet")):
    c = ind(N["control-assessment/" + key], T("ControlAssessment"), label="Assessment of %s, %s" % (meas, date)); CA[key] = c
    g.add((c, T("evaluatesControlMeasure"), M[meas])); g.add((c, T("assessedOn"), dt(date))); g.add((c, T("hasTestResult"), T(result)))
    g.add((c, T("assessedBy"), assessor)); g.add((c, T("testProcedure"), Literal(proc_))); g.add((c, T("concernsOrganisation"), org))
    if ev is not None: g.add((c, T("hasEvidence"), ev))
# compliance determinations (synthetic)
def det(key, scheme, notation, state, jur, evid=(), gap=None, cas=()):
    d = ind(N["compliance/" + key], T("ComplianceDetermination"), label="Compliance with %s (fictional)" % notation)
    g.add((d, T("concernsOrganisation"), org)); g.add((d, T("complianceWith"), concept(scheme, notation))); g.add((d, T("hasComplianceState"), T(state)))
    g.add((d, T("hasJurisdiction"), T(jur))); g.add((d, T("assessedOn"), dt("2026-10-01"))); g.add((d, T("assessedBy"), assessor))
    for e in evid: g.add((d, T("hasEvidence"), e))
    for c in cas: g.add((d, T("basedOnControlAssessment"), c))
    if gap: g.add((d, T("evidenceGap"), Literal(gap)))
det("loi25-register", "loi25", "P-39.1 s. 3.8", "CompSatisfied", "JurQuebec", evid=(E3,))
det("loi25-security", "loi25", "P-39.1 s. 10", "CompPartial", "JurQuebec", evid=(E1, E2), cas=(CA["mfa-2026-09"], CA["backups-2026-09"]),
    gap="Endpoint detection not yet deployed; the restore test missed the application configuration.")
det("gdpr-notification", "gdpr", "GDPR Art. 33(1)", "CompUndetermined", "JurEU",
    gap="No documented procedure to notify an EU supervisory authority within 72 hours; GDPR applicability under Art. 3(2) awaits qualified review.")
det("loi25-pia", "loi25", "P-39.1 s. 3.3", "CompNotAssessed", "JurQuebec", gap="Not yet assessed.")
g.serialize(os.path.join(ROOT, "tests", "samples", "nordelle.ttl"), format="turtle")
# applicability, evaluated over the profile
pg = Graph(); pg += g; pg.parse(os.path.join(ROOT, "ontology", "vocab", "legal.ttl"))
out, res = applicability.evaluate(pg, org, "2026-10-01", assessor, str(N))
out.bind("nordelle", N)
out.serialize(os.path.join(ROOT, "tests", "samples", "nordelle-applicability.ttl"), format="turtle")
print("nordelle: %d triples; applicability: %s" % (len(g), ", ".join("%s %s" % (k, v[3:]) for k, v in res.items())))
