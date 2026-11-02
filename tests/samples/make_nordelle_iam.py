# -*- coding: utf-8 -*-
"""0.11.0 identity, privilege and configuration demonstration on the SYNTHETIC Nordelle Market inc. Everything is invented
test data about a fictional company (CyberRiskGuardian 1.9.0 decision record; spec v1.1 section 23.7 sample).

The story (as of 2026-10-30), on top of the earlier Nordelle graphs:
- registers kept by counts per population, with no names: employee, contractor, service and AI-agent account populations,
  two emergency access accounts (tested in April, used on 2 September, review pending), two privileged roles (tier 0 identity
  administration, tier 1 production database administration), the Q3 access review campaign, a segregation-of-duties
  conflict on vendor creation and payment approval, the Linux server baseline promoted to an approved version 2 with a
  requirement mapped to CIS safeguard 4.1, three deviations (security degradation on three servers, the legacy point-of-sale
  server compensated by the unexpired EDR exception, seven kiosks of unknown state), two configuration changes (a verified
  normal change and a suspected unauthorised firewall change);
- the spec v1.1 section 23.7 sample: one person's identity, a shared emergency account and its use, a service account whose
  secret is held in a vault (metadata only), the configuration item of the legacy server supporting the payment service, a
  requested change and its verified remediation;
- technology context: Nordelle uses web applications, AI systems and a generative AI assistant (so the ISO/IEC 42001, OWASP
  Top 10 and OWASP LLM conditions are met; no AI agents, profile complete for technology), with a TLS certificate and a
  cryptographic inventory entry (RSA, quantum-vulnerable);
- an identity finding (service accounts without an owner) and two coverage observations (privileged MFA; known configuration).
Writes tests/samples/nordelle-iam.ttl (imports nordelle-secops).
"""
import os
from rdflib import Graph, Namespace, URIRef, Literal
from rdflib.namespace import RDF, RDFS, OWL, XSD, SKOS, DCTERMS

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
BASE = "https://w3id.org/crgo/"
ids = dict(l.rstrip("\n").split("\t") for l in open(os.path.join(ROOT, "src", "ids.tsv"), encoding="utf-8"))
T = lambda k: URIRef(BASE + "CRGO_%07d" % int(ids[k]))
N = Namespace("https://example.org/crgo-sample/nordelle/")
CCO = Namespace("https://www.commoncoreontologies.org/")
PERSON = CCO.ont00001262
_voc = {}
def concept(scheme, notation):
    if scheme not in _voc:
        _voc[scheme] = {str(n): s for s, n in Graph().parse(os.path.join(ROOT, "ontology", "vocab", scheme + ".ttl")).subject_objects(SKOS.notation)}
    return _voc[scheme][notation]

g = Graph(); g.bind("crgo", BASE); g.bind("nordelle", N); g.bind("dcterms", DCTERMS)
o = URIRef("https://example.org/crgo-sample/nordelle-iam")
g.add((o, RDF.type, OWL.Ontology)); g.add((o, OWL.imports, URIRef("https://example.org/crgo-sample/nordelle-secops")))
for v in ("crgo-iam",):
    g.add((o, OWL.imports, URIRef(BASE + v)))
for v in ("cis81", "naics-sectors"):
    g.add((o, OWL.imports, URIRef(BASE + "vocab/" + v)))
g.add((o, URIRef("http://purl.org/vocab/vann/preferredNamespaceUri"), Literal(str(N))))
g.add((o, RDFS.label, Literal("Nordelle Market inc. - SYNTHETIC identity, privilege and configuration registers for CRGO 0.11.0", lang="en")))
g.add((o, DCTERMS.type, Literal("synthetic test data")))
dt = lambda d: Literal(d + ("" if "T" in d else "T00:00:00"), datatype=XSD.dateTime)
nni = lambda x: Literal(x, datatype=XSD.nonNegativeInteger)
txt = lambda s: Literal(s, lang="en")
def ind(key, cls, label, **props):
    s = N[key]
    g.add((s, RDF.type, OWL.NamedIndividual))
    for c in (cls if isinstance(cls, (list, tuple)) else [cls]):
        g.add((s, RDF.type, URIRef(c) if c.startswith("http") else T(c)))
    g.add((s, RDFS.label, Literal(label, lang="en"))); g.add((s, DCTERMS.type, Literal("synthetic test data")))
    for k, v in props.items():
        for x in (v if isinstance(v, list) else [v]):
            g.add((s, T(k), x))
    return s

org = N.org
P = {k: N["person/" + k] for k in ("ceo", "ciso", "iam-lead", "itops", "netops", "compliance")}
idp = N["asset/identity-service"]

# ------------------------------------------------------------------ technology and organisational context
for t in ("TechWebApplication", "TechAISystem", "TechGenerativeAI"):
    g.add((org, T("usesTechnology"), T(t)))
g.add((org, T("profileCompleteFor"), Literal("usesTechnology")))
g.add((org, T("hasOrganisationSize"), T("SizeMedium"))); g.add((org, T("hasLegalForm"), T("FormCorporation")))
g.add((org, T("inIndustrySector"), concept("naics-sectors", "44-45")))
assistant = ind("asset/support-assistant", "GenerativeAIApplication", "Customer-support assistant (fictional generative AI application)", hasOwner=P["ciso"])
model = ind("asset/support-model", "AIModelArtifact", "Hosted language model used by the support assistant (fictional)")
g.add((assistant, T("systemUsesModel"), model))
cert = ind("asset/cert-shop", "DigitalCertificate", "TLS certificate of the online shop (fictional)", validUntil=dt("2027-01-15"), hasOwner=P["itops"])
g.add((N["asset/order-app"], T("dependsOn"), cert))
ind("crypto/order-app-tls", "CryptographicUseRecord", "Key exchange and signature of the online shop's TLS", cryptoUsedBy=N["asset/order-app"],
    algorithmName=Literal("RSA-2048 / ECDHE P-256"), hasQuantumStatus=T("QuantumVulnerable"), dataConfidentialityYears=nni(7))

# ------------------------------------------------------------------ identities, accounts, vault (spec v1.1 section 23.7 sample)
ident = ind("identity/iam-lead", "HumanIdentity", "Identity of the IAM lead (fictional)", representsAgent=P["iam-lead"])
ind("account/iam-lead-admin", "PrivilegedAccount", "Administrative account of the IAM lead", accountOfIdentity=ident, accountInSource=idp)
ea = ind("account/break-glass-01", "EmergencyAccessAccount", "Shared emergency access account 01", accountInSource=idp, hasOwner=P["ciso"])
svc = ind("account/svc-orders", "ServiceAccount", "Service account of the order application", accountInSource=idp, hasOwner=P["itops"])
vault = ind("asset/vault", "CredentialVault", "Secrets vault (fictional)", hasOwner=P["iam-lead"])
cred = ind("credential/svc-orders-db", "CredentialReference", "Database credential of the order application (metadata only)", managedByVault=vault,
           credentialOfAccount=svc, vaultReference=Literal("kv/orders/db-login"), lastRotatedOn=dt("2026-07-01"))
ind("dependency/orders-db", "CredentialDependency", "The order application depends on the database credential", dependencyOnCredential=cred,
    credentialUsedByService=N["asset/order-app"])
vault_ctl = ind("control/break-glass-protection", "ControlMeasure", "Emergency accounts held in the vault with split knowledge and alerting on use",
                hasControlStatus=T("CtlInPlace"), hasOwner=P["ciso"])
ind("emergency-use/2026-09-02", "EmergencyUseEvent", "Use of emergency account 01 during the September kiosk malware incident", emergencyUseOf=ea,
    occurredAt=dt("2026-09-02T22:40:00"), hasEmergencyReviewState=T("EmergReviewPending"))

# ------------------------------------------------------------------ register 1 and 3: account populations
def population(key, label, atype, total, mfa, pr, dormant, ownerless, unknown, owner, cls="AccountPopulation", **extra):
    return ind("population/" + key, cls, label, hasAccountType=T(atype), populationSize=nni(total), mfaCount=nni(mfa), phishingResistantMfaCount=nni(pr),
               dormantCount=nni(dormant), ownerlessCount=nni(ownerless), unknownStateCount=nni(unknown), hasOwner=owner,
               lastReconciledOn=dt("2026-10-15"), registerSource=Literal("Directory export of 2026-10-15, counted by the IAM lead"),
               populationDescription=txt(label), **extra)
population("employees", "Employee accounts in the corporate directory", "AcctEmployee", 420, 400, 120, 12, 3, 0, P["iam-lead"])
population("contractors", "Contractor and vendor accounts", "AcctContractor", 35, 30, 0, 4, 2, 0, P["iam-lead"])
svc_pop = population("service", "Service and workload accounts", "AcctService", 60, 0, 0, 6, 9, 5, P["itops"])
population("ai-agents", "Accounts used by AI agents", "AcctAIAgent", 0, 0, 0, 0, 0, 0, P["ciso"])
population("emergency", "Emergency access accounts", "AcctEmergency", 2, 2, 2, 0, 0, 0, P["ciso"], cls="EmergencyAccessPopulation",
           lastTestedOn=dt("2026-04-15"), lastUsedOn=dt("2026-09-02"), hasEmergencyReviewState=T("EmergReviewPending"), protectedByMeasure=vault_ctl)

# ------------------------------------------------------------------ register 2: privileged roles by tier
r0 = ind("role/idp-global-admin", "PrivilegedRole", "Identity provider global administrator", hasPrivilegeTier=T("Tier0"), administersAsset=idp)
r1 = ind("role/prod-dba", "PrivilegedRole", "Production database administrator", hasPrivilegeTier=T("Tier1"), administersAsset=N["asset/customer-db"])
ind("population/role-idp-global-admin", "PrivilegedRolePopulation", "Holders of the identity provider global administrator role", populationOfRole=r0,
    hasPrivilegeTier=T("Tier0"), populationSize=nni(4), standingCount=nni(3), justInTimeCount=nni(1), mfaCount=nni(4), hasOwner=P["ciso"],
    reviewedOn=dt("2026-09-28"), registerSource=Literal("Identity provider role report"))
ind("population/role-prod-dba", "PrivilegedRolePopulation", "Holders of the production database administrator role", populationOfRole=r1,
    hasPrivilegeTier=T("Tier1"), populationSize=nni(6), standingCount=nni(6), justInTimeCount=nni(0), mfaCount=nni(5), hasOwner=P["itops"],
    reviewedOn=dt("2026-09-28"), registerSource=Literal("Database role report"))

# ------------------------------------------------------------------ register 4: access review campaign
ind("access-review/2026-q3", "AccessReviewCampaign", "Q3 2026 access review campaign", assessmentScope=Literal("All privileged roles and the finance application"),
    dueOn=dt("2026-09-30"), completedOn=dt("2026-10-04"), itemsDue=nni(240), itemsCompleted=nni(228), revocationsRequested=nni(19),
    revocationsVerified=nni(15), reviewerConflictCount=nni(2), hasOwner=P["iam-lead"])

# ------------------------------------------------------------------ register 6: segregation of duties
e1 = ind("entitlement/vendor-create", "Entitlement", "Create or change a vendor in the finance application")
e2 = ind("entitlement/payment-approve", "Entitlement", "Approve vendor payments in the finance application")
sod = ind("sod/vendor-payment", "SegregationOfDutiesRule", "No one may both create vendors and approve their payments", prohibitsCombination=[e1, e2])
mit = ind("control/vendor-master-review", "ControlMeasure", "Monthly review of vendor master changes by the controller", hasControlStatus=T("CtlInPlace"), hasOwner=P["compliance"])
ind("sod-conflict/vendor-payment-2026-10", "SegregationOfDutiesConflict", "Three identities can create vendors and approve payments", conflictOfRule=sod,
    conflictCount=nni(3), hasOwner=P["compliance"], conflictMitigatedBy=mit, hasEvidence=N["evidence/iam-export-2026-10"])
ind("evidence/iam-export-2026-10", "ConfigurationEvidence", "Directory and finance-application role exports, 2026-10-15", localIdentifier=Literal("E-IAM-01"),
    collectedOn=dt("2026-10-15"))

# ------------------------------------------------------------------ register 5: baseline versions, requirements, deviations
bl = N["baseline/linux-server"]
v2 = ind("baseline/linux-server/v2", "BaselineVersion", "Linux server baseline, version 2", versionOfDirective=bl, versionLabel=Literal("2"),
         hasLifecycleState=T("LifeApproved"), effectiveOn=dt("2026-06-01"), hasOwner=P["itops"], reviewDueOn=dt("2027-06-01"),
         platformApplicability=Literal("Ubuntu 22.04 and 24.04 servers"),
         sourceLicenceReference=Literal("Adapted from a CIS Benchmark for Ubuntu Linux; benchmark licence CC BY-NC-SA 4.0 (internal use)"))
ind("decision/approve-linux-baseline-v2", "DecisionRecord", "CISO approves version 2 of the Linux server baseline", decisionOn=v2, decisionMadeBy=P["ciso"],
    hasDecisionOutcome=T("DecApproved"), decidedOn=dt("2026-05-20"))
req = ind("baseline/linux-server/v2/ssh-no-password", "BaselineRequirement", "SSH accepts keys only (no password authentication)", requirementInBaseline=v2,
          requirementImplements=concept("cis81", "4.1"), platformApplicability=Literal("all servers of the baseline"))
ci = ind("ci/legacy-pos-server", "ConfigurationItem", "Configuration item: legacy point-of-sale server", itemForAsset=N["asset/legacy-pos-server"],
         itemSupportsService=N["asset/payment-service"], environmentName=Literal("production"), assignedBaseline=v2, hasOwner=P["itops"])
ci2 = ind("ci/linux-app-servers", "ConfigurationItem", "Configuration item group: Linux application servers (14)", itemForAsset=N["asset/order-app"],
          environmentName=Literal("production"), assignedBaseline=v2, hasOwner=P["itops"])
kiosks = ind("population/kiosks", "Population", "Store kiosks (7)", populationSize=nni(7), populationDescription=txt("The seven store kiosks"))
ind("deviation/ssh-passwords", "BaselineDeviation", "Password authentication re-enabled on three Linux servers", deviationFromBaseline=v2, deviationFromRequirement=req,
    deviationAffects=ci2, hasDriftClass=T("DriftDegradation"), deviationCount=nni(3), identifiedOn=dt("2026-10-20"), assessedOn=dt("2026-10-28"))
ind("deviation/legacy-pos-edr", "BaselineDeviation", "No EDR agent on the legacy point-of-sale server", deviationFromBaseline=v2, deviationAffects=ci,
    hasDriftClass=T("DriftCompensated"), coveredByException=N["exception/edr-legacy-pos"], deviationCount=nni(1), identifiedOn=dt("2026-07-01"), assessedOn=dt("2026-10-28"))
ind("deviation/kiosks-stale", "BaselineDeviation", "Seven kiosks without a configuration observation in 30 days", deviationFromBaseline=v2, deviationAffects=kiosks,
    hasDriftClass=T("DriftUnknown"), deviationCount=nni(7), identifiedOn=dt("2026-10-28"), assessedOn=dt("2026-10-28"))

# ------------------------------------------------------------------ register 7: configuration changes (requested change and verified remediation)
chg_ok = ind("change/CHG-1042", "ConfigurationChangeRecord", "Re-apply key-only SSH on the three servers", changesItem=ci2, hasChangeClass=T("ChangeNormal"),
             changeTicketReference=Literal("CHG-1042"), changeVerified=Literal(True), occurredAt=dt("2026-10-29"))
ind("change/fw-2026-10-27", "ConfigurationChangeRecord", "Firewall rule opened to the kiosks network without a ticket", changesItem=N["asset/payment-service"],
    hasChangeClass=T("ChangeUnauthorisedSuspected"), changeVerified=Literal(False), occurredAt=dt("2026-10-27"))
ind("impact/CHG-1042", "ServiceImpact", "CHG-1042 may interrupt the order application during restart", mayImpactService=N["asset/order-app"])
g.add((chg_ok, T("mayImpactService"), N["asset/order-app"]))

# ------------------------------------------------------------------ findings and indicators
ind("finding/svc-ownerless", "IdentityFinding", "Nine service accounts have no accountable owner", affectsIdentity=svc_pop, hasEvidence=N["evidence/iam-export-2026-10"])
kri = ind("kri/privileged-mfa", "OutcomeMetric", "Privileged MFA coverage", hasIndicatorKind=T("KriPrivilegedMfa"), hasOwner=P["ciso"],
          measurementMethod=txt("Holders of tier 0 and tier 1 roles with MFA, over all holders of those roles"))
kri2 = ind("kri/known-configuration", "OutcomeMetric", "Known configuration coverage", hasIndicatorKind=T("KriKnownCoverage"), hasOwner=P["itops"],
           measurementMethod=txt("Configuration items with a current authoritative observation, over all configuration items; unknown shown separately"))
src = ind("source/iam-registers", "SourceRecord", "Nordelle identity and configuration registers (fictional)", localIdentifier=Literal("SRC-IAM"),
          issuerName=Literal("Nordelle IT (fictional)"), sourceVersion=Literal("2026-10"), licenceTerms=Literal("internal"), hasAccessStatus=T("AccessVerified"))
ind("kri-observation/privileged-mfa-2026-10", "CoverageObservation", "Privileged MFA coverage, October 2026", observationOf=kri, observedOn=dt("2026-10-30"),
    hasSourceRecord=src, numeratorCount=nni(9), denominatorCount=nni(10), unknownStateCount=nni(0))
ind("kri-observation/known-configuration-2026-10", "CoverageObservation", "Known configuration coverage, October 2026", observationOf=kri2, observedOn=dt("2026-10-30"),
    hasSourceRecord=src, numeratorCount=nni(15), denominatorCount=nni(22), unknownStateCount=nni(7))

g.serialize(os.path.join(ROOT, "tests", "samples", "nordelle-iam.ttl"), format="turtle")
print("nordelle-iam: %d triples" % len(g))
