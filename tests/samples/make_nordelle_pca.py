# -*- coding: utf-8 -*-
"""0.10.0 policy, compliance and audit management demonstration on the SYNTHETIC Nordelle Market inc.
(POL section 12, CMP section 13, AUD section 11 fixture lists; competency questions in tests/pca_cq/).

Everything is invented test data about a fictional company. Change records marked "hypothetical" are test records,
not statements that any such regulatory or framework change exists.

The story (as of 2026-10-12), on top of nordelle.ttl, nordelle-applicability.ttl and nordelle-grca.ttl:
- policy: families; the information security policy (v2 superseded, v3 published) gains statements on privileged
  access review, MFA and payment-segment remote access; a draft v4; an access control standard (published, review
  overdue) and a network standard whose statements conflict on the point-of-sale scope; acknowledgements; a training
  requirement; mapping assertions to Loi 25 s. 10, GDPR Art. 32(1) and SP 800-53 (approved, exact, partial, draft);
  the EDR exception is now linked to the legacy-server risk acceptance;
- compliance: a compliance programme and objective; adoption of NIST CSF 2.0; interpretation of Loi 25 s. 10; an
  applicability assessment at provision level with facts relied on and missing; a compliance assessment campaign;
  determinations (one compliant on expired evidence); a provision version; deadlines (GDPR 72-hour notice, annual
  privacy-officer report) and a submission; nonconformities with root causes; a hypothetical framework change;
- audit: audit function and charter; methodology; plan 2026 v1 and v2 (identity audit deferred by the audit
  committee); engagement ENG-2026-05 (identity and access: assurance, compliance focus) with programme, a quarterly
  privileged-access test on two accounts, a stale-evidence test, an observation validated as finding F-2026-05-01
  (root cause: process), shared corrective action, management response, follow-up; workpapers (one self-reviewed);
  a quality review; an independence conflict; conclusion and issued report; asset valuations (crown jewels).
Writes tests/samples/nordelle-pca.ttl (imports nordelle-grca).
"""
import os
from rdflib import Graph, Namespace, URIRef, Literal
from rdflib.namespace import RDF, RDFS, OWL, XSD, SKOS, DCTERMS

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
BASE = "https://w3id.org/crgo/"
ids = dict(l.rstrip("\n").split("\t") for l in open(os.path.join(ROOT, "src", "ids.tsv"), encoding="utf-8"))
T = lambda k: URIRef(BASE + "CRGO_%07d" % int(ids[k]))
N = Namespace("https://example.org/crgo-sample/nordelle/")
SRC = Namespace(BASE + "vocab/sources/")
CCO = Namespace("https://www.commoncoreontologies.org/"); BFO = Namespace("http://purl.obolibrary.org/obo/")
PERSON, GROUP = CCO.ont00001262, CCO.ont00000300
_voc = {}
def concept(scheme, notation):
    if scheme not in _voc:
        _voc[scheme] = {str(n): s for s, n in Graph().parse(os.path.join(ROOT, "ontology", "vocab", scheme + ".ttl")).subject_objects(SKOS.notation)}
    return _voc[scheme][notation]

g = Graph(); g.bind("crgo", BASE); g.bind("nordelle", N); g.bind("dcterms", DCTERMS)
o = URIRef("https://example.org/crgo-sample/nordelle-pca")
g.add((o, RDF.type, OWL.Ontology)); g.add((o, OWL.imports, URIRef("https://example.org/crgo-sample/nordelle-grca")))
for v in ("csf2", "iso27002-2022"):
    g.add((o, OWL.imports, URIRef(BASE + "vocab/" + v)))
g.add((o, URIRef("http://purl.org/vocab/vann/preferredNamespaceUri"), Literal(str(N))))
g.add((o, RDFS.label, Literal("Nordelle Market inc. - SYNTHETIC policy, compliance and audit management data for CRGO 0.10.0", lang="en")))
g.add((o, DCTERMS.type, Literal("synthetic test data")))
dt = lambda d: Literal(d + "T00:00:00", datatype=XSD.dateTime)
dec = lambda x: Literal(str(x), datatype=XSD.decimal)
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
def add(s, k, *vals):
    for v in vals: g.add((s, T(k), v))

org = N.org
P = {k: N["person/" + k] for k in ("ceo", "cae", "itops", "compliance", "chair", "ciso")}
for k, name in (("auditor2", "Nordelle internal auditor (fictional)"), ("iam-lead", "Nordelle identity and access lead (fictional)"),
                ("netops", "Nordelle network operations lead (fictional)"), ("store-mgr", "Nordelle store operations manager (fictional)"),
                ("qa-assessor", "External quality assessor (fictional)")):
    P[k] = ind("person/" + k, str(PERSON), name)
board, ac = N["gov/board"], N["gov/audit-committee"]
pol, pv3, pv2 = N["policy/infosec"], N["policy-version/infosec-3"], N["policy-version/infosec-2"]
ps_restore, ps_edr = N["policy/infosec/restore-tests"], N["policy/infosec/edr"]
s10, s38, s35 = concept("loi25", "P-39.1 s. 10"), concept("loi25", "P-39.1 s. 3.8"), concept("loi25", "P-39.1 s. 3.5 (1st para.)")
art32, art33 = concept("gdpr", "GDPR Art. 32(1)"), concept("gdpr", "GDPR Art. 33(1)")
ac2, ac2_1, ac6, cp9 = (concept("sp800-53r5", x) for x in ("AC-2", "AC-2(1)", "AC-6", "CP-9"))
gvpo = concept("csf2", "GV.PO-01")
csf = URIRef(BASE + "vocab/csf2")

# ------------------------------------------------------------------ assets and valuations (crown jewels)
for key, asset, crown, label in (("payment-service", N["asset/payment-service"], True, "payment service"), ("customer-db", N["asset/customer-db"], True, "customer database"),
                                 ("identity-service", N["asset/identity-service"], True, "identity service"), ("kiosk", N["asset/kiosk"], False, "in-store kiosk"),
                                 ("legacy-pos", N["asset/legacy-pos-server"], True, "legacy point-of-sale server")):
    ind("valuation/" + key, "AssetValuation", "Valuation of the %s (2026)" % label, valuationOf=asset, isCrownJewel=Literal(crown), valuedBy=org)

# ------------------------------------------------------------------ policy management
fam_access = ind("policy-family/access-control", "PolicyFamily", "Access control family")
fam_net = ind("policy-family/network", "PolicyFamily", "Network security family")
add(pol, "inPolicyFamily", fam_access)
add(pol, "hasOwner", P["ciso"]); add(P["ciso"], "accountableFor", pol)
clause5 = ind("policy-clause/infosec-3/5", "PolicyClause", "Information security policy v3, section 5 (access)", clauseOf=pv3, localIdentifier=Literal("5"))
def statement(key, label, version, modality=T("ModalityMust"), clause=None, **kw):
    s = ind(key, "PolicyStatement", label, statementInVersion=version, hasNormativeModality=modality, **kw)
    if clause is not None: add(s, "inClause", clause)
    return s
ps_pam = statement("policy/infosec/privileged-review", "Privileged access is reviewed quarterly", pv3, clause=clause5,
                   statementOfPolicy=pol, localIdentifier=Literal("PREQ-000014"), statementText=txt("Privileged access shall be reviewed quarterly."),
                   appliesToScope=[N["asset/identity-service"], N["asset/payment-service"]], intendedToMitigate=N["scenario/credential-compromise"],
                   derivedFromRequirement=ac2_1)
ps_mfa = statement("policy/infosec/mfa-admin", "Administrator accounts use multi-factor authentication", pv3, clause=clause5, statementOfPolicy=pol,
                   localIdentifier=Literal("PREQ-000015"), appliesToScope=N["asset/identity-service"], intendedToMitigate=N["scenario/credential-compromise"])
add(ps_restore, "localIdentifier", Literal("PREQ-000021")); add(ps_restore, "intendedToMitigate", N["scenario/ransomware"]); add(ps_restore, "appliesToScope", N["asset/customer-db"])
add(ps_edr, "localIdentifier", Literal("PREQ-000022")); add(ps_edr, "appliesToScope", N["asset/legacy-pos-server"])
add(ps_pam, "statementImplementedBy", N["control/pam-review"]); add(ps_mfa, "statementImplementedBy", N["control/mfa"])
add(ps_restore, "statementImplementedBy", N["control/backups"]); add(ps_edr, "statementImplementedBy", N["control/edr"])
pam_measure = ind("control/pam-review", "ControlMeasure", "Quarterly privileged access review", hasControlStatus=T("CtlInPlace"), implementsControl=ac2_1,
                  protectsAsset=N["asset/identity-service"], hasOwner=P["iam-lead"])
# draft v4 (POL fixture: one draft version)
pv4 = ind("policy-version/infosec-4", "PolicyVersion", "Nordelle information security policy, version 4 (draft)", versionOfDirective=pol, versionLabel=Literal("4-draft"),
          hasLifecycleState=T("LifeDraft"))
statement("policy/infosec-4/pam-monthly", "Privileged access is reviewed monthly (draft)", pv4, statementOfPolicy=pol)
add(pv4, "supersedes", pv3)
# standards with their versions; the access standard's review is overdue (CQ06)
std_access = ind("standard/access-control", "TechnicalStandard", "Access control standard", inPolicyFamily=fam_access, hasOwner=P["iam-lead"])
sv_access = ind("standard-version/access-control-1", "DirectiveVersion", "Access control standard, version 1", versionOfDirective=std_access, versionLabel=Literal("1.0"),
                hasLifecycleState=T("LifePublished"), effectiveOn=dt("2024-09-01"), reviewIntervalMonths=nni(12), reviewDueOn=dt("2025-09-01"))
ind("decision/approve-access-standard-1", "DecisionRecord", "CISO approves the access control standard v1", decisionOn=sv_access, decisionMadeBy=P["ciso"],
    hasDecisionOutcome=T("DecApproved"), decidedOn=dt("2024-08-20"))
ind("review/access-standard-2024", "DirectiveReview", "Review of the access control standard at issue (2024)", reviewOf=sv_access, hasReviewTrigger=T("RevTrigScheduled"),
    assessedOn=dt("2024-08-15"), assessedBy=P["ciso"])
add(pv3, "reviewDueOn", dt("2027-02-01"))
ind("review/infosec-2026", "DirectiveReview", "Review of the information security policy after the 2025 audit (led to v3)", reviewOf=pv2,
    hasReviewTrigger=[T("RevTrigScheduled"), T("RevTrigFinding")], reviewTriggeredBy=N["finding/F-2026-03-01"], assessedOn=dt("2026-01-10"), assessedBy=P["ciso"])
ps_vendor = statement("standard/access-control/vendor-remote", "Vendor remote administration of point-of-sale systems uses the vendor VPN", sv_access,
                      appliesToScope=N["asset/legacy-pos-server"])
std_net = ind("standard/network", "TechnicalStandard", "Network segmentation standard", inPolicyFamily=fam_net, hasOwner=P["netops"])
sv_net = ind("standard-version/network-2", "DirectiveVersion", "Network segmentation standard, version 2", versionOfDirective=std_net, versionLabel=Literal("2.0"),
             hasLifecycleState=T("LifePublished"), effectiveOn=dt("2026-03-01"), reviewIntervalMonths=nni(12))
ind("decision/approve-network-standard-2", "DecisionRecord", "CISO approves the network standard v2", decisionOn=sv_net, decisionMadeBy=P["ciso"],
    hasDecisionOutcome=T("DecApproved"), decidedOn=dt("2026-02-20"))
ind("review/network-standard-2026", "DirectiveReview", "Review of the network standard at issue (2026)", reviewOf=sv_net, hasReviewTrigger=T("RevTrigTechnology"),
    assessedOn=dt("2026-02-15"), assessedBy=P["netops"])
ps_noinbound = statement("standard/network/no-inbound-pos", "No inbound remote access to the point-of-sale segment", sv_net, modality=T("ModalityMustNot"),
                         appliesToScope=N["asset/legacy-pos-server"])
ind("guideline/password-managers", "Guideline", "Guideline: staff may use the approved password manager", appliesToScope=N["asset/identity-service"])
# acknowledgements, training
for who, day in (("store-mgr", "2026-02-10"), ("itops", "2026-02-05")):
    ind("ack/%s-infosec-3" % who, "PolicyAcknowledgement", "Acknowledgement of policy v3 by %s" % who, attestedBy=P[who], attestedOn=dt(day),
        attestationAbout=pv3, hasKnowledgeStatus=T("KsManagementDecision"))
tr = ind("training/privileged-users", "TrainingRequirement", "Annual privileged-user security training")
add(ps_pam, "requiresTraining", tr)
# mapping assertions (I1)
def mapping(key, label, src, tgt, mtype, state, conf, rationale, edition=None, reviewer=None, on=None):
    m = ind(key, "MappingAssertion", label, mappingSource=src, mappingTarget=tgt, hasMappingType=T(mtype), hasReviewState=T(state),
            mappingConfidence=dec(conf), rationale=txt(rationale))
    if edition is not None: add(m, "mappedEdition", *(edition if isinstance(edition, list) else [edition]))
    if reviewer is not None: add(m, "reviewedBy", reviewer)
    if on: add(m, "reviewedOn", dt(on))
    return m
mapping("mapping/pam-ac2-1", "Privileged review statement maps fully to SP 800-53 AC-2(1)", ps_pam, ac2_1, "MapFullCoverage", "RevApproved", 0.9,
        "The statement requires the periodic review that AC-2(1) automates; Nordelle's review is manual, which AC-2(1) does not exclude.",
        SRC["nist-sp800-53r5"], P["compliance"], "2026-03-15")
mapping("mapping/restore-loi25-s10", "Restore-test statement partly covers Loi 25 s. 10", ps_restore, s10, "MapPartialCoverage", "RevApproved", 0.7,
        "Restore tests address availability safeguards only; s. 10 also covers confidentiality measures.", SRC["qc-p-39.1"], P["compliance"], "2026-03-15")
mapping("mapping/edr-loi25-s10", "EDR statement partly covers Loi 25 s. 10", ps_edr, s10, "MapPartialCoverage", "RevApproved", 0.6,
        "Detection on servers is one of the security measures s. 10 requires.", SRC["qc-p-39.1"], P["compliance"], "2026-03-15")
mapping("mapping/mfa-loi25-s10", "MFA statement partly covers Loi 25 s. 10", ps_mfa, s10, "MapPartialCoverage", "RevApproved", 0.7,
        "Strong authentication of administrators is a security measure under s. 10.", SRC["qc-p-39.1"], P["compliance"], "2026-03-15")
mapping("mapping/mfa-gdpr-32", "MFA statement partly covers GDPR Art. 32(1) (draft)", ps_mfa, art32, "MapPartialCoverage", "RevDraft", 0.5,
        "Pending qualified review of GDPR applicability.")
for tgt, mt, scheme_src, why in ((s10, "MapPartialCoverage", "qc-p-39.1", "Backups protect availability of personal information."),
                                 (art32, "MapPartialCoverage", "eu-gdpr", "Art. 32(1)(c) names the ability to restore availability."),
                                 (cp9, "MapFullCoverage", "nist-sp800-53r5", "The backup measure implements CP-9 as written.")):
    mapping("mapping/backups-%s" % str(tgt).rsplit("/", 1)[1], "Backup measure maps to %s" % str(tgt).rsplit("/", 1)[1], N["control/backups"], tgt, mt, "RevApproved", 0.8, why,
            SRC[scheme_src], P["compliance"], "2026-04-01")
mapping("mapping/pam-gvpo", "Privileged review statement relates to CSF GV.PO-01", ps_pam, gvpo, "MapRelated", "RevUnderReview", 0.4,
        "The statement is part of the policy GV.PO-01 asks to establish.")
# the EDR exception escalated to the existing risk acceptance (POL fixture: active exception with risk escalation)
add(N["exception/edr-legacy-pos"], "authorisedByRiskAcceptance", N["risk-acceptance/legacy-pos-2026"])

# ------------------------------------------------------------------ compliance management
prog = ind("compliance/programme", "ComplianceProgramme", "Nordelle compliance programme 2026", concernsOrganisation=org,
           programmeCovers=[s10, s38, s35, art33, N["compliance/adoption-csf2"]], hasOwner=P["compliance"])
ind("compliance/objective-register-review", "ComplianceObjective", "Review every obligation of the register at least once a year", objectiveOfProgramme=prog)
ind("compliance/adoption-csf2", "FrameworkAdoption", "Nordelle adopts NIST CSF 2.0 (Govern and Protect functions) for its Québec operations",
    adoptsFramework=csf, adoptionScope=txt("Functions GV and PR, all Québec stores and the online shop"), concernsOrganisation=org,
    decisionOn=csf, decisionMadeBy=board, hasDecisionOutcome=T("DecApproved"), decidedOn=dt("2026-01-20"), validFrom=dt("2026-02-01"))
add(P["compliance"], "accountableFor", s10); add(P["ciso"], "accountableFor", s38)
interp = ind("compliance/interpretation-s10", "RequirementInterpretation", "Nordelle reading of Loi 25 s. 10 for its retail systems", interpretationOf=s10,
             hasLegalReviewState=T("LegalUnderReview"), dependsOnAssumption=N["assumption/profile-reading"], isPrivileged=Literal(False))
ind("applicability/s10-2026-10-01", "ApplicabilityAssessment", "Applicability of Loi 25 s. 10 to Nordelle (provision level)", applicabilityOf=s10,
    concernsOrganisation=org, hasApplicabilityState=T("AppApplicable"), assessedOn=dt("2026-10-01"), assessedBy=P["compliance"], hasJurisdiction=T("JurQuebec"),
    ruleVersion=Literal("legal-conditions 0.10.0"), factRelied=[txt("Establishment in Québec"), txt("Holds customer personal information")])
ind("applicability/art33-2026-10-01", "ApplicabilityAssessment", "Applicability of GDPR Art. 33(1) to Nordelle (provision level)", applicabilityOf=art33,
    concernsOrganisation=org, hasApplicabilityState=T("AppPotentiallyApplicable"), assessedOn=dt("2026-10-01"), assessedBy=P["compliance"], hasJurisdiction=T("JurEU"),
    ruleVersion=Literal("legal-conditions 0.10.0"), factRelied=txt("Online shop delivers to customers in France"),
    missingFact=txt("Whether goods are offered to persons in the EU in the sense of Art. 3(2)(a)"))
camp = ind("compliance/campaign-2026", "ComplianceAssessmentCampaign", "Compliance assessment campaign 2026 (Loi 25)", concernsOrganisation=org,
           assessmentScope=Literal("Loi 25 security and incident obligations, all systems"), assessedOn=dt("2026-10-01"), assessedBy=P["ciso"])
for d in ("loi25-register", "loi25-security", "loi25-pia"):
    add(N["compliance/" + d], "determinationIn", camp)
# compliant on expired evidence (CMP CQ4) and an earlier determination for history (CMP CQ8)
add(N["evidence/incident-register"], "validUntil", dt("2026-06-30"))
ind("compliance/loi25-register-2025", "ComplianceDetermination", "Loi 25 s. 3.8 register: 2025 determination", complianceWith=s38, concernsOrganisation=org,
    hasComplianceState=T("CompPartial"), assessedOn=dt("2025-10-01"), assessedBy=P["ciso"], hasJurisdiction=T("JurQuebec"),
    evidenceGap=Literal("Register incomplete for 2024 incidents."), hasKnowledgeStatus=T("KsAuditConclusion"), hasEvidence=N["evidence/incident-register"])
ind("compliance/sufficiency-register", "EvidenceSufficiencyAssessment", "Sufficiency of the incident register as evidence for s. 3.8", sufficiencyOf=N["evidence/incident-register"],
    sufficiencyFor=s38, hasSufficiencyConclusion=T("SuffStale"), assessedBy=P["compliance"], assessedOn=dt("2026-10-05"))
ind("compliance/provision-version/s10-2021", "ProvisionVersion", "Loi 25 s. 10 as in force since 22 September 2023", provisionVersionOf=s10,
    validFrom=dt("2023-09-22"), hasSourceRecord=SRC["qc-p-39.1"])
add(N["compliance/loi25-security"], "evaluatesProvisionVersion", N["compliance/provision-version/s10-2021"])
# deadlines and a submission (CMP CQ10)
dl72 = ind("compliance/deadline/gdpr-72h-2026-08", "ComplianceDeadline", "GDPR Art. 33(1) notice for the August phishing incident: 72 hours from awareness",
           deadlineFor=art33, hasDeadlineTriggerKind=T("DeadlineEvent"), dueOffsetHours=nni(72), deadlineTriggeredBy=N["incident/2026-08-phishing/confirmation"],
           deadlineComputation=txt("72 hours from the incident confirmation (awareness), calendar hours, Montréal time; applies only if GDPR applies"),
           hasJurisdiction=T("JurEU"))
dl_annual = ind("compliance/deadline/annual-privacy-report-2026", "ComplianceDeadline", "Annual report of the privacy officer to the board (internal commitment), due 2026-10-31",
                deadlineFor=prog, hasDeadlineTriggerKind=T("DeadlineCalendar"), dueOn=dt("2026-10-31"), hasJurisdiction=T("JurQuebec"))
dl_cai = ind("compliance/deadline/cai-register-2027", "ComplianceDeadline", "Register review before the 2027 audit cycle (internal commitment), due 2027-01-15",
             deadlineFor=s38, hasDeadlineTriggerKind=T("DeadlineCalendar"), dueOn=dt("2027-01-15"), hasJurisdiction=T("JurQuebec"))
cai = ind("authority/cai", "RegulatoryAuthority", "Commission d'accès à l'information du Québec", hasJurisdiction=T("JurQuebec"))
sub = ind("compliance/submission/cai-notice-2026-08", "RegulatorySubmission", "Notice to the CAI of the August confidentiality incident (synthetic test record)",
          submissionTo=cai, submissionUnder=s35, hasSubmissionState=T("SubAcknowledged"), submittedOn=dt("2026-08-06"), receiptAcknowledgedOn=dt("2026-08-07"),
          receiptEvidence=N["evidence/cai-receipt-2026-08"])
ind("evidence/cai-receipt-2026-08", "EvidenceItem", "Acknowledgement of receipt from the CAI portal (synthetic)", localIdentifier=Literal("cai-receipt-2026-08"),
    collectedOn=dt("2026-08-07"))
# nonconformities with root causes (CMP CQ9, AUD CQ10)
add(N["compliance/nonconformity-restore-2026"], "hasRootCauseCategory", T("RootProcess"))
nc2 = ind("compliance/nonconformity-pam-2026", "Nonconformity", "Privileged access not reviewed in Q2 2026 (statement PREQ-000014)", nonconformityWith=ps_pam,
          concernsOrganisation=org, identifiedOn=dt("2026-07-15"), hasRootCauseCategory=T("RootProcess"), raisedFrom=N["control-assessment/pam-review-2026-07"])
ca_nc2 = ind("action/CA-NC-2026-07", "CorrectiveAction", "Automate the quarterly privileged-access review reminder and evidence capture", correctsFinding=nc2,
             hasOwner=P["iam-lead"], dueOn=dt("2026-09-30"), hasActionStatus=T("ActionInProgress"))
# hypothetical framework change (POL CQ03, CMP CQ5)
ind("regulatory-change/hypothetical-ac2-revision", "RegulatoryChange", "HYPOTHETICAL test record: revision of SP 800-53 AC-2(1) wording", changeOf=ac2_1,
    hasChangeType=T("ChangeAmended"), identifiedOn=dt("2026-10-05"))
add(N["scenario/ransomware"], "triggersObligation", s10)

# ------------------------------------------------------------------ audit management
fn = ind("audit/function", "AuditFunction", "Nordelle internal audit function")
ind("audit/charter-2025", "AuditCharter", "Internal audit charter, approved by the audit committee (2025)", charterOf=fn)
meth = ind("audit/methodology-2026", "AuditMethodology", "Nordelle internal audit methodology 2026", versionLabel=Literal("2026.1"))
add(N["audit/ENG-2026-03"], "hasEngagementType", T("EngAssurance")); add(N["audit/ENG-2026-03"], "hasEngagementState", T("EngStateClosed"))
add(N["audit/ENG-2026-03"], "followsMethodology", meth)
plan1, plan2 = N["audit/plan-2026"], ind("audit/plan-2026-v2", "AuditPlan", "Internal audit plan 2026, version 2 (June revision)")
add(plan2, "supersedes", plan1); add(plan2, "followsMethodology", meth)
ent_iam = ind("audit/entity/identity-access", "AuditableEntity", "Identity and access management", auditableEntityFor=N["scenario/credential-compromise"])
ent_stores = ind("audit/entity/store-operations", "AuditableEntity", "Store operations (point of sale)", auditableEntityFor=N["scenario/ransomware"])
add(N["audit/universe"], "includesAuditableEntity", ent_iam, ent_stores)
for plan, key, eng, ent, state, extra in (
        (plan1, "v1-backup", N["audit/ENG-2026-03"], N["audit/entity/backup-recovery"], "EntryApproved", {}),
        (plan1, "v1-iam", N["audit/ENG-2026-05"], ent_iam, "EntryApproved", {}),
        (plan2, "v2-backup", N["audit/ENG-2026-03"], N["audit/entity/backup-recovery"], "EntryCompleted", {}),
        (plan2, "v2-iam", N["audit/ENG-2026-05"], ent_iam, "EntryApproved", {}),
        (plan2, "v2-stores", None, ent_stores, "EntryDeferred", {"deferralReason": txt("Point-of-sale replacement in Q1 2027; audit after replacement."),
                                                                  "approvingAuthority": ac})):
    e = ind("audit/plan-entry/" + key, "AuditPlanEntry", "Plan entry %s" % key, entryInPlan=plan, entryForAuditableEntity=ent, hasPlanEntryState=T(state),
            priorityRationale=txt("Risk-based priority from the 2026 risk assessment"), entryInformedBy=N["assessment/2026"])
    if eng is not None: add(e, "entryForEngagement", eng)
    for k, v in extra.items(): add(e, k, v)
add(N["audit/plan-entry/v1-iam"], "isMandatory", Literal(False))
ind("audit/plan-entry/v1-stores", "AuditPlanEntry", "Plan entry v1-stores", entryInPlan=plan1, entryForAuditableEntity=ent_stores, hasPlanEntryState=T("EntryApproved"),
    priorityRationale=txt("Ransomware exposure of point-of-sale systems"), estimatedEffortHours=nni(120))
eng = ind("audit/ENG-2026-05", "AuditEngagement", "ENG-2026-05 Identity and access management audit", engagementOn=ent_iam,
          hasEngagementType=[T("EngAssurance"), T("EngCompliance")], hasEngagementState=T("EngStateReporting"), followsMethodology=meth,
          periodStart=dt("2026-01-01"), periodEnd=dt("2026-06-30"), localIdentifier=Literal("ENG-2026-05"))
add(N["audit/plan-2026"], "plannedEngagement", eng)
add(P["cae"], "accountableFor", eng)
obj = ind("audit/ENG-2026-05/objective", "AuditObjective", "Privileged access is reviewed as policy requires"); add(eng, "hasAuditObjective", obj)
crit = ind("audit/ENG-2026-05/criterion-pam", "AuditCriterion", "Criterion: policy statement PREQ-000014 (quarterly privileged access review)", criterionRefersTo=ps_pam)
add(eng, "usesCriterion", crit)
proc = ind("audit/ENG-2026-05/proc-pam", "AuditProcedure", "Re-perform the quarterly privileged access review for two sampled accounts",
           usesAssessmentMethod=T("MethodTest"), servesObjective=obj, procedureStep=txt("Select two privileged accounts; obtain Q1 and Q2 review evidence; compare."))
prog_a = ind("audit/ENG-2026-05/programme", "AuditProgramme", "ENG-2026-05 work programme", hasProcedure=proc); add(eng, "followsProgramme", prog_a)
popu = ind("audit/ENG-2026-05/population", "Population", "Privileged accounts on 2026-06-30", populationSize=nni(14), populationDescription=txt("Export of the PAM vault, 2026-06-30"))
samp = ind("audit/ENG-2026-05/sampling", "SamplingPlan", "Judgemental sample of two administrator accounts", testedPopulation=popu, plannedSampleSize=nni(2),
           hasSamplingMethod=T("SampleJudgemental"), samplingRationale=txt("Highest-privilege accounts"), samplingSeed=Literal("n/a (judgemental)"))
for k, res in (("adm-01", "SampleConforming"), ("adm-07", "SampleDeviation")):
    ind("audit/ENG-2026-05/sample/" + k, "SampleItem", "Account %s" % k, sampleOf=samp, hasSampleResult=T(res))
ev_pam = ind("evidence/pam-review-export-q2", "TestEvidence", "PAM review export, Q1-Q2 2026", localIdentifier=Literal("pam-review-export-q2"),
             collectedOn=dt("2026-07-10"), periodStart=dt("2026-01-01"), periodEnd=dt("2026-06-30"), evidenceHash=Literal("9f2c" + "0" * 60))
test = ind("control-assessment/pam-review-2026-07", "ControlAssessment", "Internal audit test of the quarterly privileged access review (H1 2026)",
           evaluatesControlMeasure=pam_measure, assessedOn=dt("2026-07-12"), hasTestResult=T("TestIneffective"), assessedBy=P["auditor2"],
           performedInCapacity=T("LineInternalAudit"), hasEvidence=ev_pam, withinEngagement=eng, executesProcedure=proc, concernsOrganisation=org,
           usesSamplingPlan=samp, periodStart=dt("2026-01-01"), periodEnd=dt("2026-06-30"))
ev_old = ind("evidence/pam-policy-2023", "DocumentaryEvidence", "Privileged access procedure (2023 edition)", localIdentifier=Literal("pam-procedure-2023"),
             validUntil=dt("2025-12-31"))
ind("control-assessment/pam-design-2026-07", "ControlAssessment", "Internal audit design review of the privileged access procedure", evaluatesControlMeasure=pam_measure,
    assessedOn=dt("2026-07-05"), hasTestResult=T("TestPartlyEffective"), assessedBy=P["auditor2"], performedInCapacity=T("LineInternalAudit"), hasEvidence=ev_old,
    withinEngagement=eng, periodStart=dt("2026-01-01"), periodEnd=dt("2026-06-30"), concernsOrganisation=org, assessesAspect=T("AspectDesign"))
obs = ind("audit/ENG-2026-05/observation-1", "AuditObservation", "Observation: Q2 review evidence missing for one account", withinEngagement=eng)
fnd = ind("finding/F-2026-05-01", "AuditFinding", "F-2026-05-01 Quarterly privileged access review not performed for all accounts", withinEngagement=eng,
          usesCriterion=crit, findingCondition=txt("No Q2 review evidence for account adm-07"), hasEvidence=ev_pam, hasFindingSignificance=T("SigHigh"),
          raisedOn=dt("2026-07-20"), hasKnowledgeStatus=T("KsAuditConclusion"), findingOnControl=pam_measure, findingAboutScenario=N["scenario/credential-compromise"],
          hasRootCauseCategory=T("RootProcess"), basedOnAssessment=test, hasOwner=P["iam-lead"])
add(obs, "validatedAs", fnd)
add(ca_nc2, "correctsFinding", fnd)  # shared corrective action (AUD section 8)
resp = ind("finding/F-2026-05-01/response", "ManagementResponse", "IAM lead agrees and will automate reminders", responseTo=fnd, hasResponseStance=T("StanceAgree"),
           respondedBy=P["iam-lead"], commitsToAction=ca_nc2)
# a second, unrelated finding with the same root cause in another unit (AUD CQ10)
fnd2 = ind("finding/F-2026-03-02", "AuditFinding", "F-2026-03-02 Store backup checklist not followed", withinEngagement=N["audit/ENG-2026-03"],
           usesCriterion=N["audit/ENG-2026-03/criterion-cp9"], findingCondition=txt("Two stores skipped the weekly checklist"), hasEvidence=N["evidence/restore-reperformance-2026-05"],
           hasFindingSignificance=T("SigMedium"), raisedOn=dt("2026-06-01"), hasKnowledgeStatus=T("KsAuditConclusion"), hasRootCauseCategory=T("RootProcess"),
           findingOnControl=N["control/backups"])
add(N["finding/F-2026-03-02"], "hasOwner", P["store-mgr"])
add(N["audit/entity/backup-recovery"], "auditableEntityFor", N["scenario/ransomware"])
ca3 = ind("action/CA-2026-03-02", "CorrectiveAction", "Re-train store managers on the weekly checklist", correctsFinding=fnd2, hasOwner=P["store-mgr"],
          dueOn=dt("2026-08-31"), hasActionStatus=T("ActionAwaitingVerification"))
ind("finding/F-2026-03-02/response", "ManagementResponse", "Store operations agree", responseTo=fnd2, hasResponseStance=T("StanceAgree"), respondedBy=P["store-mgr"], commitsToAction=ca3)
# workpapers, quality review, independence
ind("audit/ENG-2026-05/wp-01", "AuditWorkpaper", "WP-01 Sample selection and testing of privileged reviews", workpaperFor=test, preparedBy=P["auditor2"],
    preparedOn=dt("2026-07-12"), reviewedBy=P["cae"], reviewedOn=dt("2026-07-18"))
ind("audit/ENG-2026-05/wp-02", "AuditWorkpaper", "WP-02 Design review of the privileged access procedure", workpaperFor=N["control-assessment/pam-design-2026-07"],
    preparedBy=P["auditor2"], preparedOn=dt("2026-07-05"))  # not reviewed (AUD CQ-08)
ind("audit/ENG-2026-03/wp-01", "AuditWorkpaper", "WP-01 Restore re-performance", workpaperFor=N["control-assessment/backups-audit-2026-05"], preparedBy=P["cae"],
    preparedOn=dt("2026-05-15"), reviewedBy=P["chair"], reviewedOn=dt("2026-05-30"))
ind("audit/quality-review-2026", "AuditQualityReview", "External quality assessment of the internal audit function (2026)", qualityReviewOf=fn,
    hasQualityReviewKind=T("QRExternal"), assessedBy=P["qa-assessor"], assessedOn=dt("2026-09-15"))
ind("coi/auditor2-iam", "ConflictOfInterestDeclaration", "Auditor 2 declares a prior role in the identity team (until 2025)", declaredBy=P["auditor2"],
    conflictConcerns=eng)
# follow-up of the shared action: none yet (AUD CQ6); conclusion and report
concl = ind("audit/ENG-2026-05/conclusion", "AuditConclusion", "ENG-2026-05 conclusion: needs improvement", conclusionOf=eng, hasEngagementRating=T("RatingNeedsImprovement"),
            hasKnowledgeStatus=T("KsAuditConclusion"))
rep = ind("audit/ENG-2026-05/report", "AuditReport", "ENG-2026-05 report, revision 1", reportOf=eng, reportsFinding=fnd, issuedOn=dt("2026-09-01"),
          versionLabel=Literal("rev. 1"), reportAudience=txt("Audit committee; CISO; IAM lead"), preparedBy=P["cae"])
ind("decision/approve-report-ENG-2026-05", "DecisionRecord", "CAE approves the ENG-2026-05 report", decisionOn=rep, decisionMadeBy=P["cae"],
    hasDecisionOutcome=T("DecApproved"), decidedOn=dt("2026-08-30"))
# MFA operating test for CQ02 (validated control)
add(N["control-assessment/mfa-2026-09"], "periodStart", dt("2026-07-01"))

g.serialize(os.path.join(ROOT, "tests", "samples", "nordelle-pca.ttl"), format="turtle")
print("nordelle-pca: %d triples" % len(g))
