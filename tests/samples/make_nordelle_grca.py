# -*- coding: utf-8 -*-
"""GRCA and remaining-gaps demonstration on the SYNTHETIC Nordelle Market inc. (GRCA work package 9; packages R4-R8).

Everything here is invented test data about a fictional company; nothing describes a real organisation, and the
regulatory change recorded below is a hypothetical test record, not a statement that any such change exists.

The story (2026):
- governance: board, audit committee, Three Lines roles held by named people over dated periods, a delegation of
  risk-acceptance authority, an independence assessment of the internal auditor;
- policy (R4): information security policy, statements derived from Loi 25 s. 10 and SP 800-53 controls, a standard,
  a procedure, a baseline; an EDR policy exception on a legacy server, approved, with a compensating control;
- audit (WP9): engagement ENG-2026-03 on backup and recovery; internal audit re-performs a restore test in May
  (partly effective) and tests backup operation over January-April on a sample; finding F-2026-03-01 with
  criterion, condition, observed and hypothesised cause, effect, significance and evidence; recommendation,
  management response, corrective action, independent follow-up verification (effective), closure in August;
  the CISO's September restore test fails again and the finding is reopened, with a second corrective action;
- conflict (CQ-GRCA-09): IT operations' September self-assessment rates the backup control effective while internal
  audit and the CISO found it partly effective;
- monitoring exception: a failed backup job alert, not reviewed by audit, so not a finding;
- assurance: a SOC 2 type 2 report from the hosting provider, with an exception and two complementary user entity
  controls, one addressed by Nordelle and one not;
- compliance (R7): a hypothetical regulatory change record that triggers review of a determination; a nonconformity
  with the policy statement; an evidence requirement; Nordelle's obligated-party role under Loi 25;
- incident (R8): a phishing event, alert, confirmed incident, reportability assessments under Loi 25 and the GDPR,
  timeline, lesson learned;
- estimates (R6): a distribution and evidence quality on a likelihood estimate; a CyberRiskGuardian result written
  back as a proposed analytical result; decision records (rejection with rationale, deferral) and a declared conflict.

Writes tests/samples/nordelle-grca.ttl (ontology https://example.org/crgo-sample/nordelle-grca, imports nordelle).
"""
import os
from rdflib import Graph, Namespace, URIRef, Literal
from rdflib.namespace import RDF, RDFS, OWL, XSD, SKOS, DCTERMS

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
BASE = "https://w3id.org/crgo/"
ids = dict(l.rstrip("\n").split("\t") for l in open(os.path.join(ROOT, "src", "ids.tsv"), encoding="utf-8"))
T = lambda k: URIRef(BASE + "CRGO_%07d" % int(ids[k]))
N = Namespace("https://example.org/crgo-sample/nordelle/")
CCO = Namespace("https://www.commoncoreontologies.org/"); BFO = Namespace("http://purl.obolibrary.org/obo/")
ORG, PERSON, GROUP = CCO.ont00001180, CCO.ont00001262, CCO.ont00000300
_voc = {}
def concept(scheme, notation):
    if scheme not in _voc:
        _voc[scheme] = {str(n): s for s, n in Graph().parse(os.path.join(ROOT, "ontology", "vocab", scheme + ".ttl")).subject_objects(SKOS.notation)}
    return _voc[scheme][notation]

g = Graph(); g.bind("crgo", BASE); g.bind("nordelle", N); g.bind("dcterms", DCTERMS)
o = URIRef("https://example.org/crgo-sample/nordelle-grca")
g.add((o, RDF.type, OWL.Ontology)); g.add((o, OWL.imports, URIRef("https://example.org/crgo-sample/nordelle")))
g.add((o, URIRef("http://purl.org/vocab/vann/preferredNamespaceUri"), Literal(str(N))))  # organisation base, declared (ADR-008)
for v in ("legal", "loi25", "gdpr", "sp800-53r5", "sp800-53a"):
    g.add((o, OWL.imports, URIRef(BASE + "vocab/" + v)))
g.add((o, RDFS.label, Literal("Nordelle Market inc. - SYNTHETIC governance, audit, assurance and incident data for CRGO 0.9.0 and 0.10.0", lang="en")))
g.add((o, DCTERMS.type, Literal("synthetic test data")))
dt = lambda d: Literal(d + "T00:00:00", datatype=XSD.dateTime)
dec = lambda x: Literal(str(x), datatype=XSD.decimal)
nni = lambda x: Literal(x, datatype=XSD.nonNegativeInteger)
def ind(key, cls, label, **props):
    s = N[key]
    g.add((s, RDF.type, OWL.NamedIndividual))
    for c in (cls if isinstance(cls, (list, tuple)) else [cls]):
        g.add((s, RDF.type, T(c) if ":" not in c and not c.startswith("http") else URIRef(c)))
    g.add((s, RDFS.label, Literal(label, lang="en"))); g.add((s, DCTERMS.type, Literal("synthetic test data")))
    for k, v in props.items():
        for x in (v if isinstance(v, list) else [v]):
            g.add((s, T(k), x))
    return s
def add(s, k, *vals):
    for v in vals: g.add((s, T(k), v))

org, ciso = N.org, N["person/ciso"]
# ------------------------------------------------------------------ governance (WP2)
board = ind("gov/board", "GoverningBody", "Nordelle board of directors (fictional)")
ac = ind("gov/audit-committee", "AuditCommittee", "Nordelle audit committee (fictional)")
add(ac, "committeeOf", board)
people = {}
for key, name in (("ceo", "Nordelle chief executive (fictional)"), ("cae", "Nordelle internal audit lead (fictional)"),
                  ("itops", "Nordelle IT operations manager (fictional)"), ("compliance", "Nordelle compliance officer (fictional)"),
                  ("chair", "Audit committee chair (fictional)")):
    people[key] = ind("person/" + key, str(PERSON), name)
people["ciso"] = ciso
for p in (people["ceo"], people["cae"], people["itops"], people["compliance"], people["chair"], ciso):
    g.add((p, RDF.type, PERSON))
def role(key, cls, label, who, start, end=None, within=org, about=None):
    r = ind("role/" + key, cls, label); add(r, "roleWithin", within)
    if about is not None: add(r, "roleFor", about)
    g.add((who, BFO.BFO_0000196, r))
    a = ind("role-assignment/" + key, "RoleAssignment", "Assignment: " + label, assignmentOfRole=r, assignedTo=who, validFrom=dt(start))
    if end: add(a, "validUntil", dt(end))
    return r
role("cae-2024", "ChiefAuditExecutiveRole", "chief audit executive role (2024-2026)", people["cae"], "2024-01-15")
role("ciso-2023", "SecondLineRole", "information security oversight role", ciso, "2023-06-01")
role("compliance-2025", "ComplianceOfficerRole", "compliance officer role", people["compliance"], "2025-03-01")
role("backup-owner-2025", "ControlOwnerRole", "control owner role for backups", people["itops"], "2025-01-01", about=N["control/backups"])
role("backup-owner-2023", "ControlOwnerRole", "control owner role for backups (former holder)", ciso, "2023-06-01", "2024-12-31", about=N["control/backups"])
role("mfa-owner-2024", "ControlOwnerRole", "control owner role for administrator MFA", ciso, "2024-01-01", about=N["control/mfa"])
role("risk-owner-ransomware", "RiskOwnerRole", "risk owner role for the ransomware scenario", people["ceo"], "2026-01-01", about=N["scenario/ransomware"])
role("chair-2025", "GoverningBodyMemberRole", "audit committee chair role", people["chair"], "2025-06-01", within=ac)
add(people["cae"], "reportsTo", ac); add(people["ciso"], "reportsTo", people["ceo"]); add(people["itops"], "reportsTo", people["ceo"])
add(ac, "oversees", N["function/internal-audit"]); add(board, "oversees", N["scenario/ransomware"])
rc = ind("gov/risk-committee", "RiskCommittee", "Nordelle risk committee (fictional)"); add(rc, "committeeOf", board); add(rc, "oversees", N["scenario/credential-compromise"])
ind("function/internal-audit", "BusinessProcess", "internal audit function (fictional)")
add(people["itops"], "operatesControl", N["control/backups"]); add(people["itops"], "accountableFor", N["control/backups"])
add(people["ceo"], "accountableFor", N["scenario/ransomware"])
deleg = ind("gov/delegation-risk-acceptance", "DelegationOfAuthority", "Board delegation to the chief executive: accept cybersecurity risks below appetite for up to 12 months",
            delegationFrom=board, delegationTo=people["ceo"], validFrom=dt("2026-01-01"), validUntil=dt("2026-12-31"),
            delegationLimit=Literal("Risks rated below the board appetite; acceptance for at most 12 months"))
add(board, "delegatesAuthorityTo", people["ceo"])
ind("gov/independence-cae-2026", "IndependenceAssessment", "Independence of the internal audit lead with respect to backup and recovery, 2026",
    independenceOf=people["cae"], independenceFrom=N["control/backups"], hasIndependenceConclusion=T("IndepIndependent"),
    assessedOn=dt("2026-04-20"), assessedBy=people["chair"], threatsConsidered=Literal("No operational role in IT since 2024; no backup responsibilities."))
# ------------------------------------------------------------------ policy and exceptions (R4, D01)
pol = ind("policy/infosec", "Policy", "Nordelle information security policy, version 3 (fictional)", validFrom=dt("2026-02-01"))
pol2 = ind("policy/infosec-v2", "Policy", "Nordelle information security policy, version 2 (superseded)", validFrom=dt("2024-02-01"), validUntil=dt("2026-01-31"))
add(pol, "supersedes", pol2)
ps_restore = ind("policy/infosec/restore-tests", "PolicyStatement", "Backups of production systems are restored in a full test at least twice a year",
                 statementOfPolicy=pol, derivedFromRequirement=[concept("loi25", "P-39.1 s. 10"), concept("sp800-53r5", "CP-9"), concept("sp800-53r5", "CP-4")])
ps_edr = ind("policy/infosec/edr", "PolicyStatement", "Endpoint detection and response runs on every server", statementOfPolicy=pol,
             derivedFromRequirement=[concept("sp800-53r5", "SI-4"), concept("loi25", "P-39.1 s. 10")])
# 0.10.0: the policy document has versions; statements belong to an exact version and state their modality (POL section 8)
pv3 = ind("policy-version/infosec-3", "PolicyVersion", "Nordelle information security policy, version 3", versionOfDirective=pol, versionLabel=Literal("3"),
          hasLifecycleState=T("LifePublished"), effectiveOn=dt("2026-02-01"), reviewDueOn=dt("2027-02-01"), reviewIntervalMonths=nni(12))
pv2 = ind("policy-version/infosec-2", "PolicyVersion", "Nordelle information security policy, version 2", versionOfDirective=pol2, versionLabel=Literal("2"),
          hasLifecycleState=T("LifeSuperseded"), effectiveOn=dt("2024-02-01"), retiredOn=dt("2026-01-31"))
add(pv3, "supersedes", pv2)
ind("decision/approve-infosec-3", "DecisionRecord", "Board approves version 3 of the information security policy", decisionOn=pv3, decisionMadeBy=board,
    hasDecisionOutcome=T("DecApproved"), decidedOn=dt("2026-01-20"))
for st in (ps_restore, ps_edr):
    add(st, "statementInVersion", pv3); add(st, "hasNormativeModality", T("ModalityMust"))
std = ind("standard/backup", "TechnicalStandard", "Backup standard: daily backups, 30-day retention, offline copy weekly (fictional)")
add(ps_restore, "specifiedByStandard", std)
procd = ind("procedure/restore-test", "Procedure", "Restore test procedure (fictional)"); add(ps_restore, "implementedByProcedure", procd)
ind("baseline/linux-server", "ConfigurationBaseline", "Linux server baseline 2026 (fictional)")
legacy = ind("asset/legacy-pos-server", "HardwareAsset", "legacy point-of-sale server (end of support 2027)")
seg = ind("control/segmentation", ["CompensatingControl"], "Network segmentation of the legacy point-of-sale server", hasControlStatus=T("CtlInPlace"))
exc = ind("exception/edr-legacy-pos", "PolicyException", "Exception: no EDR on the legacy point-of-sale server until replacement",
          exceptionTo=ps_edr, exceptionScope=legacy, approvingAuthority=people["ceo"], compensatedBy=seg, validFrom=dt("2026-07-01"), validUntil=dt("2026-12-31"),
          exceptionJustification=Literal("The vendor does not support an EDR agent on this platform; replacement is planned for Q1 2027. Residual risk: undetected compromise of the server."))
ind("decision/approve-edr-exception", "DecisionRecord", "CEO approves the EDR exception for the legacy server", decisionOn=exc, decisionMadeBy=people["ceo"],
    hasDecisionOutcome=T("DecApproved"), decidedOn=dt("2026-06-25"), underDelegation=deleg, decisionRationale=Literal("Compensating segmentation in place; exception limited to six months."))
ind("decision/reject-edr-delay", "DecisionRecord", "Board rejects accepting the EDR delay on all servers beyond 2026", decisionOn=N["control/edr"], decisionMadeBy=board,
    hasDecisionOutcome=T("DecRejected"), decidedOn=dt("2026-09-10"), decisionRationale=Literal("Ransomware risk above appetite while EDR is missing; deployment must finish in 2026."))
ind("decision/defer-dlp", "DecisionRecord", "Audit committee defers the data loss prevention project", decisionOn=N["initiative/dlp"], decisionMadeBy=ac,
    hasDecisionOutcome=T("DecDeferred"), decidedOn=dt("2026-09-10"), decisionRationale=Literal("Waiting for the 2027 budget and the results of the EDR deployment."))
ind("initiative/dlp", "TreatmentInitiative", "Data loss prevention project (fictional)")
ra_legacy = ind("risk-acceptance/legacy-pos-2026", "RiskAcceptance", "Acceptance of the residual risk of the legacy point-of-sale server until 31 December 2026",
                decidedBy=people["ceo"], expiryDate=dt("2026-12-31"), acceptingAuthority=Literal("Chief executive, under the board delegation of January 2026"))
ind("decision/accept-legacy-risk", "DecisionRecord", "CEO accepts the residual risk of the legacy server", decisionOn=ra_legacy, decisionMadeBy=people["ceo"],
    hasDecisionOutcome=T("DecApproved"), decidedOn=dt("2026-06-25"), underDelegation=deleg, decisionRationale=Literal("Below appetite with segmentation; ends with the exception."))
ind("coi/itops-rcsa", "ConflictOfInterestDeclaration", "IT operations manager declares owning the backup control assessed in the September self-assessment",
    declaredBy=people["itops"], conflictConcerns=N["control-assessment/backups-rcsa-2026-09"])
# ------------------------------------------------------------------ evidence (WP4)
def evid(key, cls, label, collected, start=None, end=None, until=None, h=None, by=None, custodian=None, restrict=None, limit=None):
    e = ind("evidence/" + key, [cls], label, localIdentifier=Literal(key), collectedOn=dt(collected), hasEvidenceBasis=T("EvDocumented"))
    for k, v in (("periodStart", start), ("periodEnd", end), ("validUntil", until)):
        if v: add(e, k, dt(v))
    if h: add(e, "evidenceHash", Literal(h))
    if by: add(e, "collectedBy", by)
    if custodian: add(e, "custodian", custodian)
    if restrict: add(e, "accessRestriction", Literal(restrict))
    if limit: add(e, "evidenceLimitation", Literal(limit))
    return e
E_logs = evid("backup-job-logs-2026q1", "TransactionalEvidence", "Backup job logs, January to April 2026", "2026-05-12", "2026-01-01", "2026-04-30",
              h="3f0c7a1e9b5d2c4486e1aa07b3d9c2f15e8a6b0d4c7f1e2a9b3c5d7e0f1a2b3c", by=people["cae"], custodian=people["cae"], restrict="internal audit team only")
E_restore_may = evid("restore-reperformance-2026-05", "TestEvidence", "Internal audit re-performance of a full restore, May 2026", "2026-05-15",
                     by=people["cae"], custodian=people["cae"], limit="One restore of the order database; other systems not restored.")
E_old_policy = evid("restore-procedure-2023", "DocumentaryEvidence", "Restore test procedure, 2023 version", "2026-05-10", until="2025-12-31",
                    limit="Superseded in 2026; kept to show the old scope.")
E_minutes = evid("ac-minutes-2026-06", "GovernanceEvidence", "Audit committee minutes, 18 June 2026", "2026-06-18")
E_soc2 = ind("evidence/cumulus-soc2-2026", ["ExternalAssuranceReport"], "Cumulus Hosting SOC 2 type 2 report, July 2025 to June 2026 (fictional)",
             localIdentifier=Literal("cumulus-soc2-2026"), hasAssuranceReportType=T("ReportSOC2Type2"), hasAssuranceOpinion=T("OpinionQualified"),
             periodStart=dt("2025-07-01"), periodEnd=dt("2026-06-30"), issuedOn=dt("2026-08-15"), reportOnServiceOf=N["org/cloudco"],
             issuedByAssurer=ind("org/assurer", str(ORG), "Vérimax CPA (fictional service auditor)"), collectedOn=dt("2026-08-20"),
             reportScope=Literal("Hosting platform; Security and Availability categories"), hasEvidenceBasis=T("EvExternal"))
ind("soc2/exception-change", "AssuranceReportException", "Change approvals missing for 3 of 40 sampled changes", exceptionInReport=E_soc2)
cuec1 = ind("soc2/cuec-console-access", "ComplementaryUserEntityControl", "User entities manage access to their own hosting console accounts", cuecOfReport=E_soc2,
            cuecAddressedBy=N["control/mfa"])
ind("soc2/cuec-backup-config", "ComplementaryUserEntityControl", "User entities define which of their data and configuration are backed up", cuecOfReport=E_soc2)
# ------------------------------------------------------------------ audit lifecycle (WP3, WP9)
uni = ind("audit/universe", "AuditUniverse", "Nordelle audit universe 2026")
ent = ind("audit/entity/backup-recovery", "AuditableEntity", "Backup and recovery of the online ordering platform", auditableEntityFor=[N["process/online-ordering"], N["asset/backups"]])
add(uni, "includesAuditableEntity", ent)
plan = ind("audit/plan-2026", "AuditPlan", "Internal audit plan 2026 (approved by the audit committee)")
eng = ind("audit/ENG-2026-03", "AuditEngagement", "ENG-2026-03 Backup and recovery", engagementOn=ent, assessedBy=people["cae"],
          periodStart=dt("2026-05-04"), periodEnd=dt("2026-06-05"), assessmentScope=Literal("Order database and application backups, January to May 2026"))
add(plan, "plannedEngagement", eng)
aobj = ind("audit/ENG-2026-03/objective", "AuditObjective", "Backups allow the ordering platform to be restored within two days")
add(eng, "hasAuditObjective", aobj)
crit = ind("audit/ENG-2026-03/criterion-cp4", "AuditCriterion", "Criterion: contingency plan tests include full recovery to a known state (SP 800-53A CP-04(04)[01]) and the restore-test policy statement",
           criterionRefersTo=[concept("sp800-53a", "CP-04(04)[01]"), ps_restore])
crit2 = ind("audit/ENG-2026-03/criterion-cp9", "AuditCriterion", "Criterion: system-level information is backed up at the defined frequency (SP 800-53A CP-09b.)",
            criterionRefersTo=concept("sp800-53a", "CP-09b."))
add(eng, "usesCriterion", crit, crit2)
p1 = ind("audit/ENG-2026-03/proc-restore", "AuditProcedure", "Re-perform a full restore of the ordering platform into an isolated environment",
         usesAssessmentMethod=T("MethodTest"), servesObjective=[concept("sp800-53a", "CP-04(04)[01]"), concept("sp800-53a", "CP-09(02)")],
         procedureStep=Literal("Restore the latest backup set of the order database and application into an isolated environment and time it.", lang="en"),
         expectedResult=Literal("Database and application configuration restored and working within 48 hours.", lang="en"),
         exceptionLogic=Literal("Any component missing, or a restore longer than 48 hours, is an exception.", lang="en"))
p2 = ind("audit/ENG-2026-03/proc-jobs", "AuditProcedure", "Test that nightly backup jobs completed, on a sample of days",
         usesAssessmentMethod=T("MethodExamine"), servesObjective=concept("sp800-53a", "CP-09b."),
         procedureStep=Literal("Select a random sample of days and inspect the job log for completion and size.", lang="en"),
         expectedResult=Literal("A completed job for every sampled day.", lang="en"), exceptionLogic=Literal("A failed or missing job is a deviation.", lang="en"))
req = ind("audit/ENG-2026-03/request-logs", "EvidenceRequest", "Request to IT operations for backup job logs January-April 2026",
          requestedFrom=people["itops"], dueOn=dt("2026-05-11"), fulfilledBy=E_logs, withinEngagement=eng)
add(p2, "requestsEvidence", req)
pop = ind("audit/ENG-2026-03/population", "Population", "Nightly backup jobs of the order database, 1 January to 30 April 2026",
          populationSize=nni(120), populationDescription=Literal("One job per night, from the backup system's job history."))
sp = ind("audit/ENG-2026-03/sampling", "SamplingPlan", "Random sample of 25 nightly jobs", testedPopulation=pop, plannedSampleSize=nni(25),
         hasSamplingMethod=T("SampleRandom"), tolerableDeviationRate=dec(0.05), expectedDeviationRate=dec(0.0),
         samplingRationale=Literal("25 items with no expected deviations supports reliance at a 5% tolerable rate (ITAF 2208 approach).", lang="en"))
add(p2, "usesSamplingPlan", sp)
for i, (day, res) in enumerate((("2026-01-14", "SampleConforming"), ("2026-02-09", "SampleConforming"), ("2026-03-22", "SampleDeviation")), 1):
    ind("audit/ENG-2026-03/sample/%02d" % i, "SampleItem", "Backup job of %s" % day, sampleOf=sp, hasSampleResult=T(res), localIdentifier=Literal(day))
ca_restore = ind("control-assessment/backups-audit-2026-05", "ControlAssessment", "Internal audit restore test of backups, May 2026",
                 evaluatesControlMeasure=N["control/backups"], assessedOn=dt("2026-05-15"), hasTestResult=T("TestPartlyEffective"), assessedBy=people["cae"],
                 performedInCapacity=T("LineInternalAudit"), assessesAspect=T("AspectDesign"), executesProcedure=p1, withinEngagement=eng,
                 usesAssessmentMethod=T("MethodTest"), hasEvidence=[E_restore_may, E_old_policy], concernsOrganisation=org,
                 testProcedure=Literal("Full restore into an isolated environment"))
ca_oe = ind("control-assessment/backups-audit-oe-2026", ["OperatingEffectivenessAssessment"], "Internal audit test of backup operation, January-April 2026",
            evaluatesControlMeasure=N["control/backups"], assessedOn=dt("2026-05-20"), hasTestResult=T("TestPartlyEffective"), assessedBy=people["cae"],
            performedInCapacity=T("LineInternalAudit"), assessesAspect=T("AspectOperation"), executesProcedure=p2, withinEngagement=eng, usesSamplingPlan=sp,
            testedPopulation=pop, periodStart=dt("2026-01-01"), periodEnd=dt("2026-04-30"), itemsTested=nni(25), deviationsFound=nni(1),
            hasEvidence=E_logs, concernsOrganisation=org)
# existing 0.9.0 CISO assessment: who performed it (decision G3)
add(N["control-assessment/backups-2026-09"], "performedInCapacity", T("LineSecond")); add(N["control-assessment/backups-2026-09"], "assessesAspect", T("AspectDesign"))
add(N["control-assessment/mfa-2026-09"], "performedInCapacity", T("LineSecond"))
# RCSA that conflicts with the audit and the CISO (CQ-GRCA-09)
E_rcsa = evid("rcsa-questionnaire-2026-09", "DocumentaryEvidence", "IT operations control self-assessment questionnaire, September 2026", "2026-09-01",
              limit="Self-reported; no re-performance.")
ind("control-assessment/backups-rcsa-2026-09", "ControlAssessment", "IT operations self-assessment of backups, September 2026",
    evaluatesControlMeasure=N["control/backups"], assessedOn=dt("2026-09-01"), hasTestResult=T("TestEffective"), assessedBy=people["itops"],
    performedInCapacity=T("LineSelfAssessment"), usesAssessmentMethod=T("MethodInterview"), hasEvidence=E_rcsa, concernsOrganisation=org)
ind("audit/ENG-2026-03/sufficiency-restore", "EvidenceSufficiencyAssessment", "Sufficiency of the restore evidence for objective CP-04(04)[01]",
    sufficiencyOf=E_restore_may, sufficiencyFor=concept("sp800-53a", "CP-04(04)[01]"), hasSufficiencyConclusion=T("SuffSufficient"),
    assessedBy=people["cae"], assessedOn=dt("2026-05-16"), withinEngagement=eng)
ind("audit/ENG-2026-03/sufficiency-old-procedure", "EvidenceSufficiencyAssessment", "Sufficiency of the 2023 restore procedure as evidence of the current procedure",
    sufficiencyOf=E_old_policy, sufficiencyFor=ps_restore, hasSufficiencyConclusion=T("SuffStale"), assessedBy=people["cae"], assessedOn=dt("2026-05-16"), withinEngagement=eng)
defi = ind("deficiency/backups-config-scope", "ControlDeficiency", "Backup scope excludes the application configuration", deficiencyOf=N["control/backups"],
           identifiedBy=ca_restore, deficiencyAspect=T("AspectDesign"), hasDeficiencySeverity=T("DefSignificant"), identifiedOn=dt("2026-05-15"))
hyp = ind("hypothesis/migration-scope", "AnalyticalHypothesis", "The application configuration dropped out of the backup scope during the 2025 migration to Cumulus Hosting",
          hypothesisAbout=N["finding/F-2026-03-01"], hasKnowledgeStatus=T("KsAnalyticalHypothesis"))
f1 = ind("finding/F-2026-03-01", "AuditFinding", "F-2026-03-01 Restores do not recover the application configuration",
         withinEngagement=eng, usesCriterion=crit, findingCondition=Literal("The May restore recovered the database in 41 hours but not the application configuration; the platform could not run.", lang="en"),
         observedCause=Literal("The backup job definitions list the database only.", lang="en"), hypothesisedCause=hyp,
         findingEffect=Literal("After ransomware, recovery would take well beyond the two-day objective.", lang="en"), hasFindingSignificance=T("SigHigh"),
         significanceMethod=Literal("Nordelle internal audit rating guide 2026 (fictional)"), hasEvidence=[E_restore_may, E_logs], raisedOn=dt("2026-05-20"),
         findingAboutScenario=N["scenario/ransomware"], findingOnControl=N["control/backups"], basedOnAssessment=ca_restore, hasKnowledgeStatus=T("KsAuditConclusion"),
         hasOwner=people["itops"])
add(defi, "raisedFrom", f1)
rec = ind("finding/F-2026-03-01/recommendation", "Recommendation", "Add the application configuration to the backup scope and include it in every restore test", recommendationFor=f1)
add(f1, "justifiesRecommendation", rec)
ca1 = ind("action/CA-2026-03-01a", "CorrectiveAction", "Add application configuration to nightly backups and update the restore procedure", correctsFinding=f1,
          hasOwner=people["itops"], dueOn=dt("2026-07-31"), hasActionStatus=T("ActionVerified"))
ind("finding/F-2026-03-01/response", "ManagementResponse", "IT operations agrees and commits to fix the backup scope by July", responseTo=[f1, rec],
    hasResponseStance=T("StanceAgree"), respondedBy=people["itops"], commitsToAction=ca1, assessedOn=dt("2026-05-27"))
concl = ind("audit/ENG-2026-03/conclusion", "AuditConclusion", "ENG-2026-03 conclusion: backup and recovery needs improvement", conclusionOf=eng,
            hasEngagementRating=T("RatingNeedsImprovement"), basedOnAssessment=[ca_restore, ca_oe], hasKnowledgeStatus=T("KsAuditConclusion"))
rep = ind("audit/ENG-2026-03/report", "AuditReport", "ENG-2026-03 audit report", reportOf=eng, reportsFinding=f1, issuedOn=dt("2026-06-05"))
ind("gov/oversight-2026-06", "OversightActivity", "Audit committee review of report ENG-2026-03, 18 June 2026", oversightBy=ac, oversightOf=rep, hasEvidence=E_minutes)
E_verif = evid("followup-restore-2026-08", "TestEvidence", "Internal audit follow-up restore including application configuration, August 2026", "2026-08-25", by=people["cae"])
ver = ind("action/CA-2026-03-01a/verification", "FollowUpVerification", "Follow-up verification of CA-2026-03-01a by internal audit", verifiesAction=ca1,
          hasVerificationResult=T("VerifEffective"), assessedBy=people["cae"], assessedOn=dt("2026-08-25"), performedInCapacity=T("LineInternalAudit"), hasEvidence=E_verif)
ind("finding/F-2026-03-01/closure", "FindingClosure", "Closure of F-2026-03-01 after follow-up verification", closesFinding=f1, closureBasedOn=ver, closedOn=dt("2026-08-26"))
ind("finding/F-2026-03-01/reopening", "FindingReopening", "Reopening of F-2026-03-01: the September restore test again missed the configuration", reopensFinding=f1,
    reopenedOn=dt("2026-09-22"), reopeningReason=Literal("CISO restore test of 20 September 2026 (evidence restore-test) recovered no application configuration."), hasEvidence=N["evidence/restore-test"])
ind("action/CA-2026-03-01b", "CorrectiveAction", "Monitor backup job definitions for drift after platform changes", correctsFinding=f1,
    hasOwner=people["itops"], dueOn=dt("2026-11-30"), hasActionStatus=T("ActionInProgress"))
ind("monitoring/backup-job-failure-2026-09-18", "MonitoringException", "Backup monitoring alert: nightly job failed on 18 September 2026",
    exceptionRaisedOn=N["control/backups"], raisedOn=dt("2026-09-18"))
# ------------------------------------------------------------------ compliance additions (WP5, R7)
inst25 = URIRef(BASE + "vocab/legal/P-39.1")
op_role = ind("role/obligated-loi25", "ObligatedPartyRole", "Nordelle's role as an enterprise bound by the Québec private-sector Act", obligatedUnder=inst25)
g.add((org, BFO.BFO_0000196, op_role))
ind("compliance/evidence-requirement-restore", "EvidenceRequirement", "Evidence for the restore-test policy statement: two signed restore test reports a year",
    evidenceRequirementFor=ps_restore, requiredEvidence=Literal("Restore test report signed by IT operations, each half-year, listing systems and components restored."))
ind("compliance/nonconformity-restore-2026", "Nonconformity", "Nonconformity with the restore-test policy statement, 2026", nonconformityWith=ps_restore,
    concernsOrganisation=org, identifiedOn=dt("2026-05-20"), raisedFrom=f1)
chg = ind("regulatory-change/hypothetical-p39-guidance", "RegulatoryChange",
          "HYPOTHETICAL test record: new regulator guidance on confidentiality-incident risk assessment (no such change is asserted)",
          changeOf=concept("loi25", "P-39.1 s. 3.5 (2nd para.)"), hasChangeType=T("ChangeGuidance"), identifiedOn=dt("2026-10-05"), effectiveOn=dt("2026-11-01"))
g.add((chg, RDFS.comment, Literal("Synthetic record for testing reassessment triggers; it does not describe any real publication.", lang="en")))
ind("trigger/hypothetical-p39-guidance", "ReassessmentTrigger", "Review the Loi 25 security determination and incident procedure after the (hypothetical) guidance",
    triggeredBy=chg, requiresReviewOf=[N["compliance/loi25-security"], N["incident/2026-08-phishing/reportability-loi25"]], identifiedOn=dt("2026-10-05"))
# ------------------------------------------------------------------ incident (R8)
ev = ind("event/2026-08-03-phish", "SecurityEvent", "Phishing e-mail opened by a customer-service agent", occurredAt=dt("2026-08-03"))
al = ind("alert/2026-08-03-impossible-travel", "SecurityAlert", "Identity service alert: sign-in to the agent's account from an unusual country", alertAbout=ev, occurredAt=dt("2026-08-03"))
inc = ind("incident/2026-08-phishing", "Incident", "Compromise of a customer-service account by phishing (fictional)")
add(inc, "incidentInformsScenario", N["scenario/credential-compromise"])
ind("incident/2026-08-phishing/confirmation", "IncidentConfirmation", "CISO confirms the account compromise", confirmsIncident=inc, confirmationBasedOn=[al, ev],
    confirmedOn=dt("2026-08-04"), assessedBy=ciso)
ind("incident/2026-08-phishing/reportability-loi25", "BreachReportabilityAssessment", "Loi 25 reportability of the phishing incident",
    reportabilityOf=inc, reportableUnder=concept("loi25", "P-39.1 s. 3.5 (2nd para.)"), hasReportabilityState=T("ReportNotReportable"),
    assessedOn=dt("2026-08-06"), assessedBy=people["compliance"], rationale=Literal("Logs show 14 order records viewed, no financial data; risk of serious injury judged absent (synthetic reasoning).", lang="en"))
ind("incident/2026-08-phishing/reportability-gdpr", "BreachReportabilityAssessment", "GDPR reportability of the phishing incident",
    reportabilityOf=inc, reportableUnder=concept("gdpr", "GDPR Art. 33(1)"), hasReportabilityState=T("ReportUndetermined"),
    assessedOn=dt("2026-08-06"), assessedBy=people["compliance"], rationale=Literal("Unknown whether any of the 14 customers are in the EU; GDPR applicability itself awaits review.", lang="en"))
for i, (when, phase, txt) in enumerate((("2026-08-03", "PhaseDetection", "Alert raised and triaged"), ("2026-08-03", "PhaseContainment", "Account disabled, sessions revoked"),
                                        ("2026-08-04", "PhaseEradication", "Password reset, mailbox rule removed"), ("2026-08-05", "PhaseRecovery", "Agent account restored with phishing-resistant MFA"),
                                        ("2026-08-20", "PhasePostIncident", "Review held; lesson recorded")), 1):
    ind("incident/2026-08-phishing/timeline/%02d" % i, "IncidentTimelineEntry", txt, timelineOf=inc, inPhase=T(phase), occurredAt=dt(when), entryDescription=Literal(txt))
ind("incident/2026-08-phishing/lesson", "LessonLearned", "Customer-service accounts need phishing-resistant MFA, not only administrators", lessonFrom=inc,
    recommendsChangeTo=[N["control/mfa"], N["estimate/likelihood-cc"]])
# ------------------------------------------------------------------ estimates and analytical results (R3, R6)
dist = ind("estimate/likelihood-cc/distribution", "EstimateDistribution", "Triangular distribution of the credential-compromise likelihood",
           hasDistributionFamily=T("DistTriangular"), distributionParameters=Literal("min=0.1;mode=0.3;max=0.6"))
add(N["estimate/likelihood-cc"], "hasDistribution", dist); add(N["estimate/likelihood-cc"], "hasEvidenceQuality", T("QualityLow"))
add(N["estimate/likelihood-cc"], "hasKnowledgeStatus", T("KsRiskEstimate"))
res = ind("dss-result/ransomware-2026-10-02", "AnalyticalResult", "CyberRiskGuardian estimated risk for the ransomware scenario (written back, proposed)",
          resultFor=N["scenario/ransomware"], computedFromInput=[N["estimate/likelihood-rw"], N["estimate/impact-rw"]], modelName=Literal("CyberRiskGuardian"),
          modelVersion=Literal("1.1.0"), computedAt=Literal("2026-10-02T14:05:00", datatype=XSD.dateTime), contractVersion=Literal("dss/v1"),
          inputDocumentHash=Literal("9b2e64f0a1c3d5e7f9b1a3c5d7e9f1a2b4c6d8e0f2a4b6c8d0e2f4a6b8c0d2e4"), numericValue=dec(1200), hasKnowledgeStatus=T("KsRiskEstimate"))
g.add((res, T("governanceStatus"), T("StatusProposed"))); g.add((res, T("proposedBy"), N["org/dss"]))
add(N["decision/reject-edr-delay"], "informedBy", res, f1)
# Nordelle's own control-to-requirement claims (organisation data, not CRGO reference mappings)
add(N["control/backups"], "implementsControl", concept("sp800-53r5", "CP-9")); add(N["control/mfa"], "implementsControl", concept("sp800-53r5", "IA-2(1)"))
# stated on Nordelle's own measures, so that the organisation graph never asserts anything about CRGO reference IRIs (ADR-008)
add(N["control/backups"], "supportsComplianceWith", concept("loi25", "P-39.1 s. 10"))
add(N["control/mfa"], "supportsComplianceWith", concept("loi25", "P-39.1 s. 10"), concept("gdpr", "GDPR Art. 32(1)"))
ind("org/dss", str(CCO.ont00001017), "CyberRiskGuardian decision-support system (software agent acting for Nordelle's analyst)")
g.serialize(os.path.join(ROOT, "tests", "samples", "nordelle-grca.ttl"), format="turtle")
print("nordelle-grca: %d triples" % len(g))
