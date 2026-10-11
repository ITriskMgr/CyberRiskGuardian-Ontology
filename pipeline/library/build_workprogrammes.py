# -*- coding: utf-8 -*-
"""0.9.0 GRCA sprint, work package 8: two ILLUSTRATIVE audit work programmes bound to SP 800-53A objectives.

    AUD-PAM-001   privileged access management (AC-2, AC-6)
    AUD-VULN-001  vulnerability remediation (RA-5, SI-2)

They show the structure of a reusable work programme (GRCA section 8): objective, criteria, methods, the 800-53A
objectives each procedure serves, expected result, exception logic and sampling rationale. They are not a validated
audit methodology: every programme and procedure carries 'illustrative only' = true. Procedure wording is CRGO's own;
the objectives are cited by their 800-53A identifiers.

Writes data/abox/crgo-workprogrammes.ttl. Like other proposed content it is not imported by crgo-full until the
project owner approves group workprogrammes/illustrative (src/approvals.tsv).
"""
import os
from rdflib import Graph, Namespace, URIRef, Literal
from rdflib.namespace import RDF, RDFS, OWL, XSD, SKOS, DCTERMS

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
BASE = "https://w3id.org/crgo/"
ids = dict(l.rstrip("\n").split("\t") for l in open(os.path.join(ROOT, "src", "ids.tsv"), encoding="utf-8"))
T = lambda k: URIRef(BASE + "CRGO_%07d" % int(ids[k]))
W = Namespace(BASE + "data/workprogrammes/")
A53 = Graph().parse(os.path.join(ROOT, "ontology", "vocab", "sp800-53a.ttl"))
OBJ = {str(n): s for s, n in A53.subject_objects(SKOS.notation)}
APPROVALS = {}
for l in open(os.path.join(ROOT, "src", "approvals.tsv"), encoding="utf-8"):
    if l.strip() and not l.startswith("#"):
        k, d, who, date, *_ = l.rstrip("\n").split("\t"); APPROVALS[k] = (d, who, date)
METHOD = {"examine": "MethodExamine", "interview": "MethodInterview", "test": "MethodTest"}

g = Graph(); g.bind("crgo", BASE); g.bind("wp", W); g.bind("dcterms", DCTERMS)
o = URIRef(BASE + "data/workprogrammes")
g.add((o, RDF.type, OWL.Ontology)); g.add((o, OWL.versionInfo, Literal("0.9.0")))
g.add((o, OWL.versionIRI, URIRef(BASE + "data/0.9.0/workprogrammes")))
g.add((o, OWL.imports, URIRef(BASE + "crgo"))); g.add((o, OWL.imports, URIRef(BASE + "vocab/sp800-53a")))
g.add((o, DCTERMS.title, Literal("CRGO illustrative audit work programmes (not a validated methodology)", lang="en")))
g.add((o, DCTERMS.title, Literal("Programmes de travail d'audit illustratifs de CRGO (méthodologie non validée)", lang="fr")))
g.add((o, DCTERMS.license, URIRef("https://creativecommons.org/licenses/by-nc/4.0/")))

def govern(s):
    a = APPROVALS.get("workprogrammes/illustrative")
    if a and a[0] == "Approve":
        g.add((s, T("governanceStatus"), T("StatusApproved"))); g.add((s, T("approvedBy"), T("Agent" + a[1])))
        g.add((s, T("approvalDate"), Literal(a[2], datatype=XSD.date)))
    else:
        g.add((s, T("governanceStatus"), T("StatusProposed")))
    g.add((s, T("proposedBy"), T("AgentClaude"))); g.add((s, T("confidence"), T("ConfMedium")))
    g.add((s, T("evidenceSource"), Literal("GRCA specification section 8; NIST SP 800-53A Rev. 5 objectives (5.2.0 OSCAL catalogue)", lang="en")))
    g.add((s, T("isIllustrative"), Literal(True))); g.add((s, T("introducedIn"), Literal("0.9.0")))

def ind(s, cls, en, fr):
    g.add((s, RDF.type, OWL.NamedIndividual)); g.add((s, RDF.type, T(cls)))
    g.add((s, RDFS.label, Literal(en, lang="en"))); g.add((s, RDFS.label, Literal(fr, lang="fr")))
    return s

PROGRAMMES = [
 ("AUD-PAM-001", "Privileged access management", "Gestion des accès privilégiés",
  "Privileged accounts are limited to authorised people, approved before creation, reviewed periodically and removed promptly when no longer needed.",
  "Les comptes privilégiés sont réservés aux personnes autorisées, approuvés avant leur création, revus périodiquement et supprimés rapidement lorsqu'ils ne sont plus nécessaires.",
  ["AC-02", "AC-06"],
  [("01", "Inventory of privileged accounts", "Inventaire des comptes privilégiés", "examine",
    "Obtain the list of privileged accounts from each in-scope system and reconcile it with the documented account types and the list of authorised roles.",
    "Every privileged account maps to a documented account type and an authorised role.",
    "Any privileged account with no authorised owner or role is an exception.",
    ["AC-02a.[01]", "AC-06(05)", "AC-02d.03[01]"], "Full population: privileged accounts are few enough to inspect all of them."),
   ("02", "Approval before creation", "Approbation avant la création", "examine",
    "For a sample of privileged accounts created in the period, inspect the access request and check that the designated approver approved it before the account was created.",
    "Each sampled account has an approval dated on or before its creation.",
    "A missing approval, or one dated after creation, is an exception; one exception in the sample means the control did not operate effectively.",
    ["AC-02e.", "AC-02f.[01]"], "Random sample of 25 creations, or all if fewer, for a low tolerable deviation rate."),
   ("03", "Periodic access review", "Revue périodique des accès", "examine",
    "Inspect the evidence of the last two privileged access reviews: who reviewed, when, which accounts were confirmed or removed, and whether removals were carried out.",
    "Reviews occurred at the defined frequency and every removal decided was carried out.",
    "A missed review, or a removal decided but not done within the defined period, is an exception.",
    ["AC-02j.", "AC-06(07)"], "Both reviews of the period are inspected; no sampling."),
   ("04", "Removal on departure", "Suppression au départ", "test",
    "Match HR departure records for the period against account deactivation dates and measure the delay for each departing person with privileged access.",
    "Privileged access of every departing person is removed within the defined time.",
    "Any privileged account still active after the defined time following departure is an exception.",
    ["AC-02h.02", "AC-02l.[01]"], "All departures of people holding privileged access in the period."),
   ("05", "Logging of privileged functions", "Journalisation des fonctions privilégiées", "test",
    "Perform or observe a privileged action on a test system and confirm it appears in the security log with user, time and action.",
    "The privileged action is logged with enough detail to attribute it.",
    "An unlogged or unattributable privileged action is an exception.",
    ["AC-06(09)"], "Judgemental selection of one privileged function per in-scope platform."),
   ("06", "Interview of account managers", "Entretien avec les gestionnaires de comptes", "interview",
    "Interview the people who manage privileged accounts about how requests, reviews and removals are handled in practice, and compare with the documented procedure.",
    "Practice matches the documented procedure.",
    "A material difference between practice and procedure is noted for follow-up testing, not as an exception on its own.",
    ["AC-02b.", "AC-02l.[02]"], "Not applicable (interview).")]),
 ("AUD-VULN-001", "Vulnerability remediation", "Correction des vulnérabilités",
  "Vulnerabilities are found by regular scanning, analysed, and remediated within the defined response times, and security updates are installed on time.",
  "Les vulnérabilités sont détectées par des analyses régulières, analysées et corrigées dans les délais définis, et les mises à jour de sécurité sont installées à temps.",
  ["RA-05", "SI-02"],
  [("01", "Scanning coverage and frequency", "Couverture et fréquence des analyses", "examine",
    "Compare the asset inventory with the scan target lists and scan schedules for the period.",
    "All in-scope systems are scanned at the defined frequency.",
    "An in-scope system missing from scans, or a missed scheduled scan, is an exception.",
    ["RA-05a.[02]", "RA-05(03)"], "Full population of in-scope systems against scan configuration."),
   ("02", "Analysis of scan results", "Analyse des résultats d'analyse", "examine",
    "Inspect the triage records of scan results for the period to see that findings were analysed, false positives justified and risk ratings assigned.",
    "Each finding of high or critical severity has a recorded analysis.",
    "A high or critical finding with no analysis is an exception.",
    ["RA-05c."], "Random sample of 25 high or critical findings."),
   ("03", "Remediation within response times", "Correction dans les délais", "test",
    "For a sample of remediated vulnerabilities, compute the time from detection to verified remediation and compare it with the defined response time for its severity.",
    "Each sampled vulnerability is remediated within its response time, or covered by an approved exception.",
    "A late remediation without an approved policy exception is an exception.",
    ["RA-05d.", "SI-02a.[03]"], "Random sample of 25, stratified by severity so that critical findings are all included."),
   ("04", "Security update installation", "Installation des mises à jour de sécurité", "test",
    "For a sample of security updates released in the period, check installation dates on in-scope systems against the defined time period.",
    "Security-relevant updates are installed within the defined time period.",
    "An update installed late, or not installed without an approved exception, is an exception.",
    ["SI-02c.[01]", "SI-02(02)"], "Random sample of 20 update-system pairs."),
   ("05", "Testing of updates before installation", "Essai des mises à jour avant installation", "interview",
    "Interview the patch management team about how updates are tested for effectiveness and side effects, and inspect one recent test record.",
    "Updates are tested before production installation, with a record.",
    "No test record for a recent update is an exception.",
    ["SI-02b.[01]", "SI-02b.[02]"], "Judgemental selection of one recent update.")]),
]
n_proc = 0
for pid, en, fr, obj_en, obj_fr, families, procs in PROGRAMMES:
    p = ind(W[pid], "AuditProgramme", "%s %s (illustrative)" % (pid, en), "%s %s (illustratif)" % (pid, fr)); govern(p)
    g.add((p, T("localIdentifier"), Literal(pid)))
    ob = ind(W[pid + "/objective"], "AuditObjective", "Objective of %s" % pid, "Objectif de %s" % pid); govern(ob)
    g.add((ob, SKOS.definition, Literal(obj_en, lang="en"))); g.add((ob, SKOS.definition, Literal(obj_fr, lang="fr")))
    g.add((p, T("hasAuditObjective"), ob))
    for fam in families:
        cr = ind(W["%s/criterion/%s" % (pid, fam)], "AuditCriterion", "%s: SP 800-53A objectives for %s" % (pid, fam), "%s : objectifs SP 800-53A pour %s" % (pid, fam)); govern(cr)
        g.add((cr, T("criterionRefersTo"), OBJ[fam]))
    for num, pen, pfr, meth, step, expected, exc, objs, samp in procs:
        pr = ind(W["%s/%s" % (pid, num)], "AuditProcedure", "%s-%s %s" % (pid, num, pen), "%s-%s %s" % (pid, num, pfr)); govern(pr)
        g.add((p, T("hasProcedure"), pr)); g.add((pr, T("usesAssessmentMethod"), T(METHOD[meth])))
        g.add((pr, T("procedureStep"), Literal(step, lang="en"))); g.add((pr, T("expectedResult"), Literal(expected, lang="en")))
        g.add((pr, T("exceptionLogic"), Literal(exc, lang="en"))); g.add((pr, T("samplingRationale"), Literal(samp, lang="en")))
        for ob_id in objs:
            g.add((pr, T("servesObjective"), OBJ[ob_id]))  # KeyError if an identifier is not in the 800-53A vocabulary
        n_proc += 1
g.serialize(os.path.join(ROOT, "data", "abox", "crgo-workprogrammes.ttl"), format="turtle")
print("work programmes: %d programmes, %d procedures, %d triples" % (len(PROGRAMMES), n_proc, len(g)))
