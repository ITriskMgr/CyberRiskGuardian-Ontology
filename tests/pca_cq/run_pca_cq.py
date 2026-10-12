# -*- coding: utf-8 -*-
"""Competency questions of the 0.10.0 specifications on the SYNTHETIC Nordelle data:
POL CQ01-CQ10 (policy management), CMP CQ1-CQ10 (compliance management), AUD CQ-01-CQ-10 (audit management),
CQ-SIEM-01-06 and CQ-SOAR-01-06. Each CQ has a positive check with its expected result written next to it, and a
negative or variant check (a copy of the base graph changed in code, so each states what it changes).
Prints PASS/FAIL; exits non-zero on any failure."""
import copy, os, re, sys
from rdflib import Graph, URIRef, Literal, Namespace
from rdflib.namespace import RDF, RDFS, OWL, XSD, SKOS

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
HERE = os.path.dirname(os.path.abspath(__file__))
ids = dict(l.rstrip("\n").split("\t") for l in open(os.path.join(ROOT, "src", "ids.tsv"), encoding="utf-8"))
T = lambda k: URIRef("https://w3id.org/crgo/CRGO_%07d" % int(ids[k]))
N = Namespace("https://example.org/crgo-sample/nordelle/")
SRC = Namespace("https://w3id.org/crgo/vocab/sources/")
dt = lambda d: Literal(d + ("" if "T" in d else "T00:00:00"), datatype=XSD.dateTime)
dec = lambda x: Literal(str(x), datatype=XSD.decimal)
_voc = {}
def concept(scheme, notation):
    if scheme not in _voc:
        _voc[scheme] = {str(n): s for s, n in Graph().parse(os.path.join(ROOT, "ontology", "vocab", scheme + ".ttl")).subject_objects(SKOS.notation)}
    return _voc[scheme][notation]

base = Graph()
for m in ("gov", "core", "measure", "crg", "evidence", "org", "vuln", "grc", "mapping", "governance", "assurance", "audit", "incident", "policy", "compliance", "siem", "soar"):
    base.parse(os.path.join(ROOT, "ontology", "crgo-%s.ttl" % m))
for v in ("legal", "sources", "loi25", "gdpr", "sp800-53r5", "csf2", "attack-detection"):
    base.parse(os.path.join(ROOT, "ontology", "vocab", v + ".ttl"))
for f in ("nordelle", "nordelle-applicability", "nordelle-grca", "nordelle-pca", "nordelle-secops", "tenant-b"):
    base.parse(os.path.join(ROOT, "tests", "samples", f + ".ttl"))

def q(name, g, **params):
    txt = open(os.path.join(HERE, name + ".rq"), encoding="utf-8").read()
    txt = re.sub(r"\{\{(\w+)\}\}", lambda m: "<%s>" % T(m.group(1)), txt)
    return list(g.query(txt, initNs={"rdfs": RDFS, "owl": OWL, "xsd": XSD}, initBindings=params))
results = []
def check(label, cond, detail=""):
    results.append(bool(cond)); print("%s  %-92s %s" % ("PASS" if cond else "FAIL", label, detail))
def variant(*remove, add=()):
    g = copy.deepcopy(base)
    for t in remove: g.remove(t)
    for t in add: g.add(t)
    return g
ASOF = dt("2026-10-12")
s10, s38, art33, art32 = concept("loi25", "P-39.1 s. 10"), concept("loi25", "P-39.1 s. 3.8"), concept("gdpr", "GDPR Art. 33(1)"), concept("gdpr", "GDPR Art. 32(1)")
ac2_1, cp9 = concept("sp800-53r5", "AC-2(1)"), concept("sp800-53r5", "CP-9")
PAM, MFA, RESTORE, EDR = N["policy/infosec/privileged-review"], N["policy/infosec/mfa-admin"], N["policy/infosec/restore-tests"], N["policy/infosec/edr"]
short = lambda xs: sorted(str(x).rsplit("/", 1)[-1] for x in xs)

# ================================================================ policy management
rows = q("POL-01", base, target=s10, edition=SRC["qc-p-39.1"])
check("POL CQ01 positive: restore, EDR and MFA statements map (approved) to Loi 25 s. 10 in the registered edition", {r.statement for r in rows} == {RESTORE, EDR, MFA}, str(short(r.statement for r in rows)))
check("POL CQ01 negative: no statement maps to Loi 25 s. 10 under another edition", q("POL-01", base, target=s10, edition=SRC["eu-gdpr"]) == [])
g = variant((N["mapping/mfa-loi25-s10"], T("hasReviewState"), T("RevApproved")), add=[(N["mapping/mfa-loi25-s10"], T("hasReviewState"), T("RevDraft"))])
check("POL CQ01 variant: a draft mapping does not count", MFA not in {r.statement for r in q("POL-01", g, target=s10, edition=SRC["qc-p-39.1"])})
rows = {r.statement for r in q("POL-02", base)}
VENDOR, NOINB = N["standard/access-control/vendor-remote"], N["standard/network/no-inbound-pos"]
check("POL CQ02 positive: privileged review (ineffective), restore (partly effective), EDR (not tested) and the two standard statements (no implementing control) lack a validated control",
      rows == {PAM, RESTORE, EDR, VENDOR, NOINB}, str(short(rows)))
check("POL CQ02 negative: the MFA statement is implemented by MFA, last found effective", MFA not in rows)
check("POL CQ02 scope: draft v4 statements are not current and are not listed", N["policy/infosec-4/pam-monthly"] not in rows)
rows = q("POL-03", base, change=N["regulatory-change/hypothetical-ac2-revision"])
check("POL CQ03 positive: the hypothetical AC-2(1) revision affects the information security policy (owner CISO) through PREQ-000014",
      {(r.statement, r.directive, r.owner) for r in rows} == {(PAM, N["policy/infosec"], N["person/ciso"])}, str(len(rows)))
g = variant((N["regulatory-change/hypothetical-ac2-revision"], T("changeOf"), ac2_1), add=[(N["regulatory-change/hypothetical-ac2-revision"], T("changeOf"), concept("sp800-53r5", "PL-1"))])
check("POL CQ03 negative: a change to PL-1 affects no Nordelle policy", q("POL-03", g, change=N["regulatory-change/hypothetical-ac2-revision"]) == [])
rows = {(r.asset, r.statement) for r in q("POL-04", base)}
check("POL CQ04 positive: identity and payment services (privileged review ineffective) and the customer database (restore partly effective)",
      rows == {(N["asset/identity-service"], PAM), (N["asset/payment-service"], PAM), (N["asset/customer-db"], RESTORE)}, str(len(rows)))
g = variant((N["valuation/customer-db"], T("isCrownJewel"), Literal(True)), add=[(N["valuation/customer-db"], T("isCrownJewel"), Literal(False))])
check("POL CQ04 negative: once the customer database is not a crown jewel it drops out", (N["asset/customer-db"], RESTORE) not in {(r.asset, r.statement) for r in q("POL-04", g)})
rows = q("POL-05", base, statement=EDR, asOf=ASOF)
check("POL CQ05 positive: the EDR exception is active on 2026-10-12, not yet expiring, and linked to the legacy-server risk acceptance",
      [(r.exception, r.expiring.toPython(), r.acceptance) for r in rows] == [(N["exception/edr-legacy-pos"], False, N["risk-acceptance/legacy-pos-2026"])], str(rows and rows[0].expiring))
rows = q("POL-05", base, statement=EDR, asOf=dt("2026-12-15"))
check("POL CQ05 temporal: on 2026-12-15 the exception expires within 30 days", rows and rows[0].expiring.toPython() is True)
check("POL CQ05 negative: no exception to the MFA statement", q("POL-05", base, statement=MFA, asOf=ASOF) == [])
rows = {r.version for r in q("POL-06", base, asOf=ASOF)}
check("POL CQ06 positive: the access control standard v1 is overdue for review (due 2025-09-01)", rows == {N["standard-version/access-control-1"]}, str(short(rows)))
check("POL CQ06 temporal: on 2025-06-01 nothing was overdue", q("POL-06", base, asOf=dt("2025-06-01")) == [])
rows = {(r.statement, r.measure, r.result) for r in q("POL-07", base, scenario=N["scenario/credential-compromise"])}
check("POL CQ07 positive: credential compromise is meant to be mitigated by privileged review (ineffective) and MFA (effective)",
      rows == {(PAM, N["control/pam-review"], T("TestIneffective")), (MFA, N["control/mfa"], T("TestEffective"))}, str(len(rows)))
check("POL CQ07 negative: no statement is meant to mitigate the website defacement scenario", q("POL-07", base, scenario=N["scenario/web-defacement"]) == [])
rows = q("POL-08", base)
check("POL CQ08 positive: candidates on the legacy POS server: vendor-VPN access and the EDR rule against 'no inbound access' (for human review; the EDR pair is benign)",
      {(r.s1, r.s2) for r in rows} == {(VENDOR, NOINB), (EDR, NOINB)})
g = variant((N["standard/network/no-inbound-pos"], T("appliesToScope"), N["asset/legacy-pos-server"]))
check("POL CQ08 negative: with different scopes there is no candidate conflict", q("POL-08", g) == [])
rows = q("POL-09", base, directive=N["policy/infosec"], date=dt("2026-06-01"))
check("POL CQ09 positive: on 2026-06-01 version 3 was in force, approved by the board decision", [(str(r.label), r.decision) for r in rows] == [("3", N["decision/approve-infosec-3"])])
rows = q("POL-09", base, directive=N["policy/infosec-v2"], date=dt("2025-06-01"))
check("POL CQ09 temporal: on 2025-06-01 version 2 was in force (no approval record held for it)", [str(r.label) for r in rows] == ["2"])
check("POL CQ09 negative: version 2 was not in force on 2026-06-01", q("POL-09", base, directive=N["policy/infosec-v2"], date=dt("2026-06-01")) == [])
rows = {(r.finding, r.action) for r in q("POL-10", base, asOf=ASOF)}
check("POL CQ10 positive: the PAM nonconformity, F-2026-05-01 (shared action due 2026-09-30) and F-2026-03-02 persist past due",
      rows == {(N["compliance/nonconformity-pam-2026"], N["action/CA-NC-2026-07"]), (N["finding/F-2026-05-01"], N["action/CA-NC-2026-07"]),
               (N["finding/F-2026-03-02"], N["action/CA-2026-03-02"])}, str(len(rows)))
check("POL CQ10 negative: on 2026-08-01 nothing was past due", q("POL-10", base, asOf=dt("2026-08-01")) == [])

# ================================================================ compliance management
rows = q("CMP-01", base, org=N.org)
reqs = {r.req for r in rows}
check("CMP CQ1 positive: Loi 25, s. 10 (applicable, facts recorded), PIPEDA, GDPR and Art. 33(1) (potentially applicable, missing fact named)",
      {URIRef("https://w3id.org/crgo/vocab/legal/P-39.1"), s10, art33, URIRef("https://w3id.org/crgo/vocab/legal/GDPR"), URIRef("https://w3id.org/crgo/vocab/legal/PIPEDA")} == reqs
      and any(r.req == art33 and r.missing is not None for r in rows) and any(r.req == s10 and r.rule is not None for r in rows), str(len(reqs)))
check("CMP CQ1 negative: not-applicable instruments (A-2.1, R-22.1) are not listed", URIRef("https://w3id.org/crgo/vocab/legal/A-2.1") not in reqs)
rows = q("CMP-02", base, req=s10)
check("CMP CQ2 positive: Loi 25 s. 10 is supported by restore, EDR and MFA statements, with the 2023 provision version on record",
      {r.statement for r in rows} == {RESTORE, EDR, MFA} and {r.pversion for r in rows} == {N["compliance/provision-version/s10-2021"]})
check("CMP CQ2 negative: GDPR Art. 32(1) has only a draft mapping from a statement, so no statement supports it yet", q("CMP-02", base, req=art32) == [])
rows = {(r.req, r.noApplicability.toPython(), r.noOwner.toPython()) for r in q("CMP-03", base, org=N.org)}
check("CMP CQ3 positive: s. 3.8 lacks an applicability decision; s. 3.5 lacks both; Art. 33(1) lacks an owner",
      rows == {(s38, True, False), (concept("loi25", "P-39.1 s. 3.5 (1st para.)"), True, True), (art33, False, True)}, str(len(rows)))
check("CMP CQ3 negative: s. 10 has both an applicability decision and an accountable owner", s10 not in {r[0] for r in rows})
rows = {(r.det, r.why.toPython()) for r in q("CMP-04", base)}
check("CMP CQ4 positive: the s. 3.8 register determination is compliant on evidence that expired before it was made and was judged out of date",
      rows == {(N["compliance/loi25-register"], "expired"), (N["compliance/loi25-register"], "judged insufficient or out of date")}, str(rows))
g = variant((N["evidence/incident-register"], T("validUntil"), dt("2026-06-30")), (N["compliance/sufficiency-register"], T("hasSufficiencyConclusion"), T("SuffStale")),
            add=[(N["compliance/sufficiency-register"], T("hasSufficiencyConclusion"), T("SuffSufficient"))])
check("CMP CQ4 negative: with current, sufficient evidence nothing is reported", q("CMP-04", g) == [])
rows = q("CMP-05", base, change=N["regulatory-change/hypothetical-ac2-revision"])
check("CMP CQ5 positive: the hypothetical AC-2(1) change reaches PREQ-000014, the privileged-review measure and the credential-compromise scenario",
      {r.statement for r in rows} == {PAM} and N["control/pam-review"] in {r.measure for r in rows} and N["scenario/credential-compromise"] in {r.scenario for r in rows})
rows = q("CMP-05", base, change=N["regulatory-change/hypothetical-p39-guidance"])
check("CMP CQ5 variant: the hypothetical guidance on Loi 25 s. 3.5 reaches both scenarios that cite it, and no policy statement",
      {r.scenario for r in rows} == {N["scenario/credential-compromise"], N["scenario/ransomware"]} and {r.statement for r in rows} == {None}, str(len(rows)))
rows = {r.source: int(r.schemes) for r in q("CMP-06", base)}
check("CMP CQ6 positive: the backup measure supports obligations from three vocabularies (Loi 25, GDPR, SP 800-53), partly and fully",
      rows == {N["control/backups"]: 3}, str({str(k).rsplit("/", 1)[1]: v for k, v in rows.items()}))
g = variant((N["mapping/backups-GDPR_Art._32_1"], T("hasReviewState"), T("RevApproved")), (N["mapping/backups-CP-9"], T("hasReviewState"), T("RevApproved")))
check("CMP CQ6 negative: with only one approved target vocabulary, no shared control is reported", q("CMP-06", g) == [])
rows = {(r.exception, r.provision) for r in q("CMP-07", base, asOf=ASOF)}
check("CMP CQ7 positive: the EDR exception concerns a statement derived from Loi 25 s. 10, with no regulatory exemption", rows == {(N["exception/edr-legacy-pos"], s10)})
g = variant(add=[(N["x/exemption"], RDF.type, T("RegulatoryExemption")), (N["x/exemption"], T("exemptionFrom"), s10), (N["x/exemption"], T("validFrom"), dt("2026-01-01"))])
check("CMP CQ7 negative: a valid regulatory exemption for s. 10 removes it", q("CMP-07", g, asOf=ASOF) == [])
rows = {(r.req, r.state) for r in q("CMP-08", base, org=N.org, date=dt("2026-01-01"))}
check("CMP CQ8 positive: on 2026-01-01 the only conclusion was s. 3.8 partially satisfied (2025)", rows == {(s38, T("CompPartial"))}, str(rows))
rows = {(r.req, r.state) for r in q("CMP-08", base, org=N.org, date=ASOF)}
check("CMP CQ8 temporal: on 2026-10-12 the 2026 determination of s. 3.8 (satisfied) replaces the 2025 one", (s38, T("CompSatisfied")) in rows and (s38, T("CompPartial")) not in rows)
rows = {(r.item, r.cause) for r in q("CMP-09", base, asOf=ASOF)}
check("CMP CQ9 positive: process-cause items with unverified past-due actions: PAM nonconformity, F-2026-05-01, F-2026-03-02",
      rows == {(N["compliance/nonconformity-pam-2026"], T("RootProcess")), (N["finding/F-2026-05-01"], T("RootProcess")), (N["finding/F-2026-03-02"], T("RootProcess"))}, str(len(rows)))
g = variant(add=[(N["x/verif"], T("verifiesAction"), N["action/CA-2026-03-02"])])
check("CMP CQ9 negative: once its action is verified, F-2026-03-02 drops out", N["finding/F-2026-03-02"] not in {r.item for r in q("CMP-09", g, asOf=ASOF)})
rows = {r.deadline for r in q("CMP-10", base, asOf=ASOF)}
check("CMP CQ10 positive: the GDPR 72-hour notice (past, unanswered) and the annual privacy report due 2026-10-31",
      rows == {N["compliance/deadline/gdpr-72h-2026-08"], N["compliance/deadline/annual-privacy-report-2026"]}, str(short(rows)))
g = variant(add=[(N["compliance/submission/cai-notice-2026-08"], T("answersDeadline"), N["compliance/deadline/gdpr-72h-2026-08"])])
check("CMP CQ10 negative: a submission answering the 72-hour deadline removes it", N["compliance/deadline/gdpr-72h-2026-08"] not in {r.deadline for r in q("CMP-10", g, asOf=ASOF)})

# ================================================================ audit management
rows = {r.entity for r in q("AUD-01", base, threshold=dec(0.6), since=dt("2025-10-12"), asOf=ASOF)}
check("AUD CQ-01 positive: store operations (ransomware, impact 0.8) has no engagement in the last 12 months", rows == {N["audit/entity/store-operations"]}, str(short(rows)))
check("AUD CQ-01 negative: identity and access (ENG-2026-05) and backup and recovery (ENG-2026-03) were audited", N["audit/entity/identity-access"] not in rows)
rows = q("AUD-02", base, finding=N["finding/F-2026-05-01"])
check("AUD CQ-02 positive: F-2026-05-01 rests on the PREQ-000014 criterion, the PAM test procedure and the Q1-Q2 export",
      {(r.requirement, r.procedure, r.evidence) for r in rows} == {(PAM, N["audit/ENG-2026-05/proc-pam"], N["evidence/pam-review-export-q2"])})
check("AUD CQ-02 negative: an observation is not a finding and has no criterion", q("AUD-02", base, finding=N["audit/ENG-2026-05/observation-1"]) == [])
rows = {r.finding for r in q("AUD-03", base, subject=N["control/backups"], asOf=ASOF)}
check("AUD CQ-03 positive: open findings on the backup measure: F-2026-03-01 (reopened) and F-2026-03-02", rows == {N["finding/F-2026-03-01"], N["finding/F-2026-03-02"]}, str(short(rows)))
rows = {r.finding for r in q("AUD-03", base, subject=PAM, asOf=ASOF)}
check("AUD CQ-03 variant: by policy statement, PREQ-000014 has F-2026-05-01 open", rows == {N["finding/F-2026-05-01"]})
check("AUD CQ-03 temporal: between closure and reopening (2026-08-30) F-2026-03-01 was not open",
      N["finding/F-2026-03-01"] not in {r.finding for r in q("AUD-03", base, subject=N["control/backups"], asOf=dt("2026-08-30"))})
g = variant(add=[(N["x/det-ac21"], T("complianceWith"), ac2_1), (N["x/det-ac21"], T("hasComplianceState"), T("CompSatisfied"))])
rows = {(r.req, r.finding) for r in q("AUD-04", g)}
check("AUD CQ-04 positive (variant): a 'satisfied' AC-2(1) determination contradicts open finding F-2026-05-01 through PREQ-000014", (ac2_1, N["finding/F-2026-05-01"]) in rows, str(len(rows)))
check("AUD CQ-04 negative: in the base data no satisfied obligation has an open contrary finding", q("AUD-04", base) == [])
rows = q("AUD-05", base, eng=N["audit/ENG-2026-05"])
check("AUD CQ-05 positive: the issued ENG-2026-05 conclusion rests on the PAM test (export) and design review, against PREQ-000014 in policy version 3",
      {r.evidence for r in rows} == {N["evidence/pam-review-export-q2"], N["evidence/pam-policy-2023"]} and {str(r.versionLabel) for r in rows} == {"3"})
g = variant((N["audit/ENG-2026-05/report"], T("issuedOn"), dt("2026-09-01")))
check("AUD CQ-05 negative: without an issued report there is no issued conclusion to support", q("AUD-05", g, eng=N["audit/ENG-2026-05"]) == [])
rows = {r.action for r in q("AUD-06", base)}
check("AUD CQ-06 positive: agreed actions CA-NC-2026-07 and CA-2026-03-02 are not independently verified", rows == {N["action/CA-NC-2026-07"], N["action/CA-2026-03-02"]}, str(short(rows)))
check("AUD CQ-06 negative: CA-2026-03-01a was verified and is not listed", N["action/CA-2026-03-01a"] not in rows)
rows = {r.test for r in q("AUD-07", base)}
check("AUD CQ-07 positive: the PAM design review relied on the 2023 procedure, expired before the tested period", N["control-assessment/pam-design-2026-07"] in rows, str(short(rows)))
check("AUD CQ-07 negative: the PAM operating test's evidence covers the tested period", N["control-assessment/pam-review-2026-07"] not in rows)
rows = {(r.engagement, str(r.why)) for r in q("AUD-08", base)}
check("AUD CQ-08 positive: ENG-2026-05 has an unreviewed workpaper (WP-02) and a declared conflict",
      rows == {(N["audit/ENG-2026-05"], "no independent review"), (N["audit/ENG-2026-05"], "declared conflict")}, str(rows))
check("AUD CQ-08 negative: ENG-2026-03's workpaper was reviewed by someone else", not any(e == N["audit/ENG-2026-03"] for e, _ in rows))
rows = q("AUD-09", base, old=N["audit/plan-2026"])
check("AUD CQ-09 positive: plan v2 completed backup and recovery and deferred store operations, authorised by the audit committee",
      {(r.entity, r.newState, r.authority) for r in rows} == {(N["audit/entity/backup-recovery"], T("EntryCompleted"), None),
                                                              (N["audit/entity/store-operations"], T("EntryDeferred"), N["gov/audit-committee"])}, str(len(rows)))
check("AUD CQ-09 negative: the unchanged identity and access entry is not reported", N["audit/entity/identity-access"] not in {r.entity for r in rows})
rows = {(r.cause, int(r.units)) for r in q("AUD-10", base)}
check("AUD CQ-10 positive: 'process' recurs across identity and access, backup and recovery, and two requirements", any(c == T("RootProcess") and n >= 3 for c, n in rows), str(rows))
g = variant((N["finding/F-2026-03-02"], T("hasRootCauseCategory"), T("RootProcess")), (N["compliance/nonconformity-restore-2026"], T("hasRootCauseCategory"), T("RootProcess")),
            (N["compliance/nonconformity-pam-2026"], T("hasRootCauseCategory"), T("RootProcess")))
check("AUD CQ-10 negative: with a single unit for the cause, no recurring theme", q("AUD-10", g) == [])

# ================================================================ SIEM
rows = {r.scenario for r in q("SIEM-01", base, threshold=dec(0.5))}
check("CQ-SIEM-01 positive: credential compromise (impact 0.6) has no validated, tested detection; ransomware does", rows == {N["scenario/credential-compromise"]}, str(short(rows)))
check("CQ-SIEM-01 negative: website defacement (impact 0.3) is below the materiality threshold", N["scenario/web-defacement"] not in rows)
rows = {(r.rule, r.source, r.state) for r in q("SIEM-02", base)}
check("CQ-SIEM-02 positive: the impossible-travel v2 rule needs silent EDR telemetry; the ransomware rule needs degraded POS syslog",
      rows == {(N["detection-rule/impossible-travel-v2"], N["telemetry/edr-servers"], T("HealthSilent")), (N["detection-rule/rw-encryption"], N["telemetry/pos-syslog"], T("HealthDegraded"))}, str(len(rows)))
check("CQ-SIEM-02 negative: the healthy IdP source and the testing correlation rule are not listed", not any(s == N["telemetry/idp-signin"] for _, s, _ in rows))
rows = {r.alert for r in q("SIEM-03", base)}
check("CQ-SIEM-03 positive: the payment-service admin alert is untriaged on a crown jewel", rows == {N["alert/2026-10-11-payment-admin"]}, str(short(rows)))
check("CQ-SIEM-03 negative: the kiosk alert is untriaged but the kiosk is not a crown jewel; the false positive is triaged", N["alert/2026-10-10-kiosk"] not in rows)
rows = {r.technique for r in q("SIEM-04", base)}
check("CQ-SIEM-04 positive: T1078 (untested) and T1110 (degraded) lack validated coverage; T1486 is validated",
      rows == {concept("attack", "T1078"), concept("attack", "T1110")}, str(short(rows)))
rows = {r.requirement for r in q("SIEM-05", base)}
check("CQ-SIEM-05 positive: the EDR statement requires monitoring (SI-4)", EDR in rows, str(short(rows)))
check("CQ-SIEM-05 negative: the restore-test statement does not require logging or monitoring", RESTORE not in rows)
rows = q("SIEM-06", base, alert=N["alert/2026-08-03-impossible-travel"])
check("CQ-SIEM-06 positive: the August alert came from rule v1, through parser v1, with ATT&CK 19.2",
      [(str(r.ruleVersion), str(r.parserVersion), str(r.attackVersion)) for r in rows] == [("1", "1", "19.2")], str([(r.ruleVersion, r.parserVersion) for r in rows]))
rows = q("SIEM-06", base, alert=N["alert/2026-10-11-payment-admin"])
check("CQ-SIEM-06 variant: the October alert came from rule v2 (no parsed event record held)", [str(r.ruleVersion) for r in rows] == ["2"])

# ================================================================ SOAR
rows = {r.action for r in q("SOAR-01", base)}
check("CQ-SOAR-01 positive: disabling accounts and isolating hosts need approval (critical-asset gate, containment)",
      rows == {N["response-action/disable-account"], N["response-action/isolate-host"]}, str(short(rows)))
check("CQ-SOAR-01 negative: collecting logs (read-only) needs no approval", N["response-action/collect-logs"] not in rows)
rows = {(r.execution, str(r.why)) for r in q("SOAR-02", base)}
check("CQ-SOAR-02 positive: the October kiosk isolation ran on a pre-authorisation that expired on 2026-09-30",
      rows == {(N["action-execution/2026-10-10-isolate"], "expired")}, str(rows))
g = variant((N["action-execution/2026-08-03-disable"], T("authorizedBy"), N["approval/2026-08-03-disable-adm"]))
check("CQ-SOAR-02 variant: without its approval the August disablement is reported as absent",
      (N["action-execution/2026-08-03-disable"], "absent") in {(r.execution, str(r.why)) for r in q("SOAR-02", g)})
rows = {r.incident for r in q("SOAR-03", base)}
check("CQ-SOAR-03 positive: the kiosk incident and the August phishing incident both have an undetermined GDPR reportability",
      rows == {N["incident/2026-10-kiosk-malware"], N["incident/2026-08-phishing"]}, str(short(rows)))
g = variant((N["incident/2026-08-phishing/reportability-gdpr"], T("hasReportabilityState"), T("ReportUndetermined")),
            add=[(N["incident/2026-08-phishing/reportability-gdpr"], T("hasReportabilityState"), T("ReportNotReportable"))])
check("CQ-SOAR-03 negative: once the GDPR question is settled the phishing incident drops out", N["incident/2026-08-phishing"] not in {r.incident for r in q("SOAR-03", g)})
rows = {r.playbook for r in q("SOAR-04", base, threshold=dec(0.5))}
check("CQ-SOAR-04 positive: the ransomware playbook (impact 0.8) has never passed simulation", rows == {N["playbook/ransomware"]}, str(short(rows)))
check("CQ-SOAR-04 negative: the compromised-account playbook v2 passed simulation", N["playbook/compromised-account"] not in rows)
rows = {r.execution for r in q("SOAR-05", base)}
check("CQ-SOAR-05 positive: the account disablement and the kiosk isolation produced verifiable evidence",
      rows == {N["action-execution/2026-08-03-disable"], N["action-execution/2026-10-10-isolate"]}, str(short(rows)))
check("CQ-SOAR-05 negative: the read-only log collection is not a containment action", N["action-execution/2026-10-10-collect"] not in rows)
rows = q("SOAR-06", base, execution=N["action-execution/2026-08-03-disable"])
check("CQ-SOAR-06 positive: the August disablement ran under compromised-account playbook v1, approved by the SOC lead (granted)",
      [(r.version, str(r.versionLabel), r.authority, r.status) for r in rows] == [(N["playbook-version/compromised-account-1"], "1", N["person/soc-lead"], T("ApprGranted"))])
check("CQ-SOAR-06 negative: an execution with no automation run returns nothing", q("SOAR-06", base, execution=N["x/none"]) == [])

print("%d of %d checks passed" % (sum(results), len(results)))
sys.exit(0 if all(results) else 1)
