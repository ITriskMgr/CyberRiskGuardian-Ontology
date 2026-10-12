# -*- coding: utf-8 -*-
"""Read-only contracts of 0.10.0 (decisions D11 and S10): compliance/v1 and secops/v1.

    compliance_context(org_files, organization, as_of, g=None) -> dict valid against contracts/compliance/v1/compliance-context.schema.json
    secops_context(org_files, organization, as_of, g=None)     -> dict valid against contracts/secops/v1/secops-context.schema.json

Both are exposed by CRGO's MCP server (tools crgo_compliance_context and crgo_secops_context). They only read: there is
no write-back, and nothing they return is a compliance claim, an effectiveness claim or an authorisation (ADR-010,
ADR-011). Tenant rules are those of dss/v1 (ADR-008): the organisation's base is the one its graph declares; records
under another organisation's base are withheld and the withholding is reported in the caveats.
"""
import datetime, json, os
from rdflib import URIRef, Literal
from rdflib.namespace import RDF, RDFS, XSD, SKOS, OWL
import dss
from dss import T, KEY, CRGO, RELEASE, error, org_base, load

ROOT = dss.ROOT
STATE = {"LifeDraft": "draft", "LifeUnderReview": "under-review", "LifeApproved": "approved", "LifePublished": "published", "LifeRetired": "retired", "LifeSuperseded": "superseded"}
MAPT = {"MapExact": "exact", "MapFullCoverage": "full-coverage", "MapPartialCoverage": "partial-coverage", "MapBroader": "broader", "MapNarrower": "narrower",
        "MapRelated": "related", "MapConflicting": "conflicting"}
REV = {"RevDraft": "draft", "RevUnderReview": "under-review", "RevApproved": "approved", "RevRejected": "rejected", "RevWithdrawn": "withdrawn"}
ROOTC = {"RootPeople": "people", "RootProcess": "process", "RootTechnology": "technology", "RootGovernance": "governance", "RootThirdParty": "third-party",
         "RootDesign": "design", "RootResourcing": "resourcing"}
COV = {"CovUntested": "untested", "CovValidated": "validated", "CovDegraded": "degraded", "CovMissing": "missing"}
DETS = {"DetDraft": "draft", "DetTesting": "testing", "DetApproved": "approved", "DetEnabled": "enabled", "DetSuppressed": "suppressed", "DetRetired": "retired"}
HEALTH = {"HealthHealthy": "healthy", "HealthDegraded": "degraded", "HealthSilent": "silent", "HealthUnknown": "unknown"}
RISKC = {"RiskReadOnly": "read-only", "RiskAdministrative": "administrative", "RiskContainment": "containment", "RiskDestructive": "destructive"}
REPS = {"ReportReportable": "reportable", "ReportNotReportable": "not-reportable", "ReportUndetermined": "undetermined"}
COMPLIANCE_CAVEATS = [
    "CRGO states records, links and their review status. A mapping, a policy statement, an acknowledgement or an attestation is never evidence of compliance or effectiveness.",
    "Applicability states are evaluations over the organisation profile, not legal advice; 'potentially applicable' needs qualified review.",
    "Compliance states are the latest determination made on or before the date asked; open-world data: an absent record is not a negative finding."]
SECOPS_CAVEATS = [
    "Coverage is a claim to be tested; only coverage supported by a detection test found effective is reported as validated.",
    "An indicator match or an alert never implies an incident or an attribution; incidents are confirmed by incident confirmations.",
    "No inference made in CRGO authorises a response action; approval checks are audit signals (ADR-011).",
    "Rule, alert, case and approval statuses are as last recorded; dated records (coverage, tests, versions, health, executions, assessments) are taken on or before the date asked, and undated ones are left out."]

def _now():
    return datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")

def _k(v, table):
    return table.get(KEY.get(v, ""), None)

def _label(g, s):
    return next((str(l) for l in g.objects(s, RDFS.label) if getattr(l, "language", None) in ("en", None)), None)

def _d(lit):
    return str(lit)[:10] if lit is not None else None

class _Scope:
    """Tenant filter: organisation records under the organisation's base, and CRGO reference IRIs."""
    def __init__(self, g, base):
        self.g, self.base, self.withheld = g, base, 0
    def mine(self, x):
        return isinstance(x, URIRef) and (str(x).startswith(self.base) or str(x).startswith(CRGO))
    def own(self, x):
        return isinstance(x, URIRef) and str(x).startswith(self.base)
    def own_only(self, xs):
        """Subjects found by a reverse lookup: only the organisation's own records count; others are withheld."""
        out = []
        for x in xs:
            if self.own(x): out.append(x)
            elif isinstance(x, URIRef) and not str(x).startswith(CRGO): self.withheld += 1
        return out
    def keep(self, xs):
        out = []
        for x in xs:
            if self.mine(x): out.append(x)
            elif isinstance(x, URIRef): self.withheld += 1
        return out

def _start(org_files, organization, as_of, g, contract):
    try:
        datetime.date.fromisoformat(as_of)
    except (TypeError, ValueError):
        return None, None, None, error("SCHEMA_INVALID", "as_of must be a date written yyyy-mm-dd.")
    g = g if g is not None else load(org_files)
    org = URIRef(organization)
    try:
        base = org_base(org, g)
    except ValueError:
        return None, None, None, error("REFERENCE_NAMESPACE", "Organisation identifiers must not be under https://w3id.org/crgo/.")
    except LookupError:
        return None, None, None, error("UNKNOWN_ORGANISATION", "No organisation graph declares a base for %s (vann:preferredNamespaceUri)." % org)
    if (org, None, None) not in g:
        return None, None, None, error("UNKNOWN_ORGANISATION", "No data for %s." % org)
    doc = {"schemaVersion": "1.0", "contract": contract, "ontologyRelease": RELEASE, "organizationId": str(org), "asOf": as_of, "generatedAt": _now()}
    return g, _Scope(g, base), Literal(as_of + "T23:59:59", datatype=XSD.dateTime), doc

def _latest(g, recs, date_prop, asof):
    dated = [(g.value(r, T(date_prop)), r) for r in recs]
    dated = [(d, r) for d, r in dated if d is not None and d <= asof]
    return max(dated, key=lambda x: x[0].toPython())[1] if dated else None

COMPONENT_TESTS = ("DetectionTest", "PlaybookSimulation")
def _latest_assessment(g, measure, asof, sc):
    """Latest assessment of a control measure by the organisation on or before asof; a detection test or playbook
    simulation tests one rule or playbook, not the measure, and is left out."""
    recs = [a for a in sc.own_only(g.subjects(T("evaluatesControlMeasure"), measure))
            if not any((a, RDF.type, T(c)) in g for c in COMPONENT_TESTS)]
    return _latest(g, recs, "assessedOn", asof)

def _open(g, item, asof, sc=None):
    """A finding or nonconformity is open on asof unless closed on or before it and not reopened since (own records only)."""
    own = (lambda xs: sc.own_only(xs)) if sc is not None else list
    closes = [c for c in own(g.subjects(T("closesFinding"), item)) if g.value(c, T("closedOn")) is not None and g.value(c, T("closedOn")) <= asof]
    if not closes:
        return True
    last = max(g.value(c, T("closedOn")).toPython() for c in closes)
    return any(g.value(r, T("reopenedOn")) is not None and last < g.value(r, T("reopenedOn")).toPython() <= asof.toPython()
               for r in own(g.subjects(T("reopensFinding"), item)))

# ======================================================================== compliance/v1
def compliance_context(org_files, organization, as_of, g=None):
    g, sc, asof, doc = _start(org_files, organization, as_of, g, "compliance/v1")
    if g is None:
        return doc
    org = URIRef(organization)
    ours = lambda cls: [s for s in g.subjects(RDF.type, T(cls)) if sc.own(s)]
    raised = lambda r, p: g.value(r, T(p)) is None or g.value(r, T(p)) <= asof
    # obligations: those the programme covers and those the organisation has determinations or applicability assessments on
    reqs = set()
    for p in ours("ComplianceProgramme"):
        if g.value(p, T("concernsOrganisation")) == org:
            reqs |= {x for x in g.objects(p, T("programmeCovers")) if (x, RDF.type, T("FrameworkAdoption")) not in g}
    for d in ours("ComplianceDetermination"):
        if g.value(d, T("concernsOrganisation")) == org and raised(d, "assessedOn"):
            reqs |= set(g.objects(d, T("complianceWith")))
    reqs = set(sc.keep(sorted(reqs)))
    obligations = []
    for req in sorted(reqs):
        app = _latest(g, [a for a in sc.own_only(g.subjects(T("applicabilityOf"), req)) if g.value(a, T("concernsOrganisation")) == org], "assessedOn", asof)
        det = _latest(g, [d for d in sc.own_only(g.subjects(T("complianceWith"), req)) if g.value(d, T("concernsOrganisation")) == org], "assessedOn", asof)
        ev_status = "none"
        if det is not None:
            evs = sc.keep(g.objects(det, T("hasEvidence")))
            if evs: ev_status = "current"
            dd = g.value(det, T("assessedOn"))
            if any(g.value(e, T("validUntil")) is not None and g.value(e, T("validUntil")) < dd for e in evs): ev_status = "expired"
            if any(g.value(s, T("hasSufficiencyConclusion")) in (T("SuffInsufficient"), T("SuffStale")) for e in evs for s in g.subjects(T("sufficiencyOf"), e)):
                ev_status = "judged-insufficient"
        stmts, direct = [], []
        for m in sc.own_only(g.subjects(T("mappingTarget"), req)):
            s = g.value(m, T("mappingSource"))
            if s is None or not sc.mine(s): continue
            if (s, RDF.type, T("PolicyStatement")) not in g:   # a control measure mapped directly
                la = _latest_assessment(g, s, asof, sc)
                direct.append({"id": str(s), "mapping": str(m), "mappingType": _k(g.value(m, T("hasMappingType")), MAPT) or "related",
                               **({"latestResult": dss.RES.get(KEY.get(g.value(la, T("hasTestResult")), ""), "not-tested"),
                                   "latestAssessedOn": _d(g.value(la, T("assessedOn")))} if la is not None else {})})
                continue
            v = g.value(s, T("statementInVersion"))
            stmts.append({"id": str(s), "mapping": str(m), "mappingType": _k(g.value(m, T("hasMappingType")), MAPT) or "related",
                          "reviewState": _k(g.value(m, T("hasReviewState")), REV) or "draft", **({"version": str(v)} if v is not None else {})})
        measures = list(direct)
        for st in {x["id"] for x in stmts}:
            for mm in sc.keep(g.objects(URIRef(st), T("statementImplementedBy"))):
                la = _latest_assessment(g, mm, asof, sc)
                measures.append({"id": str(mm), "viaStatement": st, **({"latestResult": dss.RES.get(KEY.get(g.value(la, T("hasTestResult")), ""), "not-tested"),
                                                                       "latestAssessedOn": _d(g.value(la, T("assessedOn")))} if la is not None else {})})
        findings = sorted({str(f) for c in g.subjects(T("criterionRefersTo"), req) for f in sc.own_only(g.subjects(T("usesCriterion"), c)) if raised(f, "raisedOn") and _open(g, f, asof, sc)} |
                          {str(f) for st in {x["id"] for x in stmts} for c in g.subjects(T("criterionRefersTo"), URIRef(st)) for f in g.subjects(T("usesCriterion"), c)
                           if sc.own(f) and raised(f, "raisedOn") and _open(g, f, asof, sc)})
        obligations.append({"id": str(req), **({"label": _label(g, req)} if _label(g, req) else {}),
                            "applicability": dss.APP.get(KEY.get(g.value(app, T("hasApplicabilityState")), ""), "not-assessed") if app is not None else "not-assessed",
                            "complianceState": dss.COMP.get(KEY.get(g.value(det, T("hasComplianceState")), ""), "not-assessed") if det is not None else "not-assessed",
                            **({"determinedOn": _d(g.value(det, T("assessedOn"))), "determination": str(det)} if det is not None else {}),
                            "evidenceStatus": ev_status, "owners": sorted(str(w) for w in sc.keep(g.subjects(T("accountableFor"), req))),
                            "supportingStatements": stmts, "implementingMeasures": measures, "openFindings": findings})
    versions = []
    for v in ours("DirectiveVersion") + [x for x in ours("PolicyVersion") if (x, RDF.type, T("DirectiveVersion")) not in g] + ours("PlaybookVersion"):
        if any(x["id"] == str(v) for x in versions): continue
        eff, due = g.value(v, T("effectiveOn")), [x for x in g.objects(v, T("reviewDueOn"))]
        due = max(due, key=lambda x: x.toPython()) if due else None
        st = _k(g.value(v, T("hasLifecycleState")), STATE) or "draft"
        versions.append({"id": str(v), "directive": str(g.value(v, T("versionOfDirective"))), "versionLabel": str(g.value(v, T("versionLabel")) or ""), "state": st,
                         **({"effectiveOn": _d(eff)} if eff is not None else {}), **({"reviewDueOn": _d(due)} if due is not None else {}),
                         "reviewOverdue": bool(st == "published" and due is not None and due < asof)})
    exceptions = []
    for e in ours("PolicyException"):
        f, u = g.value(e, T("validFrom")), g.value(e, T("validUntil"))
        tos = sc.keep(g.objects(e, T("exceptionTo")))
        provs = {p for t in tos for p in list(g.objects(t, T("derivedFromRequirement"))) + [g.value(m, T("mappingTarget")) for m in g.subjects(T("mappingSource"), t)]
                 if p is not None and (p, T("provisionOf"), None) in g}
        exempt = {p for p in provs for x in sc.own_only(g.subjects(T("exemptionFrom"), p)) if g.value(x, T("validFrom")) is not None and g.value(x, T("validFrom")) <= asof
                  and (g.value(x, T("validUntil")) is None or g.value(x, T("validUntil")) >= asof)}
        ra = g.value(e, T("authorisedByRiskAcceptance"))
        exceptions.append({"id": str(e), "exceptionTo": [str(t) for t in tos], **({"validFrom": _d(f)} if f is not None else {}), **({"validUntil": _d(u)} if u is not None else {}),
                           "active": bool(f is not None and u is not None and f <= asof <= u), **({"riskAcceptance": str(ra)} if ra is not None and sc.mine(ra) else {}),
                           "legalProvisionsConcerned": sorted(str(p) for p in provs), "provisionsWithoutExemption": sorted(str(p) for p in provs - exempt)})
    deadlines = []
    for dl in ours("ComplianceDeadline"):
        due = g.value(dl, T("dueOn"))
        if due is None and g.value(dl, T("dueOffsetHours")) is not None:
            ev = g.value(dl, T("deadlineTriggeredBy")); t0 = g.value(ev, T("confirmedOn")) or g.value(ev, T("occurredAt")) if ev is not None else None
            if t0 is not None:
                due = Literal(t0.toPython() + datetime.timedelta(hours=int(g.value(dl, T("dueOffsetHours")))), datatype=XSD.dateTime)
        jur = g.value(dl, T("hasJurisdiction"))
        deadlines.append({"id": str(dl), "deadlineFor": [str(x) for x in sc.keep(g.objects(dl, T("deadlineFor")))],
                          "trigger": "event" if g.value(dl, T("hasDeadlineTriggerKind")) == T("DeadlineEvent") else "calendar",
                          **({"due": str(due.toPython().isoformat())[:19]} if due is not None else {}), "answered": any(True for _ in g.subjects(T("answersDeadline"), dl)),
                          **({"jurisdiction": str(jur)} if jur is not None else {})})
    findings = []
    for kind, cls in (("audit-finding", "AuditFinding"), ("nonconformity", "Nonconformity")):
        for f in ours(cls):
            if not raised(f, "raisedOn") or not raised(f, "identifiedOn"): continue
            acts = sc.own_only(g.subjects(T("correctsFinding"), f))
            overdue = [str(a) for a in acts if g.value(a, T("dueOn")) is not None and g.value(a, T("dueOn")) < asof
                       and g.value(a, T("hasActionStatus")) not in (T("ActionVerified"), T("ActionCancelled"))]
            rc = [_k(c, ROOTC) for c in g.objects(f, T("hasRootCauseCategory"))]
            findings.append({"id": str(f), "kind": kind, "open": _open(g, f, asof, sc), "rootCauses": sorted(x for x in rc if x), "overdueActions": sorted(overdue)})
    doc.update({"obligations": obligations, "directiveVersions": sorted(versions, key=lambda x: x["id"]), "exceptions": exceptions,
                "deadlines": deadlines, "findings": sorted(findings, key=lambda x: x["id"]), "caveats": list(COMPLIANCE_CAVEATS)})
    if sc.withheld:
        doc["caveats"].append("%d link(s) to records of another organisation were withheld (ADR-008)." % sc.withheld)
    return doc

# ======================================================================== secops/v1
def approval_reason(g, x, act, t, aps):
    """None if execution x of action act, started at t, relied on a valid approval; otherwise why not. Same rule as the
    SHACL shape ActionApproval and CQ-SOAR-02 (src/build_shapes.py VALID_APPROVAL)."""
    if not aps:
        return "absent"
    gate_auth = {w for gt in g.objects(act, T("requiresApproval")) for w in g.objects(gt, T("gateAuthority"))}
    classes = set(g.objects(act, T("hasActionRiskClass")))
    reasons = []
    for a in aps:
        dd, frm, until, rev = (g.value(a, T(k)) for k in ("decidedOn", "validFrom", "validUntil", "revokedOn"))
        if g.value(a, T("hasDecisionOutcome")) != T("DecApproved") or (a, T("hasApprovalStatus"), T("ApprDenied")) in g: reasons.append("not-granted"); continue
        if not ((a, T("decisionOn"), x) in g or (a, T("decisionOn"), act) in g or (a, T("preauthorisesAction"), act) in g
                or any((a, T("preauthorisesAction"), c) in g for c in classes)): reasons.append("not-corresponding"); continue
        if gate_auth and not (set(g.objects(a, T("decisionMadeBy"))) & gate_auth): reasons.append("wrong-authority"); continue
        if dd is None or frm is None or dd > t or frm > t: reasons.append("not-yet-valid"); continue
        if rev is not None and rev <= t: reasons.append("revoked"); continue
        if until is not None and until < t: reasons.append("expired"); continue
        return None
    order = ["expired", "revoked", "not-yet-valid", "wrong-authority", "not-corresponding", "not-granted"]
    return min(reasons, key=order.index)

def secops_context(org_files, organization, as_of, g=None):
    g, sc, asof, doc = _start(org_files, organization, as_of, g, "secops/v1")
    if g is None:
        return doc
    ours = lambda cls: [s for s in g.subjects(RDF.type, T(cls)) if sc.own(s)]
    def health(src):
        h = _latest(g, [o for o in sc.own_only(g.subjects(T("observationOf"), src)) if (o, T("hasTelemetryHealthState"), None) in g], "observedOn", asof)
        return _k(g.value(h, T("hasTelemetryHealthState")), HEALTH) if h is not None else "unknown"
    crown = {g.value(v, T("valuationOf")) for v in sc.own_only(g.subjects(T("isCrownJewel"), Literal(True)))}
    scen_ids = set()
    for c in ours("DetectionCoverage"): scen_ids |= set(g.objects(c, T("coversScenario")))
    for p in ours("ResponsePlaybook"): scen_ids |= set(g.objects(p, T("addressesScenario")))
    scen_ids |= {s for s in g.subjects(RDF.type, T("AssessmentScenario")) if sc.own(s)}
    scenarios = []
    for s in sorted(sc.keep(sorted(scen_ids))):
        cov = []
        for c in sc.own_only(g.subjects(T("coversScenario"), s)):
            on = g.value(c, T("assessedOn"))
            if on is None or on > asof: continue   # coverage statements are dated; later or undated ones are left out
            st = _k(g.value(c, T("hasCoverageStatus")), COV) or "untested"
            providers = set(g.objects(c, T("coverageBy")))
            tested = any(sc.own(t) and g.value(t, T("hasTestResult")) == T("TestEffective") and g.value(t, T("assessedOn")) is not None
                         and g.value(t, T("assessedOn")) <= asof and set(g.objects(t, T("testedRule"))) & providers for t in g.objects(c, T("supportedByTest")))
            cov.append({"id": str(c), "status": st, "validatedByTest": bool(st == "validated" and tested),
                        "techniques": sorted({str(n) for t in g.objects(c, T("coversTechnique")) for n in g.objects(t, SKOS.notation)})})
        pbs = []
        for p in sc.own_only(g.subjects(T("addressesScenario"), s)):
            def in_force(v):
                eff, ret = g.value(v, T("effectiveOn")), g.value(v, T("retiredOn"))
                return eff is not None and eff <= asof and (ret is None or ret > asof)
            cur = [v for v in sc.own_only(g.subjects(T("versionOfDirective"), p)) if in_force(v)]
            passed = any(g.value(sim, T("hasTestResult")) == T("TestEffective") and g.value(sim, T("assessedOn")) is not None and g.value(sim, T("assessedOn")) <= asof
                         for v in cur for sim in sc.own_only(g.subjects(T("simulatedPlaybook"), v)))
            pbs.append({"id": str(p), "currentVersions": sorted(str(v) for v in cur), "simulationPassed": bool(passed)})
        scenarios.append({"id": str(s), **({"label": _label(g, s)} if _label(g, s) else {}), "coverage": cov,
                          "detectionGaps": sorted(str(x) for x in g.objects(s, T("hasControlGap")) if (x, RDF.type, T("DetectionGap")) in g and sc.own(x)),
                          "playbooks": pbs})
    rules = []
    for r in ours("DetectionRule") + [x for x in ours("CorrelationRule") if (x, RDF.type, T("DetectionRule")) not in g]:
        srcs = [x for x in sc.keep(g.objects(r, T("requiresSource")))]
        rules.append({"id": str(r), **({"label": _label(g, r)} if _label(g, r) else {}), "status": _k(g.value(r, T("hasDetectionStatus")), DETS) or "draft",
                      "version": str(g.value(r, T("versionLabel")) or ""),
                      "requiredSources": [{"id": str(x), "health": health(x) if (x, RDF.type, T("TelemetrySource")) in g else "not-a-source"} for x in srcs]})
    alerts = []
    for a in ours("SecurityAlert"):
        disp = g.value(a, T("hasAlertDisposition"))
        if disp not in (None, T("DispUnreviewed")): continue
        if g.value(a, T("recordedAt")) is None or g.value(a, T("recordedAt")) > asof: continue   # undated or later alerts are left out
        assets = sc.keep(g.objects(a, T("involvesAsset")))
        alerts.append({"id": str(a), "assets": sorted(str(x) for x in assets), "crownJewel": any(x in crown for x in assets)})
    gates = []
    for gt in ours("ApprovalGate"):
        gates.append({"id": str(gt), "riskClasses": sorted(x for x in (_k(c, RISKC) for c in g.objects(gt, T("gateForRiskClass"))) if x),
                      "criticalAssets": g.value(gt, T("gateForCriticalAssets")) == Literal(True), "authorities": sorted(str(x) for x in sc.keep(g.objects(gt, T("gateAuthority")))),
                      "actions": sorted(str(x) for x in sc.own_only(g.subjects(T("requiresApproval"), gt)) if (x, RDF.type, T("ResponseAction")) in g)})
    unapproved = []
    for x in ours("ActionExecution"):
        t, act = g.value(x, T("executionStartedAt")), g.value(x, T("performsAction"))
        if t is None or act is None or t > asof: continue
        gated = g.value(act, T("hasActionRiskClass")) in (T("RiskContainment"), T("RiskDestructive")) or (act, T("requiresApproval"), None) in g
        if not gated: continue
        aps = [a for a in g.objects(x, T("authorizedBy")) if sc.own(a)]
        reason = approval_reason(g, x, act, t, aps)
        if reason is None: continue
        unapproved.append({"id": str(x), "action": str(act), "reason": reason})
    triage = []
    for c in sc.own_only(g.subjects(T("confirmsIncident"), None)):
        inc = g.value(c, T("confirmsIncident"))
        if not (sc.own(c) and sc.own(inc)) or (g.value(c, T("confirmedOn")) is not None and g.value(c, T("confirmedOn")) > asof): continue
        ras = [r for r in sc.own_only(g.subjects(T("reportabilityOf"), inc)) if g.value(r, T("assessedOn")) is not None and g.value(r, T("assessedOn")) <= asof]
        und = [r for r in ras if g.value(r, T("hasReportabilityState")) == T("ReportUndetermined")]
        if not ras or und:
            triage.append({"incident": str(inc), "assessments": sorted(str(r) for r in und), "reason": "no-assessment" if not ras else "undetermined"})
    doc.update({"scenarios": scenarios, "detectionRules": sorted(rules, key=lambda x: x["id"]), "untriagedAlerts": sorted(alerts, key=lambda x: x["id"]),
                "approvalGates": gates, "executionsWithoutValidApproval": unapproved, "openRegulatoryTriage": sorted(triage, key=lambda x: x["incident"]),
                "caveats": list(SECOPS_CAVEATS)})
    if sc.withheld:
        doc["caveats"].append("%d link(s) to records of another organisation were withheld (ADR-008)." % sc.withheld)
    return doc

def validate(doc, contract):
    import jsonschema
    name = {"compliance/v1": "compliance-context.schema.json", "secops/v1": "secops-context.schema.json"}[contract]
    schema = json.load(open(os.path.join(ROOT, "contracts", contract, name), encoding="utf-8"))
    v = jsonschema.Draft202012Validator(schema, format_checker=jsonschema.FormatChecker())
    return sorted("%s: %s" % ("/".join(map(str, e.path)) or "(root)", e.message) for e in v.iter_errors(doc))
