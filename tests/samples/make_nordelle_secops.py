# -*- coding: utf-8 -*-
"""0.10.0 SIEM and SOAR demonstration on the SYNTHETIC Nordelle Market inc. (competency questions CQ-SIEM-01..06 and
CQ-SOAR-01..06 in tests/pca_cq/). Everything is invented test data about a fictional company.

The story (as of 2026-10-12), on top of the earlier Nordelle graphs:
- telemetry: identity-provider sign-in logs (healthy), EDR on servers (silent: EDR not deployed), point-of-sale
  syslog (degraded); a parser (v1 until 2026-09-01, v2 after) and an OCSF normalisation profile;
- detection: a strategy for ransomware encryption adapting an ATT&CK detection strategy, with an enabled rule
  validated by a detection test; a strategy for valid-account abuse whose rule is enabled but never tested and needs
  the silent EDR source; coverage statements (validated, untested, degraded); a detection gap on credential compromise;
- alerts: the August impossible-travel alert (true positive, investigated, incident confirmed); a new alert on the
  payment service (unreviewed); a threat indicator match (potentially indicates a threat event; no incident);
- hunting hypothesis and a behavioural baseline;
- response: a playbook "compromised account" (v1 superseded, v2 in use) whose v2 passed simulation, and a ransomware
  playbook never simulated; response actions (disable account: containment; isolate host: containment; collect
  logs: read-only) behind an approval gate for critical assets; the August account disablement ran under v1 with a
  granted approval; a September host isolation ran on an expired pre-authorisation; evidence of both; a forensic
  image; impact, communications (CAI notice recorded as the regulatory submission), recovery verification, a
  time-to-contain measurement, and a lesson that led to a corrective action;
- a second incident (September malware on a kiosk) whose GDPR reportability is still undetermined.
Writes tests/samples/nordelle-secops.ttl (imports nordelle-pca).
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
CCO = Namespace("https://www.commoncoreontologies.org/")
PERSON = CCO.ont00001262
_voc = {}
def concept(scheme, notation):
    if scheme not in _voc:
        _voc[scheme] = {str(n): s for s, n in Graph().parse(os.path.join(ROOT, "ontology", "vocab", scheme + ".ttl")).subject_objects(SKOS.notation)}
    return _voc[scheme][notation]

g = Graph(); g.bind("crgo", BASE); g.bind("nordelle", N); g.bind("dcterms", DCTERMS)
o = URIRef("https://example.org/crgo-sample/nordelle-secops")
g.add((o, RDF.type, OWL.Ontology)); g.add((o, OWL.imports, URIRef("https://example.org/crgo-sample/nordelle-pca")))
for v in ("attack", "attack-detection", "ocsf", "d3fend"):
    g.add((o, OWL.imports, URIRef(BASE + "vocab/" + v)))
g.add((o, URIRef("http://purl.org/vocab/vann/preferredNamespaceUri"), Literal(str(N))))
g.add((o, RDFS.label, Literal("Nordelle Market inc. - SYNTHETIC security monitoring and response (SIEM/SOAR) data for CRGO 0.10.0", lang="en")))
g.add((o, DCTERMS.type, Literal("synthetic test data")))
dt = lambda d: Literal(d + ("" if "T" in d else "T00:00:00"), datatype=XSD.dateTime)
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
P = {k: N["person/" + k] for k in ("ceo", "cae", "itops", "compliance", "ciso", "iam-lead", "netops", "store-mgr")}
P["soc"] = ind("person/soc-analyst", str(PERSON), "Nordelle SOC analyst (fictional)")
P["soc2"] = ind("person/soc-lead", str(PERSON), "Nordelle SOC lead (fictional)")
att = lambda t: concept("attack", t)
det = lambda x: concept("attack-detection", x)
ocsf = lambda x: concept("ocsf", x)
T1078, T1486, T1110 = att("T1078"), att("T1486"), att("T1110")
siem_tool = Literal("Fictional SIEM 9")

# ------------------------------------------------------------------ an extra, low-impact scenario (CQ-SIEM-01 negative)
ind("scenario/web-defacement", "AssessmentScenario", "Defacement of the marketing website")
ind("estimate/impact-wd", "ImpactEstimate", "Impact of website defacement", estimateOf=N["scenario/web-defacement"], numericValue=dec(0.3))

# ------------------------------------------------------------------ telemetry
idp = ind("telemetry/idp-signin", "TelemetrySource", "Identity provider sign-in logs", sourceAsset=N["asset/identity-service"], sourceSystem=siem_tool,
          providesDataComponent=[det("DC0067"), det("DC0002")])
edr = ind("telemetry/edr-servers", "TelemetrySource", "EDR telemetry from servers", sourceAsset=N["asset/legacy-pos-server"])
pos = ind("telemetry/pos-syslog", "TelemetrySource", "Point-of-sale syslog", sourceAsset=N["asset/legacy-pos-server"])
for key, src, state, day in (("idp-2026-10-11", idp, "HealthHealthy", "2026-10-11"), ("edr-2026-10-11", edr, "HealthSilent", "2026-10-11"),
                             ("pos-2026-10-11", pos, "HealthDegraded", "2026-10-11")):
    ind("telemetry-health/" + key, "TelemetryHealthObservation", "Telemetry health %s" % key, observationOf=src, observedOn=dt(day),
        hasTelemetryHealthState=T(state), hasSourceRecord=N["source/siem-health-feed"])
ind("source/siem-health-feed", "SourceRecord", "Fictional SIEM 9 health dashboard export", localIdentifier=Literal("siem-health-feed"),
    issuerName=Literal("Nordelle SOC (fictional)"), sourceVersion=Literal("9.4"), licenceTerms=Literal("internal"), hasAccessStatus=T("AccessVerified"))
prof = ind("normalisation/idp-authentication", "NormalizationProfile", "IdP sign-ins to OCSF Authentication", profileForSource=idp,
           mapsToEventClass=ocsf("3002"), versionLabel=Literal("1.0"))
p1 = ind("parser/idp-v1", "ParserDefinition", "IdP parser v1", profileForSource=idp, versionLabel=Literal("1"), validFrom=dt("2025-01-01"), validUntil=dt("2026-09-01"))
p2 = ind("parser/idp-v2", "ParserDefinition", "IdP parser v2", profileForSource=idp, versionLabel=Literal("2"), validFrom=dt("2026-09-01"))
ev = ind("event-record/2026-08-03-signin", "SecurityEventRecord", "Sign-in record of the August phishing event", observationOf=N["event/2026-08-03-phish"],
         observedOn=dt("2026-08-03T09:12:00"), recordedAt=dt("2026-08-03T09:12:40"), emittedBy=idp, normalizedUnder=prof, parsedBy=p1,
         hasSourceRecord=N["source/siem-health-feed"], localIdentifier=Literal("evt-7781"))

# ------------------------------------------------------------------ detection
pam = N["control/pam-review"]
mon = ind("control/siem-monitoring", "ControlMeasure", "Security monitoring of identity and server events", hasControlStatus=T("CtlInPlace"),
          implementsControl=concept("sp800-53r5", "SI-4"), hasControlFunction=T("FnDetection"), hasOwner=P["soc2"])
st_rw = ind("detection-strategy/ransomware-encryption", "DetectionStrategy", "Detect mass file encryption on file servers", targetsTechnique=T1486,
            adaptsReferenceStrategy=det("DET0215"))
st_va = ind("detection-strategy/valid-account-abuse", "DetectionStrategy", "Detect abuse of valid administrator accounts", targetsTechnique=T1078,
            adaptsReferenceStrategy=det("DET0560"))
rule_rw = ind("detection-rule/rw-encryption", "DetectionRule", "Rule: burst of file renames with high-entropy extensions", implementsStrategy=st_rw,
              hasDetectionStatus=T("DetEnabled"), versionLabel=Literal("3"), ruleLanguage=Literal("Sigma"), ruleIdentifier=Literal("nordelle-rw-0003"),
              requiresSource=pos, ruleForMeasure=mon, targetsTechnique=T1486, referenceVersion=Literal("19.2"))
rule_va1 = ind("detection-rule/impossible-travel-v1", "DetectionRule", "Rule: impossible travel for administrators (v1)", implementsStrategy=st_va,
               hasDetectionStatus=T("DetRetired"), versionLabel=Literal("1"), ruleLanguage=Literal("native"), ruleForMeasure=mon, referenceVersion=Literal("17.1"))
rule_va2 = ind("detection-rule/impossible-travel-v2", "DetectionRule", "Rule: impossible travel for administrators (v2)", implementsStrategy=st_va,
               hasDetectionStatus=T("DetEnabled"), versionLabel=Literal("2"), ruleLanguage=Literal("native"), requiresSource=[idp, edr], ruleForMeasure=mon,
               targetsTechnique=T1078, referenceVersion=Literal("19.2"))
add(rule_va2, "supersedes", rule_va1)
corr = ind("detection-rule/brute-then-success", "CorrelationRule", "Correlation: failed sign-ins followed by success", implementsStrategy=st_va,
           hasDetectionStatus=T("DetTesting"), versionLabel=Literal("1"), requiresSource=idp, targetsTechnique=T1110)
dtest = ind("detection-test/rw-encryption-2026-06", "DetectionTest", "Replay of a ransomware encryption sample against the rule", testedRule=rule_rw,
            evaluatesControlMeasure=mon, assessedOn=dt("2026-06-10"), hasTestResult=T("TestEffective"), assessedBy=P["soc2"], hasEvidence=N["evidence/rw-replay"],
            concernsOrganisation=org, performedInCapacity=T("LineSecond"))
ind("evidence/rw-replay", "TestEvidence", "Replay test log (ransomware rule)", localIdentifier=Literal("rw-replay-2026-06"), collectedOn=dt("2026-06-10"))
ind("coverage/ransomware", "DetectionCoverage", "Coverage of the ransomware scenario by the encryption rule", coverageBy=[st_rw, rule_rw],
    coversScenario=N["scenario/ransomware"], coversTechnique=T1486, hasCoverageStatus=T("CovValidated"), supportedByTest=dtest, assessedOn=dt("2026-06-10"))
ind("coverage/credential-compromise", "DetectionCoverage", "Coverage of credential compromise by impossible-travel rule", coverageBy=[st_va, rule_va2],
    coversScenario=N["scenario/credential-compromise"], coversTechnique=T1078, hasCoverageStatus=T("CovUntested"), assessedOn=dt("2026-09-01"))
ind("coverage/brute-force", "DetectionCoverage", "Coverage of password guessing by the correlation rule", coverageBy=corr, coversTechnique=T1110,
    hasCoverageStatus=T("CovDegraded"), assessedOn=dt("2026-09-01"))
gap = ind("detection-gap/edr-servers", "DetectionGap", "No server EDR telemetry: valid-account abuse on servers is undetected", gapInTelemetry=edr,
          gapForTechnique=T1078, missingControl=concept("sp800-53r5", "SI-4"))
add(N["scenario/credential-compromise"], "hasControlGap", gap)
# alerts
a_old = N["alert/2026-08-03-impossible-travel"]
add(a_old, "generatedByRule", rule_va1); add(a_old, "hasAlertDisposition", T("DispTruePositive")); add(a_old, "involvesAsset", N["asset/identity-service"])
add(a_old, "openedInvestigation", N["investigation/2026-08-phishing"]); add(a_old, "recordedAt", dt("2026-08-03T09:13:00"))
a_new = ind("alert/2026-10-11-payment-admin", "SecurityAlert", "Impossible travel on a payment-service administrator (unreviewed)", generatedByRule=rule_va2,
            hasAlertDisposition=T("DispUnreviewed"), involvesAsset=N["asset/payment-service"], recordedAt=dt("2026-10-11T22:05:00"))
a_kiosk = ind("alert/2026-10-10-kiosk", "SecurityAlert", "Malware beacon from an in-store kiosk, raised by the kiosk antivirus (unreviewed)",
              hasAlertDisposition=T("DispUnreviewed"), involvesAsset=N["asset/kiosk"], recordedAt=dt("2026-10-10T13:45:00"), sourceSystem=Literal("kiosk antivirus (fictional)"))
a_fp = ind("alert/2026-10-09-payment-fp", "SecurityAlert", "Impossible travel on payment admin: VPN exit node (false positive)", generatedByRule=rule_va2,
           hasAlertDisposition=T("DispFalsePositive"), involvesAsset=N["asset/payment-service"], recordedAt=dt("2026-10-09T07:30:00"))
ti_src = ind("cti/isac-feed", "ThreatIntelligenceSource", "Retail ISAC indicator feed (fictional)", localIdentifier=Literal("retail-isac-feed"),
             issuerName=Literal("Fictional Retail ISAC"), sourceVersion=Literal("2026-10"), licenceTerms=Literal("member sharing agreement"),
             hasAccessStatus=T("AccessVerified"), hasInformationMarking=T("TlpAmber"))
ioc = ind("indicator/2026-10-domain", "ThreatIndicator", "Phishing domain used against retailers", indicatorPattern=Literal("[domain-name:value = 'login-nordelle.example']"),
          patternLanguage=Literal("stix"), indicatorFromSource=ti_src, validFrom=dt("2026-10-01"), validUntil=dt("2026-12-31"), statedConfidence=dec(70),
          confidenceMethod=txt("STIX 2.1 confidence, 0-100, as given by the feed"), hasInformationMarking=T("TlpAmber"),
          potentiallyIndicates=N["scenario/credential-compromise/event"])
add(a_new, "matchedIndicator", ioc)
ind("hunt/2026-10-dormant-admins", "HuntingHypothesis", "Dormant administrator accounts may be used after the August phishing", hypothesisAbout=N["scenario/credential-compromise"])
ind("baseline/admin-signins", "BehavioralBaseline", "Sign-in baseline of administrator accounts", baselineOf=N["asset/identity-service"], periodStart=dt("2026-01-01"), periodEnd=dt("2026-06-30"))

# ------------------------------------------------------------------ response
inv = ind("investigation/2026-08-phishing", "SecurityInvestigation", "Investigation of the August impossible-travel alert", investigatesAlert=a_old,
          hasCaseStatus=T("CaseClosed"), investigationOpenedAt=dt("2026-08-03T09:20:00"), concludedIncident=N["incident/2026-08-phishing"], involvesAsset=N["asset/identity-service"])
inc = N["incident/2026-08-phishing"]
add(inc, "hasIncidentCategory", T("CatSocialEngineering"), T("CatUnauthorisedAccess")); add(inc, "hasIncidentSeverity", T("SevHigh"))
pb = ind("playbook/compromised-account", "ResponsePlaybook", "Playbook: compromised account", addressesScenario=N["scenario/credential-compromise"], hasOwner=P["soc2"])
pb_rw = ind("playbook/ransomware", "ResponsePlaybook", "Playbook: ransomware on a server", addressesScenario=N["scenario/ransomware"], hasOwner=P["soc2"])
act_disable = ind("response-action/disable-account", "ResponseAction", "Disable a user account", hasActionRiskClass=T("RiskContainment"),
                  correspondsToDefensiveTechnique=concept("d3fend", "D3-AL"))
act_isolate = ind("response-action/isolate-host", "ResponseAction", "Isolate a host from the network", hasActionRiskClass=T("RiskContainment"),
                  correspondsToDefensiveTechnique=concept("d3fend", "D3-NI"))
act_collect = ind("response-action/collect-logs", "ResponseAction", "Collect sign-in logs", hasActionRiskClass=T("RiskReadOnly"))
gate = ind("approval-gate/containment", "ApprovalGate", "Containment and destructive actions need SOC lead approval; CISO approval on crown jewels",
           gateForRiskClass=[T("RiskContainment"), T("RiskDestructive")], gateAuthority=[P["soc2"], P["ciso"]], gateForCriticalAssets=Literal(True))
add(act_disable, "requiresApproval", gate); add(act_isolate, "requiresApproval", gate)
trig = ind("trigger/admin-impossible-travel", "PlaybookTrigger", "Trigger: impossible-travel alert on an administrator", hasTriggerKind=T("TrigAlert"))
def version(key, label, pbk, n, state, eff, retired=None):
    v = ind(key, "PlaybookVersion", label, versionOfDirective=pbk, versionLabel=Literal(n), hasLifecycleState=T(state), effectiveOn=dt(eff), playbookTrigger=trig)
    if retired: add(v, "retiredOn", dt(retired))
    ind("decision/approve-" + key.replace("/", "-"), "DecisionRecord", "SOC lead approves %s" % label, decisionOn=v, decisionMadeBy=P["soc2"],
        hasDecisionOutcome=T("DecApproved"), decidedOn=dt(eff))
    return v
v1 = version("playbook-version/compromised-account-1", "Compromised account playbook v1", pb, "1", "LifeSuperseded", "2025-11-01", "2026-09-15")
v2 = version("playbook-version/compromised-account-2", "Compromised account playbook v2", pb, "2", "LifePublished", "2026-09-15")
add(v2, "supersedes", v1)
vrw = version("playbook-version/ransomware-1", "Ransomware playbook v1", pb_rw, "1", "LifePublished", "2026-05-01")
for v, tag in ((v1, "v1"), (v2, "v2"), (vrw, "rw")):
    s1 = ind("playbook-step/%s-collect" % tag, "PlaybookStep", "Step: collect logs (%s)" % tag, stepPerformsAction=act_collect)
    s2 = ind("playbook-step/%s-contain" % tag, "PlaybookStep", "Step: contain (%s)" % tag, stepPerformsAction=act_isolate if tag == "rw" else act_disable,
             requiresApproval=gate)
    add(s1, "playbookNextStep", s2); add(v, "includesStep", s1, s2)
ind("simulation/compromised-account-2", "PlaybookSimulation", "Tabletop and lab run of the compromised-account playbook v2", simulatedPlaybook=v2,
    evaluatesControlMeasure=N["control/incident-response"], assessedOn=dt("2026-09-20"), hasTestResult=T("TestEffective"), assessedBy=P["ciso"],
    hasEvidence=N["evidence/sim-report-2026-09"], concernsOrganisation=org)
ind("control/incident-response", "ControlMeasure", "Incident response capability", hasControlStatus=T("CtlInPlace"), hasControlFunction=T("FnResponse"),
    implementsControl=concept("sp800-53r5", "IR-4"))
ind("evidence/sim-report-2026-09", "DocumentaryEvidence", "Simulation report, compromised-account playbook v2", localIdentifier=Literal("sim-2026-09"))
# August: account disablement under v1 with a granted approval (CQ-SOAR-06)
appr = ind("approval/2026-08-03-disable-adm", "ApprovalDecision", "SOC lead approves disabling the compromised account", decisionOn=N["action-execution/2026-08-03-disable"],
           decisionMadeBy=P["soc2"], hasDecisionOutcome=T("DecApproved"), decidedOn=dt("2026-08-03T09:30:00"), hasApprovalStatus=T("ApprGranted"),
           validFrom=dt("2026-08-03T09:30:00"), validUntil=dt("2026-08-03T21:30:00"))
run1 = ind("execution/2026-08-03-run", "AutomationExecution", "Run of the compromised-account playbook v1 (August)", usesPlaybookVersion=v1,
           executionTriggeredBy=a_old, executionFor=inv, hasExecutionStatus=T("ExecSucceeded"), executionStartedAt=dt("2026-08-03T09:25:00"),
           executionEndedAt=dt("2026-08-03T09:41:00"), attemptIdentifier=Literal("run-5521"))
x1 = ind("action-execution/2026-08-03-disable", "ActionExecution", "Disable account adm-07", partOfExecution=run1, performsAction=act_disable,
         actionTarget=N["account/adm-07"], involvesAsset=N["asset/identity-service"], hasExecutionStatus=T("ExecSucceeded"),
         executionStartedAt=dt("2026-08-03T09:35:00"), attemptIdentifier=Literal("run-5521-2"), authorizedBy=appr, producedEvidence=N["evidence/disable-log"])
ind("account/adm-07", "InformationAsset", "Administrator account adm-07 (fictional)")
ind("evidence/disable-log", "ResponseEvidence", "Identity provider audit log entry: account disabled", localIdentifier=Literal("idp-audit-99812"),
    collectedOn=dt("2026-08-03T09:36:00"))
# September: host isolation on an expired pre-authorisation (CQ-SOAR-02), and a read-only collection without approval (fine)
pre = ind("approval/2026-pre-isolate-kiosks", "ApprovalDecision", "Pre-authorisation: isolate in-store kiosks (Q3 2026 only)", decisionOn=act_isolate,
          preauthorisesAction=act_isolate, decisionMadeBy=P["ciso"], hasDecisionOutcome=T("DecApproved"), decidedOn=dt("2026-07-01"),
          hasApprovalStatus=T("ApprExpired"), validFrom=dt("2026-07-01"), validUntil=dt("2026-09-30"))
run2 = ind("execution/2026-10-10-run", "AutomationExecution", "Run of the ransomware playbook on the kiosk alert", usesPlaybookVersion=vrw, executionTriggeredBy=a_kiosk,
           hasExecutionStatus=T("ExecSucceeded"), executionStartedAt=dt("2026-10-10T14:00:00"), attemptIdentifier=Literal("run-6010"))
ind("action-execution/2026-10-10-isolate", "ActionExecution", "Isolate kiosk K-12", partOfExecution=run2, performsAction=act_isolate, actionTarget=N["asset/kiosk"],
    involvesAsset=N["asset/kiosk"], hasExecutionStatus=T("ExecSucceeded"), executionStartedAt=dt("2026-10-10T14:02:00"), attemptIdentifier=Literal("run-6010-1"),
    authorizedBy=pre, producedEvidence=N["evidence/isolate-log"])
ind("evidence/isolate-log", "ResponseEvidence", "Network controller log: kiosk K-12 quarantined", localIdentifier=Literal("nac-55102"), collectedOn=dt("2026-10-10T14:03:00"))
ind("action-execution/2026-10-10-collect", "ActionExecution", "Collect kiosk logs", partOfExecution=run2, performsAction=act_collect, actionTarget=N["asset/kiosk"],
    hasExecutionStatus=T("ExecSucceeded"), executionStartedAt=dt("2026-10-10T14:01:00"), attemptIdentifier=Literal("run-6010-0"))
# kiosk incident with undetermined GDPR reportability (CQ-SOAR-03)
inc2 = ind("incident/2026-10-kiosk-malware", "Incident", "Malware on an in-store kiosk (October 2026)", hasIncidentCategory=T("CatMalware"), hasIncidentSeverity=T("SevMedium"))
ind("incident/2026-10-kiosk-malware/confirmation", "IncidentConfirmation", "Kiosk malware confirmed", confirmsIncident=inc2, confirmedOn=dt("2026-10-10"), assessedBy=P["soc2"])
ind("incident/2026-10-kiosk-malware/reportability-gdpr", "BreachReportabilityAssessment", "GDPR reportability of the kiosk incident", reportabilityOf=inc2,
    reportableUnder=concept("gdpr", "GDPR Art. 33(1)"), hasReportabilityState=T("ReportUndetermined"), assessedOn=dt("2026-10-11"), assessedBy=P["compliance"])
inv2 = ind("investigation/2026-10-kiosk", "SecurityInvestigation", "Investigation of the kiosk beacon", investigatesAlert=a_kiosk, hasCaseStatus=T("CaseContained"),
           investigationOpenedAt=dt("2026-10-10T13:50:00"), concludedIncident=inc2)
add(a_kiosk, "openedInvestigation", inv2)
# forensic image, impact, communications, recovery, measurement, lesson
ind("forensic/kiosk-k12-disk", "ForensicArtifact", "Disk image of kiosk K-12", localIdentifier=Literal("fx-k12-001"), custodian=P["soc2"],
    evidenceHash=Literal("4be1" + "0" * 60), collectedOn=dt("2026-10-10T16:00:00"))
imp = ind("impact/2026-08-phishing-records", "IncidentImpact", "Customer records viewed by the attacker", impactOnDimension=T("DimConfidentiality"),
          impactIsEstimated=Literal(True), impactDescription=txt("About 1,200 customer records may have been viewed"))
add(inc, "hasObservedImpact", imp)
ind("communication/2026-08-cai", "IncidentCommunication", "Notice to the CAI", communicationAbout=inc, hasAudience=T("AudRegulator"), sentAt=dt("2026-08-06"),
    recordedAsSubmission=N["compliance/submission/cai-notice-2026-08"])
ind("communication/2026-08-board", "IncidentCommunication", "Briefing of the audit committee", communicationAbout=inc, hasAudience=T("AudGoverningBody"), sentAt=dt("2026-08-10"))
ind("recovery/2026-08-identity", "RecoveryVerification", "Identity service verified clean and accounts restored", verifiesRecoveryOf=N["asset/identity-service"],
    recoveryAfter=inc, assessedOn=dt("2026-08-05"), assessedBy=P["ciso"], hasEvidence=N["evidence/disable-log"])
ind("measurement/2026-08-ttc", "ResponseMeasurement", "Time to contain, August phishing incident", measuresMetric=T("MetricTimeToContain"), valueHours=dec(0.4),
    metricMethod=txt("From the alert (09:12) to the account disablement (09:35)"), measurementOf=inc)
ca = ind("action/CA-IR-2026-08", "CorrectiveAction", "Deploy phishing-resistant MFA for administrators", correctsFinding=N["finding/F-2026-05-01"],
         hasOwner=P["iam-lead"], dueOn=dt("2026-12-31"), hasActionStatus=T("ActionOpen"))
add(N["incident/2026-08-phishing/lesson"], "ledToAction", ca)

g.serialize(os.path.join(ROOT, "tests", "samples", "nordelle-secops.ttl"), format="turtle")
print("nordelle-secops: %d triples" % len(g))
