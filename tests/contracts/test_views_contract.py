# -*- coding: utf-8 -*-
"""Read contracts compliance/v1 and secops/v1 (decisions D11, S10): schemas, examples, expected content on the synthetic
Nordelle data, dating, tenant separation and errors. Prints PASS/FAIL; exits non-zero on any failure."""
import copy, json, os, sys
from rdflib import URIRef, Literal
from rdflib.namespace import XSD
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "pipeline", "contracts"))
import dss, views  # noqa: E402
N = "https://example.org/crgo-sample/nordelle/"; B = "https://example.org/crgo-sample/boreal/"
FILES = [os.path.join(ROOT, "tests", "samples", f) for f in ("nordelle.ttl", "nordelle-applicability.ttl", "nordelle-grca.ttl", "nordelle-pca.ttl", "nordelle-secops.ttl", "tenant-b.ttl")]
res = []
def check(label, cond, detail=""):
    res.append(bool(cond)); print("%s  %-86s %s" % ("PASS" if cond else "FAIL", label, detail))
G = dss.load(FILES)
c = views.compliance_context(FILES, N + "org", "2026-10-12", g=G)
s = views.secops_context(FILES, N + "org", "2026-10-12", g=G)
check("compliance: document conforms to compliance-context.schema.json", views.validate(c, "compliance/v1") == [], str(views.validate(c, "compliance/v1"))[:200])
check("secops: document conforms to secops-context.schema.json", views.validate(s, "secops/v1") == [], str(views.validate(s, "secops/v1"))[:200])
for name, contract in (("compliance/v1/examples/compliance-context.nordelle.json", "compliance/v1"), ("secops/v1/examples/secops-context.nordelle.json", "secops/v1")):
    check("example %s conforms" % name.split("/")[-1], views.validate(json.load(open(os.path.join(ROOT, "contracts", name))), contract) == [])
ob = {o["id"]: o for o in c["obligations"]}
s10 = "https://w3id.org/crgo/vocab/loi25/P-39.1_s._10"; s38 = "https://w3id.org/crgo/vocab/loi25/P-39.1_s._3.8"
check("compliance: Loi 25 s. 10 is applicable, partially satisfied, with three supporting statements and the backup measure mapped directly",
      ob[s10]["applicability"] == "applicable" and ob[s10]["complianceState"] == "partially-satisfied" and len(ob[s10]["supportingStatements"]) == 3
      and any(m["id"] == N + "control/backups" and "mapping" in m for m in ob[s10]["implementingMeasures"]))
check("compliance: s. 3.8 is satisfied on evidence judged insufficient (expired / out of date)", ob[s38]["complianceState"] == "satisfied" and ob[s38]["evidenceStatus"] == "judged-insufficient")
check("compliance: no obligation is reported compliant because of a mapping alone", all(o["complianceState"] == "not-assessed" or "determination" in o for o in c["obligations"]))
dv = {v["id"]: v for v in c["directiveVersions"]}
check("compliance: the access control standard v1 is overdue for review; policy v3 is not", dv[N + "standard-version/access-control-1"]["reviewOverdue"] and not dv[N + "policy-version/infosec-3"]["reviewOverdue"])
ex = {e["id"]: e for e in c["exceptions"]}[N + "exception/edr-legacy-pos"]
check("compliance: the EDR exception is active, linked to the risk acceptance, and concerns s. 10 without exemption",
      ex["active"] and ex["riskAcceptance"] == N + "risk-acceptance/legacy-pos-2026" and ex["provisionsWithoutExemption"] == [s10])
dl = {d["id"]: d for d in c["deadlines"]}
check("compliance: the GDPR 72-hour deadline is computed from the confirmation (2026-08-07T00:00) and unanswered",
      dl[N + "compliance/deadline/gdpr-72h-2026-08"]["due"] == "2026-08-07T00:00:00" and not dl[N + "compliance/deadline/gdpr-72h-2026-08"]["answered"])
fd = {f["id"]: f for f in c["findings"]}
check("compliance: F-2026-03-01 (reopened) and F-2026-05-01 are open; F-2026-05-01 has an overdue action",
      fd[N + "finding/F-2026-03-01"]["open"] and fd[N + "finding/F-2026-05-01"]["overdueActions"] == [N + "action/CA-NC-2026-07"])
c_t = views.compliance_context(FILES, N + "org", "2026-08-30", g=G)
check("compliance/temporal: on 2026-08-30 F-2026-03-01 was closed and F-2026-05-01 had no overdue action",
      not {f["id"]: f for f in c_t["findings"]}[N + "finding/F-2026-03-01"]["open"] and {f["id"]: f for f in c_t["findings"]}[N + "finding/F-2026-05-01"]["overdueActions"] == [])
sc = {x["id"]: x for x in s["scenarios"]}
check("secops: ransomware coverage is validated by a test; credential compromise coverage is untested with a detection gap",
      any(cv["validatedByTest"] for cv in sc[N + "scenario/ransomware"]["coverage"]) and all(not cv["validatedByTest"] for cv in sc[N + "scenario/credential-compromise"]["coverage"])
      and sc[N + "scenario/credential-compromise"]["detectionGaps"] == [N + "detection-gap/edr-servers"])
check("secops: the ransomware playbook has not passed simulation; the compromised-account playbook has",
      not sc[N + "scenario/ransomware"]["playbooks"][0]["simulationPassed"] and sc[N + "scenario/credential-compromise"]["playbooks"][0]["simulationPassed"])
rl = {r["id"]: r for r in s["detectionRules"]}
check("secops: the impossible-travel v2 rule needs the silent EDR source", {x["id"]: x["health"] for x in rl[N + "detection-rule/impossible-travel-v2"]["requiredSources"]}[N + "telemetry/edr-servers"] == "silent")
check("secops: the payment-service alert is untriaged on a crown jewel; the false positive is not listed",
      {a["id"]: a["crownJewel"] for a in s["untriagedAlerts"]} == {N + "alert/2026-10-11-payment-admin": True, N + "alert/2026-10-10-kiosk": False})
check("secops: only the October isolation lacks a valid approval (expired pre-authorisation)",
      s["executionsWithoutValidApproval"] == [{"id": N + "action-execution/2026-10-10-isolate", "action": N + "response-action/isolate-host", "reason": "expired"}])
check("secops: both incidents have undetermined GDPR reportability", {t["incident"] for t in s["openRegulatoryTriage"]} == {N + "incident/2026-08-phishing", N + "incident/2026-10-kiosk-malware"})
s_t = views.secops_context(FILES, N + "org", "2026-10-09", g=G)
check("secops/temporal: on 2026-10-09 the October execution and the kiosk incident are not yet visible",
      s_t["executionsWithoutValidApproval"] == [] and N + "incident/2026-10-kiosk-malware" not in {t["incident"] for t in s_t["openRegulatoryTriage"]})
check("secops: never an authorisation: the caveats say so", any("authorises" in x for x in s["caveats"]))
g2 = copy.deepcopy(G); g2.add((URIRef(N + "exception/edr-legacy-pos"), dss.T("exceptionTo"), URIRef(B + "control/backups")))
g2.add((URIRef(B + "alert/x"), dss.T("involvesAsset"), URIRef(N + "asset/payment-service")))
c_l = views.compliance_context(FILES, N + "org", "2026-10-12", g=g2); s_l = views.secops_context(FILES, N + "org", "2026-10-12", g=g2)
check("tenant: another organisation's records are withheld and reported", B not in json.dumps(c_l) and B not in json.dumps(s_l) and any("withheld" in x for x in c_l["caveats"]))
b = views.compliance_context(FILES, B + "org", "2026-10-12", g=G)
check("tenant: Boréal's context contains nothing of Nordelle", N not in json.dumps(b) and views.validate(b, "compliance/v1") == [])
for org, code in (("https://w3id.org/crgo/data/x/org", "REFERENCE_NAMESPACE"), ("https://example.org/unknown/org", "UNKNOWN_ORGANISATION")):
    e1, e2 = views.compliance_context(FILES, org, "2026-10-12", g=G), views.secops_context(FILES, org, "2026-10-12", g=G)
    check("error: %s for %s" % (code, org), e1.get("code") == code and e2.get("code") == code and dss.validate_doc(e1, "error.schema.json") == [])
print("%d of %d checks passed" % (sum(res), len(res)))
sys.exit(0 if all(res) else 1)
