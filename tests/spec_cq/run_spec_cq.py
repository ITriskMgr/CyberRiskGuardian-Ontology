# -*- coding: utf-8 -*-
"""Competency questions CQ-03, 04, 05, 07, 08 and 11 of the v0.8 -> v1.0 specification (section 12), with positive,
negative, absent-data and contradictory-observation fixtures built from the synthetic Nordelle company.

Graph: the nine CRGO modules, the legal, GDPR, Loi 25 and source vocabularies, tests/samples/nordelle.ttl and the
applicability results. Fixtures are variants of that graph made in code, so each one states what it changes.
Every check prints PASS or FAIL; the script exits non-zero on any failure."""
import copy, os, sys
from rdflib import Graph, URIRef, Literal, Namespace
from rdflib.namespace import RDF, RDFS, XSD, DCTERMS

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "pipeline", "grc"))
import applicability  # noqa: E402
ids = dict(l.rstrip("\n").split("\t") for l in open(os.path.join(ROOT, "src", "ids.tsv"), encoding="utf-8"))
T = lambda k: URIRef("https://w3id.org/crgo/CRGO_%07d" % int(ids[k]))
N = Namespace("https://example.org/crgo-sample/nordelle/")
LEG = Namespace("https://w3id.org/crgo/vocab/legal/")
HERE = os.path.dirname(os.path.abspath(__file__))

base = Graph()
for m in ("gov", "core", "measure", "crg", "evidence", "org", "vuln", "grc", "mapping"):
    base.parse(os.path.join(ROOT, "ontology", "crgo-%s.ttl" % m))
for v in ("legal", "sources", "loi25", "gdpr"):
    base.parse(os.path.join(ROOT, "ontology", "vocab", v + ".ttl"))
base.parse(os.path.join(ROOT, "tests", "samples", "nordelle.ttl"))
sample = Graph(); sample += base
sample.parse(os.path.join(ROOT, "tests", "samples", "nordelle-applicability.ttl"))

def q(name, g, **params):
    txt = open(os.path.join(HERE, name + ".rq"), encoding="utf-8").read()
    import re
    txt = re.sub(r"\{\{(\w+)\}\}", lambda m: "<%s>" % T(m.group(1)), txt)
    init = {k: v for k, v in params.items()}
    return list(g.query(txt, initNs={"rdfs": RDFS, "dcterms": DCTERMS}, initBindings=init))

results = []
def check(label, cond, detail=""):
    results.append(cond); print("%s  %-74s %s" % ("PASS" if cond else "FAIL", label, detail))

def reassess(g, org=N.org, date="2026-10-01"):
    """Re-run the applicability evaluator on a variant profile (removing earlier results first)."""
    for a in list(g.subjects(RDF.type, T("ApplicabilityAssessment"))):
        g.remove((a, None, None))
    out, res = applicability.evaluate(g, org, date, N["person/ciso"], str(N))
    g += out
    return res

# ---- CQ-03
rows = q("CQ-03", sample, asset=N["asset/order-app"])
check("CQ-03 order application: both hypothetical scenarios, with the objective", {r.scenario for r in rows} == {N["scenario/credential-compromise"], N["scenario/ransomware"]}
      and all(r.objective == N["objective/online-revenue"] for r in rows), "%d rows" % len(rows))
check("CQ-03 negative: asset no scenario touches returns nothing", q("CQ-03", sample, asset=N["asset/kiosk"]) == [])
g = copy.deepcopy(sample); g.add((N["incident/2026-01"], RDF.type, T("Incident"))); g.add((N["incident/2026-01"], T("affectsAsset"), N["asset/order-app"]))
check("CQ-03 category guard: an incident is never returned as a scenario", N["incident/2026-01"] not in {r.scenario for r in q("CQ-03", g, asset=N["asset/order-app"])})
# ---- CQ-04
rows = q("CQ-04", sample)
got = {(r.scenario, r.measure, r.result) for r in rows}
check("CQ-04 assessed mitigations: MFA effective, backups partly effective", got == {(N["scenario/credential-compromise"], N["control/mfa"], T("TestEffective")),
      (N["scenario/ransomware"], N["control/backups"], T("TestPartlyEffective"))}, "%d rows" % len(rows))
check("CQ-04 planned, untested EDR is not claimed as a mitigation", N["control/edr"] not in {r.measure for r in rows})
g = copy.deepcopy(sample); ca = N["control-assessment/mfa-2026-10"]
for t in [(ca, RDF.type, T("ControlAssessment")), (ca, T("evaluatesControlMeasure"), N["control/mfa"]), (ca, T("hasTestResult"), T("TestIneffective")),
          (ca, T("assessedOn"), Literal("2026-10-05T00:00:00", datatype=XSD.dateTime))]: g.add(t)
check("CQ-04 negative: a later 'ineffective' test removes MFA from the answer", N["control/mfa"] not in {r.measure for r in q("CQ-04", g)})
# ---- CQ-05
rows = q("CQ-05", sample)
ev = {(r.measure, r.evidence) for r in rows}
check("CQ-05 evidence with dates for MFA and backups", (N["control/mfa"], N["evidence/mfa-config"]) in ev and (N["control/backups"], N["evidence/restore-test"]) in ev
      and all(r.gathered is not None for r in rows if r.evidence is not None))
check("CQ-05 evidence gap visible: EDR assessment has no evidence", any(r.measure == N["control/edr"] and r.evidence is None for r in rows))
rows2 = q("CQ-05", g)  # g holds the contradictory later MFA test
mfa = [r for r in rows2 if r.measure == N["control/mfa"]]
check("CQ-05 contradictory assessments: both MFA results returned, in date order", [r.result for r in mfa] == [T("TestEffective"), T("TestIneffective")])
# ---- CQ-07
rows = q("CQ-07", sample, org=N.org)
got = {str(r.instrument).rsplit("/", 1)[1]: r.state for r in rows}
check("CQ-07 Loi 25 applicable; GDPR and PIPEDA potentially applicable", got == {"P-39.1": T("AppApplicable"), "GDPR": T("AppPotentiallyApplicable"),
      "PIPEDA": T("AppPotentiallyApplicable")}, str({k: str(v)[-3:] for k, v in got.items()}))
counts = {str(r.instrument).rsplit("/", 1)[1]: int(r.provisions) for r in rows}
check("CQ-07 provision counts", counts.get("GDPR") == 40 and counts.get("P-39.1", 0) >= 29, str(counts))
def variant(remove=(), add=(), uncomplete=()):
    g = copy.deepcopy(sample)
    for s_, p_ in remove:
        for t in list(g.triples((s_, p_, None))): g.remove(t)
    for t in add: g.add(t)
    for k in uncomplete: g.remove((N.org, T("profileCompleteFor"), Literal(k)))
    return g
PA = N["processing/customer-orders"]; C_ = lambda k: (N.org, T("profileCompleteFor"), Literal(k))
qc_only = dict(remove=[(N.org, T("offersServicesIn")), (PA, T("dataSubjectsIn"))],
               add=[(N.org, T("offersServicesIn"), T("JurQuebec")), (PA, T("dataSubjectsIn"), T("JurQuebec"))])
res = reassess(variant(remove=qc_only["remove"], add=qc_only["add"], uncomplete=["monitorsBehaviourIn"]))
check("CQ-07 Québec-only company that does not say where it monitors behaviour -> GDPR unknown", res.get("GDPR") == "AppUnknown", str({k: v[3:] for k, v in res.items()}))
check("CQ-07 ... and transfers to recipients not stated -> PIPEDA unknown, not 'not applicable'", res.get("PIPEDA") == "AppUnknown")
res = reassess(variant(remove=qc_only["remove"], add=qc_only["add"] + [C_("transfersDataTo")]))
check("CQ-07 negative: Québec-only company, monitoring and transfers stated -> GDPR and PIPEDA not applicable",
      res.get("GDPR") == "AppNotApplicable" and res.get("PIPEDA") == "AppNotApplicable", str({k: v[3:] for k, v in res.items()}))
g = variant(remove=[(N.org, T("carriedOutBy"))], uncomplete=["carriedOutBy"])
for a in list(g.subjects(T("carriedOutBy"), N.org)): g.remove((a, None, None))
res = reassess(g); unk = q("CQ-07u", g, org=N.org)
check("CQ-07 absent data: no processing activity recorded -> Loi 25 and GDPR unknown, not 'not applicable'",
      res.get("P-39.1") == "AppUnknown" and res.get("GDPR") == "AppUnknown", str({k: v[3:] for k, v in res.items()}))
check("CQ-07u names the missing fact (processing of personal information)", any(r.condition == LEG["condition/P39-1-PI"] for r in unk), "%d rows" % len(unk))
res = reassess(variant(add=[(N.org, T("hasOrganisationType"), T("OrgPublicBody"))]))
check("CQ-07 enterprise that is also a public body -> Loi 25 excluded by its s. 3 exception, A-2.1 applicable",
      res.get("P-39.1") == "AppNotApplicable" and res.get("A-2.1") == "AppApplicable", str({k: v[3:] for k, v in res.items()}))
res = reassess(variant(remove=qc_only["remove"] + [(N.org, T("hasOrganisationType"))],
                       add=qc_only["add"] + [C_("transfersDataTo"), (N.org, T("hasOrganisationType"), T("OrgEnterprise")), (N.org, T("hasOrganisationType"), T("OrgFRFI"))]))
check("CQ-07 Québec insurer regulated by OSFI, no cross-border data -> B-13 applicable, PIPEDA not applicable",
      res.get("OSFI-B-13") == "AppApplicable" and res.get("PIPEDA") == "AppNotApplicable", str({k: v[3:] for k, v in res.items()}))
res = reassess(variant(remove=[(N.org, T("establishedIn"))], add=[(N.org, T("establishedIn"), T("JurCanadaOtherProvince"))]))
check("CQ-07 Ontario-type firm selling into Québec -> Loi 25 potentially applicable, PIPEDA applicable",
      res.get("P-39.1") == "AppPotentiallyApplicable" and res.get("PIPEDA") == "AppApplicable", str({k: v[3:] for k, v in res.items()}))
res = reassess(variant(remove=[(N.org, T("establishedIn"))], add=[(N.org, T("establishedIn"), T("JurEU"))]), date="2017-06-01")
check("CQ-07 date: EU-established firm assessed on 2017-06-01 -> GDPR not yet applicable (applies from 2018-05-25)", res.get("GDPR") == "AppNotApplicable", str(res.get("GDPR")))
res = reassess(variant(remove=[(N.org, T("establishedIn"))], add=[(N.org, T("establishedIn"), T("JurEU"))]))
check("CQ-07 same firm on 2026-10-01 -> GDPR applicable (Art. 3(1), plain)", res.get("GDPR") == "AppApplicable", str(res.get("GDPR")))
# ---- CQ-08
rows = q("CQ-08", sample, org=N.org)
byd = {}
for r in rows: byd.setdefault(str(r.determination).rsplit("/", 1)[1], []).append(r)
check("CQ-08 four determinations", set(byd) == {"loi25-register", "loi25-security", "gdpr-notification", "loi25-pia"})
check("CQ-08 satisfied register determination rests on evidence", all(r.evidence is not None for r in byd["loi25-register"]))
check("CQ-08 undetermined and not-assessed items carry an explicit evidence gap",
      all(r.gap is not None and r.evidence is None for k in ("gdpr-notification", "loi25-pia") for r in byd[k]))
# ---- CQ-11
rows = q("CQ-11", sample, ra=N["assessment/2026"])
items = {(str(r.kind), r.item) for r in rows}
check("CQ-11 assumptions of the 2026 assessment", {i for k, i in items if k == "assumption"} == {N["assumption/admin-targeting"], N["assumption/restore-time"]})
check("CQ-11 negative: assumption of an estimate outside the assessment excluded", ("assumption", N["assumption/old"]) not in items)
srcs = {i for k, i in items if k == "source version"}
check("CQ-11 source versions of the legal texts behind the determinations (Loi 25, GDPR)",
      {URIRef("https://w3id.org/crgo/vocab/sources/qc-p-39.1"), URIRef("https://w3id.org/crgo/vocab/sources/eu-gdpr")} <= srcs, "%d sources" % len(srcs))
print("%d of %d specification competency checks pass" % (sum(results), len(results)))
sys.exit(0 if all(results) else 1)
