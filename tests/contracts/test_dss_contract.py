# -*- coding: utf-8 -*-
"""DSS contract dss/v1: schemas, examples, error cases, tenant separation and the write-back path (ADR-007, ADR-008).
Prints PASS/FAIL; exits non-zero on any failure. Writes only to build/ (a scratch proposed graph)."""
import copy, json, os, sys
from rdflib import Graph, URIRef
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "pipeline", "contracts"))
import dss  # noqa: E402
EX = os.path.join(ROOT, "contracts", "dss", "v1", "examples")
N = "https://example.org/crgo-sample/nordelle/"; B = "https://example.org/crgo-sample/boreal/"
FILES = [os.path.join(ROOT, "tests", "samples", f) for f in ("nordelle.ttl", "nordelle-applicability.ttl", "nordelle-grca.ttl", "tenant-b.ttl")]
res = []
def check(label, cond, detail=""):
    res.append(bool(cond)); print("%s  %-82s %s" % ("PASS" if cond else "FAIL", label, detail))
G = dss.load(FILES)
ctx = dss.risk_context(FILES, N + "org", N + "scenario/ransomware", "2026-10-11", g=G)
check("read: Nordelle ransomware context conforms to risk-context.schema.json", dss.validate_doc(ctx, "risk-context.schema.json") == [], str(dss.validate_doc(ctx, "risk-context.schema.json"))[:200])
check("read: the stored example conforms to the schema", dss.validate_doc(json.load(open(os.path.join(EX, "risk-context.nordelle-ransomware.json"))), "risk-context.schema.json") == [])
check("read: no risk score in the context (CRGO does not compute risk)", not any(k in json.dumps(ctx) for k in ('"estimatedRisk"', '"residualRisk"', '"riskScore"')))
check("read: the open finding and both conflicting results reach the DSS",
      any(N + "finding/F-2026-03-01" in c["openFindings"] for c in ctx["controlLinks"]) and
      {a["line"] for c in ctx["controlLinks"] for a in c["latestAssessments"]} >= {"self-assessment", "internal-audit", "second-line"})
check("read: obligations carry applicability and compliance state, never 'compliant' from a mapping",
      all(o["applicability"] in ("applicable", "not-applicable", "potentially-applicable", "unknown", "not-assessed") for o in ctx["candidateObligations"]))
check("read: estimates outside an assessment are left out, with a caveat", all("unrelated" not in e["id"] for e in ctx["estimates"]) and any("left out" in c for c in ctx["caveats"]))
ctx_t = dss.risk_context(FILES, N + "org", N + "scenario/ransomware", "2026-05-01", g=G)
check("read/temporal: on 1 May 2026 the September results and the May finding are not yet visible",
      all(a["assessedOn"] <= "2026-05-01" for c in ctx_t["controlLinks"] for a in c["latestAssessments"]) and not any(c["openFindings"] for c in ctx_t["controlLinks"]))
g2 = copy.deepcopy(G); g2.add((URIRef(N + "scenario/ransomware"), dss.T("affectsAsset"), URIRef(B + "control/backups")))
ctx_l = dss.risk_context(FILES, N + "org", N + "scenario/ransomware", "2026-10-11", g=g2)
check("tenant: a stray link to another organisation's record is withheld and reported", B not in json.dumps(ctx_l) and any("withheld" in c for c in ctx_l["caveats"]))
g3 = copy.deepcopy(G)
from rdflib import Literal as _L
from rdflib.namespace import XSD as _X
g3.add((URIRef(B + "finding/x"), dss.T("findingOnControl"), URIRef(N + "control/backups"))); g3.add((URIRef(B + "finding/x"), dss.T("raisedOn"), _L("2026-06-01T00:00:00", datatype=_X.dateTime)))
g3.add((URIRef(N + "scenario/ransomware"), dss.T("triggersObligation"), URIRef(B + "obligation/x")))
ctx_f = dss.risk_context(FILES, N + "org", N + "scenario/ransomware", "2026-10-11", g=g3)
check("tenant: another organisation's finding and obligation linked to Nordelle are withheld", B not in json.dumps(ctx_f) and any("withheld" in c for c in ctx_f["caveats"]))
g4 = copy.deepcopy(G); d2 = URIRef(N + "compliance/loi25-security-2026-10-20")
for p_, o_ in G.predicate_objects(URIRef(N + "compliance/loi25-security")):
    g4.add((d2, p_, o_))
g4.set((d2, dss.T("assessedOn"), _L("2026-10-20T00:00:00", datatype=_X.dateTime))); g4.set((d2, dss.T("hasComplianceState"), dss.T("CompSatisfied")))
s10 = "https://w3id.org/crgo/vocab/loi25/P-39.1_s._10"
st = lambda c: next(o.get("complianceState") for o in c["candidateObligations"] if o["id"] == s10)
check("read/temporal: a determination made after as_of is not used; on a later date the latest one is",
      st(dss.risk_context(FILES, N + "org", N + "scenario/ransomware", "2026-10-11", g=g4)) == "partially-satisfied"
      and st(dss.risk_context(FILES, N + "org", N + "scenario/ransomware", "2026-10-25", g=g4)) == "satisfied")
check("tenant: asking for another organisation's scenario is refused", dss.risk_context(FILES, N + "org", B + "control/backups", "2026-10-11", g=G).get("code") == "TENANT_MISMATCH")
check("tenant: an organisation id under https://w3id.org/crgo/ is refused", dss.risk_context(FILES, "https://w3id.org/crgo/org/x", N + "scenario/ransomware", "2026-10-11", g=G).get("code") == "REFERENCE_NAMESPACE")
check("read: an unknown scenario is an error, not an empty context", dss.risk_context(FILES, N + "org", N + "scenario/none", "2026-10-11", g=G).get("code") == "UNKNOWN_SUBJECT")
# write-back
OUT = os.path.join(ROOT, "build", "contract-test-nordelle-dss-proposed.ttl")
if os.path.exists(OUT): os.remove(OUT)
wb = json.load(open(os.path.join(EX, "assessment-result.nordelle-ransomware.json")))
r = dss.submit_assessment(wb, FILES, OUT, g=G)
check("write: the example is stored as a proposed analytical result in the organisation's proposed graph", r.get("status") == "proposed" and os.path.exists(OUT), str(r)[:160])
pg = Graph().parse(OUT); s = URIRef(r.get("stored", "x"))
check("write: stored with knowledge status 'risk estimate' and status proposed, model and version kept",
      (s, dss.T("hasKnowledgeStatus"), dss.T("KsRiskEstimate")) in pg and (s, dss.T("governanceStatus"), dss.T("StatusProposed")) in pg
      and str(pg.value(s, dss.T("modelVersion"))) == "1.1.0" and str(s).startswith(N))
check("write: never into the organisation's fact graph (only *-dss-proposed.ttl)", dss.submit_assessment(wb, FILES, os.path.join(ROOT, "build", "nordelle-facts.ttl"), g=G).get("code") == "REFERENCE_NAMESPACE")
OTHER = os.path.join(ROOT, "build", "contract-test-boreal-dss-proposed.ttl")
_og = Graph(); _o = URIRef("https://example.org/crgo-sample/boreal-dss-proposed"); _og.add((_o, dss.RDF.type, dss.OWL.Ontology)); _og.add((_o, dss.VANN_NS, _L(B))); _og.serialize(OTHER, format="turtle")
check("write: never into another organisation's proposed graph", dss.submit_assessment(wb, FILES, OTHER, g=G).get("code") == "TENANT_MISMATCH")
check("write: placeholder model version in any case ('tbd') is refused", dss.submit_assessment(dict(wb, modelVersion="tbd"), FILES, OUT, g=G).get("code") == "MODEL_VERSION_MISSING")
check("write: never into a reference file", dss.submit_assessment(wb, FILES, os.path.join(ROOT, "ontology", "x.ttl"), g=G).get("code") == "REFERENCE_NAMESPACE")
EXPECT = {"status-approved": "STATUS_NOT_PROPOSED", "model-version-tbd": "MODEL_VERSION_MISSING", "reference-namespace-subject": "REFERENCE_NAMESPACE",
          "other-tenant-subject": "TENANT_MISMATCH", "other-tenant-input": "TENANT_MISMATCH", "unknown-subject": "UNKNOWN_SUBJECT",
          "negative-value": "SCHEMA_INVALID", "missing-inputs": "SCHEMA_INVALID", "currency-without-code": "SCHEMA_INVALID"}
for name, code in sorted(EXPECT.items()):
    d = json.load(open(os.path.join(EX, "invalid", name + ".json")))
    out = dss.submit_assessment(d, FILES, OUT, g=G)
    ok = out.get("code") == code and dss.validate_doc(out, "error.schema.json") == []
    check("write error case %-28s -> %s" % (name, code), ok, out.get("code", "stored!"))
# SHACL on the stored result
try:
    from pyshacl import validate
    data = Graph()
    for m in ("gov", "core", "measure", "evidence", "governance"):
        data.parse(os.path.join(ROOT, "ontology", "crgo-%s.ttl" % m))
    data += pg
    c, _, txt = validate(data, shacl_graph=Graph().parse(os.path.join(ROOT, "shapes", "crgo-shapes.ttl")), inference="none", advanced=True, allow_warnings=True)
    check("write: the stored result conforms to the SHACL shapes (AnalyticalResult)", c, "" if c else txt[:300])
except ImportError:
    check("pySHACL available", False)
print("%d of %d contract checks passed" % (sum(res), len(res)))
sys.exit(0 if all(res) else 1)
