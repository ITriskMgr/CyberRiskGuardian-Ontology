# -*- coding: utf-8 -*-
"""Check that the CRGO graph of a CRG assessment reproduces CRG's numbers: totals and stored sensitivity cases."""
import json, os, sys
import rdflib
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
ids = dict(l.rstrip("\n").split("\t") for l in open(os.path.join(ROOT, "src", "ids.tsv"), encoding="utf-8"))
c = lambda k: "<https://w3id.org/crgo/CRGO_%07d>" % int(ids[k])
g = rdflib.Graph(); g.parse(os.path.join(HERE, "medibec30.ttl"))
data = json.load(open(os.path.join(HERE, "medibec30.json"), encoding="utf-8"))
q = """SELECT (SUM(?v) AS ?total) WHERE { ?q a %s ; %s ?v ; %s ?case . ?case %s %s }"""
tot = lambda cls: float(next(iter(g.query(q % (c(cls), c("numericValue"), c("inSensitivityCase"), c("hasCaseType"), c("CaseCentral")))))[0])
ok = True
est, res = tot("EstimatedRisk"), tot("ResidualRisk")
print("total estimated %.0f (CRG regression 84,491), residual %.0f (41,104)" % (est, res))
ok &= round(est) == 84491 and round(res) == 41104
q2 = """SELECT ?v WHERE { ?s %s "%s" . ?q %s ?s ; a %s ; %s ?v ; %s ?case . ?case %s %s }"""
for s in data.get("SENS", []):
    for case, ck in (("lower", "CaseLower"), ("higher", "CaseHigher")):
        v = float(next(iter(g.query(q2 % (c("localIdentifier"), s["id"], c("estimateOf"), c("EstimatedRisk"), c("numericValue"),
                                           c("inSensitivityCase"), c("hasCaseType"), c(ck)))))[0])
        if abs(v - s[case]["est"]) > 1e-6 * max(1, v):
            ok = False; print("sensitivity mismatch", s["id"], case, v, s[case]["est"])
print("sensitivity cases: %d scenarios checked" % len(data.get("SENS", [])))
print("round trip OK" if ok else "ROUND TRIP FAILED")
sys.exit(0 if ok else 1)
