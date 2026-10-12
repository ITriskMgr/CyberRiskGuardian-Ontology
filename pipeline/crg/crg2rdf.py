# -*- coding: utf-8 -*-
"""CyberRiskGuardian -> CRGO bridge.

Converts a CRG assessment file (the JSON data model of assets/scenario-template.json) into CRGO
instance data (Turtle and JSON-LD). Risk quantities are computed with CRG's own crg_calc.py, never
re-implemented, so the RDF reproduces CRG's numbers exactly.

Usage:
    python3 pipeline/crg/crg2rdf.py ASSESSMENT.json --crg-calc PATH/TO/crg_calc.py --base https://example.org/a/ [--org-label NAME] [--out out.ttl]

The base must be the organisation's own namespace (never under https://w3id.org/crgo/, ADR-008); the output declares
it with vann:preferredNamespaceUri and names the assessed organisation <base>org.

Mapping notes (lossy fields are kept as text; see docs/crg-mapping.md):
- params {v, qual, rat, ev, conf} -> CRG parameter estimate with numericValue, qualitativeReading, rationale,
  hasEvidence, hasConfidence.
- consequences keys -> ConsequenceDescription with ImpactDimension ("Confidentiality/privacy" -> confidentiality + privacy).
- EVIDENCE basis strings -> EvidenceBasis by keyword; the original string is kept as rdfs:comment.
- owners and stakeholders are text in CRG; they stay text (rdfs:comment) until positions are modelled.
"""
import argparse, importlib.util, json, os, re
from rdflib import Graph, Namespace, Literal, URIRef
from rdflib.namespace import RDF, RDFS, OWL, XSD

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
ids = dict(l.rstrip("\n").split("\t") for l in open(os.path.join(ROOT, "src", "ids.tsv"), encoding="utf-8"))
C = lambda k: URIRef("https://w3id.org/crgo/CRGO_%07d" % int(ids[k]))
D = lambda v: Literal(repr(round(float(v), 9)), datatype=XSD.decimal)

PARAM = {"PbA": "ThreatPresence", "Pbx": "ExploitationProbability", "De": "ExpectedDamage", "Dm": "MaximumDamage",
         "Th": "Resilience", "Mu": "Criticality"}
KRI = {"est": "EstimatedRisk", "tol": "ToleratedRisk", "mit": "MitigatedRisk", "res": "ResidualRisk",
       "ratio": "RiskToToleranceRatio", "pre_ratio": "PreTreatmentRatio"}
CONF = {"high": "ConfHigh", "medium": "ConfMedium", "low": "ConfLow"}
DIM = {"confidentiality/privacy": ["DimConfidentiality", "DimPrivacy"], "confidentiality": ["DimConfidentiality"],
       "privacy": ["DimPrivacy"], "integrity": ["DimIntegrity"], "availability": ["DimAvailability"],
       "operations": ["DimOperational"], "operational": ["DimOperational"], "financial": ["DimFinancial"],
       "regulatory": ["DimLegal"], "legal": ["DimLegal"], "reputation": ["DimReputation"], "safety": ["DimSafety"],
       "strategic": ["DimStrategic"]}
REQ = {"low": "ReqLow", "medium": "ReqModerate", "moderate": "ReqModerate", "high": "ReqHigh", "very high": "ReqVeryHigh"}
PRIO = {"immediate": "PrioImmediate", "near-term": "PrioNearTerm", "near term": "PrioNearTerm", "planned": "PrioPlanned"}
FN = {"governance": "FnGovernance", "prevention": "FnPrevention", "detection": "FnDetection", "response": "FnResponse",
      "recovery": "FnRecovery", "resilience": "FnResilience"}
TOL = {"Below tolerance": "TolBelow", "Approximately at tolerance": "TolAt", "Above tolerance": "TolAbove"}

def basis(s):
    t = s.lower()
    for pat, k in [(r"exercise|simulation|inject|illustrative - validate", "EvExercise"), (r"document", "EvDocumented"),
                   (r"external|methodolog|calibration|benchmark|sector", "EvExternal"), (r"expert|sme|interview|workshop", "EvSME"),
                   (r"\bai\b|analyst estimate", "EvAIEstimate"), (r"assum|inferen", "EvInference")]:
        if re.search(pat, t):
            return k
    return None

def disposition(s):
    t = s.lower()
    if t.startswith("selected"): return "DispSelect"
    if t.startswith("merged") or t.startswith("consolidated"): return "DispConsolidate"
    if t.startswith("deferred"): return "DispDefer"
    if "consider" in t: return "DispConsider"
    return None

def load_calc(path):
    spec = importlib.util.spec_from_file_location("crg_calc", path)
    m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
    return m

VANN_NS = URIRef("http://purl.org/vocab/vann/preferredNamespaceUri")
ORG_CLASS = URIRef("https://www.commoncoreontologies.org/ont00001180")

def convert(data, calc, base, org_label=None):
    X = Namespace(base)
    g = Graph()
    for p, n in [("crgo", "https://w3id.org/crgo/"), ("x", X), ("xsd", XSD), ("owl", OWL)]:
        g.bind(p, n)
    A = lambda *t: [g.add(x) for x in t]
    o = URIRef(base.rstrip("/#"))
    A((o, RDF.type, OWL.Ontology), (o, OWL.imports, URIRef("https://w3id.org/crgo/crgo")))
    # 0.9.0 (ADR-008): the organisation graph declares its base, and the assessed organisation is an individual,
    # so that the DSS contract (crgo_risk_context, crgo_submit_assessment) can scope requests to it
    A((o, VANN_NS, Literal(str(X))), (X.org, RDF.type, OWL.NamedIndividual), (X.org, RDF.type, ORG_CLASS))
    if org_label: A((X.org, RDFS.label, Literal(org_label, lang="en")))
    run = calc.run(data)
    res = {r["id"]: r for r in run["results"]}
    a = X.assessment
    A((a, RDF.type, C("RiskAssessment")), (a, C("usesCalculationMethod"), C("MethodCRG_v1_0c")),
      (a, C("assessmentFactor"), D(run["factor"])), (a, C("hasRiskAppetite"), X.appetite),
      (X.appetite, RDF.type, C("RiskAppetiteStatement")), (X.appetite, C("numericValue"), D(run["appetite"])),
      (a, C("assessesOrganization"), X.org))
    if "PERIOD" in data: A((a, C("assessmentHorizon"), Literal(data["PERIOD"])))
    if "CASE_APPETITE" in data: A((a, C("caseAppetite"), D(data["CASE_APPETITE"])))
    if "CURRENCY" in data: A((a, C("currencyCode"), Literal(data["CURRENCY"])))
    if "SOURCE" in data: A((a, RDFS.comment, Literal("Source: " + data["SOURCE"], lang="en")))
    calc_act = X.calculation
    A((calc_act, RDF.type, C("CalculationActivity")), (calc_act, C("usesMethod"), C("MethodCRG_v1_0c")))
    for e in data.get("EVIDENCE", []):
        eid, title, bas = e[0], e[1], e[2]
        n = X["evidence-" + eid]
        A((n, RDF.type, C("EvidenceItem")), (n, C("localIdentifier"), Literal(eid)), (n, C("evidenceLocator"), Literal(title)),
          (n, RDFS.comment, Literal("Basis as stated: " + bas, lang="en")))
        if len(e) > 3: A((n, RDFS.comment, Literal(e[3], lang="en")))
        if basis(bas): A((n, C("hasEvidenceBasis"), C(basis(bas))))
    evid = lambda s: [X["evidence-" + m] for m in sorted(set(re.findall(r"\bE\d+\b", s or ""))) if any(e[0] == m for e in data.get("EVIDENCE", []))]
    crown = {}
    for cj in data.get("CROWN", []):
        n = X["asset-" + cj[0]]; v = X["valuation-" + cj[0]]; crown[cj[0]] = n
        A((n, RDF.type, C("Asset")), (n, C("localIdentifier"), Literal(cj[0])), (n, RDFS.label, Literal(cj[1], lang="en")),
          (v, RDF.type, C("AssetValuation")), (v, C("valuationOf"), n), (v, C("isCrownJewel"), Literal(True)),
          (v, C("purposeText"), Literal(cj[2], lang="en")), (v, RDFS.comment, Literal("Owner: " + cj[3], lang="en")))
        for k, val in zip(("hasConfidentialityRequirement", "hasIntegrityRequirement", "hasAvailabilityRequirement"), cj[4:7]):
            if val.lower() in REQ: A((v, C(k), C(REQ[val.lower()])))
        if len(cj) > 7: A((v, RDFS.comment, Literal("Depends on: " + cj[7], lang="en")))
        if len(cj) > 8: A((v, RDFS.comment, Literal("Provider: " + cj[8], lang="en")))
    for s in data["SCEN"]:
        sid = s["id"]; n = X["scenario-" + sid]; r = res[sid]
        A((n, RDF.type, C("AssessmentScenario")), (n, C("localIdentifier"), Literal(sid)), (n, RDFS.label, Literal(s["name"], lang="en")),
          (a, C("includesScenario"), n))
        for k, p in [("statement", "statement"), ("background", "background"), ("narrative", "narrative")]:
            if s.get(k): A((n, C(p), Literal(s[k], lang="en")))
        for k in ("stakeholders", "processes", "owner", "ref"):
            if s.get(k): A((n, RDFS.comment, Literal("%s: %s" % (k.capitalize(), s[k]), lang="en")))
        if s.get("threat_source"):
            t = X["source-" + sid]; A((t, RDF.type, C("ThreatSourceDescription")), (t, RDFS.label, Literal(s["threat_source"], lang="en")),
                                      (n, C("hasThreatSourceDescription"), t))
        if s.get("threat_event"):
            t = X["event-" + sid]; A((t, RDF.type, C("ThreatEventDescription")), (t, RDFS.label, Literal(s["threat_event"], lang="en")),
                                     (n, C("hasThreatEvent"), t))
        for i, vtext in enumerate(s.get("vulns", []), 1):
            t = X["vuln-%s-%d" % (sid, i)]
            A((t, RDF.type, C("VulnerabilityDescription")), (t, RDFS.label, Literal(vtext, lang="en")), (n, C("hasVulnerabilityDescription"), t))
            for e in evid(vtext): A((t, C("hasEvidence"), e))
        for cj in sorted(set(re.findall(r"\bCJ\d+\b", s.get("assets", "")))):
            if cj in crown: A((n, C("affectsAsset"), crown[cj]))
        if s.get("assets"): A((n, RDFS.comment, Literal("Assets: " + s["assets"], lang="en")))
        for i, ctext in enumerate(s.get("controls", []), 1):
            t = X["control-%s-%d" % (sid, i)]
            A((t, RDF.type, C("ControlMeasure")), (t, RDFS.label, Literal(ctext, lang="en")), (t, C("hasControlStatus"), C("CtlInPlace")),
              (n, C("mitigatedBy"), t))
            for e in evid(ctext): A((t, C("hasEvidence"), e))
        prev = None
        for i, step in enumerate(s.get("sequence", []), 1):
            t = X["step-%s-%d" % (sid, i)]
            A((t, RDF.type, C("ScenarioStep")), (t, RDFS.label, Literal(step, lang="en")), (t, C("stepOrder"), Literal(i)), (n, C("hasStep"), t))
            if prev is not None: A((prev, C("nextStep"), t))
            prev = t
        for k, text in s.get("consequences", {}).items():
            t = X["consequence-%s-%s" % (sid, re.sub(r"[^A-Za-z]", "", k))]
            A((t, RDF.type, C("ConsequenceDescription")), (t, RDFS.label, Literal("%s: %s" % (k, text), lang="en")), (n, C("hasConsequence"), t))
            for dmn in DIM.get(k.lower(), []): A((t, C("hasImpactDimension"), C(dmn)))
        inputs = []
        for k, cls in PARAM.items():
            p = s["params"][k]; p = p if isinstance(p, dict) else {"v": p}
            t = X["%s-%s" % (sid, k)]
            A((t, RDF.type, C(cls)), (t, C("estimateOf"), n), (t, C("assessedIn"), a), (t, C("numericValue"), D(p["v"])),
              (t, C("onScale"), C("ScaleUnitInterval")), (t, C("hasRiskStage"), C("StageInherent")))
            if p.get("qual"): A((t, C("qualitativeReading"), Literal(p["qual"], lang="en")))
            if p.get("rat"): A((t, C("rationale"), Literal(p["rat"], lang="en")))
            if p.get("conf", "").lower() in CONF: A((t, C("hasConfidence"), C(CONF[p["conf"].lower()])))
            for e in evid(p.get("ev", "")): A((t, C("hasEvidence"), e))
            inputs.append(t)
        for k, cls in (("red_p", "ProbabilityReduction"), ("red_i", "ImpactReduction")):
            t = X["%s-%s" % (sid, k)]
            A((t, RDF.type, C(cls)), (t, C("estimateOf"), n), (t, C("assessedIn"), a), (t, C("numericValue"), D(s[k])),
              (t, C("onScale"), C("ScaleUnitInterval")))
            inputs.append(t)
        t = X["%s-cvss" % sid]
        A((t, RDF.type, C("CVSSInput")), (t, C("estimateOf"), n), (t, C("numericValue"), D(r["cvss"])), (t, C("onScale"), C("ScaleCVSS")))
        if isinstance(s.get("cvss"), str) and s["cvss"].startswith("CVSS:"):
            A((t, C("cvssVector"), Literal(s["cvss"])), (t, C("cvssVersion"), Literal(s["cvss"].split("/")[0].split(":")[1])))
            try:
                A((t, C("cvssSeverity"), Literal(calc.cvss4(s["cvss"])[1])))
            except Exception:
                pass
        if s.get("cvss_note"): A((t, C("rationale"), Literal(s["cvss_note"], lang="en")))
        inputs.append(t)
        for k, cls in KRI.items():
            t = X["%s-%s" % (sid, cls)]
            A((t, RDF.type, C(cls)), (t, C("estimateOf"), n), (t, C("numericValue"), D(r[k])), (t, C("generatedBy"), calc_act),
              (t, C("assessedIn"), a), (t, C("inSensitivityCase"), X["case-%s-central" % sid]))
            for i in inputs: A((t, C("usedInput"), i))
        A((X["%s-RiskToToleranceRatio" % sid], C("hasToleranceClassification"), C(TOL[r["cls"]])))
        A((X["case-%s-central" % sid], RDF.type, C("SensitivityCase")), (X["case-%s-central" % sid], C("caseOf"), n),
          (X["case-%s-central" % sid], C("hasCaseType"), C("CaseCentral")))
        if s.get("treatment") or s.get("horizon"):
            t = X["decision-" + sid]
            A((t, RDF.type, C("RiskTreatmentDecision")), (n, C("hasTreatmentDecision"), t), (t, C("hasTreatmentOption"), C("TreatModify")))
            if s.get("treatment"): A((t, C("treatmentSummary"), Literal(s["treatment"], lang="en")))
            if s.get("horizon"): A((t, C("treatmentHorizon"), Literal(s["horizon"])))
    # sensitivity cases computed by CRG for the scenarios listed in SENS_IDS
    for sid in data.get("SENS_IDS", []):
        s = next(x for x in data["SCEN"] if x["id"] == sid); n = X["scenario-" + sid]
        for d, case in ((-0.10, "lower"), (0.10, "higher")):
            r = calc.calc(calc.shift(s, d), run["appetite"], run["factor"])
            c = X["case-%s-%s" % (sid, case)]
            A((c, RDF.type, C("SensitivityCase")), (c, C("caseOf"), n), (c, C("hasCaseType"), C("CaseLower" if case == "lower" else "CaseHigher")))
            for k in ("est", "res", "ratio"):
                t = X["%s-%s-%s" % (sid, case, KRI[k])]
                A((t, RDF.type, C(KRI[k])), (t, C("estimateOf"), n), (t, C("numericValue"), D(r[k])), (t, C("generatedBy"), calc_act),
                  (t, C("inSensitivityCase"), c))
            A((X["%s-%s-RiskToToleranceRatio" % (sid, case)], C("hasToleranceClassification"), C(TOL[calc.classify(r["ratio"])])))
    for i in data.get("INITIATIVES", []):
        t = X["initiative-" + i[0]]
        A((t, RDF.type, C("TreatmentInitiative")), (t, C("localIdentifier"), Literal(i[0])), (t, RDFS.label, Literal(i[1], lang="en")))
        if i[2]: A((t, RDFS.comment, Literal(i[2], lang="en")))
        for sid in i[3]: A((t, C("addresses"), X["scenario-" + sid]))
        A((t, RDFS.comment, Literal("Owner: " + i[4], lang="en")))
        if i[5].lower() in PRIO: A((t, C("hasPriority"), C(PRIO[i[5].lower()])))
        A((t, C("initialCost"), D(i[6])), (t, C("recurringCost"), D(i[7])), (t, C("plannedStart"), Literal(i[8])), (t, C("plannedEnd"), Literal(i[9])),
          (t, C("successIndicator"), Literal(i[10], lang="en")))
        if len(i) > 12 and i[12].lower() in FN: A((t, C("hasControlFunction"), C(FN[i[12].lower()])))
    for k in data.get("KRIS", []):
        t = X["kri-" + k[0]]
        A((t, RDF.type, C("KeyRiskIndicator")), (t, C("localIdentifier"), Literal(k[0])), (t, RDFS.label, Literal(k[1], lang="en")),
          (t, C("measurementMethod"), Literal(k[3], lang="en")), (t, C("dataSource"), Literal(k[4], lang="en")),
          (t, RDFS.comment, Literal("Owner: " + k[5], lang="en")), (t, C("reportingFrequency"), Literal(k[6], lang="en")),
          (t, C("targetValue"), Literal(k[7])), (t, C("warningThreshold"), Literal(k[8])), (t, C("criticalThreshold"), Literal(k[9])))
        for sid in re.findall(r"\bS\d+\b", k[2]): A((t, C("monitors"), X["scenario-" + sid]))
    for c in data.get("CANDIDATES", []):
        t = X["candidate-" + c[0]]
        A((t, RDF.type, C("AssessmentScenario")), (t, C("localIdentifier"), Literal(c[0])), (t, RDFS.label, Literal(c[1], lang="en")),
          (t, RDFS.comment, Literal("Disposition as stated: " + c[7], lang="en")))
        if disposition(c[7]): A((t, C("hasDisposition"), C(disposition(c[7]))))
        if len(c) > 8 and c[8]: A((t, C("rationale"), Literal(c[8], lang="en")))
        m = re.match(r"Selected \((S\d+)\)", c[7])
        if m: A((X["scenario-" + m.group(1)], C("refines"), t))
    return g, run

def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("assessment"); ap.add_argument("--crg-calc", required=True); ap.add_argument("--base", required=True)
    ap.add_argument("--out"); ap.add_argument("--jsonld")
    ap.add_argument("--org-label", help="name of the assessed organisation (its IRI is <base>org)")
    a = ap.parse_args()
    data = json.load(open(a.assessment, encoding="utf-8"))
    g, run = convert(data, load_calc(a.crg_calc), a.base, a.org_label)
    out = a.out or os.path.splitext(a.assessment)[0] + ".ttl"
    g.serialize(out, format="turtle")
    if a.jsonld:
        g.serialize(a.jsonld, format="json-ld", auto_compact=True)
    print("%d triples -> %s; total estimated %.0f, residual %.0f" % (len(g), out, run["totals"]["est"], run["totals"]["res"]))

if __name__ == "__main__":
    main()
