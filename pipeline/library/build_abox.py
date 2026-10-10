# -*- coding: utf-8 -*-
"""Turn the repaired scenario families (data/library/families.csv) into CRGO instance data:
data/abox/crgo-library.ttl. One LibraryScenario per family, with descriptions, theme, asset
categories, CRG parameter estimates (family medians, low confidence) and, where computable,
the CRG v1.0c risk quantities from a single recorded calculation run."""
import json, math, os, statistics
import pandas as pd
from rdflib import BNode, Graph, Namespace, Literal, URIRef
from rdflib.namespace import RDF, RDFS, OWL, XSD

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
ids = dict(l.rstrip("\n").split("\t") for l in open(os.path.join(ROOT, "src", "ids.tsv"), encoding="utf-8"))
C = lambda k: URIRef("https://w3id.org/crgo/CRGO_%07d" % int(ids[k]))
LIB = Namespace("https://w3id.org/crgo/data/library/")
THEME = Namespace("https://w3id.org/crgo/vocab/theme/")
VOC = "https://w3id.org/crgo/vocab/"
SCHEME_NS = {"attack": "attack", "csf2": "csf2", "sp80053r5": "sp800-53r5", "iso27002": "iso27002-2022", "loi25": "loi25"}
CONF = {"H": "ConfHigh", "M": "ConfMedium", "L": "ConfLow"}
CASE_APPETITE = {"CanaRetail": 0.50, "ACRB": 0.30, "MediBec": 0.40, "Chez": 0.40, "MediBec-CRG": 0.30}
D = lambda v: Literal(repr(round(float(v), 6)), datatype=XSD.decimal)
ok = lambda v: v is not None and not (isinstance(v, float) and math.isnan(v))

PARAM_CLASS = {"PbA": "ThreatPresence", "Pbx": "ExploitationProbability", "De": "ExpectedDamage", "Dm": "MaximumDamage",
               "Th": "Resilience", "Mu": "Criticality", "red_p": "ProbabilityReduction", "red_i": "ImpactReduction"}
KRI_CLASS = {"est": "EstimatedRisk", "tol": "ToleratedRisk", "mit": "MitigatedRisk", "res": "ResidualRisk",
             "ratio": "RiskToToleranceRatio", "pre_ratio": "PreTreatmentRatio"}
TOL = {"below": "TolBelow", "at": "TolAt", "above": "TolAbove"}

def safe(i):
    import re
    i = i.replace("&", "and").replace(" ", "_").replace("(", "_").replace(")", "")
    return re.sub(r"[^A-Za-z0-9._-]", "", i)

def crg(p, cvss, appetite):
    base = p["PbA"] * p["Pbx"] * cvss * p["Mu"] / p["Th"] * 1000
    est = base * (p["De"] + p["Dm"]) / 2; tol = base * appetite
    mit = est * p["red_p"] * p["red_i"]; res = est - mit; ratio = res / tol
    return dict(est=est, tol=tol, mit=mit, res=res, ratio=ratio, pre_ratio=est / tol,
                cls="below" if ratio < 0.90 else ("at" if ratio <= 1.10 else "above"))

LINK_APPROVALS = {}
for _l in open(os.path.join(ROOT, "src", "approvals.tsv"), encoding="utf-8"):
    if _l.startswith("links/"):
        _k, _d, _who, _date, *_ = _l.rstrip("\n").split("\t")
        if _d == "Approve":
            LINK_APPROVALS[_k] = (_who, _date)

def annotated(g, s, p, o, conf, note=None, group=None):
    """Assert s p o and annotate the assertion with its confidence and governance (OWL 2 axiom annotation).
    group (links/<scheme>/<confidence>) looks up a bulk approval recorded in src/approvals.tsv."""
    g.add((s, p, o))
    a = BNode()
    ok = LINK_APPROVALS.get(group) if group else None
    for t in [(a, RDF.type, OWL.Axiom), (a, OWL.annotatedSource, s), (a, OWL.annotatedProperty, p), (a, OWL.annotatedTarget, o),
              (a, C("confidence"), C(CONF[conf])), (a, C("proposedBy"), C("AgentClaude")),
              (a, C("governanceStatus"), C("StatusApproved" if ok else "StatusProposed"))]:
        g.add(t)
    if ok:
        g.add((a, C("approvedBy"), C("Agent" + ok[0]))); g.add((a, C("approvalDate"), Literal(ok[1], datatype=XSD.date)))
    if note:
        g.add((a, RDFS.comment, Literal(note, lang="en")))

def main():
    f = pd.read_csv(os.path.join(ROOT, "data", "library", "families.csv"))
    review = pd.read_csv(os.path.join(ROOT, "data", "library", "family_review.csv")).set_index("family")
    links = pd.read_csv(os.path.join(ROOT, "data", "library", "links.csv"), dtype=str)
    g = Graph()
    for p, n in [("lib", LIB), ("crgo", "https://w3id.org/crgo/"), ("theme", THEME), ("owl", OWL), ("xsd", XSD)]:
        g.bind(p, n)
    o = URIRef("https://w3id.org/crgo/data/library")
    A = lambda *t: [g.add(x) for x in t]
    A((o, RDF.type, OWL.Ontology), (o, OWL.imports, URIRef("https://w3id.org/crgo/crgo")),
      (o, OWL.versionInfo, Literal("0.3.0")),
      (o, RDFS.label, Literal("CRGO scenario library (from the 2023 generator, repaired)", lang="en")),
      (o, RDFS.label, Literal("Bibliothèque de scénarios CRGO (générateur 2023, réparée)", lang="fr")),
      (o, RDFS.comment, Literal("Generic risk scenarios written by gpt-3.5-turbo in 2023 for a fictitious healthcare organisation, "
                                "repaired and merged into families (decision Q-E, option 3). All values are AI estimates requiring "
                                "validation; use them as calibration priors, not as organisational evidence.", lang="en")))
    # one evidence item and one calculation run for the whole library
    A((LIB.E2023, RDF.type, C("EvidenceItem")), (LIB.E2023, C("localIdentifier"), Literal("LIB-2023")),
      (LIB.E2023, C("hasEvidenceBasis"), C("EvAIEstimate")),
      (LIB.E2023, C("evidenceLocator"), Literal("2023 scenario generator output combined_file.xlsx; repaired rows in data/library/rows.jsonl")),
      (LIB.Run2026, RDF.type, C("RiskAssessment")), (LIB.Run2026, RDFS.label, Literal("library calibration run, 2026", lang="en")),
      (LIB.Run2026, RDFS.label, Literal("calcul d'étalonnage de la bibliothèque, 2026", lang="fr")),
      (LIB.Run2026, C("usesCalculationMethod"), C("MethodCRG_v1_0c")), (LIB.Run2026, C("assessmentFactor"), D(1000)),
      (LIB.Run2026, C("hasRiskAppetite"), LIB.Appetite030),
      (LIB.Appetite030, RDF.type, C("RiskAppetiteStatement")), (LIB.Appetite030, C("numericValue"), D(0.30)),
      (LIB.Calc2026, RDF.type, C("CalculationActivity")), (LIB.Calc2026, C("usesMethod"), C("MethodCRG_v1_0c")))
    n_est = n_kri = n_links = 0
    links_by = {}
    for l in links.itertuples():
        links_by.setdefault(l.family, []).append(l)
    for _, r in f.iterrows():
        fid = r.family
        s = LIB[fid]
        A((s, RDF.type, C("LibraryScenario")), (s, C("localIdentifier"), Literal("LIB-" + fid)),
          (s, RDFS.label, Literal(r["name"], lang="en")), (s, C("applicableSector"), Literal("healthcare")),
          (s, C("hasScenarioCategory"), THEME[r.theme]), (s, C("derivedFrom"), Literal("combined_file.xlsx rows " + r.rows)),
          (LIB.Run2026, C("includesScenario"), s))
        if isinstance(r.narrative, str) and r.narrative:
            A((s, C("statement"), Literal(r.narrative, lang="en")))
        ev = LIB[fid + "-event"]
        A((ev, RDF.type, C("ThreatEventDescription")), (ev, RDFS.label, Literal(r["name"], lang="en")), (s, C("hasThreatEvent"), ev))
        rv = review.loc[fid] if fid in review.index else None
        src = rv.threat_source_types if rv is not None and isinstance(rv.threat_source_types, str) else ""
        if src:
            ts = LIB[fid + "-source"]
            A((ts, RDF.type, C("ThreatSourceDescription")), (s, C("hasThreatSourceDescription"), ts))
            for t in src.split():
                A((ts, C("hasThreatSourceType"), C(t)))
        if rv is not None and isinstance(rv.theme, str) and rv.theme and rv.theme != r.theme:
            annotated(g, s, C("hasScenarioCategory"), THEME[rv.theme], "M", "Second theme proposed during framework linking.")
        if isinstance(r.asset_categories, str):
            for t in r.asset_categories.split():
                A((s, C("affectsAssetCategory"), C(t)))
        if isinstance(r.impact_dimensions, str) and r.impact_dimensions:
            cd = LIB[fid + "-consequence"]
            A((cd, RDF.type, C("ConsequenceDescription")), (s, C("hasConsequence"), cd))
            for t in r.impact_dimensions.split():
                A((cd, C("hasImpactDimension"), C(t)))
        if isinstance(r.mitigations, str):
            for m in r.mitigations.split(" | "):
                A((s, C("suggestedMitigation"), Literal(m, lang="en")))
        for l in links_by.get(fid, []):
            target = URIRef(VOC + SCHEME_NS[l.scheme] + "/" + safe(l.id))
            note = None if l.basis == "judged" else "Added by " + l.basis + "."
            grp = "links/%s/%s" % (l.scheme, l.confidence)
            if l.scheme == "attack":
                annotated(g, ev, C("hasExternalReference"), target, l.confidence, note, grp)
            elif l.scheme == "loi25":
                annotated(g, s, C("triggersObligation"), target, l.confidence, note, grp)
            else:
                annotated(g, s, C("hasRelevantRequirement"), target, l.confidence, note, grp)
            n_links += 1
        inputs = []
        for k, cls in PARAM_CLASS.items():
            if not ok(r[k]):
                continue
            e = LIB["%s-%s" % (fid, k)]
            A((e, RDF.type, C(cls)), (e, C("estimateOf"), s), (e, C("assessedIn"), LIB.Run2026), (e, C("numericValue"), D(r[k])),
              (e, C("onScale"), C("ScaleUnitInterval")), (e, C("hasConfidence"), C("ConfLow")), (e, C("hasEvidence"), LIB.E2023),
              (e, C("sampleSize"), Literal(int(r[k + "_n"]), datatype=XSD.nonNegativeInteger)))
            if r[k + "_n"] > 1:
                A((e, C("lowerBound"), D(r[k + "_min"])), (e, C("upperBound"), D(r[k + "_max"])))
            inputs.append(e); n_est += 1
        if ok(r.cvss):
            e = LIB[fid + "-cvss"]
            A((e, RDF.type, C("CVSSInput")), (e, C("estimateOf"), s), (e, C("numericValue"), D(r.cvss)), (e, C("onScale"), C("ScaleCVSS")),
              (e, C("cvssVersion"), Literal("3.1 (LLM estimate, no vector)")), (e, C("hasConfidence"), C("ConfLow")),
              (e, C("hasEvidence"), LIB.E2023), (e, C("sampleSize"), Literal(int(r.cvss_n), datatype=XSD.nonNegativeInteger)))
            inputs.append(e); n_est += 1
        if ok(r.get("crg_est")):
            for k, cls in KRI_CLASS.items():
                e = LIB["%s-%s" % (fid, cls)]
                A((e, RDF.type, C(cls)), (e, C("estimateOf"), s), (e, C("numericValue"), D(r["crg_" + k])),
                  (e, C("generatedBy"), LIB.Calc2026), (e, C("hasConfidence"), C("ConfLow")))
                for i in inputs:
                    A((e, C("usedInput"), i))
                n_kri += 1
            A((LIB["%s-RiskToToleranceRatio" % fid], C("hasToleranceClassification"), C(TOL[r.crg_cls])))
        if ok(r.cost):
            t = LIB[fid + "-treatment"]
            A((t, RDF.type, C("TreatmentInitiative")), (t, RDFS.label, Literal("suggested treatment for " + r["name"], lang="en")),
              (t, C("addresses"), s), (t, C("initialCost"), D(r.cost)))
            if r.cost_n > 1:
                A((t, RDFS.comment, Literal("Median of %d source estimates (range %.0f to %.0f dollars)." % (r.cost_n, r.cost_min, r.cost_max), lang="en")))
    n_case = cases(g, A, f)
    out = os.path.join(ROOT, "data", "abox"); os.makedirs(out, exist_ok=True)
    g.serialize(os.path.join(out, "crgo-library.ttl"), format="turtle")
    print("families %d, estimates %d, risk quantities %d, framework links %d, %s, triples %d" % (len(f), n_est, n_kri, n_links, n_case, len(g)))

def cases(g, A, fam):
    """Case scenarios from the teaching cases (instructor annex values) and the MediBec worked CRG assessment:
    each becomes a LibraryScenario that refines the families it matches; matched families also receive
    case-calibrated estimates (median of the matching case values)."""
    W = os.path.join(ROOT, "data", "work", "cases")
    sc = json.load(open(os.path.join(ROOT, "data", "library", "case_scenarios.json"), encoding="utf-8"))
    matches = {m["sid"]: m["families"] for m in map(json.loads, open(os.path.join(ROOT, "data", "library", "case_matches.jsonl"), encoding="utf-8"))}
    evid, runs = {}, {}
    def evidence(case_key, case):
        if case_key not in evid:
            e = LIB["E-" + safe(case_key)]
            crgwork = case_key == "MediBec-CRG"
            A((e, RDF.type, C("EvidenceItem")), (e, C("localIdentifier"), Literal("CASE-" + case_key)),
              (e, C("hasEvidenceBasis"), C("EvExternal")),
              (e, C("evidenceLocator"), Literal(case)),
              (e, RDFS.comment, Literal("Worked CyberRiskGuardian assessment of the fictional MediBec case (analyst estimates on a teaching case)."
                                        if crgwork else "Instructor annex values of a fictional teaching case: calibration aids, not organisational evidence.", lang="en")))
            evid[case_key] = e
            run = LIB["Run-" + safe(case_key)]
            ap = LIB["Appetite-" + safe(case_key)]
            A((run, RDF.type, C("RiskAssessment")), (run, RDFS.label, Literal("case calibration: " + case_key, lang="en")),
              (run, C("usesCalculationMethod"), C("MethodCRG_v1_0c")), (run, C("assessmentFactor"), D(1000)), (run, C("hasRiskAppetite"), ap),
              (ap, RDF.type, C("RiskAppetiteStatement")), (ap, C("numericValue"), D(CASE_APPETITE.get(case_key, 0.30))))
            runs[case_key] = run
        return evid[case_key], runs[case_key]
    def estimates(subject, key, vals, run, evs, conf, bounds=None):
        made = []
        for k, cls in list(PARAM_CLASS.items()) + [("cvss", "CVSSInput")]:
            if k not in vals:
                continue
            e = LIB["%s-%s" % (key, k)]
            A((e, RDF.type, C(cls)), (e, C("estimateOf"), subject), (e, C("assessedIn"), run), (e, C("numericValue"), D(vals[k])),
              (e, C("onScale"), C("ScaleCVSS" if k == "cvss" else "ScaleUnitInterval")), (e, C("hasConfidence"), C(conf)))
            for ev_ in evs:
                A((e, C("hasEvidence"), ev_))
            if bounds and k in bounds:
                n, lo, hi = bounds[k]
                A((e, C("sampleSize"), Literal(n, datatype=XSD.nonNegativeInteger)))
                if n > 1:
                    A((e, C("lowerBound"), D(lo)), (e, C("upperBound"), D(hi)))
            made.append(e)
        return made
    def risk(subject, key, vals, inputs, appetite):
        if all(k in vals for k in PARAM_CLASS) and vals.get("cvss") and min(vals[k] for k in ("PbA", "Pbx", "Mu", "Th")) > 0:
            r = crg(vals, vals["cvss"], appetite)
            for k, cls in KRI_CLASS.items():
                e = LIB["%s-%s" % (key, cls)]
                A((e, RDF.type, C(cls)), (e, C("estimateOf"), subject), (e, C("numericValue"), D(r[k])), (e, C("generatedBy"), LIB.Calc2026))
                for i in inputs:
                    A((e, C("usedInput"), i))
            A((LIB["%s-RiskToToleranceRatio" % key], C("hasToleranceClassification"), C(TOL[r["cls"]])))
            return 1
        return 0
    per_family, n_case_risk = {}, 0
    for x in sc:
        case_key = x["sid"].split("/")[0]
        ev, run = evidence(case_key, x["case"])
        cid = "C-" + safe(x["sid"].replace("/", "-"))
        s = LIB[cid]
        A((s, RDF.type, C("LibraryScenario")), (s, C("localIdentifier"), Literal(x["sid"])), (s, RDFS.label, Literal(x["name"], lang="en")),
          (s, C("applicableSector"), Literal(x["sector"].split(" (")[0])), (s, C("derivedFrom"), Literal(x["case"])))
        if x.get("threat_event"):
            A((s, C("statement"), Literal(x["threat_event"], lang="en")))
        vals = {k: v for k, v in x["estimates"].items() if k in PARAM_CLASS or k == "cvss"}
        inputs = estimates(s, cid, vals, run, [ev], "ConfMedium")
        n_case_risk += risk(s, cid, vals, inputs, CASE_APPETITE.get(case_key, 0.30))
        for m in matches.get(x["sid"], []):
            annotated(g, s, C("refines"), LIB[m["family"]], "H" if m["m"] == "H" else "M", "Case scenario matched to library family.")
            per_family.setdefault(m["family"], []).append((m["m"], vals, ev))
    # case-calibrated family estimates: use high-grade matches when there are any
    n_fam = 0
    for fid, ms in per_family.items():
        best = [m for m in ms if m[0] == "H"] or ms
        conf = "ConfMedium" if best[0][0] == "H" else "ConfLow"
        vals, bounds = {}, {}
        for k in list(PARAM_CLASS) + ["cvss"]:
            v = [m[1][k] for m in best if k in m[1]]
            if v:
                vals[k] = statistics.median(v); bounds[k] = (len(v), min(v), max(v))
        if not vals:
            continue
        key = fid + "-case"
        inputs = estimates(LIB[fid], key, vals, LIB.RunCases, sorted({m[2] for m in best}), conf, bounds)
        risk(LIB[fid], key, vals, inputs, 0.30)
        n_fam += 1
    A((LIB.RunCases, RDF.type, C("RiskAssessment")), (LIB.RunCases, RDFS.label, Literal("case-calibrated library estimates, 2026", lang="en")),
      (LIB.RunCases, C("usesCalculationMethod"), C("MethodCRG_v1_0c")), (LIB.RunCases, C("assessmentFactor"), D(1000)),
      (LIB.RunCases, C("hasRiskAppetite"), LIB.Appetite030))
    return "case scenarios %d (risk computed for %d), families with case estimates %d" % (len(sc), n_case_risk, n_fam)

if __name__ == "__main__":
    main()
