# -*- coding: utf-8 -*-
"""Turn the repaired scenario families (data/library/families.csv) into CRGO instance data:
data/abox/crgo-library.ttl. One LibraryScenario per family, with descriptions, theme, asset
categories, CRG parameter estimates (family medians, low confidence) and, where computable,
the CRG v1.0c risk quantities from a single recorded calculation run."""
import math, os
import pandas as pd
from rdflib import Graph, Namespace, Literal, URIRef
from rdflib.namespace import RDF, RDFS, OWL, XSD

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
ids = dict(l.rstrip("\n").split("\t") for l in open(os.path.join(ROOT, "src", "ids.tsv"), encoding="utf-8"))
C = lambda k: URIRef("https://w3id.org/crgo/CRGO_%07d" % int(ids[k]))
LIB = Namespace("https://w3id.org/crgo/data/library/")
THEME = Namespace("https://w3id.org/crgo/vocab/theme/")
D = lambda v: Literal(repr(round(float(v), 6)), datatype=XSD.decimal)
ok = lambda v: v is not None and not (isinstance(v, float) and math.isnan(v))

PARAM_CLASS = {"PbA": "ThreatPresence", "Pbx": "ExploitationProbability", "De": "ExpectedDamage", "Dm": "MaximumDamage",
               "Th": "Resilience", "Mu": "Criticality", "red_p": "ProbabilityReduction", "red_i": "ImpactReduction"}
KRI_CLASS = {"est": "EstimatedRisk", "tol": "ToleratedRisk", "mit": "MitigatedRisk", "res": "ResidualRisk",
             "ratio": "RiskToToleranceRatio", "pre_ratio": "PreTreatmentRatio"}
TOL = {"below": "TolBelow", "at": "TolAt", "above": "TolAbove"}

def main():
    f = pd.read_csv(os.path.join(ROOT, "data", "library", "families.csv"))
    g = Graph()
    for p, n in [("lib", LIB), ("crgo", "https://w3id.org/crgo/"), ("theme", THEME), ("owl", OWL), ("xsd", XSD)]:
        g.bind(p, n)
    o = URIRef("https://w3id.org/crgo/data/library")
    A = lambda *t: [g.add(x) for x in t]
    A((o, RDF.type, OWL.Ontology), (o, OWL.imports, URIRef("https://w3id.org/crgo/crgo")),
      (o, OWL.versionInfo, Literal("0.2.0")),
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
    n_est = n_kri = 0
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
        if isinstance(r.threat_source_types, str) and r.threat_source_types:
            ts = LIB[fid + "-source"]
            A((ts, RDF.type, C("ThreatSourceDescription")), (s, C("hasThreatSourceDescription"), ts))
            for t in r.threat_source_types.split():
                A((ts, C("hasThreatSourceType"), C(t)))
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
    out = os.path.join(ROOT, "data", "abox"); os.makedirs(out, exist_ok=True)
    g.serialize(os.path.join(out, "crgo-library.ttl"), format="turtle")
    print("families %d, estimates %d, risk quantities %d, triples %d" % (len(f), n_est, n_kri, len(g)))

if __name__ == "__main__":
    main()
