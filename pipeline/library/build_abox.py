# -*- coding: utf-8 -*-
"""Turn the repaired scenario families (data/library/families.csv) into CRGO instance data:
data/abox/crgo-library.ttl. One LibraryScenario per family, with descriptions, theme, asset
categories, CRG parameter estimates (family medians, low confidence) and, where computable,
the CRG v1.0c risk quantities from a single recorded calculation run."""
import csv, json, math, os, statistics
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
SCHEME_NS = {"attack": "attack", "csf2": "csf2", "sp80053r5": "sp800-53r5", "iso27002": "iso27002-2022", "loi25": "loi25", "lrsss": "lrsss", "cwe": "cwe"}
CONF = {"H": "ConfHigh", "M": "ConfMedium", "L": "ConfLow"}
CASE_APPETITE = {"CanaRetail": 0.50, "ACRB": 0.30, "MediBec": 0.40, "Chez": 0.40, "MediBec-CRG": 0.30}
D = lambda v: Literal(repr(round(float(v), 6)), datatype=XSD.decimal)
ok = lambda v: v is not None and not (isinstance(v, float) and math.isnan(v))

PARAM_CLASS = {"PbA": "ThreatPresence", "Pbx": "ExploitationProbability", "De": "ExpectedDamage", "Dm": "MaximumDamage",
               "Th": "Resilience", "Mu": "Criticality", "red_p": "ProbabilityReduction", "red_i": "ImpactReduction"}
KRI_CLASS = {"est": "EstimatedRisk", "tol": "ToleratedRisk", "mit": "MitigatedRisk", "res": "ResidualRisk",
             "ratio": "RiskToToleranceRatio", "pre_ratio": "PreTreatmentRatio"}
TOL = {"below": "TolBelow", "at": "TolAt", "above": "TolAbove"}
import re as _re
WEAK = r"(?:lack of|lacking|inadequate|insufficient|weak|unpatched|outdated|obsolete|misconfigur\w*|improper|poor|absence of|absent|failure to|failing to|unsecured|unencrypted|insecure|incomplete|ineffective|missing|unmonitored|unprotected|uncontrolled|excessive|overprivileged|default|vulnerable|vulnerabilit\w*|legacy|untrained|neglect\w*)"

def weakness(name):
    """Weakness phrase in a scenario name: the whole name when it starts with one ('Inadequate patch management'),
    or the clause after 'due to', 'through', 'via'... ('Data leakage through insecure APIs' -> 'insecure APIs')."""
    n = name.strip().rstrip(":. ")
    n = _re.sub(r"^\d+\s+", "", n)
    if _re.match(r"(?i)^(?:no )|^" + WEAK, n, _re.I):
        return n
    m = _re.search(r"(?i)\b(?:due to|through|via|caused by|resulting from|because of|from|with)\s+(" + WEAK + r".*)$", n)
    return m.group(1) if m else None

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

def annotated(g, s, p, o, conf, note=None, group=None, corroborated=None):
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
    if corroborated:
        g.add((a, C("corroboratedBy"), Literal(corroborated, lang="en")))

CORR = {}
_cp = os.path.join(ROOT, "data", "library", "ctid_corroboration.csv")
if os.path.exists(_cp):
    import csv as _csv
    for _r in _csv.DictReader(open(_cp, encoding="utf-8")):
        if _r["corroborated"] == "yes":
            CORR[(_r["family"], _r["control"])] = "MITRE CTID Mappings Explorer (ATT&CK 16.1 to SP 800-53 Rev. 5): control mitigates %s" % _r["via_techniques"]

_np = os.path.join(ROOT, "data", "library", "nist_corroboration.csv")
if os.path.exists(_np):
    import csv as _csv2
    for _r in _csv2.DictReader(open(_np, encoding="utf-8")):
        if _r["corroborated"] == "yes":
            CORR[(_r["family"], _r["scheme"], _r["id"])] = ("NIST crosswalk via this scenario's SP 800-53 links (%s): " % _r["via_controls"]) + (
                "CSF 1.1 to SP 800-53r5 mapping carried to CSF 2.0" if _r["scheme"] == "csf2" else "OLIR mapping of SP 800-53r5 to ISO/IEC 27001:2022 Annex A")

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
      (o, OWL.versionInfo, Literal("0.9.0")),
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
    n_weak = [0]
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
        wk = weakness(r["name"])
        if wk:
            vd = LIB[fid + "-weakness"]
            A((vd, RDF.type, C("VulnerabilityDescription")), (vd, RDFS.label, Literal(wk[0].upper() + wk[1:], lang="en")))
            annotated(g, s, C("hasVulnerabilityDescription"), vd, "M", "Added by rule: weakness named in the scenario title.")
            n_weak[0] += 1
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
            if l.basis.startswith("judged, CWE pass"):
                note, grp = "Judged in the CWE pass of 2026-10-11" + (" (CWE-1104 replaced by CWE-1395 by rule)." if "replaced" in l.basis else "."), "links/cwe/%s" % l.confidence
            elif l.basis.startswith("CTID mapping"):
                note, grp = "Proposed from the MITRE CTID mapping and the controls usual for the same techniques (%s)." % l.basis.split(": ", 1)[1], "links/ctid-sp80053r5/%s" % l.confidence
            elif l.basis.startswith("judged, Loi 25 pass"):
                # second Loi 25 pass: its own approval group, so the 0.3.0 group approvals do not cover it
                note, grp = "Judged in the Loi 25 pass of 2026-10-10 (families with a privacy impact and no judged obligation).", "links/loi25-pass2/%s" % l.confidence
            else:
                note = None if l.basis == "judged" else "Added by " + l.basis + "."
                grp = "links/%s/%s" % (l.scheme, l.confidence)
            if l.scheme == "attack":
                annotated(g, ev, C("hasExternalReference"), target, l.confidence, note, grp)
            elif l.scheme == "cwe":
                vd = LIB[fid + "-weakness"]
                if (s, C("hasVulnerabilityDescription"), vd) not in g:
                    A((vd, RDF.type, C("VulnerabilityDescription")), (vd, RDFS.label, Literal("Weakness exploited in: " + r["name"], lang="en")))
                    annotated(g, s, C("hasVulnerabilityDescription"), vd, "M", "Added with the CWE pass of 2026-10-11 to carry the CWE references.", "links/cwe/" + l.confidence)
                annotated(g, vd, C("hasExternalReference"), target, l.confidence, note, grp)
            elif l.scheme == "loi25":
                annotated(g, s, C("triggersObligation"), target, l.confidence, note, grp)
            else:
                annotated(g, s, C("hasRelevantRequirement"), target, l.confidence, note, grp,
                          corroborated=CORR.get((fid, l.id)) if l.scheme == "sp80053r5" else CORR.get((fid, l.scheme, l.id)))
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
    n_auth = authored(g, A)
    n_case = cases(g, A, f)
    out = os.path.join(ROOT, "data", "abox"); os.makedirs(out, exist_ok=True)
    # 0.8.0: FIRST EPSS scores for the CISA KEV vulnerabilities, as likelihood estimates of each KEV concept
    epss_file = os.path.join(ROOT, "data", "raw", "external", "epss_scores-2026-10-04.csv.gz")
    kev_file = os.path.join(ROOT, "data", "raw", "external", "cisa_kev.json")
    n_epss = 0
    if os.path.exists(epss_file) and os.path.exists(kev_file):
        import gzip, json as _json
        kev_ids = {v["cveID"] for v in _json.load(open(kev_file))["vulnerabilities"]}
        ev = LIB["E-EPSS-2026-10-04"]
        A((ev, RDF.type, C("EvidenceItem")), (ev, C("localIdentifier"), Literal("FIRST-EPSS-2026-10-04")), (ev, C("hasEvidenceBasis"), C("EvExternal")),
          (ev, C("evidenceLocator"), Literal("FIRST Exploit Prediction Scoring System, scores of 2026-10-04, model v2026.06.15 (epss_scores-2026-10-04.csv.gz, retrieved by CyberRiskGuardian; https://www.first.org/epss/)")),
          (ev, RDFS.comment, Literal("EPSS estimates the probability that a published vulnerability is exploited in the wild in the next 30 days. Scores change daily; these are a dated snapshot, kept only for the vulnerabilities of the CISA KEV catalogue.", lang="en")))
        with gzip.open(epss_file, "rt") as fh:
            fh.readline()
            for row in csv.DictReader(fh):
                if row["cve"] not in kev_ids: continue
                e = LIB["EPSS-" + row["cve"]]
                A((e, RDF.type, C("Likelihood")), (e, C("estimateOf"), URIRef(VOC + "kev/" + safe(row["cve"]))), (e, C("numericValue"), D(row["epss"])),
                  (e, C("onScale"), C("ScaleUnitInterval")), (e, C("hasConfidence"), C("ConfMedium")), (e, C("hasEvidence"), ev),
                  (e, RDFS.comment, Literal("EPSS percentile %s" % row["percentile"], lang="en")))
                n_epss += 1
    print("EPSS estimates for KEV vulnerabilities:", n_epss)
    # 0.8.0: sector frequency evidence from VCDB (pipeline/external/vcdb.py): share of a sector's confirmed public incidents
    # (2015-2025, campaigns counted once) that involve a theme or a threat-source type
    vf = os.path.join(ROOT, "data", "library", "vcdb_frequencies.csv")
    n_vcdb = 0
    if os.path.exists(vf):
        seen_ev = set()
        for r in csv.DictReader(open(vf, encoding="utf-8")):
            ev = LIB["E-VCDB-" + r["sector"]]
            if ev not in seen_ev:
                seen_ev.add(ev)
                A((ev, RDF.type, C("EvidenceItem")), (ev, C("localIdentifier"), Literal("VCDB-" + r["sector"])), (ev, C("hasEvidenceBasis"), C("EvExternal")),
                  (ev, RDFS.label, Literal("VCDB incidents, %s, 2015-2025 (n = %s)" % (r["sector_label"], r["incidents"]), lang="en")),
                  (ev, C("evidenceLocator"), Literal("VERIS Community Database, github.com/vz-risk/VCDB, commit f6f98c0 (2026-09-30), CC BY-SA 4.0; counts derived by pipeline/external/vcdb.py")),
                  (ev, RDFS.comment, Literal("Built from public reports: over-represents disclosed breaches and sectors with mandatory reporting. Shares are relative frequencies in that record, not incident rates.", lang="en")))
            target = THEME[r["category"]] if r["category"].startswith("Theme") else C(r["category"])
            e = LIB["VCDB-%s-%s" % (r["sector"], r["category"])]
            A((e, RDF.type, C("Estimate")), (e, C("estimateOf"), target), (e, C("numericValue"), D(r["share"])), (e, C("onScale"), C("ScaleUnitInterval")),
              (e, C("hasConfidence"), C("ConfMedium")), (e, C("hasEvidence"), ev), (e, C("sampleSize"), Literal(int(r["incidents"]), datatype=XSD.nonNegativeInteger)),
              (e, RDFS.label, Literal("Share of %s incidents involving %s: %s of %s" % (r["sector_label"], r["category"], r["count"], r["incidents"]), lang="en")))
            n_vcdb += 1
    print("VCDB sector frequency estimates:", n_vcdb)
    g.serialize(os.path.join(out, "crgo-library.ttl"), format="turtle")
    print("authored %d; " % n_auth, end="")
    print("families %d, estimates %d, risk quantities %d, framework links %d, weaknesses %d, %s, triples %d" % (len(f), n_est, n_kri, n_links, n_weak[0], n_case, len(g)))

def authored(g, A):
    """Generic scenarios written by Claude to fill gaps found in the Phase 4 blind test (approved for addition by the
    project owner on 2026-10-10). No estimates: they get values when a case or assessment calibrates them."""
    frozen = dict(l.rstrip("\n").split("\t") for l in open(os.path.join(ROOT, "data", "library", "family_ids.tsv"), encoding="utf-8") if l.strip() and not l.startswith("#"))
    n = 0
    for a in json.load(open(os.path.join(ROOT, "data", "library", "authored_scenarios.json"), encoding="utf-8")):
        fid = frozen[a["key"]]; s = LIB[fid]
        A((s, RDF.type, C("LibraryScenario")), (s, C("localIdentifier"), Literal("LIB-" + fid)), (s, RDFS.label, Literal(a["name"], lang="en")),
          (s, C("statement"), Literal(a["statement"], lang="en")), (s, C("applicableSector"), Literal("generic")),
          (s, C("hasScenarioCategory"), THEME[a["theme"]]), (s, C("derivedFrom"), Literal("Authored by Claude (gap analysis: Phase 4 blind test for AUTH-001 to 003, ACRB evaluation for AUTH-004 to 006), " + a["key"])),
          (s, C("proposedBy"), C("AgentClaude")), (LIB.Run2026, C("includesScenario"), s))
        ok = LINK_APPROVALS.get("links/authored/" + a["key"])  # approving a written scenario's group approves the scenario too
        A((s, C("governanceStatus"), C("StatusApproved" if ok else "StatusProposed")))
        if ok: A((s, C("approvedBy"), C("Agent" + ok[0])), (s, C("approvalDate"), Literal(ok[1], datatype=XSD.date)))
        ev = LIB[fid + "-event"]
        A((ev, RDF.type, C("ThreatEventDescription")), (ev, RDFS.label, Literal(a["name"], lang="en")), (s, C("hasThreatEvent"), ev))
        ts = LIB[fid + "-source"]
        A((ts, RDF.type, C("ThreatSourceDescription")), (s, C("hasThreatSourceDescription"), ts))
        for t in a["threat_source_types"]: A((ts, C("hasThreatSourceType"), C(t)))
        for t in a["asset_categories"]: A((s, C("affectsAssetCategory"), C(t)))
        cd = LIB[fid + "-consequence"]
        A((cd, RDF.type, C("ConsequenceDescription")), (s, C("hasConsequence"), cd))
        for t in a["impact_dimensions"]: A((cd, C("hasImpactDimension"), C(t)))
        for i, w in enumerate(a["weaknesses"], 1):
            vd = LIB["%s-weakness-%d" % (fid, i)]
            A((vd, RDF.type, C("VulnerabilityDescription")), (vd, RDFS.label, Literal(w, lang="en")))
            annotated(g, s, C("hasVulnerabilityDescription"), vd, "H")
        for scheme in ("attack", "csf2", "sp80053r5", "iso27002", "loi25", "lrsss"):
            for i, c in a.get(scheme, []):
                target = URIRef(VOC + SCHEME_NS[scheme] + "/" + safe(i))
                grp = "links/authored/" + a["key"]  # one approval group per written scenario
                if scheme == "attack": annotated(g, ev, C("hasExternalReference"), target, c, None, grp)
                elif scheme in ("loi25", "lrsss"): annotated(g, s, C("triggersObligation"), target, c, None, grp)
                else: annotated(g, s, C("hasRelevantRequirement"), target, c, None, grp)
        n += 1
    return n

def cases(g, A, fam):
    """Case scenarios from the teaching cases (instructor annex values) and the MediBec worked CRG assessment:
    each becomes a LibraryScenario that refines the families it matches; matched families also receive
    case-calibrated estimates (median of the matching case values)."""
    W = os.path.join(ROOT, "data", "work", "cases")
    sc = json.load(open(os.path.join(ROOT, "data", "library", "case_scenarios.json"), encoding="utf-8"))
    matches = {m["sid"]: m["families"] for m in map(json.loads, open(os.path.join(ROOT, "data", "library", "case_matches.jsonl"), encoding="utf-8"))}
    evid, runs = {}, {}
    import csv as _csv
    case_links = {}
    for l in _csv.DictReader(open(os.path.join(ROOT, "data", "library", "case_links.csv"), encoding="utf-8")):
        case_links.setdefault(l["case"], []).append(l)
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
    fam_theme = dict(zip(fam.family, fam.theme))
    import sys as _sys; _sys.path.insert(0, HERE); import themes as T
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
        # theme: the most common primary theme of the refined families, else from the scenario text
        ths = [fam_theme[m["family"]] for m in matches.get(x["sid"], []) if m["family"] in fam_theme]
        th = max(set(ths), key=ths.count) if ths else T.theme_of(x["name"] + " " + x.get("threat_event", ""), True)
        annotated(g, s, C("hasScenarioCategory"), THEME[th], "M", "Theme of the refined library families." if ths else "Theme from the scenario text.")
        for l in case_links.get(x["sid"], []):  # case scenarios that match no family are linked directly
            target = URIRef(VOC + SCHEME_NS[l["scheme"]] + "/" + safe(l["id"]))
            if l["scheme"] == "attack":
                cev = LIB[cid + "-event"]
                A((cev, RDF.type, C("ThreatEventDescription")), (cev, RDFS.label, Literal(x["name"], lang="en")), (s, C("hasThreatEvent"), cev))
                annotated(g, cev, C("hasExternalReference"), target, l["confidence"])
            else:
                annotated(g, s, C("hasRelevantRequirement"), target, l["confidence"])
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
