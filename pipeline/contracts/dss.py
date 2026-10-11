# -*- coding: utf-8 -*-
"""CRGO side of the DSS contract dss/v1 (decision R-b; ADR-007, ADR-008).

    risk_context(org_files, organization, scenario, as_of)  -> dict valid against risk-context.schema.json
    submit_assessment(document, org_files, out_file)         -> dict (stored result) or an error document

The contract is exchanged as JSON documents through CRGO's MCP server (tools crgo_risk_context and
crgo_submit_assessment) or as files; CyberRiskGuardian has no REST interface, so the specification's GET/POST examples
are mapped onto these two calls (contracts/dss/v1/README.md).

Rules enforced here:
- tenant separation (ADR-008): an organisation's IRIs share one base, never https://w3id.org/crgo/; a context for one
  organisation contains no IRI under another organisation's base; a write-back for one organisation may only refer to
  its own subjects and inputs (or to CRGO reference IRIs);
- write-backs are stored only as proposed analytical results with knowledge status 'risk estimate', in the
  organisation's proposed graph file, never in a reference file of the repository.
"""
import datetime, hashlib, json, os
from rdflib import Graph, URIRef, Literal, Namespace
from rdflib.namespace import RDF, RDFS, OWL, XSD, SKOS, DCTERMS

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SCHEMAS = os.path.join(ROOT, "contracts", "dss", "v1")
CRGO = "https://w3id.org/crgo/"
ids = dict(l.rstrip("\n").split("\t") for l in open(os.path.join(ROOT, "src", "ids.tsv"), encoding="utf-8"))
T = lambda k: URIRef(CRGO + "CRGO_%07d" % int(ids[k]))
KEY = {T(k): k for k in ids}
RELEASE = next((l.split('"')[1] for l in open(os.path.join(ROOT, "src", "build.py"), encoding="utf-8") if l.startswith("VERSION")), "0.0.0")
APP = {"AppApplicable": "applicable", "AppNotApplicable": "not-applicable", "AppPotentiallyApplicable": "potentially-applicable", "AppUnknown": "unknown"}
COMP = {"CompSatisfied": "satisfied", "CompPartial": "partially-satisfied", "CompUnsatisfied": "unsatisfied", "CompNotAssessed": "not-assessed", "CompUndetermined": "undetermined"}
RES = {"TestEffective": "effective", "TestPartlyEffective": "partly-effective", "TestIneffective": "ineffective", "TestNotTested": "not-tested"}
LINE = {"LineSelfAssessment": "self-assessment", "LineSecond": "second-line", "LineInternalAudit": "internal-audit", "LineExternal": "external"}
ASPECT = {"AspectDesign": "design", "AspectImplementation": "implementation", "AspectOperation": "operation"}
CTL = {"CtlInPlace": "in-place", "CtlPlanned": "planned", "CtlProposed": "proposed"}
CONF = {"ConfHigh": "high", "ConfMedium": "medium", "ConfLow": "low"}
QUAL = {"QualityHigh": "high", "QualityModerate": "moderate", "QualityLow": "low", "QualityVeryLow": "very-low"}
CAVEATS = ["CRGO states facts, links and their review status; it does not compute risk. Scores come from the DSS (ADR-007).",
           "Applicability states are CRGO evaluations over the organisation profile, not legal advice; 'potentially applicable' needs qualified review.",
           "A control mapped to an obligation supports compliance; it never proves it.",
           "Estimates are analyst estimates: validation required (CyberRiskGuardian evidence discipline)."]

VANN_NS = URIRef("http://purl.org/vocab/vann/preferredNamespaceUri")
GRANDFATHERED = {CRGO + "data/medibec/"}

def declared_bases(g):
    """Organisation bases declared by organisation graphs (ontology header, vann:preferredNamespaceUri; ADR-008)."""
    return {str(b) for o in g.subjects(RDF.type, OWL.Ontology) for b in g.objects(o, VANN_NS)
            if not str(b).startswith(CRGO) or str(b) in GRANDFATHERED}

def org_base(org, g):
    """The declared base the organisation IRI falls under (longest match); never guessed from the IRI."""
    s = str(org)
    if s.startswith(CRGO) and not any(s.startswith(b) for b in GRANDFATHERED):
        raise ValueError("REFERENCE_NAMESPACE")
    cands = sorted((b for b in declared_bases(g) if s.startswith(b)), key=len, reverse=True)
    if not cands:
        raise LookupError("UNKNOWN_ORGANISATION")
    return cands[0]

def load(org_files, reference=True):
    g = Graph()
    if reference:
        for m in ("gov", "core", "measure", "crg", "evidence", "org", "vuln", "grc", "mapping", "governance", "assurance", "audit", "incident"):
            g.parse(os.path.join(ROOT, "ontology", "crgo-%s.ttl" % m))
        for v in ("legal", "attack", "loi25", "gdpr", "a21", "pipeda", "sp800-53r5"):
            g.parse(os.path.join(ROOT, "ontology", "vocab", v + ".ttl"))
    for f in org_files:
        g.parse(f)
    return g

def _date(lit):
    return str(lit)[:10]

def _label(g, s):
    return next((str(l) for l in g.objects(s, RDFS.label) if getattr(l, "language", None) in ("en", None)), str(s))

def _key(v, table):
    return table.get(KEY.get(v, ""), None)

def risk_context(org_files, organization, scenario, as_of, g=None):
    """Build the read document for one organisation and scenario at a date (ISO yyyy-mm-dd)."""
    g = g if g is not None else load(org_files)
    org, scen = URIRef(organization), URIRef(scenario)
    try:
        base = org_base(org, g)
    except ValueError:
        return error("REFERENCE_NAMESPACE", "Organisation identifiers must not be under https://w3id.org/crgo/.")
    except LookupError:
        return error("UNKNOWN_ORGANISATION", "No organisation graph declares a base for %s (vann:preferredNamespaceUri)." % org)
    if (org, None, None) not in g:
        return error("UNKNOWN_ORGANISATION", "No data for %s." % org)
    if not str(scen).startswith(base) and not str(scen).startswith(CRGO + "data/library/"):
        return error("TENANT_MISMATCH", "Scenario %s is neither the organisation's nor a CRGO library scenario." % scen)
    if (scen, RDF.type, None) not in g:
        return error("UNKNOWN_SUBJECT", "Unknown scenario %s." % scen)
    asof = Literal(as_of + "T23:59:59", datatype=XSD.dateTime)
    mine = lambda x: str(x).startswith(base) or str(x).startswith(CRGO)
    ref = lambda x: str(x).startswith(CRGO)   # obligations must be reference provisions
    dated = lambda rec, prop: (g.value(rec, T(prop)) is not None and g.value(rec, T(prop)) <= asof)
    kind = "library" if (scen, RDF.type, T("LibraryScenario")) in g else "assessment"
    doc = {"schemaVersion": "1.0", "contract": "dss/v1", "ontologyRelease": RELEASE, "organizationId": str(org), "asOf": as_of,
           "generatedAt": datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
           "scenario": {"id": str(scen), "label": _label(g, scen), "kind": kind, "knowledgeStatus": "analytical-hypothesis",
                        "threatEvents": [{"id": str(e), "label": _label(g, e)} for e in g.objects(scen, T("hasThreatEvent")) if mine(e)],
                        "techniques": sorted({str(n) for e in g.objects(scen, T("hasThreatEvent")) for c in g.objects(e, T("hasExternalReference"))
                                              for n in g.objects(c, SKOS.notation) if str(c).startswith(CRGO + "vocab/attack/")})},
           "relatedAssets": [], "candidateObligations": [], "controlLinks": [], "estimates": [], "evidenceRefs": [], "caveats": list(CAVEATS)}
    leaked = 0
    def add_prov(xs):
        nonlocal leaked
        for x in xs:
            if ref(x): provisions.add(x)
            else: leaked += 1
    assets = [a for a in g.objects(scen, T("affectsAsset"))]
    for a in assets:
        if not mine(a): leaked += 1; continue
        doc["relatedAssets"].append({"id": str(a), "label": _label(g, a), "relation": "affects"})
        for d in g.objects(a, T("dependsOn")):
            if mine(d) and d not in assets:
                doc["relatedAssets"].append({"id": str(d), "label": _label(g, d), "relation": "depends-on"})
    measures = [m for m in g.objects(scen, T("mitigatedBy"))]
    provisions = set(g.objects(scen, T("triggersObligation")))
    leaked += sum(1 for p in provisions if not ref(p)); provisions = {p for p in provisions if ref(p)}
    evidence = set()
    for m in measures:
        if not mine(m): leaked += 1; continue
        link = {"id": str(m), "label": _label(g, m), "mappingStatus": "organisation-fact", "latestAssessments": [], "openFindings": []}
        st = _key(g.value(m, T("hasControlStatus")), CTL)
        if st: link["controlStatus"] = st
        add_prov(g.objects(m, T("supportsComplianceWith")))
        for c in g.objects(m, T("implementsControl")):
            add_prov(g.objects(c, T("supportsComplianceWith")))
        latest = {}
        for a in g.subjects(T("evaluatesControlMeasure"), m):
            on = g.value(a, T("assessedOn"))
            if on is None or on > asof or not mine(a): continue
            line = _key(g.value(a, T("performedInCapacity")), LINE) or "unstated"
            if line not in latest or on > latest[line][0]:
                latest[line] = (on, a)
        for line, (on, a) in sorted(latest.items()):
            row = {"id": str(a), "result": _key(g.value(a, T("hasTestResult")), RES) or "not-tested", "line": line, "assessedOn": _date(on)}
            asp = _key(g.value(a, T("assessesAspect")), ASPECT)
            if asp: row["aspect"] = asp
            link["latestAssessments"].append(row)
            evidence |= {e for e in g.objects(a, T("hasEvidence")) if mine(e)}
        for f in g.subjects(T("findingOnControl"), m):
            if not mine(f): leaked += 1; continue
            if not dated(f, "raisedOn"): continue          # undated or later findings are not shown
            closed = [c for c in g.subjects(T("closesFinding"), f) if mine(c) and dated(c, "closedOn")]
            reopened = [r for r in g.subjects(T("reopensFinding"), f) if mine(r) and dated(r, "reopenedOn")]
            last_close = max((g.value(c, T("closedOn")) for c in closed), default=None)
            last_reopen = max((g.value(r, T("reopenedOn")) for r in reopened), default=None)
            if last_close is None or (last_reopen is not None and last_reopen > last_close):
                link["openFindings"].append(str(f))
        doc["controlLinks"].append(link)
    for p in sorted(provisions, key=str):
        insts = sorted(g.objects(p, T("provisionOf")), key=str)  # a provision can belong to an Act and a regulation made under it
        own = lambda rec: mine(rec) and g.value(rec, T("concernsOrganisation")) == org and dated(rec, "assessedOn")
        assessed = [i for i in insts if any(own(a) for a in g.subjects(T("applicabilityOf"), i))]
        inst = (assessed or insts or [None])[0]
        ob = {"id": str(p), "applicability": "not-assessed"}
        n = g.value(p, SKOS.notation)
        if n: ob["notation"] = str(n)
        if inst is not None:
            ob["instrument"] = str(inst)
            # the latest assessment made on or before the date (an earlier as_of never sees a later result)
            a = max((a for a in g.subjects(T("applicabilityOf"), inst) if own(a)), key=lambda a: (g.value(a, T("assessedOn")), str(a)), default=None)
            if a is not None:
                ob["applicability"] = _key(g.value(a, T("hasApplicabilityState")), APP) or "unknown"
                und = sorted(str(c) for c in g.objects(a, T("conditionUndetermined")))
                if und: ob["unresolvedConditions"] = und
        d = max((d for d in g.subjects(T("complianceWith"), p) if own(d)), key=lambda d: (g.value(d, T("assessedOn")), str(d)), default=None)
        if d is not None:
            ob["complianceState"] = _key(g.value(d, T("hasComplianceState")), COMP) or "undetermined"
            gap = g.value(d, T("evidenceGap"))
            if gap: ob["evidenceGap"] = str(gap)
        doc["candidateObligations"].append(ob)
    stray = 0
    for e in g.subjects(T("estimateOf"), scen):
        if not mine(e): leaked += 1; continue
        if (e, T("assessedIn"), None) not in g: stray += 1; continue  # estimates outside any assessment are not passed on
        v = g.value(e, T("numericValue"))
        if v is None: continue
        kinds = [KEY.get(t) for t in g.objects(e, RDF.type) if t in KEY]
        row = {"id": str(e), "kind": next((k for k in kinds if k), "Estimate"), "value": float(v)}
        sc = g.value(e, T("onScale"))
        if sc is not None: row["scale"] = KEY.get(sc, str(sc))
        cf = _key(g.value(e, T("hasConfidence")), CONF)
        if cf: row["confidence"] = cf
        asm = [{"id": str(x), "label": _label(g, x)} for x in g.objects(e, T("dependsOnAssumption")) if mine(x)]
        if asm: row["assumptions"] = asm
        d = g.value(e, T("hasDistribution"))
        if d is not None:
            row["distribution"] = {k: v for k, v in (("family", KEY.get(g.value(d, T("hasDistributionFamily")), "")), ("parameters", str(g.value(d, T("distributionParameters")) or ""))) if v}
        q = _key(g.value(e, T("hasEvidenceQuality")), QUAL)
        if q: row["evidenceQuality"] = q
        doc["estimates"].append(row)
    doc["evidenceRefs"] = sorted(str(e) for e in evidence)
    if stray:
        doc["caveats"].append("%d estimate(s) not attached to any risk assessment were left out." % stray)
    if leaked:
        doc["caveats"].append("%d linked record(s) under another organisation's base were withheld (tenant separation, ADR-008)." % leaked)
    return doc

def error(code, message, details=None):
    e = {"error": True, "code": code, "message": message}
    if details: e["details"] = details
    return e

def validate_doc(doc, schema_name):
    import jsonschema
    schema = json.load(open(os.path.join(SCHEMAS, schema_name), encoding="utf-8"))
    v = jsonschema.Draft202012Validator(schema, format_checker=jsonschema.FormatChecker())
    return sorted("%s: %s" % ("/".join(map(str, e.path)) or "(root)", e.message) for e in v.iter_errors(doc))

def submit_assessment(document, org_files, out_file, g=None):
    """Validate a DSS write-back and store it as a proposed analytical result in the organisation's proposed graph."""
    errs = validate_doc(document, "assessment-result.schema.json")
    if errs:
        code = "STATUS_NOT_PROPOSED" if any(e.startswith("status") for e in errs) else \
               "MODEL_VERSION_MISSING" if any(e.startswith("modelVersion") for e in errs) else \
               "REFERENCE_NAMESPACE" if any(e.startswith(("organizationId", "subjectId")) and "should not be valid" in e for e in errs) else "SCHEMA_INVALID"
        return error(code, "The write-back document does not conform to dss/v1.", errs)
    out = os.path.abspath(out_file)
    for ref_dir in ("ontology", os.path.join("data", "abox"), "shapes", "src", "contracts", "pipeline"):
        if out.startswith(os.path.join(ROOT, ref_dir) + os.sep):
            return error("REFERENCE_NAMESPACE", "Write-backs go to the organisation's proposed graph, never into a CRGO reference file (%s)." % ref_dir)
    if not out.endswith("-dss-proposed.ttl"):
        return error("REFERENCE_NAMESPACE", "Write-backs go only to a '<name>-dss-proposed.ttl' file, not into the organisation's fact graph.")
    org, subj = URIRef(document["organizationId"]), URIRef(document["subjectId"])
    g = g if g is not None else load(org_files, reference=False)
    try:
        base = org_base(org, g)
    except ValueError:
        return error("REFERENCE_NAMESPACE", "Organisation identifiers must not be under https://w3id.org/crgo/.")
    except LookupError:
        return error("UNKNOWN_ORGANISATION", "No organisation graph declares a base for %s." % org)
    if not str(subj).startswith(base):
        return error("TENANT_MISMATCH", "Subject %s is not under the organisation's base %s." % (subj, base))
    if (subj, None, None) not in g:
        return error("UNKNOWN_SUBJECT", "Unknown subject %s in the organisation's data." % subj)
    bad = [i for i in document["inputs"] if not (i.startswith(CRGO) or (i.startswith(base) and (URIRef(i), None, None) in g))]
    if bad:
        return error("INPUT_UNKNOWN" if all(i.startswith(base) for i in bad) else "TENANT_MISMATCH", "Inputs must be the organisation's own records or CRGO reference IRIs.", bad)
    digest = hashlib.sha256(json.dumps(document, sort_keys=True).encode("utf-8")).hexdigest()
    r = URIRef(base + "dss-result/" + digest[:16])
    pg = Graph()
    if os.path.exists(out):
        pg.parse(out)
        if declared_bases(pg) != {base}:
            return error("TENANT_MISMATCH", "%s is the proposed graph of another organisation (declared base %s)." % (os.path.basename(out), sorted(declared_bases(pg))))
    else:
        o = URIRef(base.rstrip("/") + "-dss-proposed")
        pg.add((o, RDF.type, OWL.Ontology)); pg.add((o, OWL.imports, URIRef(CRGO + "crgo"))); pg.add((o, VANN_NS, Literal(base)))
        pg.add((o, RDFS.label, Literal("Results written back by the DSS for %s: proposed, not approved" % org, lang="en")))
    pg.bind("crgo", CRGO)
    for t in [(r, RDF.type, OWL.NamedIndividual), (r, RDF.type, T("AnalyticalResult")), (r, T("resultFor"), subj),
              (r, RDFS.label, Literal("%s of %s computed by %s %s" % (document["assessmentKind"], subj.rsplit("/", 1)[-1], document["modelId"], document["modelVersion"]), lang="en")),
              (r, T("modelName"), Literal(document["modelId"])), (r, T("modelVersion"), Literal(document["modelVersion"])),
              (r, T("computedAt"), Literal(document["computedAt"].replace("Z", ""), datatype=XSD.dateTime)), (r, T("contractVersion"), Literal("dss/v1")),
              (r, T("inputDocumentHash"), Literal(document["inputDocumentSha256"])), (r, T("numericValue"), Literal(str(document["result"]["value"]), datatype=XSD.decimal)),
              (r, T("rationale"), Literal("Assessment kind: %s; unit: %s; producer: %s" % (document["assessmentKind"], document["result"]["unit"], document["provenance"]["producer"]), lang="en")),
              (r, T("hasKnowledgeStatus"), T("KsRiskEstimate")), (r, T("governanceStatus"), T("StatusProposed")), (r, DCTERMS.source, Literal(document["provenance"]["producer"]))]:
        pg.add(t)
    for i in document["inputs"]:
        pg.add((r, T("computedFromInput"), URIRef(i)))
    pg.serialize(out, format="turtle")
    return {"stored": str(r), "status": "proposed", "knowledgeStatus": "risk estimate", "file": os.path.relpath(out, ROOT)}
