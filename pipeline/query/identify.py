# -*- coding: utf-8 -*-
"""Threat, vulnerability and risk identification over CRGO (requirement R1).

Functions return plain dicts (JSON-ready) for CyberRiskGuardian:
  identify(...)            candidate scenarios matching ALL given filters (asset categories, themes, sector,
                           ATT&CK techniques, keywords), ranked by fit
  sweep(...)               profile-wide identification: scenarios matching ANY element of a profile, near-duplicates
                           merged, a few per theme, empty themes reported as gaps
  scenario(id)             one scenario in full (id = "LIB-F0123", a case id such as "MediBec/MED-A1", or an IRI)
  scenarios_for_control()  which scenarios a framework requirement addresses
  controls_for_technique() which controls the library associates with an ATT&CK technique
  list_values(kind)        allowed values: asset_category, theme, threat_source_type, impact_dimension, sector

Link confidence: 'H' (high only), 'M' (high and medium = the approved links, default) or 'L' (all, including
low-confidence suggestions). Library values are AI estimates for a fictitious healthcare organisation, and case
values are instructor annex values of teaching cases: calibration aids, never organisational evidence.
"""
import os, re, sys
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, HERE)
import store  # noqa: E402

IDS = dict(l.rstrip("\n").split("\t") for l in open(os.path.join(ROOT, "src", "ids.tsv"), encoding="utf-8"))
T = lambda k: "<https://w3id.org/crgo/CRGO_%07d>" % int(IDS[k])
KEY_OF = {"https://w3id.org/crgo/CRGO_%07d" % int(v): k for k, v in IDS.items()}
LIB = "https://w3id.org/crgo/data/library/"
VOC = "https://w3id.org/crgo/vocab/"
CONF_ORDER = {"ConfHigh": "H", "ConfMedium": "M", "ConfLow": "L"}
ALLOW = {"H": {"H"}, "M": {"H", "M"}, "L": {"H", "M", "L"}}
PARAMS = {"ThreatPresence": "PbA", "ExploitationProbability": "Pbx", "ExpectedDamage": "De", "MaximumDamage": "Dm",
          "Resilience": "Th", "Criticality": "Mu", "ProbabilityReduction": "red_p", "ImpactReduction": "red_i", "CVSSInput": "cvss"}
CAVEAT = ("Library values are AI estimates (2023) for a fictitious healthcare organisation; case-calibrated values come from "
          "instructor annex values of teaching cases. Both are calibration priors: label them 'Analytical estimate — validation "
          "required' and replace them with organisational evidence.")
PFX = "PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>\nPREFIX skos: <http://www.w3.org/2004/02/skos/core#>\nPREFIX owl: <http://www.w3.org/2002/07/owl#>\n"
_st = None

def _store():
    global _st
    if _st is None:
        _st = store.open_store()
    return _st

def _q(q):
    return list(_store().query(PFX + q))

def _v(t):
    return None if t is None else t.value

def _label(iri):
    r = _q('SELECT ?l WHERE { <%s> rdfs:label|skos:prefLabel ?l FILTER(lang(?l) = "en") } LIMIT 1' % iri)
    return _v(r[0]["l"]) if r else iri.rsplit("/", 1)[-1]

def _resolve_value(kind, value):
    """Accept a key (CatCloud), an English label ('cloud and third-party services') or a theme key/label."""
    if kind == "theme":
        for k, l in [(x["key"], x["label"]) for x in list_values("theme")]:
            if value in (k, l) or value.lower() == l.lower():
                return VOC + "theme/" + k
        raise ValueError("unknown theme: %s" % value)
    if value in IDS:
        return "https://w3id.org/crgo/CRGO_%07d" % int(IDS[value])
    for x in list_values(kind):
        if value.lower() in (x["label"].lower(), x["key"].lower()):
            return "https://w3id.org/crgo/CRGO_%07d" % int(IDS[x["key"]])
    raise ValueError("unknown %s: %s" % (kind, value))

def list_values(kind):
    """Allowed filter values with their keys and labels."""
    if kind == "theme":
        rows = _q('SELECT ?c ?n ?l WHERE { ?c skos:inScheme <%stheme> ; skos:notation ?n ; skos:prefLabel ?l FILTER(lang(?l) = "en") } ORDER BY ?n' % VOC)
        return [{"key": _v(r["n"]), "label": _v(r["l"])} for r in rows]
    if kind == "sector":
        rows = _q("SELECT DISTINCT ?s WHERE { ?x %s ?s } ORDER BY ?s" % T("applicableSector"))
        return [{"key": _v(r["s"]), "label": _v(r["s"])} for r in rows]
    cls = {"asset_category": "AssetCategory", "threat_source_type": "ThreatSourceType", "impact_dimension": "ImpactDimension"}[kind]
    rows = _q('SELECT ?x ?l WHERE { ?x a %s ; rdfs:label ?l FILTER(lang(?l) = "en") } ORDER BY ?l' % T(cls))
    return [{"key": KEY_OF.get(_v(r["x"]), _v(r["x"])), "label": _v(r["l"])} for r in rows]

def _links(subject, prop, min_conf):
    """Annotated links from subject through prop, with confidence and status, filtered by confidence."""
    rows = _q("""SELECT ?c ?n ?l ?scheme ?conf ?status ?corr WHERE {
      <%s> %s ?c . ?c skos:notation ?n ; skos:prefLabel ?l ; skos:inScheme ?scheme . FILTER(lang(?l) = "en")
      ?ax a owl:Axiom ; owl:annotatedSource <%s> ; owl:annotatedProperty %s ; owl:annotatedTarget ?c ; %s ?conf ; %s ?status .
      OPTIONAL { ?ax %s ?corr }
    }""" % (subject, T(prop), subject, T(prop), T("confidence"), T("governanceStatus"), T("corroboratedBy")))
    out = []
    for r in rows:
        c = CONF_ORDER.get(KEY_OF.get(_v(r["conf"]), ""), "L")
        if c in ALLOW[min_conf]:
            out.append({"id": _v(r["n"]), "title": _v(r["l"]), "framework": _v(r["scheme"]).rsplit("/", 1)[-1], "confidence": c,
                        "status": "approved" if KEY_OF.get(_v(r["status"])) == "StatusApproved" else "proposed"})
            if r["corr"] is not None:
                out[-1]["corroborated_by"] = _v(r["corr"])
    return sorted(out, key=lambda x: ("HML".index(x["confidence"]), x["id"]))

def _estimates(s):
    rows = _q("""SELECT ?e ?cls ?val ?conf ?low ?high ?n ?ev WHERE {
      ?e %s <%s> ; a ?cls ; %s ?val . OPTIONAL { ?e %s ?conf } OPTIONAL { ?e %s ?low ; %s ?high } OPTIONAL { ?e %s ?n }
      OPTIONAL { ?e %s ?evi . ?evi %s ?ev } }""" % (T("estimateOf"), s, T("numericValue"), T("hasConfidence"), T("lowerBound"), T("upperBound"),
                                                   T("sampleSize"), T("hasEvidence"), T("localIdentifier")))
    sets = {}
    for r in rows:
        k = KEY_OF.get(_v(r["cls"]))
        e = _v(r["e"])
        src = "case_calibrated" if "-case-" in e else ("case" if "/C-" in e else ("library_2023" if s.startswith(LIB) else "assessment"))
        d = sets.setdefault(src, {"values": {}, "risk": {}, "evidence": set()})
        if k in PARAMS:
            item = {"value": float(_v(r["val"]))}
            if r["low"] is not None: item.update(low=float(_v(r["low"])), high=float(_v(r["high"])))
            if r["n"] is not None: item["n"] = int(_v(r["n"]))
            d["values"][PARAMS[k]] = item
            if r["conf"] is not None: d["confidence"] = CONF_ORDER.get(KEY_OF.get(_v(r["conf"])), "")
        elif k in ("EstimatedRisk", "ResidualRisk", "RiskToToleranceRatio", "ToleratedRisk"):
            d["risk"][{"EstimatedRisk": "estimated", "ResidualRisk": "residual", "RiskToToleranceRatio": "ratio", "ToleratedRisk": "tolerated"}[k]] = round(float(_v(r["val"])), 3)
        if r["ev"] is not None:
            d["evidence"].add(_v(r["ev"]))
    for d in sets.values():
        d["evidence"] = sorted(d["evidence"])
        if not d["risk"]: d.pop("risk")
    return sets

def _iri(id_):
    if id_.startswith("http"): return id_
    r = _q('SELECT ?s WHERE { ?s %s "%s" } LIMIT 1' % (T("localIdentifier"), id_.replace('"', "")))
    if not r: raise ValueError("unknown scenario: %s" % id_)
    return _v(r[0]["s"])

def scenario(id_, min_confidence="M", brief=False, holdout=()):
    """Everything CRGO knows about one scenario, filtered by link confidence. holdout: case keys to hide."""
    s = _iri(id_)
    one = lambda p: [_v(r["o"]) for r in _q("SELECT ?o WHERE { <%s> %s ?o }" % (s, p))]
    d = {"id": (one(T("localIdentifier")) or [s])[0], "iri": s, "name": _label(s),
         "kind": "case scenario" if "/C-" in s else ("library scenario" if s.startswith(LIB) else "assessment scenario")}
    sector = one(T("applicableSector"))
    if sector: d["sector"] = sector[0]
    st = one(T("statement"))
    if st and not brief: d["statement"] = st[0]
    d["themes"] = [{"key": t.rsplit("/", 1)[-1], "label": _label(t)} for t in one(T("hasScenarioCategory"))]
    d["asset_categories"] = [_label(c) for c in one(T("affectsAssetCategory"))]
    d["threat_source_types"] = [_label(t) for t in [_v(r["t"]) for r in _q("SELECT ?t WHERE { <%s> %s ?d . ?d %s ?t }" % (s, T("hasThreatSourceDescription"), T("hasThreatSourceType")))]]
    d["weaknesses"] = [_label(v) for v in one(T("hasVulnerabilityDescription"))]
    events = one(T("hasThreatEvent"))
    d["attack_techniques"] = [x for ev in events for x in _links(ev, "hasExternalReference", min_confidence)]
    req = _links(s, "hasRelevantRequirement", min_confidence)
    d["controls"] = {fw: [x for x in req if x["framework"] == fw] for fw in ("csf2", "sp800-53r5", "iso27002-2022")}
    d["obligations"] = _links(s, "triggersObligation", min_confidence)
    vds = one(T("hasVulnerabilityDescription"))
    d["cwe"] = sorted({(x["id"], x["title"], x["confidence"], x["status"]) for v in vds for x in _links(v, "hasExternalReference", min_confidence)},
                      key=lambda x: ("HML".index(x[2]), x[0]))
    d["cwe"] = [{"id": i, "title": t, "confidence": c, "status": st} for i, t, c, st in d["cwe"]]
    if d["obligations"] or req:
        d["other_regimes"] = other_regimes([x["id"] for x in d["obligations"] if x["framework"] == "loi25"],
                                           [x["id"] for x in d["controls"]["csf2"]])
    tids = [x["id"] for x in d["attack_techniques"]]
    if tids:
        d["countermeasures_d3fend"] = defences_for_techniques(tids)
        d["exploitation_evidence"] = kev_evidence(tids, [x["id"] for x in d["cwe"]])
    if not d["attack_techniques"] and not req:  # case scenarios inherit from the families they refine
        fams = one(T("refines"))
        if fams:
            d["refines"] = [{"id": scenario_id(f), "name": _label(f)} for f in fams]
    refined_by = [_v(r["c"]) for r in _q("SELECT ?c WHERE { ?c %s <%s> }" % (T("refines"), s)) if _case_key(_v(r["c"])) not in holdout]
    if refined_by: d["refined_by"] = [_label(c) for c in refined_by]
    if not brief:
        d["estimates"] = _estimates(s)
        if holdout:
            held = {"CASE-" + h for h in holdout}
            d["estimates"] = {k: v for k, v in d["estimates"].items() if not set(v.get("evidence", [])) & held}
        d["caveat"] = CAVEAT
    return d

SYNONYMS = [["telehealth", "telemedicine", "teleconsultation", "virtual care", "remote consultation"],
            ["generative ai", "genai", "chatgpt", "llm", "large language model", "ai tool", "ai assistant"],
            ["hl7", "dicom", "pacs", "interface engine", "medical imaging transfer"],
            ["mfa", "multi-factor", "multifactor", "two-factor", "2fa"],
            ["ransomware", "encrypt", "extortion"], ["backup", "restore", "recovery"], ["wi-fi", "wifi", "wireless"],
            ["email", "e-mail", "business email compromise", "bec"], ["usb", "removable media", "portable media"],
            ["cloud", "saas", "tenant", "m365", "office 365", "azure"], ["oauth", "app consent", "access token", "session token", "token theft"],
            ["mfa fatigue", "push fatigue", "push notification", "mfa bombing", "prompt bombing", "mfa push"],
            ["radiology", "medical image", "medical imaging", "imaging", "pacs", "x-ray", "mri"],
            ["wan", "wide area network", "network link", "network outage", "connectivity loss", "telecommunication outage", "hub"],
            ["rogue access point", "evil twin", "rogue wi-fi", "rogue wifi"], ["local storage", "nas", "network attached storage", "file share", "local server"],
            ["asset inventory", "inventory", "unmanaged device", "shadow it"], ["adaptive authentication", "conditional access", "contextual access"],
            ["insider sabotage", "sabotage", "disgruntled", "departing employee"],
            ["help desk", "helpdesk", "service desk"], ["vendor", "supplier", "third party", "third-party"],
            ["patient portal", "web portal", "online portal"], ["disposal", "decommission", "retired device", "e-waste"],
            # 0.8.0: banking and payments (ACRB evaluation); scenarios are mostly worded for healthcare, so these find the generic ones
            ["atm", "automated teller", "cash machine", "jackpotting", "teller machine"],
            ["pos", "point of sale", "point-of-sale", "payment terminal", "card reader", "skimming"],
            ["core banking", "mainframe", "general ledger", "financial records", "financial management system"],
            ["online banking", "e-banking", "internet banking", "mobile banking", "customer portal", "web portal", "online portal"],
            ["payment processor", "payment provider", "card processor", "payment gateway", "payment system"],
            ["account enumeration", "rate limiting", "api abuse", "credential stuffing"],
            ["certificate", "tls", "ssl", "pki", "certificate expiry", "expired certificate"],
            ["fraud", "embezzlement", "financial manipulation", "unauthorized transaction", "unauthorised transaction"]]
HEALTH_WORDS = re.compile(r"(?i)\b(patient|patients|medical|health|healthcare|hospital|clinic|clinical|ehr|emr|pharmacy|prescription|laborator|nurse|physician|telemedicine|telehealth)")
def _health_penalty(score, sector, keywords):
    """0.8.0: lower healthcare-worded scenarios slightly when the profile has no health term, so that generic or
    sector-appropriate wording ranks first for other sectors (ACRB evaluation, observation 2)."""
    profile = " ".join([sector or ""] + list(keywords))
    if HEALTH_WORDS.search(profile):
        return score
    return {s: v - 0.5 if HEALTH_WORDS.search(_label(s) or "") else v for s, v in score.items()}
CAVEAT_SHORT = "Calibration priors, not organisational evidence: label 'Analytical estimate — validation required'."
RISK_UNIT = "CRG risk units (Excel Guide v1.0c, factor 1000, appetite 0.30): relative, comparable across scenarios, not a 0-1 score"
_text = None

def _expand(keywords):
    """Each keyword becomes a group: the keyword itself (always kept, with simple spelling variants) plus its synonyms
    when the whole keyword is a member of a synonym group. Single words are never swapped for a phrase's group."""
    out = []
    for k in keywords:
        k = k.lower().strip()
        grp = [k] + [v for v in (k.replace("centre", "center"), k.replace("center", "centre"), k.replace("-", " "), k.replace(" ", "-")) if v != k]
        for g in SYNONYMS:
            if k in g:
                grp += [w for w in g if w not in grp]
        out.append(grp)
    return out

def _index():
    """Searchable text per scenario: name, statement, weakness labels and linked ATT&CK technique names."""
    global _text
    if _text is None:
        _text = {}
        for q in ["SELECT ?s ?t WHERE { ?s a %s ; rdfs:label ?t }" % T("LibraryScenario"),
                  "SELECT ?s ?t WHERE { ?s a %s ; %s ?t }" % (T("LibraryScenario"), T("statement")),
                  "SELECT ?s ?t WHERE { ?s %s ?v . ?v rdfs:label ?t }" % T("hasVulnerabilityDescription"),
                  "SELECT ?s ?t WHERE { ?s %s ?e . ?e %s ?c . ?c skos:prefLabel ?t }" % (T("hasThreatEvent"), T("hasExternalReference"))]:
            for r in _q(q):
                _text[_v(r["s"])] = _text.get(_v(r["s"]), "") + " " + _v(r["t"]).lower()
    return _text

def _hits(text, groups):
    """Number of keyword groups found as whole words (plural allowed) in text."""
    return sum(1 for g in groups if any(re.search(r"\b" + re.escape(w) + r"s?\b", text) for w in g))

# Risks commonly assessed in any organisation: the sweep looks for one representative of each (baseline=True)
BASELINE = [("phishing and credential theft", ["phishing", "credential theft"]), ("ransomware", ["ransomware"]),
            ("business email compromise", ["business email compromise", "bec", "invoice fraud", "payment fraud", "ceo fraud"]),
            ("help-desk social engineering", ["help desk", "helpdesk", "service desk", "password reset"]),
            ("accidental disclosure by staff", ["accidental disclosure", "misdirected", "human error", "accidental"]),
            ("lost or stolen device", ["lost", "stolen", "theft of"]), ("removable media", ["usb", "removable media", "portable media"]),
            ("disposal of equipment and media", ["disposal", "decommission", "retired", "e-waste"]),
            ("third-party compromise", ["third-party", "third party", "vendor", "supplier"]),
            ("cloud misconfiguration", ["cloud misconfiguration", "misconfigured cloud", "exposed storage", "public bucket"]),
            ("unpatched systems", ["unpatched", "patch management", "outdated software"]),
            ("insider misuse or sabotage", ["insider", "sabotage", "disgruntled"]),
            ("network or telecom outage", ["outage", "network failure", "telecommunication", "connectivity"]),
            ("backup and recovery failure", ["backup", "recovery failure", "restore"]),
            ("impersonation of the organisation", ["impersonat", "spoofed domain", "fake website", "brand"]),
            ("web application vulnerability", ["web application", "sql injection", "cross-site", "portal vulnerability"]),
            ("denial of service", ["denial of service", "ddos"]), ("privileged account misuse", ["privileged account", "admin account", "privileged access"]),
            # 0.8.0, approved 2026-10-11 (ACRB evaluation): risks that combine two concepts, and two risks the library lacked
            ("vendor remote access", ["remote access by suppliers", "unauthorized remote access by suppliers", "vendor remote", "remote support tool", "supplier remote access", "vendor with remote access"]),
            ("insider fraud or record manipulation", ["embezzlement", "financial records", "record manipulation", "manipulation of financial"]),
            ("asset inventory gaps", ["inventory of technology assets", "asset inventory", "unmanaged asset", "unmanaged device"]),
            ("certificate expiry", ["expired digital certificate", "expired certificate", "certificate expir"])]

def _baseline_hits(text):
    """Commonly assessed risks named in a scenario NAME (whole-word match), not anywhere in its text."""
    return [name for name, words in BASELINE if any(re.search(r"\b" + re.escape(w) + r"\w{0,3}\b", text) for w in words)]

def _members(prop, values, kind):
    iris = " ".join("<%s>" % _resolve_value(kind, v) for v in values)
    return {_v(r["s"]) for r in _q("SELECT DISTINCT ?s WHERE { ?s %s ?x . VALUES ?x { %s } }" % (T(prop), iris))}

def _technique_members(techniques):
    rows = _q("""SELECT DISTINCT ?s WHERE { ?s %s ?ev . ?ev %s ?t . ?t skos:broader* ?root . ?root skos:notation ?tn .
                 ?root skos:inScheme <%sattack> . VALUES ?tn { %s } }""" % (T("hasThreatEvent"), T("hasExternalReference"), VOC, " ".join('"%s"' % t for t in techniques)))
    return {_v(r["s"]) for r in rows}

def _sector_members(sector):
    return {_v(r["s"]) for r in _q('SELECT DISTINCT ?s WHERE { ?s %s ?x FILTER(CONTAINS(LCASE(?x), "%s")) }' % (T("applicableSector"), sector.lower().replace('"', "")))}

_case_keys = None

def _case_key(iri):
    """Case of a case scenario, from its identifier (e.g. 'MediBec-CRG/S1' -> 'MediBec-CRG'); None for other scenarios."""
    global _case_keys
    if _case_keys is None:
        _case_keys = {_v(r["s"]): _v(r["i"]).split("/")[0] for r in _q('SELECT ?s ?i WHERE { ?s a %s ; %s ?i FILTER(CONTAINS(STR(?s), "/C-")) }'
                                                                      % (T("LibraryScenario"), T("localIdentifier")))}
    return _case_keys.get(iri)

_risk_cache = {}

def _library_risk(holdout=()):
    """Estimated risk per scenario: the 2023 library value; case-calibrated values only if none of their evidence is held out."""
    key = tuple(sorted(holdout))
    if key in _risk_cache:
        return _risk_cache[key]
    held = {"CASE-" + h for h in holdout}
    case_ev = {}
    for r in _q("SELECT ?s ?id WHERE { ?e %s ?s ; %s <%sRunCases> ; %s ?ev . ?ev %s ?id }"
                % (T("estimateOf"), T("assessedIn"), LIB, T("hasEvidence"), T("localIdentifier"))):
        case_ev.setdefault(_v(r["s"]), set()).add(_v(r["id"]))
    risk = {}
    for r in _q("SELECT ?s ?e ?v WHERE { ?e a %s ; %s ?s ; %s ?v }" % (T("EstimatedRisk"), T("estimateOf"), T("numericValue"))):
        s, e, v = _v(r["s"]), _v(r["e"]), float(_v(r["v"]))
        calibrated, case_sc = "-case-" in e, "/C-" in s
        if calibrated and case_ev.get(s, set()) & held:
            continue
        if case_sc and (_case_key(s) or "") in holdout:
            continue
        pri = 2 if (calibrated or case_sc) else 1
        if s not in risk or pri > risk[s][0]:
            risk[s] = (pri, v)
    _risk_cache[key] = risk
    return risk

_library = None

def _allowed(s, include_cases, holdout):
    """Candidates are library scenarios only (never assessment scenarios); case scenarios unless excluded or held out."""
    global _library
    if _library is None:
        _library = {_v(r["s"]) for r in _q("SELECT ?s WHERE { ?s a %s }" % T("LibraryScenario"))}
    if s not in _library:
        return False
    return (include_cases and _case_key(s) not in holdout) if "/C-" in s else True

def _brief(s, min_confidence, risk, score, holdout=()):
    d = scenario(s, min_confidence, brief=True, holdout=holdout)
    d.update(fit=score, estimated_risk=round(risk[s][1], 1) if s in risk else None,
             risk_basis={2: "case-calibrated", 1: "library 2023"}.get(risk.get(s, (0,))[0]), risk_unit=RISK_UNIT, caveat=CAVEAT_SHORT)
    return d

def identify(asset_categories=(), themes=(), sector=None, techniques=(), keywords=(), min_confidence="M", limit=20,
             include_cases=True, holdout=()):
    """Candidate risk scenarios for an organisation profile. Filters of different kinds combine with AND; several
    values of one kind with OR. Keywords match whole words, with synonyms, in names, statements, weaknesses and the
    names of linked ATT&CK techniques. Ranked by fit to the request (keyword groups and filter values matched), then
    by estimated risk. holdout: case keys (e.g. 'MediBec-CRG', 'MediBec') whose scenarios and calibrations are ignored,
    for blind evaluation."""
    holdout = tuple(holdout)
    sets = []
    if asset_categories: sets.append(_members("affectsAssetCategory", asset_categories, "asset_category"))
    if themes: sets.append(_members("hasScenarioCategory", themes, "theme"))
    if sector: sets.append(_sector_members(sector))
    if techniques: sets.append(_technique_members(techniques))
    idx = _index()
    groups = _expand(keywords)
    cands = set(idx) if not sets else set.intersection(*sets)
    cands = {s for s in cands if _allowed(s, include_cases, holdout)}
    score = {}
    for s in cands:
        h = _hits(idx.get(s, ""), groups) if groups else 0
        if groups and not h:
            continue
        score[s] = 2 * h
    if asset_categories and len(asset_categories) > 1:
        for v in asset_categories:
            for s in _members("affectsAssetCategory", [v], "asset_category") & set(score): score[s] += 1
    score = _health_penalty(score, sector, keywords)
    risk = _library_risk(holdout)
    ranked = sorted(score, key=lambda s: (-score[s], -risk.get(s, (0, 0))[1]))
    out = [_brief(s, min_confidence, risk, score[s], holdout) for s in ranked[:limit]]
    return {"query": {k: v for k, v in dict(asset_categories=list(asset_categories), themes=list(themes), sector=sector, techniques=list(techniques),
                                            keywords=list(keywords), min_confidence=min_confidence, holdout=list(holdout)).items() if v},
            "matches": len(score), "returned": len(out), "scenarios": out, "risk_unit": RISK_UNIT, "caveat": CAVEAT}

def _tokens(name):
    stop = {"the", "a", "an", "of", "to", "and", "or", "in", "on", "for", "by", "with", "due", "from", "at", "through", "via", "attack", "risk", "scenario"}
    return {w for w in re.findall(r"[a-z0-9]+", name.lower()) if w not in stop}

def sweep(asset_categories=(), themes=(), sector=None, techniques=(), keywords=(), per_theme=3, min_confidence="M",
          include_cases=True, holdout=(), max_total=60, baseline=True):
    """Profile-wide identification. Every library scenario matching ANY element of the profile is scored by how many
    elements it matches (techniques and keyword groups count double); near-duplicates are merged under one
    representative ('see_also'). The result keeps: up to per_theme representatives for each requested theme, one
    representative for each commonly assessed risk (baseline=True, see BASELINE), and then the best-scoring others
    that match at least two profile elements. Requested themes and baseline risks with no scenario are reported."""
    holdout = tuple(holdout)
    idx = _index()
    score = {}
    def add(ss, w=1):
        for s in ss:
            if _allowed(s, include_cases, holdout): score[s] = score.get(s, 0) + w
    for v in asset_categories: add(_members("affectsAssetCategory", [v], "asset_category"))
    for v in themes: add(_members("hasScenarioCategory", [v], "theme"))
    if techniques: add(_technique_members(techniques), 2)
    for g in _expand(keywords):
        add({s for s, t in idx.items() if _hits(t, [g])}, 2)
    base = {}
    if baseline:
        for r in _q("SELECT ?s ?n WHERE { ?s a %s ; rdfs:label ?n }" % T("LibraryScenario")):
            s = _v(r["s"])
            if _allowed(s, include_cases, holdout):
                for name in _baseline_hits(_v(r["n"]).lower()):
                    base.setdefault(name, set()).add(s)
    if sector:
        sec = _sector_members(sector)
        score = {s: v + (1 if s in sec else 0) for s, v in score.items()}
    score = _health_penalty(score, sector, keywords)
    theme_of = {}
    for r in _q("SELECT ?s ?th WHERE { ?s %s ?th }" % T("hasScenarioCategory")):
        theme_of.setdefault(_v(r["s"]), _v(r["th"]).rsplit("/", 1)[-1])
    pool = set(score) | {s for ss in base.values() for s in ss}
    name = {s: _label(s) for s in pool}
    risk = _library_risk(holdout)
    key = lambda s: (-score.get(s, 0), -risk.get(s, (0, 0))[1])
    reps, seen, rep_of = [], {}, {}
    for s in sorted(pool, key=key):
        tk = _tokens(name[s])
        rep = next((r for r in reps if theme_of.get(r) == theme_of.get(s) and len(tk & _tokens(name[r])) / max(1, len(tk | _tokens(name[r]))) >= 0.4), None)
        if rep: seen.setdefault(rep, []).append(s); rep_of[s] = rep
        else: reps.append(s); rep_of[s] = s
    wanted = [_resolve_value("theme", t).rsplit("/", 1)[-1] for t in themes]
    chosen, why = [], {}
    def take(s, reason):
        if s in why:
            if reason not in why[s]: why[s] += "; " + reason
        elif len(chosen) < max_total:
            chosen.append(s); why[s] = reason
    for th in wanted:
        for s in [r for r in reps if theme_of.get(r) == th and r in score][:per_theme]:
            take(s, "requested theme")
    base_gaps = []
    for nm, _ in BASELINE:
        cands = sorted(base.get(nm, ()), key=key)  # scenarios whose name states the risk
        if cands: take(cands[0], "commonly assessed: " + nm)
        elif baseline: base_gaps.append(nm)
    for s in [r for r in reps if score.get(r, 0) >= 2]:
        take(s, "matches the profile")
    out = []
    for s in chosen:
        d = _brief(s, min_confidence, risk, score.get(s, 0), holdout)
        d["selected_because"] = why[s]
        d["see_also"] = [{"id": scenario_id(x), "name": name[x]} for x in seen.get(s, [])[:6]]
        out.append(d)
    _sf = sector_frequency(sector) if sector else None
    return {"profile": {k: v for k, v in dict(asset_categories=list(asset_categories), themes=list(themes), sector=sector, techniques=list(techniques),
                                              keywords=list(keywords), holdout=list(holdout)).items() if v},
            "candidates": len(pool), "distinct": len(reps), "returned": len(out),
            "themes_covered": sorted({theme_of.get(s, "ThemeOther") for s in chosen}),
            "theme_gaps": sorted(set(wanted) - {theme_of.get(r) for r in reps if r in score}), "baseline_gaps": base_gaps,
            "scenarios": out, "sector_frequency": _sf, "risk_unit": RISK_UNIT, "caveat": CAVEAT}

def defences_for_techniques(tids, top=8):
    """D3FEND defensive techniques judged for the ATT&CK techniques (0.7.0): most shared, then most confident first."""
    vals = " ".join('"%s"' % t for t in tids)
    rows = _q("""SELECT ?n ?l ?t ?conf ?st WHERE { VALUES ?tn { %s } ?t skos:notation ?tn ; skos:inScheme <%sattack> ;
                 skos:relatedMatch ?d . ?d skos:inScheme <%sd3fend> ; skos:notation ?n ; skos:prefLabel ?l .
                 ?ax owl:annotatedSource ?t ; owl:annotatedTarget ?d ; %s ?conf ; %s ?st }""" % (vals, VOC, VOC, T("confidence"), T("governanceStatus")))
    agg = {}
    for r in rows:
        c = CONF_ORDER.get(KEY_OF.get(_v(r["conf"]), ""), "L")
        e = agg.setdefault(_v(r["n"]), {"id": _v(r["n"]), "title": _v(r["l"]), "techniques": set(), "confidence": "L",
                                        "status": "approved" if KEY_OF.get(_v(r["st"])) == "StatusApproved" else "proposed"})
        e["techniques"].add(_v(r["t"]).rsplit("/", 1)[-1])
        if "HML".index(c) < "HML".index(e["confidence"]): e["confidence"] = c
    out = sorted(agg.values(), key=lambda e: (-len(e["techniques"]), "HML".index(e["confidence"]), e["title"]))[:top]
    for e in out:
        e["for_techniques"] = sorted(e.pop("techniques")); e["source"] = "judged against MITRE D3FEND 1.6.0"
    return out

def other_regimes(loi25_ids, csf_ids):
    """The scenario's obligations under other regimes, through CRGO's correspondences (0.8.0): Québec public bodies
    (A-2.1) and federal private sector (PIPEDA) from its Loi 25 obligations; OSFI B-13 principles (federally regulated
    financial institutions) from the CSF 2.0 categories of its CSF links. Which regime applies depends on the organisation."""
    out = {}
    if loi25_ids:
        vals = " ".join('"%s"' % i for i in loi25_ids)
        for scheme, key in (("a21", "quebec_public_bodies_A-2.1"), ("pipeda", "federal_private_sector_PIPEDA"), ("gdpr", "eu_GDPR")):
            rows = _q("""SELECT DISTINCT ?n ?l WHERE { VALUES ?x { %s } ?c skos:notation ?x ; skos:inScheme <%sloi25> .
                         { ?c skos:closeMatch ?o } UNION { ?c skos:relatedMatch ?o } ?o skos:inScheme <%s%s> ; skos:notation ?n ; skos:prefLabel ?l .
                         FILTER(lang(?l) = "en") } ORDER BY ?n""" % (vals, VOC, VOC, scheme))
            if rows: out[key] = [{"id": _v(r["n"]), "title": _v(r["l"])} for r in rows]
    if csf_ids:
        cats = sorted({i.split("-")[0] for i in csf_ids})
        vals = " ".join('"%s"' % c for c in cats)
        rows = _q("""SELECT DISTINCT ?n ?l WHERE { VALUES ?x { %s } ?c skos:notation ?x ; skos:inScheme <%scsf2> .
                     ?p skos:relatedMatch ?c ; skos:inScheme <%sosfi-b13> ; skos:notation ?n ; skos:prefLabel ?l . FILTER(lang(?l) = "en") } ORDER BY ?n""" % (vals, VOC, VOC))
        if rows: out["financial_institutions_OSFI_B-13"] = [{"id": _v(r["n"]), "title": _v(r["l"])} for r in rows]
    if out:
        out["note"] = "Correspondences compiled by CRGO; check which regime applies to the organisation (public body, federally regulated, private sector in Québec, health body under R-22.1; the GDPR when offering goods or services to people in the EU, Art. 3(2))."
    return out

VCDB_SECTOR = [("finance", r"bank|financ|insur|credit union|caisse|payment"), ("healthcare", r"health|hospital|clinic|medical|care"),
               ("public", r"public|government|municipal|ministry|agency"), ("education", r"educat|school|universit|college"),
               ("retail", r"retail|shop|store|commerce"), ("manufacturing", r"manufactur|industr|factory"),
               ("information", r"information|software|telecom|media|technology"), ("professional", r"professional|consult|law|account"),
               ("accommodation", r"hotel|restaurant|hospitality|accommodation|food service")]

def sector_frequency(sector):
    """Share of confirmed public incidents (VCDB, 2015-2025, campaigns counted once) in the matching sector that involve
    each theme or threat-source type, next to all sectors. Relative frequencies in a record of disclosed incidents."""
    key = next((k for k, rx in VCDB_SECTOR if re.search(rx, sector or "", re.I)), None)
    if not key:
        return None
    out = {}
    for k in (key, "all"):
        rows = _q("""SELECT ?t ?v ?n ?lab WHERE { ?ev %s "VCDB-%s" ; rdfs:label ?lab . ?e %s ?ev ; %s ?t ; %s ?v ; %s ?n }""" % (
            T("localIdentifier"), k, T("hasEvidence"), T("estimateOf"), T("numericValue"), T("sampleSize")))
        out[k] = {"evidence": _v(rows[0]["lab"]) if rows else None,
                  "shares": sorted([{"category": _label(_v(r["t"])) or _v(r["t"]).rsplit("/", 1)[-1], "share": float(_v(r["v"]))} for r in rows],
                                   key=lambda x: -x["share"])}
    out["source"] = "VERIS Community Database (CC BY-SA 4.0), counts derived by CRGO; over-represents disclosed breaches and sectors with mandatory reporting."
    return out

def kev_evidence(tids, cwes=()):
    """Exploitation evidence: CISA KEV vulnerabilities mapped (MITRE CTID) to the scenario's ATT&CK techniques, and KEV
    vulnerabilities that are instances of its CWE weaknesses; counts, ransomware use and the FIRST EPSS scores of those
    vulnerabilities (median and maximum). Evidence that such techniques and weaknesses are exploited, not an inventory."""
    import statistics
    out = {}
    for kind, ids, scheme in (("by_technique", tids, "attack"), ("by_weakness", cwes, "cwe")):
        if not ids: continue
        vals = " ".join('"%s"' % i for i in ids)
        rows = _q("""SELECT ?x ?k ?note ?epss WHERE {
                     VALUES ?x { %s } ?c skos:notation ?x ; skos:inScheme <%s%s> . ?k skos:relatedMatch ?c ; skos:inScheme <%skev> ; skos:note ?note .
                     OPTIONAL { ?e %s ?k ; %s ?epss } }""" % (vals, VOC, scheme, VOC, T("observationOf"), T("numericValue")))
        agg = {}
        for r in rows:
            a = agg.setdefault(_v(r["x"]), {"kev": set(), "ransom": set(), "epss": {}})
            k = _v(r["k"]); a["kev"].add(k)
            if "ransomware campaign use: Known" in _v(r["note"]): a["ransom"].add(k)
            if r["epss"] is not None: a["epss"][k] = float(_v(r["epss"]))
        out[kind] = [{"id": x, "kev_vulnerabilities": len(a["kev"]), "known_ransomware_use": len(a["ransom"]),
                      "epss_median": round(statistics.median(a["epss"].values()), 3) if a["epss"] else None,
                      "epss_max": round(max(a["epss"].values()), 3) if a["epss"] else None}
                     for x, a in sorted(agg.items(), key=lambda kv: -len(kv[1]["kev"]))]
    out["source"] = ("CISA KEV catalogue; KEV to ATT&CK mapping by MITRE CTID; FIRST EPSS scores of 2026-10-04 (probability of exploitation "
                     "in the next 30 days). KEV vulnerabilities are already exploited, so their EPSS is high (median about 0.49, against "
                     "about 0.007 for all published vulnerabilities). Evidence that such techniques and weaknesses are exploited somewhere, "
                     "not a list of the organisation's vulnerabilities and not a direct value for CRG's probability of exploitation.")
    return out

def scenario_id(iri):
    r = _q('SELECT ?i WHERE { <%s> %s ?i } LIMIT 1' % (iri, T("localIdentifier")))
    return _v(r[0]["i"]) if r else iri

def scenarios_for_control(framework, control_id, min_confidence="M", limit=50):
    """Library scenarios that a framework requirement (csf2, sp800-53r5, iso27002-2022) addresses."""
    rows = _q('SELECT DISTINCT ?s ?name WHERE { ?c skos:notation "%s" ; skos:inScheme <%s%s> . ?s %s ?c ; rdfs:label ?name }'
              % (control_id, VOC, framework, T("hasRelevantRequirement")))
    out = []
    for r in rows:
        ls = [x for x in _links(_v(r["s"]), "hasRelevantRequirement", min_confidence) if x["id"] == control_id]
        if ls: out.append({"id": "LIB-" + _v(r["s"]).rsplit("/", 1)[-1], "name": _v(r["name"]), "confidence": ls[0]["confidence"]})
    out.sort(key=lambda x: ("HML".index(x["confidence"]), x["name"]))
    return {"framework": framework, "control": control_id, "title": _label("%s%s/%s" % (VOC, framework, re.sub(r"[()]", "_", control_id).rstrip("_"))),
            "matches": len(out), "scenarios": out[:limit]}

def controls_for_technique(technique, min_confidence="M", top=10):
    """Controls most often linked to library scenarios whose threat event uses an ATT&CK technique (or its sub-techniques)."""
    rows = _q("""SELECT ?s WHERE { ?root skos:notation "%s" ; skos:inScheme <%sattack> . ?t skos:broader* ?root .
                 ?ev %s ?t . ?s %s ?ev }""" % (technique, VOC, T("hasExternalReference"), T("hasThreatEvent")))
    scen = {_v(r["s"]) for r in rows}
    count = {}
    for s in scen:
        for x in _links(s, "hasRelevantRequirement", min_confidence):
            k = (x["framework"], x["id"], x["title"]); count[k] = count.get(k, 0) + 1
    by = {}
    for (fw, i, t), n in sorted(count.items(), key=lambda kv: -kv[1]):
        if len(by.setdefault(fw, [])) < top: by[fw].append({"id": i, "title": t, "scenarios": n})
    rep = _q('SELECT ?n WHERE { ?o skos:notation "%s" ; <http://purl.org/dc/terms/isReplacedBy> ?x . ?x skos:notation ?n }' % technique)
    return {"technique": technique, "name": _label("%sattack/%s" % (VOC, technique)), "replaced_by": _v(rep[0]["n"]) if rep else None,
            "scenarios": len(scen), "controls": by}

if __name__ == "__main__":
    import json
    print(json.dumps(identify(asset_categories=["CatOTIoT"], sector="health", limit=3), indent=1, ensure_ascii=False)[:3000])
