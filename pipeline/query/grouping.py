# -*- coding: utf-8 -*-
"""Candidate grouping and scenario validation over the CRGO identification export (0.11.2).

Pure functions over export-shaped dicts (data/export/crgo-identification.json, or the CyberRiskGuardian snapshot built
from it): no SPARQL store, no network, no clock. The same rules are ported line for line to the desktop browser
(js/crgo_group.js) and tested against contracts/library-proposal/v1/examples/golden-grouping.json, so the MCP server and
the offline snapshot give identical answers for identical inputs. The rules are written down in
contracts/library-proposal/v1/README.md; change them only together with ALGORITHM_* and the golden file.

  static_clusters(records, primary)       near-duplicate clusters of the library, computed once at export time
  group(candidates, ref, local, min_conf) crgo-grouping/1: candidates -> families, unique proposals, own scenarios
  validate(scenario, ref, local, min_conf) crgo-validation/1: findings (never errors) for one scenario descriptor

Determinism (survey W5 section 5): integer arithmetic only (5*|A∩B| >= 2*|A∪B|, Jaccard compared by cross-multiplying),
every sort ends on an identifier compared by code point, text is NFC-normalised before lower-casing, theme regexes run
with ASCII semantics (as JavaScript RegExp without the u flag), group ids are hashes of sorted member refs, and the
output is sorted, so it depends neither on input order nor on PYTHONHASHSEED.
"""
import hashlib, json, os, re, unicodedata

ALGORITHM_GROUP = "crgo-grouping/1"
ALGORITHM_VALID = "crgo-validation/1"
CAVEAT = ("Ontology-proposed grouping and findings: suggestions for the analyst, who accepts, edits or rejects them. "
          "Library values are calibration priors, not organisational evidence: label them 'Analytical estimate — validation required'.")
STOP = ("a", "an", "and", "at", "attack", "by", "due", "for", "from", "in", "of", "on", "or", "risk", "scenario", "the", "through",
        "to", "via", "with")            # identify._tokens, sorted
CANDIDATES_MAX = 200                   # = identify.LIMIT_MAX; grouping is cross-candidate, so it is not chunked
LIST_MAX = 50
CONF_RANK = {"H": 0, "M": 1, "L": 2}
ALLOW = {"H": ("H",), "M": ("H", "M"), "L": ("H", "M", "L")}
KIND_ORDER = {"family": 0, "unique": 1, "own": 2}
FRAMEWORKS = ("csf2", "sp800-53r5", "iso27002-2022")
RX_CWE = re.compile(r"^CWE-[0-9]{1,6}$")
_WS = re.compile(r"[ \t\n\r\f\v ]+")


# ---------------------------------------------------------------- text
def nfc(s):
    return unicodedata.normalize("NFC", str(s if s is not None else ""))

def norm_text(s):
    """NFC, lower case, runs of whitespace (space, tab, CR, LF, FF, VT, no-break space) to one space, trimmed."""
    return _WS.sub(" ", nfc(s).lower()).strip()

def tokens(s):
    """Name tokens: [a-z0-9]+ runs of the normalised text, minus STOP (identify._tokens with NFC)."""
    return {w for w in re.findall(r"[a-z0-9]+", norm_text(s)) if w not in STOP}

def base_technique(t):
    return t.split(".")[0]

def sha10(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:10]

def canonical(obj):
    """Canonical JSON: keys sorted, no spaces, non-ASCII kept (JavaScript: a recursive key sort, then JSON.stringify)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


# ---------------------------------------------------------------- static clusters (export time)
def risk_of(rec):
    """Estimated risk used for ordering: case-calibrated (or case) value first, else the 2023 library value, else 0
    (as the desktop's crgo.js risk())."""
    e = rec.get("estimates") or {}
    for k in ("case_calibrated", "case", "library_2023"):
        r = (e.get(k) or {}).get("risk") or {}
        if r.get("estimated") is not None:
            return float(r["estimated"])
    return 0.0

def static_clusters(records, primary):
    """{id: cluster id} for records (export dicts), primary: {id: primary theme key}. Records are visited in the order
    (primary theme, -risk, id); a record joins the first representative already seen with the same primary theme and
    5*|A∩B| >= 2*max(1,|A∪B|) on name tokens, else it becomes a representative. Cluster id = representative id."""
    order = sorted(records, key=lambda r: (primary[r["id"]], -risk_of(r), r["id"]))
    reps, out = [], {}
    for r in order:
        tk = tokens(r.get("name", ""))
        rep = None
        for (rid, th, rtk) in reps:
            if th == primary[r["id"]] and 5 * len(tk & rtk) >= 2 * max(1, len(tk | rtk)):
                rep = rid; break
        if rep is None:
            reps.append((r["id"], primary[r["id"]], tk)); rep = r["id"]
        out[r["id"]] = rep
    return out


# ---------------------------------------------------------------- reference data
class Reference:
    """The export (or snapshot) prepared for grouping and validation. doc must carry 'values', 'scenarios' with
    'cluster' and 'primary_theme', and the 'grouping' block written by export_json.py from 0.11.2."""

    def __init__(self, doc):
        g = doc.get("grouping")
        if not g:
            raise ValueError("the export has no 'grouping' block: rebuild it with CRGO 0.11.2 or later (pipeline/query/export_json.py)")
        self.release = doc.get("version") or doc.get("release")
        self.values = {k: doc["values"][k] for k in ("asset_category", "theme", "threat_source_type", "impact_dimension")}
        self.labels = {k: {x["key"]: x["label"] for x in v} for k, v in self.values.items()}
        self.lookup = {k: self._lookup(v) for k, v in self.values.items()}
        self.active = set(g["attack"]["active"])
        self.replaced = dict(g["attack"]["replaced"])
        self.deprecated = set(g["attack"]["deprecated"])
        self.cwe_ids = set(g["cwe_ids"])
        self.cwe_broader = g["cwe_broader"]
        self.cwe_techniques = g["cwe_techniques"]
        self.theme_rules = [(k, re.compile(p, re.ASCII)) for k, p in g["theme_rules"]]
        self.records = [r for r in doc["scenarios"]]
        self.by_id = {r["id"]: r for r in self.records}
        self.library = [r for r in self.records if r.get("kind") == "library scenario"]
        self.titles = {}
        for r in self.library:
            for t in r.get("attack_techniques", []): self.titles.setdefault(("attack", t["id"]), t.get("title", ""))
            for t in r.get("cwe", []): self.titles.setdefault(("cwe", t["id"]), t.get("title", ""))
            for fw, xs in (r.get("controls") or {}).items():
                for t in xs: self.titles.setdefault((fw, t["id"]), t.get("title", ""))
            for t in r.get("obligations", []): self.titles.setdefault(("obligation", t["id"]), t.get("title", ""))
        self._prep = {}

    @staticmethod
    def _lookup(vals):
        m = {}
        for x in vals:
            m[x["key"]] = x["key"]
            m.setdefault(norm_text(x["label"]), x["key"])
            m.setdefault(norm_text(x["key"]), x["key"])
        return m

    def key_of(self, kind, value):
        """Vocabulary key for a key (exact) or an English label or key (case-insensitive, NFC); None when unknown."""
        v = nfc(value).strip()
        lk = self.lookup[kind]
        return lk.get(v) or lk.get(norm_text(v))

    def successor(self, t):
        """Final successor of a revoked ATT&CK id (the export already resolves chains); the id itself otherwise."""
        seen = set()
        while t in self.replaced and t not in seen:
            seen.add(t); t = self.replaced[t]
        return t

    def known_technique(self, t):
        return t in self.active or t in self.replaced or t in self.deprecated

    def infer_theme(self, text):
        t = norm_text(text)
        for k, rx in self.theme_rules:
            if rx.search(t):
                return k
        return "ThemeOther"

    def prepared(self, local, min_conf):
        """Library and local records reduced to what matching needs, for one confidence level."""
        key = (min_conf, _local_info(local)["sha256"])
        if key in self._prep:
            return self._prep[key]
        out = [self._prep_rec(r, "library", min_conf) for r in self.library]
        out += [self._prep_rec(r, "local", min_conf) for r in sorted(local, key=lambda r: r["id"])]
        out.sort(key=lambda p: p["id"])
        self._prep = {key: out}          # one cache entry: local stores change between calls
        return out

    def _prep_rec(self, r, source, min_conf):
        cats = {self.key_of("asset_category", c) for c in r.get("asset_categories", [])} - {None}
        techs = {base_technique(self.successor(t["id"])) for t in r.get("attack_techniques", []) if t.get("confidence") in ALLOW[min_conf]}
        return {"id": r["id"], "pt": r["primary_theme"], "cluster": r["cluster"], "tok": tokens(r.get("name", "")),
                "techs": techs, "cats": cats, "risk": risk_of(r), "source": source, "rec": r}


def load_reference(path=None):
    """The committed export as a Reference (cached per path)."""
    root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    path = path or os.path.join(root, "data", "export", "crgo-identification.json")
    if path not in _REF:
        with open(path, encoding="utf-8") as fh:
            _REF[path] = Reference(json.load(fh))
    return _REF[path]
_REF = {}


# ---------------------------------------------------------------- candidates
CANDIDATE_KEYS = ("ref", "name", "statement", "techniques", "cwe", "asset_categories", "threat_source_types", "themes", "crgo_id")

def check_candidate(c, where="candidate"):
    """Shape check of a candidate descriptor (candidate.schema.json, without a JSON-schema library so that the browser
    port can repeat it). Returns a list of messages; empty = valid."""
    errs = []
    if not isinstance(c, dict):
        return ["%s: must be an object" % where]
    extra = sorted(set(c) - set(CANDIDATE_KEYS))
    if extra:
        errs.append("%s: fields not allowed: %s (no parameters or organisation figures)" % (where, ", ".join(extra)))
    ref = c.get("ref")
    if not isinstance(ref, str) or not re.match(r"^[A-Za-z0-9][A-Za-z0-9._:\-]{0,39}$", ref):
        errs.append("%s: ref is required, 1-40 characters A-Z a-z 0-9 . _ : - (starting with a letter or digit)" % where)
    for k, n in (("name", 300), ("statement", 4000), ("crgo_id", 100)):
        if k in c and (not isinstance(c[k], str) or len(c[k]) > n):
            errs.append("%s: %s must be a string of at most %d characters" % (where, k, n))
    if not (isinstance(c.get("name"), str) and c["name"].strip()) and not (isinstance(c.get("statement"), str) and c["statement"].strip()):
        errs.append("%s: name or statement is required" % where)
    for k in ("techniques", "cwe", "asset_categories", "threat_source_types", "themes"):
        if k in c:
            v = c[k]
            if not isinstance(v, list) or len(v) > LIST_MAX or not all(isinstance(x, str) and len(x) <= 100 for x in v):
                errs.append("%s: %s must be a list of at most %d strings of at most 100 characters" % (where, k, LIST_MAX))
    return errs

def _uniq_sorted(xs):
    return sorted(set(xs))

def normalise(c, ref):
    """A candidate in CRGO terms: known keys, successor techniques, primary theme (given or inferred)."""
    name, statement = nfc(c.get("name", "")).strip(), nfc(c.get("statement", "")).strip()
    n = {"ref": c["ref"], "name": name, "statement": statement, "crgo_id": nfc(c.get("crgo_id", "")).strip(),
         "unknown": {"asset_categories": [], "threat_source_types": [], "themes": []},
         "unknown_techniques": [], "replaced": {}, "deprecated": [], "techs_full": [], "cwe": [], "cwe_unknown": []}
    for field, kind in (("asset_categories", "asset_category"), ("threat_source_types", "threat_source_type"), ("themes", "theme")):
        keys = []
        for v in c.get(field, []) or []:
            v = nfc(v).strip()
            if not v: continue
            k = ref.key_of(kind, v)
            if k is None: n["unknown"][field].append(v)
            elif k not in keys: keys.append(k)
        n[field] = keys
    for f in n["unknown"]: n["unknown"][f] = _uniq_sorted(n["unknown"][f])
    full = set()
    for t in c.get("techniques", []) or []:
        t = nfc(t).strip().upper()
        if not t: continue
        if not ref.known_technique(t):
            n["unknown_techniques"].append(t); continue
        s = ref.successor(t)
        if s != t: n["replaced"][t] = s
        if t in ref.deprecated and t not in ref.replaced: n["deprecated"].append(t)
        full.add(s)
    n["unknown_techniques"] = _uniq_sorted(n["unknown_techniques"])
    n["deprecated"] = _uniq_sorted(n["deprecated"])
    n["techs_full"] = sorted(full)
    n["techs"] = {base_technique(t) for t in full}
    for w in c.get("cwe", []) or []:
        w = nfc(w).strip().upper()
        if not w: continue
        if re.match(r"^[0-9]{1,6}$", w): w = "CWE-" + w
        if RX_CWE.match(w) and w in ref.cwe_ids: n["cwe"].append(w)
        else: n["cwe_unknown"].append(w)
    n["cwe"], n["cwe_unknown"] = _uniq_sorted(n["cwe"]), _uniq_sorted(n["cwe_unknown"])
    if n["themes"]:
        n["pt"], n["theme_inferred"] = n["themes"][0], False
    else:
        n["pt"], n["theme_inferred"] = ref.infer_theme(name or statement), True
    n["theme_set"] = set(n["themes"]) | {n["pt"]}
    n["tok"] = tokens(name or statement)
    n["cats"] = set(n["asset_categories"])
    return n

def _better(a, b):
    """True when match a beats match b: near, then Jaccard (cross-multiplied), then facet, then risk, then smaller id."""
    if a["near"] != b["near"]: return a["near"]
    x, y = a["inter"] * b["union"], b["inter"] * a["union"]
    if x != y: return x > y
    if a["facet"] != b["facet"]: return a["facet"]
    if a["p"]["risk"] != b["p"]["risk"]: return a["p"]["risk"] > b["p"]["risk"]
    return a["p"]["id"] < b["p"]["id"]

def match(n, ref, prep):
    """(prepared record, rule) or (None, None). rule: kept | near_duplicate | theme_technique_asset."""
    by_id = {p["id"]: p for p in prep}
    cid = n["crgo_id"]
    if cid:
        r = ref.by_id.get(cid)
        target = cid
        if r is not None and r.get("kind") == "case scenario":
            fams = sorted(x["id"] for x in r.get("refines", []) if x["id"] in by_id)
            target = fams[0] if fams else None
        if target in by_id:
            return by_id[target], "kept"
    best = None
    for p in prep:
        inter = len(n["tok"] & p["tok"]); union = max(1, len(n["tok"] | p["tok"]))
        near = p["pt"] == n["pt"] and 5 * inter >= 2 * union
        facet = p["pt"] in n["theme_set"] and bool(n["techs"] & p["techs"]) and bool(n["cats"] & p["cats"])
        if not (near or facet): continue
        m = {"p": p, "near": near, "facet": facet, "inter": inter, "union": union}
        if best is None or _better(m, best): best = m
    if best is None: return None, None
    return best["p"], ("near_duplicate" if best["near"] else "theme_technique_asset")

def _local_info(local):
    return {"count": len(local), "sha256": hashlib.sha256(canonical(sorted(local, key=lambda r: r["id"])).encode("utf-8")).hexdigest()}

def _representative(p):
    r = p["rec"]
    return {"id": r["id"], "name": r.get("name", ""), "statement": r.get("statement") or None,
            "themes": [t["key"] for t in r.get("themes", [])], "source": p["source"]}

def _check_list(candidates):
    if not isinstance(candidates, list):
        raise ValueError("candidates must be a list of candidate objects")
    if not candidates:
        raise ValueError("candidates: at least one candidate is required")
    if len(candidates) > CANDIDATES_MAX:
        raise ValueError("candidates: at most %d per call (received %d); grouping is across candidates, so do not split a screening" % (CANDIDATES_MAX, len(candidates)))
    errs = [e for i, c in enumerate(candidates) for e in check_candidate(c, "candidates[%d]" % i)]
    if errs: raise ValueError("; ".join(errs[:20]))
    refs = [c["ref"] for c in candidates]
    dup = sorted({r for r in refs if refs.count(r) > 1})
    if dup: raise ValueError("candidates: duplicate ref(s): %s" % ", ".join(dup))

def group(candidates, ref, local=(), min_confidence="M"):
    """crgo-grouping/1. candidates: list of candidate descriptors (candidate.schema.json); local: approved local records
    (export shape, from the installation's crgo-local-extension.json). Raises ValueError on a bad shape."""
    _check_list(candidates)
    local = list(local or [])
    prep = ref.prepared(local, min_confidence)
    norm = [normalise(c, ref) for c in candidates]
    matched, unmatched = {}, []
    members = {}
    for n in norm:
        p, rule = match(n, ref, prep)
        members[n["ref"]] = {"ref": n["ref"], "match": {"id": p["id"], "rule": rule} if p else None,
                             "primary_theme": n["pt"], "theme_inferred": n["theme_inferred"], "replaced_techniques": dict(sorted(n["replaced"].items()))}
        if p: matched.setdefault(p["cluster"], []).append(n["ref"])
        else: unmatched.append(n)
    groups = []
    rep_of = {p["id"]: p for p in prep}
    for cl, refs in matched.items():
        groups.append({"cluster_id": cl, "kind": "family" if len(refs) >= 2 else "unique",
                       "representative": _representative(rep_of[cl]) if cl in rep_of else None,
                       "members": [members[r] for r in sorted(refs)], "theme_gap": None})
    # unmatched: union-find on (primary theme, a shared base technique, a shared asset category)
    parent = {n["ref"]: n["ref"] for n in unmatched}
    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]; x = parent[x]
        return x
    um = sorted(unmatched, key=lambda n: n["ref"])
    for i, a in enumerate(um):
        for b in um[i + 1:]:
            if a["pt"] == b["pt"] and a["techs"] & b["techs"] and a["cats"] & b["cats"]:
                ra, rb = find(a["ref"]), find(b["ref"])
                if ra != rb: parent[max(ra, rb)] = min(ra, rb)
    comps = {}
    for n in um: comps.setdefault(find(n["ref"]), []).append(n)
    for ns in comps.values():
        refs = sorted(n["ref"] for n in ns)
        pt = ns[0]["pt"]
        groups.append({"cluster_id": "GRP-" + sha10("\n".join(refs)), "kind": "family" if len(refs) >= 2 else "own",
                       "representative": None, "members": [members[r] for r in refs], "theme_gap": pt})
    groups.sort(key=lambda g: (KIND_ORDER[g["kind"]], g["cluster_id"]))
    out = {"algorithm": ALGORITHM_GROUP, "release": ref.release, "min_confidence": min_confidence, "local": _local_info(local),
           "groups": groups, "theme_gaps": sorted({g["theme_gap"] for g in groups if g["theme_gap"]}),
           "unknown_techniques": _uniq_sorted(t for n in norm for t in n["unknown_techniques"])}
    unk = {f: _uniq_sorted(v for n in norm for v in n["unknown"][f]) for f in ("asset_categories", "threat_source_types", "themes")}
    unk["cwe"] = _uniq_sorted(w for n in norm for w in n["cwe_unknown"])
    unk = {k: v for k, v in unk.items() if v}
    if unk: out["unknown_values"] = unk
    ids = _uniq_sorted(n["crgo_id"] for n in norm if n["crgo_id"] and (members[n["ref"]]["match"] or {}).get("rule") != "kept")
    if ids: out["unknown_crgo_ids"] = ids
    out["caveat"] = CAVEAT
    return out


# ---------------------------------------------------------------- validation
MESSAGES = {
    "LIBRARY_MATCH": "Matches CRGO scenario %s (%s).",
    "THEME_MATCH_ONLY": "No CRGO scenario matches; scenarios of the theme %s share a technique or an asset category (theme gap: own scenario).",
    "OUTSIDE_ONTOLOGY": "Outside the ontology: no CRGO scenario matches and no scenario of the theme %s shares a technique or an asset category (own scenario).",
    "TECHNIQUE_UNKNOWN": "ATT&CK technique %s is not in CRGO.",
    "TECHNIQUE_REVOKED": "ATT&CK technique %s is revoked; its successor is %s.",
    "TECHNIQUE_DEPRECATED": "ATT&CK technique %s is deprecated and has no successor.",
    "CWE_UNKNOWN": "%s is not in the CWE list CRGO holds.",
    "CWE_TECHNIQUE_UNLINKED": "No technique of the scenario is linked to %s or its parent weaknesses (expected one of: %s).",
    "CWE_NO_REFERENCE": "CRGO has no technique reference for %s or its parent weaknesses: consistency cannot be judged.",
    "ASSET_CATEGORY_UNKNOWN": "Asset category %s is not in the CRGO vocabulary.",
    "THREAT_SOURCE_TYPE_UNKNOWN": "Threat source type %s is not in the CRGO vocabulary.",
    "THEME_UNKNOWN": "Theme %s is not in the CRGO vocabulary.",
    "CRGO_ID_UNKNOWN": "CRGO scenario %s is unknown.",
}

def _finding(code, severity, field, value, args, suggestion=None):
    f = {"code": code, "severity": severity, "field": field, "value": value, "message": MESSAGES[code] % args}
    if suggestion is not None: f["suggestion"] = suggestion
    return f

def cwe_reference(ref, cwe):
    """Base techniques referenced for a CWE: its own entry and those of its ancestors (skos:broader, breadth first);
    None when neither the CWE nor any ancestor has an entry."""
    seen, queue, found, techs = set(), [cwe], False, set()
    while queue:
        w = queue.pop(0)
        if w in seen: continue
        seen.add(w)
        if w in ref.cwe_techniques:
            found = True; techs.update(ref.cwe_techniques[w])
        queue.extend(sorted(ref.cwe_broader.get(w, [])))
    return sorted(techs) if found else None

def _links(xs, min_conf):
    out = [{"id": x["id"], "title": x.get("title", ""), "confidence": x["confidence"], "status": x.get("status", "proposed")}
           for x in xs if x.get("confidence") in ALLOW[min_conf]]
    return sorted(out, key=lambda x: (CONF_RANK[x["confidence"]], x["id"]))

def _aggregate(prep, techs, min_conf, top=10):
    count, titles = {}, {}
    for p in prep:
        if not (techs & p["techs"]): continue
        r = p["rec"]
        for fw in FRAMEWORKS:
            for x in (r.get("controls") or {}).get(fw, []):
                if x.get("confidence") in ALLOW[min_conf]:
                    count[(fw, x["id"])] = count.get((fw, x["id"]), 0) + 1; titles[(fw, x["id"])] = x.get("title", "")
        for x in r.get("obligations", []):
            if x.get("confidence") in ALLOW[min_conf]:
                count[("obligation", x["id"])] = count.get(("obligation", x["id"]), 0) + 1; titles[("obligation", x["id"])] = x.get("title", "")
    def top_of(fw):
        xs = sorted(((k[1], n) for k, n in count.items() if k[0] == fw), key=lambda kv: (-kv[1], kv[0]))[:top]
        return [{"id": i, "title": titles[(fw, i)], "scenarios": n} for i, n in xs]
    return {fw: top_of(fw) for fw in FRAMEWORKS}, top_of("obligation")

def theme_matches(n, prep):
    """Theme match (validation, when no scenario matches): a library or local scenario with the same primary theme that
    shares a base ATT&CK technique or an asset category with the descriptor."""
    return any(p["pt"] == n["pt"] and (n["techs"] & p["techs"] or n["cats"] & p["cats"]) for p in prep)

def validate(scenario, ref, local=(), min_confidence="M"):
    """crgo-validation/1 for one scenario descriptor (same shape as a candidate; 'ref' optional). Unknown vocabulary,
    revoked techniques and CWE inconsistencies are findings, never errors. Raises ValueError on a bad shape."""
    if isinstance(scenario, dict) and "ref" not in scenario:
        scenario = dict(scenario, ref="scenario")
    errs = check_candidate(scenario, "scenario")
    if errs: raise ValueError("; ".join(errs))
    local = list(local or [])
    prep = ref.prepared(local, min_confidence)
    n = normalise(scenario, ref)
    p, rule = match(n, ref, prep)
    theme_match = bool(p) or theme_matches(n, prep)
    F = []
    if p:
        F.append(_finding("LIBRARY_MATCH", "info", "match", p["id"], (p["id"], rule)))
    elif theme_match:
        F.append(_finding("THEME_MATCH_ONLY", "info", "themes", n["pt"], (n["pt"],)))
    else:
        F.append(_finding("OUTSIDE_ONTOLOGY", "attention", "themes", n["pt"], (n["pt"],)))
    for t in n["unknown_techniques"]:
        F.append(_finding("TECHNIQUE_UNKNOWN", "attention", "techniques", t, (t,)))
    for t, s in sorted(n["replaced"].items()):
        F.append(_finding("TECHNIQUE_REVOKED", "attention", "techniques", t, (t, s), s))
    for t in n["deprecated"]:
        F.append(_finding("TECHNIQUE_DEPRECATED", "attention", "techniques", t, (t,)))
    for w in n["cwe_unknown"]:
        F.append(_finding("CWE_UNKNOWN", "attention", "cwe", w, (w,)))
    for w in n["cwe"]:
        exp = cwe_reference(ref, w)
        if exp is None:
            F.append(_finding("CWE_NO_REFERENCE", "info", "cwe", w, (w,)))
        elif n["techs"] and not (n["techs"] & set(exp)):
            F.append(_finding("CWE_TECHNIQUE_UNLINKED", "attention", "cwe", w, (w, ", ".join(exp[:10]) + (" ..." if len(exp) > 10 else ""))))
    for field, code in (("asset_categories", "ASSET_CATEGORY_UNKNOWN"), ("threat_source_types", "THREAT_SOURCE_TYPE_UNKNOWN"), ("themes", "THEME_UNKNOWN")):
        for v in n["unknown"][field]:
            F.append(_finding(code, "attention", field, v, (v,)))
    if n["crgo_id"] and not (p and rule == "kept"):
        F.append(_finding("CRGO_ID_UNKNOWN", "attention", "crgo_id", n["crgo_id"], (n["crgo_id"],)))
    if p:
        r = p["rec"]
        controls = {fw: _links((r.get("controls") or {}).get(fw, []), min_confidence) for fw in FRAMEWORKS}
        obligations, basis = _links(r.get("obligations", []), min_confidence), "match"
    elif n["techs"]:
        (controls, obligations), basis = _aggregate(prep, n["techs"], min_confidence), "techniques"
    else:
        controls, obligations, basis = {fw: [] for fw in FRAMEWORKS}, [], "none"
    if not theme_match: state = "outside_ontology"
    elif any(f["severity"] == "attention" for f in F): state = "needs_attention"
    else: state = "consistent"
    return {"algorithm": ALGORITHM_VALID, "release": ref.release, "min_confidence": min_confidence, "local": _local_info(local),
            "state": state, "match": {"id": p["id"], "cluster_id": p["cluster"], "rule": rule} if p else None,
            "theme_gap": None if p else n["pt"],
            "primary_theme": n["pt"], "theme_inferred": n["theme_inferred"], "replaced_techniques": dict(sorted(n["replaced"].items())),
            "findings": F, "controls_basis": basis, "controls": controls, "obligations": obligations, "caveat": CAVEAT}


# ---------------------------------------------------------------- local records (approved proposals)
def local_record(pid, proposal, ref, approver, date):
    """An approved proposal as an export-shaped record of this installation's ontology (source 'local'). Its links carry
    status 'proposed': they are approved for this installation, not by the CRGO project owner."""
    lab = ref.labels
    link = lambda scheme, xs: [{"id": i, "title": ref.titles.get((scheme, i), ""), "confidence": c, "status": "proposed"} for i, c in xs]
    rec = {"id": pid, "name": proposal["name"], "kind": "local scenario", "source": "local", "statement": proposal["statement"],
           "themes": [{"key": k, "label": lab["theme"][k]} for k in proposal["themes"]],
           "asset_categories": [lab["asset_category"][k] for k in proposal.get("asset_categories", [])],
           "threat_source_types": [lab["threat_source_type"][k] for k in proposal.get("threat_source_types", [])],
           "impact_dimensions": [lab["impact_dimension"][k] for k in proposal.get("impact_dimensions", [])],
           "weaknesses": list(proposal.get("weaknesses", [])),
           "attack_techniques": link("attack", proposal.get("techniques", [])),
           "controls": {"csf2": link("csf2", proposal.get("csf2", [])), "sp800-53r5": link("sp800-53r5", proposal.get("sp80053r5", [])),
                        "iso27002-2022": link("iso27002-2022", proposal.get("iso27002", []))},
           "obligations": link("obligation", proposal.get("loi25", [])),
           "cwe": link("cwe", proposal.get("cwe", [])),
           "primary_theme": proposal["themes"][0], "cluster": pid, "approved_by": approver, "approved_on": date}
    return rec

def local_clusters(local, ref):
    """Cluster and primary theme of local records against the library's representatives: the static rule, with local
    records visited after the library (they have no risk value and their ids sort after 'LIB-'), in id order."""
    reps = []
    for r in ref.library:
        if r["cluster"] == r["id"]:
            reps.append((r["primary_theme"], -risk_of(r), r["id"], tokens(r.get("name", ""))))
    reps.sort(key=lambda x: (x[0], x[1], x[2]))
    reps = [(x[2], x[0], x[3]) for x in reps]
    out = []
    for r in sorted(local, key=lambda r: r["id"]):
        r = dict(r); r["primary_theme"] = r["themes"][0]["key"]
        tk = tokens(r.get("name", ""))
        rep = next((rid for rid, th, rtk in reps if th == r["primary_theme"] and 5 * len(tk & rtk) >= 2 * max(1, len(tk | rtk))), None)
        if rep is None:
            reps.append((r["id"], r["primary_theme"], tk)); rep = r["id"]
        r["cluster"] = rep
        out.append(r)
    return out
