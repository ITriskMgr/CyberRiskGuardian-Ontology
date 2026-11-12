# -*- coding: utf-8 -*-
"""Export every library and case scenario as one JSON file for tools that cannot run a SPARQL store:
data/export/crgo-identification.json. Links of all confidence levels are included with their confidence and status.

From 0.11.2 the export also carries what candidate grouping and validation need offline (contract library-proposal/v1,
pipeline/query/grouping.py): per scenario 'primary_theme' and 'cluster' (static near-duplicate clusters), and a
top-level 'grouping' block (ATT&CK active / replaced / deprecated ids, CWE ids and hierarchy, CWE -> ATT&CK references,
the theme rules)."""
import csv, json, os, sys, time
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(ROOT, "pipeline", "library"))
import identify as I  # noqa: E402
import grouping as G  # noqa: E402

VERSION = "0.11.2"

def primary_themes(scen):
    """Primary theme per scenario: the family's theme (data/library/families.csv) or the authored scenario's theme,
    always among the scenario's themes; for case scenarios and anything else, the smallest theme key."""
    fam = {r["family"]: r["theme"] for r in csv.DictReader(open(os.path.join(ROOT, "data", "library", "families.csv"), encoding="utf-8"))}
    fid = dict(l.rstrip("\n").split("\t") for l in open(os.path.join(ROOT, "data", "library", "family_ids.tsv"), encoding="utf-8")
               if l.strip() and not l.startswith("#"))
    fam.update({fid[a["key"]]: a["theme"] for a in json.load(open(os.path.join(ROOT, "data", "library", "authored_scenarios.json"), encoding="utf-8"))})
    out = {}
    for s in scen:
        keys = sorted(t["key"] for t in s["themes"])
        t = fam.get(s["id"][4:]) if s["kind"] == "library scenario" else None
        out[s["id"]] = t if t in keys else (keys[0] if keys else "ThemeOther")
    return out

def grouping_block(scen):
    """Reference data for grouping and validation, from the store (vocabularies and mappings) and the export itself."""
    V = I.VOC
    rows = I._q('SELECT ?n ?dep ?rn WHERE { ?c skos:inScheme <%sattack> ; skos:notation ?n . OPTIONAL { ?c owl:deprecated ?dep } '
                'OPTIONAL { ?c <http://purl.org/dc/terms/isReplacedBy> ?r . ?r skos:notation ?rn } }' % V)
    rep, dep, allt = {}, set(), set()
    for r in rows:
        n = r["n"].value; allt.add(n)
        if r["dep"] is not None and r["dep"].value in ("true", "1"): dep.add(n)
        if r["rn"] is not None: rep[n] = r["rn"].value
    def final(t):
        seen = set()
        while t in rep and t not in seen:
            seen.add(t); t = rep[t]
        return t
    replaced = {t: final(t) for t in sorted(rep)}
    attack = {"active": sorted(allt - dep - set(rep)), "replaced": replaced, "deprecated": sorted(dep - set(rep))}
    cwe_ids = sorted(r["n"].value for r in I._q('SELECT ?n WHERE { ?c skos:inScheme <%scwe> ; skos:notation ?n }' % V))
    broader = {}
    for r in I._q('SELECT ?n ?b WHERE { ?c skos:inScheme <%scwe> ; skos:notation ?n ; skos:broader ?p . ?p skos:inScheme <%scwe> ; skos:notation ?b }' % (V, V)):
        broader.setdefault(r["n"].value, set()).add(r["b"].value)
    pairs = set()
    base = lambda t: G.base_technique(final(t))
    for src in ("capec", "kev"):   # a CAPEC pattern or a KEV entry related to both a CWE and an ATT&CK technique
        for r in I._q('SELECT DISTINCT ?w ?t WHERE { ?k skos:inScheme <%s%s> ; skos:relatedMatch ?a, ?c . ?a skos:inScheme <%sattack> ; skos:notation ?t . '
                      '?c skos:inScheme <%scwe> ; skos:notation ?w }' % (V, src, V, V)):
            pairs.add((r["w"].value, base(r["t"].value)))
    for s in scen:                 # library co-occurrence: approved (H, M) CWE and technique links of the same scenario
        if s["kind"] != "library scenario": continue
        ws = [x["id"] for x in s.get("cwe", []) if x["confidence"] in ("H", "M")]
        ts = [x["id"] for x in s.get("attack_techniques", []) if x["confidence"] in ("H", "M")]
        pairs.update((w, base(t)) for w in ws for t in ts)
    cwe_t = {}
    for w, t in sorted(pairs): cwe_t.setdefault(w, []).append(t)
    import themes as TH
    order = sorted(TH.THEMES, key=lambda th: TH.EVENT_FIRST.index(th[0]) if th[0] in TH.EVENT_FIRST else len(TH.EVENT_FIRST))
    return {"schema": "crgo-grouping-data/1", "algorithms": [G.ALGORITHM_GROUP, G.ALGORITHM_VALID],
            "note": "Reference data for candidate grouping and scenario validation (contracts/library-proposal/v1/README.md).",
            "stop_words": list(G.STOP), "attack": attack, "cwe_ids": cwe_ids,
            "cwe_broader": {k: sorted(v) for k, v in sorted(broader.items())}, "cwe_techniques": cwe_t,
            "theme_rules": [[th[0], th[-1]] for th in order], "event_first": list(TH.EVENT_FIRST)}

def annotate(scen):
    """Add primary_theme and cluster to every scenario (library: static clusters; case: cluster of its first family)."""
    prim = primary_themes(scen)
    lib = [s for s in scen if s["kind"] == "library scenario"]
    cl = G.static_clusters(lib, prim)
    for s in scen:
        s["primary_theme"] = prim[s["id"]]
        if s["id"] in cl:
            s["cluster"] = cl[s["id"]]
        else:
            fams = sorted(x["id"] for x in s.get("refines", []) if x["id"] in cl)
            s["cluster"] = cl[fams[0]] if fams else None
    return cl

def main():
    t0 = time.time()
    ids = [r["s"].value for r in I._q("SELECT ?s WHERE { ?s a %s } ORDER BY ?s" % I.T("LibraryScenario"))]
    scen = [I.scenario(s, "L") for s in ids]
    cl = annotate(scen)
    out = {"title": "CyberRiskGuardian Ontology - identification export", "version": VERSION,
           "licence": "CC BY-NC 4.0; framework identifiers and titles keep their owners' terms (see NOTICE.md)",
           "caveat": I.CAVEAT,
           "values": {k: I.list_values(k) for k in ("asset_category", "theme", "threat_source_type", "impact_dimension", "sector")},
           "grouping": grouping_block(scen),
           "scenarios": scen}
    os.makedirs(os.path.join(ROOT, "data", "export"), exist_ok=True)
    path = os.path.join(ROOT, "data", "export", "crgo-identification.json")
    json.dump(out, open(path, "w", encoding="utf-8"), ensure_ascii=False, separators=(",", ":"))
    g = out["grouping"]
    print("%d scenarios, %d library clusters (%d singletons), ATT&CK %d active / %d replaced / %d deprecated, CWE %d (%d with references) -> %s (%.1f MB, %.0f s)" % (
        len(ids), len(set(cl.values())), sum(1 for c in set(cl.values()) if list(cl.values()).count(c) == 1),
        len(g["attack"]["active"]), len(g["attack"]["replaced"]), len(g["attack"]["deprecated"]), len(g["cwe_ids"]), len(g["cwe_techniques"]),
        path, os.path.getsize(path) / 1e6, time.time() - t0))

if __name__ == "__main__":
    main()
