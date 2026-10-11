# -*- coding: utf-8 -*-
"""Export every library and case scenario as one JSON file for tools that cannot run a SPARQL store:
data/export/crgo-identification.json. Links of all confidence levels are included with their confidence and status."""
import json, os, sys, time
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, HERE)
import identify as I  # noqa: E402

def main():
    t0 = time.time()
    ids = [r["s"].value for r in I._q("SELECT ?s WHERE { ?s a %s } ORDER BY ?s" % I.T("LibraryScenario"))]
    out = {"title": "CyberRiskGuardian Ontology - identification export", "version": "0.8.0",
           "licence": "CC BY-NC 4.0; framework identifiers and titles keep their owners' terms (see NOTICE.md)",
           "caveat": I.CAVEAT,
           "values": {k: I.list_values(k) for k in ("asset_category", "theme", "threat_source_type", "impact_dimension", "sector")},
           "scenarios": [I.scenario(s, "L") for s in ids]}
    os.makedirs(os.path.join(ROOT, "data", "export"), exist_ok=True)
    path = os.path.join(ROOT, "data", "export", "crgo-identification.json")
    json.dump(out, open(path, "w", encoding="utf-8"), ensure_ascii=False, separators=(",", ":"))
    print("%d scenarios -> %s (%.1f MB, %.0f s)" % (len(ids), path, os.path.getsize(path) / 1e6, time.time() - t0))

if __name__ == "__main__":
    main()
