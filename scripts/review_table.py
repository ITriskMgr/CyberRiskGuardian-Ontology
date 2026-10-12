# -*- coding: utf-8 -*-
"""Print a Markdown table of the terms numbered above a given ID (default 884: the 0.10.0 terms), from build/terms.json."""
import json, os, sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
low = int(sys.argv[1]) if len(sys.argv) > 1 else 884
T = json.load(open(os.path.join(ROOT, "build", "terms.json"), encoding="utf-8"))
order = ["class", "value set (class)", "value", "object property", "data property"]
rows = [t for t in T if int(t["iri"].rsplit("_", 1)[1]) > low]
for mod in ["policy", "compliance", "audit", "assurance", "grc", "mapping"]:
    sel = [t for t in rows if t["module"] == mod]
    if not sel: continue
    print("\n### crgo-%s (%d)\n" % (mod, len(sel)))
    print("| IRI | Kind | Label (en / fr) | Parent, domain/range or value set | Definition (en) |")
    print("|---|---|---|---|---|")
    for t in sorted(sel, key=lambda t: (order.index(t["kind"]), int(t["iri"].rsplit("_", 1)[1]))):
        d = t["def_en"].replace("|", "\\|")
        print("| %s | %s | %s / %s | %s | %s |" % (t["iri"].rsplit("/", 1)[1], t["kind"], t["label_en"], t["label_fr"], t["parent"] or "—", d))
