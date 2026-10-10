# -*- coding: utf-8 -*-
"""Check the w3id.org rewrite rules against the IRIs CRGO actually uses, by simulating Apache mod_rewrite for the
common cases (Accept: text/turtle and text/html). Every IRI in the published files must resolve to a target."""
import glob, os, re, sys
import rdflib
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
rules, conds = [], []
for line in open(os.path.join(ROOT, "w3id", "crgo", ".htaccess"), encoding="utf-8"):
    line = line.strip()
    if line.startswith("RewriteCond"):
        parts = line.split()
        conds.append((parts[2], "[OR]" in line))
    elif line.startswith("RewriteRule"):
        _, pat, target, flags = line.split(None, 3)
        rules.append((re.compile(pat), target, list(conds))); conds = []
def resolve(path, accept):
    for pat, target, cs in rules:
        # mod_rewrite: conditions are ANDed, except that [OR] joins a condition with the next one
        groups, cur = [], []
        for c, is_or in cs:
            cur.append(c)
            if not is_or: groups.append(cur); cur = []
        if cur: groups.append(cur)
        if all(any(re.search(c, accept) for c in grp) for grp in groups):
            m = pat.match(path)
            if m:
                return m.expand(target.replace("$", "\\"))
    return None
iris = set()
for f in ["ontology/crgo.ttl", "ontology/crgo-core.ttl", "ontology/crgo-full.ttl", "ontology/vocab/csf2.ttl", "data/abox/crgo-library.ttl"]:
    g = rdflib.Graph(); g.parse(os.path.join(ROOT, f))
    iris |= {str(t) for t in set(g.subjects()) | set(g.objects()) if isinstance(t, rdflib.URIRef) and str(t).startswith("https://w3id.org/crgo/")}
bad, samples = [], {}
for i in sorted(iris):
    path = i[len("https://w3id.org/crgo/"):]
    for acc in ("text/turtle", "text/html"):
        r = resolve(path, acc)
        if r is None or (acc == "text/turtle" and not re.search(r"\.(ttl|owl|jsonld|nt)$", r)):
            bad.append((i, acc, r))
        kind = re.sub(r"[0-9]+", "N", path.split("/")[0])[:20]
        samples.setdefault((kind, acc), (i, r))
for (k, acc), (i, r) in sorted(samples.items())[:16]:
    print("   %-11s %-55s -> %s" % (acc, i[len("https://w3id.org/"):][:55], (r or "NONE")[:90]))
print("   %d IRIs checked, %d unresolved" % (len(iris), len(bad)))
for b in bad[:10]: print("   UNRESOLVED", b)
sys.exit(1 if bad else 0)
