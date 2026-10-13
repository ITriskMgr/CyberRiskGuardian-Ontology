# -*- coding: utf-8 -*-
"""Interactive ontology map (docs/map/index.html, published on GitHub Pages at /map/).

Reads the OWL modules, the BFO/CCO/PROV/Time slices, the scenario library and the SKOS vocabularies, and fills
docs/site-src/map-template.html and map-template.js. Also writes build/map/artifact.html (the same page without the
document skeleton) for publishing as a claude.ai artifact. Run after build.py and the vocabulary builders:
    python3 scripts/make_map.py
"""
import glob, json, os, re, sys
from rdflib import Graph, URIRef, RDF, RDFS, OWL, Literal
from rdflib.namespace import SKOS
from rdflib.collection import Collection
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))
BASE = "https://w3id.org/crgo/"
MODS = ["gov","core","measure","crg","evidence","org","vuln","grc","mapping","governance","assurance","audit","incident","policy","compliance","siem","soar"]
ext = Graph()
for f in ["imports/bfo-core.ttl","imports/cco-slice.ttl","imports/prov-slice.ttl","imports/time-slice.ttl"]:
    ext.parse(os.path.join(ROOT, f))
allg = Graph()
for g in [ext]: allg += g
modg = {}
for m in MODS:
    g = Graph().parse(os.path.join(ROOT, "ontology", "crgo-%s.ttl" % m)); modg[m] = g; allg += g
def lit(g, s, p, lang):
    for o in g.objects(s, p):
        if isinstance(o, Literal) and o.language == lang: return str(o)
    return None
def short(u): return str(u).replace(BASE, "")
def members(g, node):
    out = []
    if isinstance(node, URIRef): return [str(node)]
    for p in (OWL.unionOf,):
        for lst in g.objects(node, p):
            out += [str(x) for x in Collection(g, lst) if isinstance(x, URIRef)]
    return out
BUCKETS = [(str(SKOS.Concept), "concept"), ("http://purl.obolibrary.org/obo/BFO_0000040", "material"),
           ("http://purl.obolibrary.org/obo/BFO_0000031", "ice"), ("http://purl.obolibrary.org/obo/BFO_0000023", "role"),
           ("http://purl.obolibrary.org/obo/BFO_0000016", "disposition"), ("http://purl.obolibrary.org/obo/BFO_0000017", "realizable"),
           ("http://purl.obolibrary.org/obo/BFO_0000019", "quality"), ("http://purl.obolibrary.org/obo/BFO_0000020", "quality"),
           ("http://purl.obolibrary.org/obo/BFO_0000015", "process"), ("http://purl.obolibrary.org/obo/BFO_0000003", "process"),
           ("http://purl.obolibrary.org/obo/BFO_0000008", "process"), ("http://purl.obolibrary.org/obo/BFO_0000029", "material"),
           ("http://purl.obolibrary.org/obo/BFO_0000004", "material")]
def anc(u):
    seen, st = [], [URIRef(u)]
    while st:
        x = st.pop(0)
        for p in allg.objects(x, RDFS.subClassOf):
            if isinstance(p, URIRef) and p not in seen: seen.append(p); st.append(p)
    return [str(s) for s in seen]
def bucket(u):
    a = anc(u)
    for b, k in BUCKETS:
        if b in a: return k
    return "none"
classes, oprops, dprops, extneed = [], [], [], set()
for m, g in modg.items():
    for s in g.subjects(RDF.type, OWL.Class):
        if not isinstance(s, URIRef) or not str(s).startswith(BASE + "CRGO_"): continue
        if (s, OWL.deprecated, Literal(True)) in g: continue
        parents = [str(p) for p in g.objects(s, RDFS.subClassOf) if isinstance(p, URIRef)]
        vals = sorted({lit(g, i, RDFS.label, "en") or short(i) for i in allg.subjects(RDF.type, s) if (i, RDF.type, OWL.NamedIndividual) in allg})
        c = dict(id=short(s), en=lit(g, s, RDFS.label, "en"), fr=lit(g, s, RDFS.label, "fr"), den=lit(g, s, SKOS.definition, "en"),
                 dfr=lit(g, s, SKOS.definition, "fr"), mod=m, parents=[short(p) if p.startswith(BASE) else p for p in parents],
                 bucket=bucket(s), values=vals)
        for p in parents:
            if not p.startswith(BASE): extneed.add(p)
        classes.append(c)
    for s in g.subjects(RDF.type, OWL.ObjectProperty):
        if not str(s).startswith(BASE) or (s, OWL.deprecated, Literal(True)) in g: continue
        dom = sum((members(g, o) for o in g.objects(s, RDFS.domain)), [])
        rng = sum((members(g, o) for o in g.objects(s, RDFS.range)), [])
        oprops.append(dict(id=short(s), en=lit(g, s, RDFS.label, "en"), fr=lit(g, s, RDFS.label, "fr"), den=lit(g, s, SKOS.definition, "en"),
                           dfr=lit(g, s, SKOS.definition, "fr"), mod=m, dom=dom, rng=rng,
                           sup=[str(o) for o in g.objects(s, RDFS.subPropertyOf) if isinstance(o, URIRef)]))
    for s in g.subjects(RDF.type, OWL.DatatypeProperty):
        if not str(s).startswith(BASE) or (s, OWL.deprecated, Literal(True)) in g: continue
        dom = sum((members(g, o) for o in g.objects(s, RDFS.domain)), [])
        dprops.append(dict(id=short(s), en=lit(g, s, RDFS.label, "en"), fr=lit(g, s, RDFS.label, "fr"), mod=m, dom=dom))
extd = {}
todo = list(extneed)
while todo:
    u = todo.pop()
    if u in extd: continue
    U = URIRef(u)
    ps = [str(p) for p in allg.objects(U, RDFS.subClassOf) if isinstance(p, URIRef) and not str(p).startswith(BASE)]
    extd[u] = dict(en=lit(allg, U, RDFS.label, "en") or lit(allg, U, SKOS.prefLabel, "en") or str(allg.value(U, RDFS.label) or u.split("/")[-1].split("#")[-1]), parents=ps)
    todo += ps
classes.sort(key=lambda c: c["id"]); oprops.sort(key=lambda c: c["id"]); dprops.sort(key=lambda c: c["id"])
D = dict(classes=classes, ext=extd, oprops=oprops, dprops=dprops)

# ---------------------------------------------------------------- facts: release, library, vocabularies
bsrc = open(os.path.join(ROOT, "src", "build.py"), encoding="utf-8").read()
VERSION = re.search(r'^VERSION = "([^"]+)"', bsrc, re.M).group(1)
ISSUED = re.search(r'^ISSUED = "([^"]+)"', bsrc, re.M).group(1)
NEW_MODS = ["policy", "compliance", "siem", "soar"]          # modules first released in VERSION
NEW_VOCABS = {"attack-detection", "ocsf"}
lib = Graph().parse(os.path.join(ROOT, "data", "abox", "crgo-library.ttl"))
scen = set(lib.subjects(RDF.type, URIRef(BASE + "CRGO_0000024")))
links = sum(1 for s in scen for o in lib.objects(s, None) if isinstance(o, URIRef) and str(o).startswith(BASE + "vocab/"))
VOCAB = [  # (group en, group fr, [(file, display name)])
    ("Frameworks and controls", "Référentiels et mesures", [("csf2", "NIST CSF 2.0"), ("sp800-53r5", "SP 800-53 Rev. 5"), ("sp800-53a", "SP 800-53A"),
        ("iso27002-2022", "ISO/IEC 27002:2022"), ("cobit2019", "COBIT 2019"), ("ccm41", "CSA CCM 4.1"), ("coso-erm", "COSO ERM"), ("theme", "scenario themes")]),
    ("Threats, weaknesses and countermeasures", "Menaces, faiblesses et contre-mesures", [("attack", "MITRE ATT&CK"), ("capec", "CAPEC"), ("cwe", "CWE"),
        ("d3fend", "D3FEND"), ("kev", "CISA KEV")]),
    ("Detection and events", "Détection et événements", [("attack-detection", "ATT&CK detection"), ("ocsf", "OCSF 1.9.0")]),
    ("Law and regulation", "Lois et règlements", [("loi25", "Loi 25 (P-39.1)"), ("lrsss", "R-22.1"), ("a21", "A-2.1"), ("pipeda", "PIPEDA"),
        ("gdpr", "GDPR"), ("osfi-b13", "OSFI B-13")]),
    ("Audit, assurance and compliance", "Audit, assurance et conformité", [("iia-gias", "IIA GIAS"), ("iia-tr", "IIA Topical Req."), ("itaf", "ISACA ITAF"),
        ("tsc", "Trust Services Criteria"), ("iso19011", "ISO 19011"), ("iso27007", "ISO/IEC 27007"), ("iso27008", "ISO/IEC 27008"),
        ("iso37301", "ISO 37301"), ("iso37302", "ISO 37302")])]
vocab, total = [], 0
for gen, gfr, items in VOCAB:
    row = []
    for f, name in items:
        v = Graph().parse(os.path.join(ROOT, "ontology", "vocab", f + ".ttl"))
        n = len(set(v.subjects(RDF.type, SKOS.Concept))); total += n
        row.append([name, n, f in NEW_VOCABS])
    vocab.append(dict(en=gen, fr=gfr, items=row))
META = dict(version=VERSION, date=ISSUED, scenarios=len(scen), links=links, concepts=total, vocab=vocab, newMods=NEW_MODS)

# ---------------------------------------------------------------- fill the template
src = os.path.join(ROOT, "docs", "site-src")
page = open(os.path.join(src, "map-template.html"), encoding="utf-8").read()
js = open(os.path.join(src, "map-template.js"), encoding="utf-8").read()
js = js.replace("__DATA__", json.dumps(D, ensure_ascii=False, separators=(",", ":"))).replace("__META__", json.dumps(META, ensure_ascii=False))
body = page + "<script>\n" + js + "</script>\n"
os.makedirs(os.path.join(ROOT, "build", "map"), exist_ok=True)
open(os.path.join(ROOT, "build", "map", "artifact.html"), "w", encoding="utf-8").write(body)
skeleton = ('<!doctype html>\n<html lang="en">\n<head>\n<meta charset="utf-8">\n'
            '<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">\n'
            '<meta name="description" content="Interactive map of the CyberRiskGuardian Ontology (CRGO) %s: classes, relations, modules and reference vocabularies, in English and French.">\n'
            '<style>:root{box-sizing:border-box;padding-top:env(safe-area-inset-top,0px);padding-bottom:env(safe-area-inset-bottom,0px)}body{margin:0;padding:0;font:14px -apple-system,BlinkMacSystemFont,sans-serif}img{max-width:100%%}[hidden]{display:none!important}</style>\n'
            '</head>\n<body>\n' % VERSION)
os.makedirs(os.path.join(ROOT, "docs", "map"), exist_ok=True)
gh = body.replace("<title>CRGO Ontology Map</title>\n", "", 1)
skeleton = skeleton.replace("<style>", "<title>CRGO Ontology Map</title>\n<style>", 1)
open(os.path.join(ROOT, "docs", "map", "index.html"), "w", encoding="utf-8").write(skeleton + gh + "</body>\n</html>\n")
print("map: %d classes, %d relations, %d attributes; %d scenarios, %d links, %d concepts -> docs/map/index.html, build/map/artifact.html"
      % (len(classes), len(oprops), len(dprops), len(scen), links, total))
