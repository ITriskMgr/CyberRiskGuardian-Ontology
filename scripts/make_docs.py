# -*- coding: utf-8 -*-
"""Prepare the input for WIDOCO: the four CRGO modules as one file under the umbrella IRI, plus the labels and
definitions of the BFO and CCO terms they reference (annotations only, so WIDOCO shows names instead of IRIs)."""
import glob, os
import rdflib
from rdflib import URIRef
from rdflib.namespace import RDF, RDFS, OWL, SKOS
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
g = rdflib.Graph()
for f in ["ontology/crgo.ttl"] + ["ontology/crgo-%s.ttl" % m for m in ("gov", "core", "measure", "crg", "evidence", "org", "vuln", "grc", "mapping")]:
    g.parse(os.path.join(ROOT, f))
umb = URIRef("https://w3id.org/crgo/crgo")
for o in list(g.subjects(RDF.type, OWL.Ontology)):
    if o != umb:
        for t in list(g.triples((o, None, None))): g.remove(t)
for t in list(g.triples((umb, OWL.imports, None))): g.remove(t)
ext = rdflib.Graph()
for f in ("imports/bfo-core.ttl", "imports/cco-slice.ttl", "imports/prov-slice.ttl", "imports/time-slice.ttl"):
    ext.parse(os.path.join(ROOT, f))
used = {o for o in g.objects() if isinstance(o, URIRef) and ("commoncoreontologies" in str(o) or "purl.obolibrary.org/obo/BFO_" in str(o) or "w3.org/ns/prov#" in str(o) or "w3.org/2006/time#" in str(o))}
for t in used:
    for p in (RDFS.label, SKOS.definition, URIRef("http://purl.obolibrary.org/obo/IAO_0000115")):
        for v in ext.objects(t, p):
            g.add((t, RDFS.label if p == RDFS.label else SKOS.definition, v))
    for ty in ext.objects(t, RDF.type):
        if ty in (OWL.Class, OWL.ObjectProperty):
            g.add((t, RDF.type, ty))
os.makedirs(os.path.join(ROOT, "build"), exist_ok=True)
g.serialize(os.path.join(ROOT, "build", "crgo-doc.ttl"), format="turtle")
print("WIDOCO input: %d triples, %d external terms labelled" % (len(g), len(used)))

# ---------------------------------------------------------------- run WIDOCO and assemble the site (docs/ = GitHub Pages root)
import re, shutil, subprocess, sys
jar = os.environ.get("WIDOCO_JAR")
if not jar:
    sys.exit("Set WIDOCO_JAR to the WIDOCO jar to generate the site (input written to build/crgo-doc.ttl).")
out = os.path.join(ROOT, "build", "site")
shutil.rmtree(out, ignore_errors=True)
subprocess.run(["java", "-jar", jar, "-ontFile", os.path.join(ROOT, "build", "crgo-doc.ttl"), "-outFolder", out, "-rewriteAll",
                "-lang", "en-fr", "-webVowl", "-uniteSections", "-includeAnnotationProperties", "-getOntologyMetadata"],
               check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
src = os.path.join(ROOT, "docs", "site-src")
refs = open(os.path.join(src, "references.html"), encoding="utf-8").read()
for lang in ("en", "fr"):
    p = os.path.join(out, "doc", "index-%s.html" % lang)
    t = open(p, encoding="utf-8").read()
    intro = open(os.path.join(src, "intro-%s.html" % lang), encoding="utf-8").read()
    t = re.sub(r'(<h2 id="intro"[^>]*>.*?</span>\s*</h2>).*?(?=<h2|</div>\s*<div id="overv")', lambda m: m.group(1) + "\n" + intro + "\n", t, count=1, flags=re.S)
    t = re.sub(r'(<h2 id="ref"[^>]*>.*?</span>\s*</h2>).*?(?=<h2|</div>\s*<div id="ack")', lambda m: m.group(1) + "\n" + refs + "\n", t, count=1, flags=re.S)
    assert "place holder text" not in t.lower() and "add your references" not in t.lower(), "placeholder left in " + p
    open(p, "w", encoding="utf-8").write(t)
site = os.path.join(ROOT, "docs")
shutil.rmtree(os.path.join(site, "doc"), ignore_errors=True)
shutil.copytree(os.path.join(out, "doc"), os.path.join(site, "doc"))
shutil.copy(os.path.join(src, "index.html"), os.path.join(site, "index.html"))
open(os.path.join(site, ".nojekyll"), "w").close()
print("site: docs/index.html and docs/doc/ (English and French)")
