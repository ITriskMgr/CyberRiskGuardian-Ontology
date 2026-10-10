# -*- coding: utf-8 -*-
"""Generate the CyberRiskGuardian Ontology modules from spec_core.py and spec_props.py.

Usage: python3 src/build.py   (run from the repository root)
Writes ontology/*.ttl, keeps opaque IRIs stable through src/ids.tsv, and writes build/terms.json
for the review workbook.
"""
import json, os, sys
from rdflib import Graph, Namespace, URIRef, Literal, BNode
from rdflib.namespace import RDF, RDFS, OWL, XSD, SKOS, DCTERMS
from rdflib.collection import Collection

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))
from spec_core import S, CLASSES, VALUE_SETS, INDIVIDUALS  # noqa: E402
from spec_props import OBJECT_PROPERTIES, DATA_PROPERTIES, ANNOTATION_PROPERTIES  # noqa: E402

VERSION = "0.3.0"
FIRST_RELEASE = {"0.1.0": 328, "0.2.0": 334}  # highest term number introduced in each earlier release
BASE = "https://w3id.org/crgo/"
CRGO = Namespace(BASE)
BFO = Namespace("http://purl.obolibrary.org/obo/")
CCO = Namespace("https://www.commoncoreontologies.org/")
VANN = Namespace("http://purl.org/vocab/vann/")
LICENSE = "https://creativecommons.org/licenses/by-nc/4.0/"
MODULES = {
    "gov": ("crgo-gov", "CyberRiskGuardian Ontology - governance module", "Ontologie CyberRiskGuardian - module de gouvernance", []),
    "core": ("crgo-core", "CyberRiskGuardian Ontology - core module", "Ontologie CyberRiskGuardian - module central", ["gov", "IMPORT:bfo", "IMPORT:cco"]),
    "measure": ("crgo-measure", "CyberRiskGuardian Ontology - measurement module", "Ontologie CyberRiskGuardian - module de mesure", ["core"]),
    "crg": ("crgo-crg", "CyberRiskGuardian Ontology - CyberRiskGuardian method module", "Ontologie CyberRiskGuardian - module de la méthode CyberRiskGuardian", ["measure"]),
}
IMPORTS = {"IMPORT:bfo": "http://purl.obolibrary.org/obo/bfo.owl", "IMPORT:cco": BASE + "imports/cco-slice"}

# ---------------------------------------------------------------- stable ids
ids_path = os.path.join(ROOT, "src", "ids.tsv")
ids = {}
if os.path.exists(ids_path):
    for line in open(ids_path, encoding="utf-8"):
        k, v = line.rstrip("\n").split("\t")
        ids[k] = int(v)

def iri(key):
    if ":" in key:  # external CURIE
        p, local = key.split(":", 1)
        return {"bfo": BFO, "cco": CCO, "skos": SKOS, "xsd": XSD}[p][local]
    if key not in ids:
        ids[key] = max(ids.values(), default=0) + 1
    return CRGO["CRGO_%07d" % ids[key]]

# register every key first, in spec order, so numbering is deterministic
all_keys = [c[0] for c in CLASSES]
for vs in VALUE_SETS:
    all_keys += [vs[0], vs[0] + "Scheme"] + [m[0] for m in vs[7]]
all_keys += [i[0] for i in INDIVIDUALS]
all_keys += [p[0] for p in OBJECT_PROPERTIES] + [p[0] for p in DATA_PROPERTIES] + [p[0] for p in ANNOTATION_PROPERTIES]
assert len(all_keys) == len(set(all_keys)), "duplicate keys: %s" % [k for k in all_keys if all_keys.count(k) > 1]
for k in all_keys:
    iri(k)
with open(ids_path, "w", encoding="utf-8") as f:
    for k, v in sorted(ids.items(), key=lambda kv: kv[1]):
        f.write("%s\t%d\n" % (k, v))

ann = {a[0]: iri(a[0]) for a in ANNOTATION_PROPERTIES}
CONF = {"H": iri("ConfHigh"), "M": iri("ConfMedium"), "L": iri("ConfLow")}
PROPOSED = iri("StatusProposed")
STATUS = {"Approve": iri("StatusApproved"), "Reject": iri("StatusRejected")}
CLAUDE = iri("AgentClaude")
AGENTS = {"MAL": iri("AgentMAL")}
KEY_OF = {iri(k): k for k in all_keys}
# Review decisions recorded by the project owner: key, decision, approver, date, comment.
APPROVALS = {}
_ap = os.path.join(os.path.dirname(os.path.abspath(__file__)), "approvals.tsv")
if os.path.exists(_ap):
    for line in open(_ap, encoding="utf-8"):
        if line.startswith("#") or not line.strip():
            continue
        k, decision, who, date, *note = line.rstrip("\n").split("\t")
        APPROVALS[k] = (decision, who, date, note[0] if note else "")

graphs = {m: Graph() for m in MODULES}
terms = []  # for the review workbook

def bind(g):
    for p, n in [("crgo", CRGO), ("obo", BFO), ("cco", CCO), ("skos", SKOS), ("owl", OWL), ("xsd", XSD), ("dcterms", DCTERMS), ("vann", VANN)]:
        g.bind(p, n)

def gov(g, s, sources, conf, rationale):
    a = APPROVALS.get(KEY_OF.get(s))
    if a and a[0] in STATUS:
        g.add((s, ann["governanceStatus"], STATUS[a[0]]))
        g.add((s, ann["approvedBy"], AGENTS[a[1]]))
        g.add((s, ann["approvalDate"], Literal(a[2], datatype=XSD.date)))
        if a[3]:
            g.add((s, ann["reviewNote"], Literal(a[3], lang="en")))
    else:
        g.add((s, ann["governanceStatus"], PROPOSED))
    g.add((s, ann["confidence"], CONF[conf]))
    if rationale:
        g.add((s, ann["confidenceRationale"], Literal(rationale, lang="en")))
    for k in sources:
        g.add((s, ann["evidenceSource"], Literal(S[k], lang="en")))
    g.add((s, ann["proposedBy"], CLAUDE))
    num = int(str(s).rsplit("_", 1)[1])
    g.add((s, ann["introducedIn"], Literal(next((v for v, mx in sorted(FIRST_RELEASE.items()) if num <= mx), VERSION))))

def labels(g, s, en, fr, den, dfr, alts=()):
    g.add((s, RDFS.label, Literal(en, lang="en")))
    g.add((s, RDFS.label, Literal(fr, lang="fr")))
    g.add((s, SKOS.definition, Literal(den, lang="en")))
    g.add((s, SKOS.definition, Literal(dfr, lang="fr")))
    for t, lang in alts:
        g.add((s, SKOS.altLabel, Literal(t, lang=lang)))

def record(kind, module, key, en, fr, den, dfr, parent, sources, conf, rationale, extra=""):
    terms.append(dict(kind=kind, module=module, key=key, iri=str(iri(key)), label_en=en, label_fr=fr, def_en=den, def_fr=dfr,
                      parent=parent, sources="; ".join(S[k] for k in sources), confidence=conf, rationale=rationale, extra=extra))

def label_of(key):
    if key is None:
        return ""
    for c in CLASSES:
        if c[0] == key:
            return c[3]
    for vs in VALUE_SETS:
        if vs[0] == key:
            return vs[2]
    return key

# ---------------------------------------------------------------- annotation properties (gov)
g = graphs["gov"]
for key, en, fr, den, dfr in ANNOTATION_PROPERTIES:
    s = iri(key)
    g.add((s, RDF.type, OWL.AnnotationProperty))
    labels(g, s, en, fr, den, dfr)
    gov(g, s, ["P1"], "H", "")
    record("annotation property", "gov", key, en, fr, den, dfr, "", ["P1"], "H", "")
g.add((ann["evidenceSource"], RDFS.subPropertyOf, DCTERMS.source))
g.add((ann["derivedFrom"], RDFS.subPropertyOf, DCTERMS.source))
for ext in [DCTERMS.source, SKOS.definition, SKOS.altLabel, SKOS.scopeNote, SKOS.notation, VANN.preferredNamespacePrefix, VANN.preferredNamespaceUri, DCTERMS.license, DCTERMS.title, DCTERMS.creator, DCTERMS.description, DCTERMS.created]:
    g.add((ext, RDF.type, OWL.AnnotationProperty))

# skos structural vocabulary declared locally (no SKOS import)
for m in ("gov",):
    g = graphs[m]
    g.add((SKOS.Concept, RDF.type, OWL.Class))
    g.add((SKOS.ConceptScheme, RDF.type, OWL.Class))
    g.add((SKOS.inScheme, RDF.type, OWL.ObjectProperty))

# ---------------------------------------------------------------- classes
for key, module, parents, en, fr, den, dfr, srcs, conf, rat, alts in CLASSES:
    g = graphs[module]; s = iri(key)
    g.add((s, RDF.type, OWL.Class))
    for p in parents:
        g.add((s, RDFS.subClassOf, iri(p)))
    labels(g, s, en, fr, den, dfr, alts)
    gov(g, s, srcs, conf, rat)
    record("class", module, key, en, fr, den, dfr, ", ".join(label_of(p) if ":" not in p else p for p in parents), srcs, conf, rat,
           "; ".join(a[0] for a in alts))

# ---------------------------------------------------------------- value sets
for key, module, en, fr, den, dfr, srcs, members in VALUE_SETS:
    g = graphs[module]; c = iri(key); sch = iri(key + "Scheme")
    g.add((c, RDF.type, OWL.Class)); g.add((c, RDFS.subClassOf, SKOS.Concept))
    labels(g, c, en, fr, den, dfr); gov(g, c, srcs, "H", "Value set; members listed below.")
    record("value set (class)", module, key, en, fr, den, dfr, "skos:Concept", srcs, "H", "Value set")
    g.add((sch, RDF.type, SKOS.ConceptScheme)); g.add((sch, RDF.type, OWL.NamedIndividual))
    labels(g, sch, en + " scheme", "schéma : " + fr, "Concept scheme of the " + en + " value set.", "Schéma de concepts de l'ensemble de valeurs « " + fr + " ».")
    gov(g, sch, srcs, "H", "")
    for i, (mk, men, mfr, mden, mdfr) in enumerate(members, 1):
        m = iri(mk)
        g.add((m, RDF.type, OWL.NamedIndividual)); g.add((m, RDF.type, c))
        g.add((m, SKOS.inScheme, sch))
        g.add((m, SKOS.notation, Literal(str(i))))
        labels(g, m, men, mfr, mden, mdfr)
        gov(g, m, srcs, "H", "")
        record("value", module, mk, men, mfr, mden, mdfr, en, srcs, "H", "")

# ---------------------------------------------------------------- other individuals
for key, module, types, en, fr, den, dfr, srcs in INDIVIDUALS:
    g = graphs[module]; s = iri(key)
    g.add((s, RDF.type, OWL.NamedIndividual))
    for t in types:
        g.add((s, RDF.type, iri(t)))
    labels(g, s, en, fr, den, dfr)
    gov(g, s, srcs, "H", "")
    record("individual", module, key, en, fr, den, dfr, ", ".join(label_of(t) for t in types), srcs, "H", "")

# ---------------------------------------------------------------- object properties
for key, module, en, fr, den, dfr, dom, rng, srcs, conf, rat, chars, sup in OBJECT_PROPERTIES:
    g = graphs[module]; s = iri(key)
    g.add((s, RDF.type, OWL.ObjectProperty))
    if dom: g.add((s, RDFS.domain, iri(dom)))
    if rng: g.add((s, RDFS.range, iri(rng)))
    if sup: g.add((s, RDFS.subPropertyOf, iri(sup)))
    note = ""
    if "transitive" in chars:
        g.add((s, RDF.type, OWL.TransitiveProperty))
    if "functional" in chars:  # kept out of OWL to stay within OWL 2 EL; enforced by SHACL in Phase 4
        note = "At most one value per subject; enforced by SHACL (Phase 4), not by an OWL functional axiom, to keep the module in OWL 2 EL."
        g.add((s, SKOS.scopeNote, Literal(note, lang="en")))
    labels(g, s, en, fr, den, dfr)
    gov(g, s, srcs, conf, rat)
    record("object property", module, key, en, fr, den, dfr, "domain: %s; range: %s" % (label_of(dom) or "—", label_of(rng) or "—"), srcs, conf, rat, note)

# ---------------------------------------------------------------- data properties
for key, module, en, fr, den, dfr, dom, rng, srcs, conf, rat, functional in DATA_PROPERTIES:
    g = graphs[module]; s = iri(key)
    g.add((s, RDF.type, OWL.DatatypeProperty))
    if functional: g.add((s, RDF.type, OWL.FunctionalProperty))
    if dom: g.add((s, RDFS.domain, iri(dom)))
    if rng: g.add((s, RDFS.range, iri(rng)))
    labels(g, s, en, fr, den, dfr)
    gov(g, s, srcs, conf, rat)
    record("data property", module, key, en, fr, den, dfr, "domain: %s; range: %s" % (label_of(dom) or "—", rng or "literal"), srcs, conf, rat,
           "functional" if functional else "")

# ---------------------------------------------------------------- ontology headers and output
os.makedirs(os.path.join(ROOT, "ontology"), exist_ok=True)
DESC = ("Formal OWL 2 DL ontology for identifying, analysing and treating cybersecurity risk with risk scenarios, "
        "aligned to BFO-2020 (ISO/IEC 21838-2) and Common Core Ontologies, and to the CyberRiskGuardian method. "
        "Each element carries its own governance status; new elements stay proposed until the domain expert approves them.")
for m, (name, ten, tfr, imps) in MODULES.items():
    g = graphs[m]; bind(g)
    o = URIRef(BASE + name)
    g.add((o, RDF.type, OWL.Ontology))
    g.add((o, OWL.versionIRI, URIRef("%s%s/%s" % (BASE, VERSION, name))))
    g.add((o, OWL.versionInfo, Literal(VERSION)))
    g.add((o, DCTERMS.title, Literal(ten, lang="en"))); g.add((o, DCTERMS.title, Literal(tfr, lang="fr")))
    g.add((o, DCTERMS.description, Literal(DESC, lang="en")))
    g.add((o, DCTERMS.creator, Literal("Marc-André Léger")))
    g.add((o, DCTERMS.license, URIRef(LICENSE)))
    g.add((o, DCTERMS.created, Literal("2026-10-08")))
    g.add((o, VANN.preferredNamespacePrefix, Literal("crgo")))
    g.add((o, VANN.preferredNamespaceUri, Literal(BASE)))
    for i in imps:
        g.add((o, OWL.imports, URIRef(IMPORTS[i] if i.startswith("IMPORT:") else BASE + MODULES[i][0])))

def write_commented(g, path, title):
    """Serialise with rdflib, then add a label comment above each crgo subject block."""
    txt = g.serialize(format="turtle")
    labels_en = {str(s): str(o) for s, o in g.subject_objects(RDFS.label) if getattr(o, "language", None) == "en"}
    out = ["# %s" % title, "# Generated by src/build.py from src/spec_*.py - edit the spec, not this file.", ""]
    for line in txt.splitlines():
        if line.startswith("crgo:CRGO_") and not line.startswith(" "):
            local = line.split()[0][len("crgo:"):]
            lab = labels_en.get(BASE + local)
            if lab:
                out.append("# --- " + lab)
        out.append(line)
    open(path, "w", encoding="utf-8").write("\n".join(out) + "\n")

for m, (name, ten, tfr, imps) in MODULES.items():
    write_commented(graphs[m], os.path.join(ROOT, "ontology", name + ".ttl"), ten)

# umbrella ontology
u = Graph(); bind(u)
o = URIRef(BASE + "crgo")
u.add((o, RDF.type, OWL.Ontology)); u.add((o, OWL.versionIRI, URIRef(BASE + VERSION + "/crgo")))
u.add((o, OWL.versionInfo, Literal(VERSION)))
u.add((o, DCTERMS.title, Literal("CyberRiskGuardian Ontology", lang="en"))); u.add((o, DCTERMS.title, Literal("Ontologie CyberRiskGuardian", lang="fr")))
u.add((o, DCTERMS.description, Literal(DESC, lang="en"))); u.add((o, DCTERMS.creator, Literal("Marc-André Léger")))
u.add((o, DCTERMS.license, URIRef(LICENSE)))
u.add((o, VANN.preferredNamespacePrefix, Literal("crgo"))); u.add((o, VANN.preferredNamespaceUri, Literal(BASE)))
for m in MODULES.values():
    u.add((o, OWL.imports, URIRef(BASE + m[0])))
write_commented(u, os.path.join(ROOT, "ontology", "crgo.ttl"), "CyberRiskGuardian Ontology - umbrella (imports all modules)")

os.makedirs(os.path.join(ROOT, "build"), exist_ok=True)
json.dump(terms, open(os.path.join(ROOT, "build", "terms.json"), "w", encoding="utf-8"), ensure_ascii=False, indent=1)
counts = {}
for t in terms:
    counts[t["kind"]] = counts.get(t["kind"], 0) + 1
print("terms:", len(terms), counts)
