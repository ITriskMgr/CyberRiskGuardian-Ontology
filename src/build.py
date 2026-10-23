# -*- coding: utf-8 -*-
"""Generate the CyberRiskGuardian Ontology modules from spec_core.py and spec_props.py.

Usage: python3 src/build.py   (run from the repository root)
Writes ontology/*.ttl, keeps opaque IRIs stable through src/ids.tsv, and writes build/terms.json
for the review workbook.
"""
import json, os, sys
from rdflib import Graph, Namespace, URIRef, Literal, BNode
from rdflib.namespace import RDF, RDFS, OWL, XSD, SKOS, DCTERMS, FOAF
from rdflib.collection import Collection

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))
from spec_core import S, CLASSES, VALUE_SETS, INDIVIDUALS, CHANGES_0101, EDITORIAL_0101  # noqa: E402
from spec_props import OBJECT_PROPERTIES, DATA_PROPERTIES, ANNOTATION_PROPERTIES  # noqa: E402
import spec_v09 as V9  # noqa: E402  (0.9.0 modules: evidence, org, vuln, grc, mapping)
import spec_grca as VG  # noqa: E402  (0.9.0 GRCA and R4-R8: governance, assurance, audit, incident; additions to evidence, grc, mapping)
import spec_pca as VP  # noqa: E402  (0.10.0: policy, compliance and audit management; decisions D1-D14)
import spec_secops as VS  # noqa: E402  (0.10.0: SIEM and SOAR; decisions S1-S12)
S.update(V9.SOURCES_09); S.update(VG.SOURCES_GRCA); S.update(VP.SOURCES_PCA); S.update(VS.SOURCES_SECOPS)
CLASSES = CLASSES + V9.CLASSES_09 + VG.CLASSES_GRCA + VP.CLASSES_PCA + VS.CLASSES_SECOPS
VALUE_SETS = VALUE_SETS + V9.VALUE_SETS_09 + VG.VALUE_SETS_GRCA + VP.VALUE_SETS_PCA + VS.VALUE_SETS_SECOPS
INDIVIDUALS = INDIVIDUALS + V9.INDIVIDUALS_09 + VG.INDIVIDUALS_GRCA + VP.INDIVIDUALS_PCA + VS.INDIVIDUALS_SECOPS
OBJECT_PROPERTIES = OBJECT_PROPERTIES + V9.OBJECT_PROPERTIES_09 + VG.OBJECT_PROPERTIES_GRCA + VP.OBJECT_PROPERTIES_PCA + VS.OBJECT_PROPERTIES_SECOPS
DATA_PROPERTIES = DATA_PROPERTIES + V9.DATA_PROPERTIES_09 + VG.DATA_PROPERTIES_GRCA + VP.DATA_PROPERTIES_PCA + VS.DATA_PROPERTIES_SECOPS
EXTENSIONS = VP.EXTENSIONS_PCA + VS.EXTENSIONS_SECOPS  # members added to earlier value sets
# Decision D9 (0.10.0): widenings of approved terms; fields replaced by key, with a change note on the term.
CHANGE_NOTES = {}
def _modify(rows, layout):
    out = []
    for r in rows:
        m = VP.MODIFY_PCA.get(r[0])
        if m:
            r = list(r)
            for f, v in m.items():
                if f in layout: r[layout[f]] = v
            CHANGE_NOTES[r[0]] = m["note"]; r = tuple(r)
        out.append(r)
    return out
CLASSES = _modify(CLASSES, {"den": 5, "dfr": 6, "alts": 10})
OBJECT_PROPERTIES = _modify(OBJECT_PROPERTIES, {"den": 4, "dfr": 5, "dom": 6, "rng": 7})
DATA_PROPERTIES = _modify(DATA_PROPERTIES, {"den": 4, "dfr": 5, "dom": 6, "rng": 7})
assert set(CHANGE_NOTES) == set(VP.MODIFY_PCA), set(VP.MODIFY_PCA) - set(CHANGE_NOTES)
# 0.10.1: changes to approved terms made in spec_core.py (CRG terminology of the textbook v2.51), approved as changes/0.10.1
assert not set(CHANGES_0101) & set(CHANGE_NOTES)
CHANGE_NOTES.update(CHANGES_0101)

VERSION = "0.10.1"
PRIOR = "0.10.0"
ISSUED = "2026-10-23"
FIRST_RELEASE = {"0.1.0": 328, "0.2.0": 334, "0.3.0": 335, "0.4.0": 335, "0.5.0": 335, "0.6.0": 335, "0.7.0": 336, "0.8.0": 336, "0.9.0": 884, "0.10.0": 1325}  # highest term number introduced in each earlier release
BASE = "https://w3id.org/crgo/"
CRGO = Namespace(BASE)
BFO = Namespace("http://purl.obolibrary.org/obo/")
CCO = Namespace("https://www.commoncoreontologies.org/")
VANN = Namespace("http://purl.org/vocab/vann/")
PROV = Namespace("http://www.w3.org/ns/prov#")
TIME = Namespace("http://www.w3.org/2006/time#")
LICENSE = "https://creativecommons.org/licenses/by-nc/4.0/"
MODULES = {
    "gov": ("crgo-gov", "CyberRiskGuardian Ontology - governance module", "Ontologie CyberRiskGuardian - module de gouvernance", []),
    "core": ("crgo-core", "CyberRiskGuardian Ontology - core module", "Ontologie CyberRiskGuardian - module central", ["gov", "IMPORT:bfo", "IMPORT:cco"]),
    "measure": ("crgo-measure", "CyberRiskGuardian Ontology - measurement module", "Ontologie CyberRiskGuardian - module de mesure", ["core"]),
    "crg": ("crgo-crg", "CyberRiskGuardian Ontology - CyberRiskGuardian method module", "Ontologie CyberRiskGuardian - module de la méthode CyberRiskGuardian", ["measure"]),
    # 0.9.0 (decision D2: new content in new modules, the four modules above unchanged)
    "evidence": ("crgo-evidence", "CyberRiskGuardian Ontology - sources, observations and assumptions module", "Ontologie CyberRiskGuardian - module des sources, observations et hypothèses", ["measure", "IMPORT:prov", "IMPORT:time"]),
    "org": ("crgo-org", "CyberRiskGuardian Ontology - organisation profile module", "Ontologie CyberRiskGuardian - module du profil d'organisation", ["core"]),
    "vuln": ("crgo-vuln", "CyberRiskGuardian Ontology - vulnerability observations module", "Ontologie CyberRiskGuardian - module des observations de vulnérabilités", ["evidence"]),
    "grc": ("crgo-grc", "CyberRiskGuardian Ontology - legal applicability and compliance module", "Ontologie CyberRiskGuardian - module d'applicabilité juridique et de conformité", ["evidence", "org"]),
    "mapping": ("crgo-mapping", "CyberRiskGuardian Ontology - typed correspondence relations module", "Ontologie CyberRiskGuardian - module des relations de correspondance typées", ["core"]),  # 0.10.0: was ["gov"]; mapping assertions are CCO information content entities
    # 0.9.0 GRCA sprint (decision G2) and remaining-gaps package R8
    "governance": ("crgo-governance", "CyberRiskGuardian Ontology - corporate governance, policy and decision records module", "Ontologie CyberRiskGuardian - module de gouvernance d'entreprise, des politiques et des décisions", ["grc"]),
    "assurance": ("crgo-assurance", "CyberRiskGuardian Ontology - assurance, evidence and control effectiveness module", "Ontologie CyberRiskGuardian - module d'assurance, de preuves et d'efficacité des mesures", ["governance"]),
    "audit": ("crgo-audit", "CyberRiskGuardian Ontology - audit lifecycle and remediation module", "Ontologie CyberRiskGuardian - module du cycle d'audit et de la remédiation", ["assurance", "compliance"]),
    "incident": ("crgo-incident", "CyberRiskGuardian Ontology - security events and incidents module", "Ontologie CyberRiskGuardian - module des événements et incidents de sécurité", ["evidence"]),
    # 0.10.0 (decision D1)
    "policy": ("crgo-policy", "CyberRiskGuardian Ontology - policy management module", "Ontologie CyberRiskGuardian - module de gestion des politiques", ["governance", "mapping"]),
    "compliance": ("crgo-compliance", "CyberRiskGuardian Ontology - compliance management module", "Ontologie CyberRiskGuardian - module de gestion de la conformité", ["grc", "policy"]),
    "siem": ("crgo-siem", "CyberRiskGuardian Ontology - security monitoring and detection (SIEM) module", "Ontologie CyberRiskGuardian - module de surveillance et de détection de sécurité (SIEM)", ["incident", "grc"]),
    "soar": ("crgo-soar", "CyberRiskGuardian Ontology - security orchestration, automation and response (SOAR) module", "Ontologie CyberRiskGuardian - module d'orchestration, d'automatisation et de réponse de sécurité (SOAR)", ["siem", "audit"]),
}
IMPORTS = {"IMPORT:bfo": "http://purl.obolibrary.org/obo/bfo.owl", "IMPORT:cco": BASE + "imports/cco-slice",
           "IMPORT:prov": BASE + "imports/prov-slice", "IMPORT:time": BASE + "imports/time-slice"}

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
        return {"bfo": BFO, "cco": CCO, "skos": SKOS, "xsd": XSD, "prov": PROV, "time": TIME}[p][local]
    if key not in ids:
        ids[key] = max(ids.values(), default=0) + 1
    return CRGO["CRGO_%07d" % ids[key]]

# register every key first, in spec order, so numbering is deterministic
all_keys = [c[0] for c in CLASSES]
for vs in VALUE_SETS:
    all_keys += [vs[0], vs[0] + "Scheme"] + [m[0] for m in vs[7]]
for ext in EXTENSIONS:
    all_keys += [m[0] for m in ext[3]]
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
GROUP_ROWS = {}  # 0.10.0: every row of a group key, so that a later, scoped approval extends an earlier one
_ap = os.path.join(os.path.dirname(os.path.abspath(__file__)), "approvals.tsv")
if os.path.exists(_ap):
    for line in open(_ap, encoding="utf-8"):
        if line.startswith("#") or not line.strip():
            continue
        k, decision, who, date, *note = line.rstrip("\n").split("\t")
        APPROVALS[k] = (decision, who, date, note[0] if note else "")
        GROUP_ROWS.setdefault(k, []).append(APPROVALS[k])

graphs = {m: Graph() for m in MODULES}
terms = []  # for the review workbook

def bind(g):
    for p, n in [("crgo", CRGO), ("obo", BFO), ("cco", CCO), ("skos", SKOS), ("owl", OWL), ("xsd", XSD), ("dcterms", DCTERMS), ("vann", VANN), ("prov", PROV), ("time", TIME)]:
        g.bind(p, n)

# A group approval terms/<module> may be scoped in its note ("scope: up to CRGO_nnnnnnn"): it then covers only the terms
# that existed when it was given, so that terms added to the module later stay proposed until approved in their turn.
import re as _re
def scope_of(note):
    m = _re.search(r"scope: up to CRGO_(\d+)", note or "")
    return int(m.group(1)) if m else None

def gov(g, s, sources, conf, rationale):
    # a term is approved by its own key, or (0.9.0) by its module's group key terms/<module>, within GROUP_SCOPE
    num = int(str(s).rsplit("_", 1)[1])
    a = APPROVALS.get(KEY_OF.get(s))
    changed = KEY_OF.get(s) in CHANGE_NOTES and KEY_OF.get(s) not in VP.D9_APPROVED  # changed in 0.10.0, not covered by D9
    if changed:
        a = APPROVALS.get("changes/0.10.1" if KEY_OF.get(s) in CHANGES_0101 else "changes/0.10.0")
    if not a and not changed:
        # the first row of terms/<module> whose scope covers this term (rows without a scope cover every term)
        rows = GROUP_ROWS.get("terms/" + next((m for m, gg in graphs.items() if gg is g), ""), [])
        a = next((r for r in rows if scope_of(r[3]) is None or num <= scope_of(r[3])), None)
    if a and a[0] in STATUS:
        g.add((s, ann["governanceStatus"], STATUS[a[0]]))
        g.add((s, ann["approvedBy"], AGENTS[a[1]]))
        g.add((s, ann["approvalDate"], Literal(a[2], datatype=XSD.date)))
        note = _re.sub(r"\s*scope: up to CRGO_\d+[^;]*;?", "", a[3]).strip() if a[3] else ""
        if note:
            g.add((s, ann["reviewNote"], Literal(note, lang="en")))
    else:
        g.add((s, ann["governanceStatus"], PROPOSED))
    g.add((s, ann["confidence"], CONF[conf]))
    if rationale:
        g.add((s, ann["confidenceRationale"], Literal(rationale, lang="en")))
    for k in sources:
        g.add((s, ann["evidenceSource"], Literal(S[k], lang="en")))
    g.add((s, ann["proposedBy"], CLAUDE))
    g.add((s, ann["introducedIn"], Literal(next((v for v, mx in sorted(FIRST_RELEASE.items(), key=lambda kv: tuple(map(int, kv[0].split(".")))) if num <= mx), VERSION))))  # numeric order (0.10.1: "0.10.0" sorts before "0.2.0" as text)

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

# ---------------------------------------------------------------- members added to earlier value sets (0.10.0)
for vskey, module, srcs, members in EXTENSIONS:
    g = graphs[module]; c = iri(vskey); sch = iri(vskey + "Scheme")
    base_n = len(next(v for v in VALUE_SETS if v[0] == vskey)[7])
    en_vs = next(v for v in VALUE_SETS if v[0] == vskey)[2]
    for i, (mk, men, mfr, mden, mdfr) in enumerate(members, base_n + 1):
        m = iri(mk)
        g.add((m, RDF.type, OWL.NamedIndividual)); g.add((m, RDF.type, c))
        g.add((m, SKOS.inScheme, sch))
        g.add((m, SKOS.notation, Literal(str(i))))
        labels(g, m, men, mfr, mden, mdfr)
        gov(g, m, srcs, "H", "")
        record("value", module, mk, men, mfr, mden, mdfr, en_vs, srcs, "H", "added in 0.10.0")

# ---------------------------------------------------------------- disjointness (approved 2026-10-10, Phase 4 review)
# Value sets are pairwise disjoint (a confidence level is never a threat source type); each module states it for the
# value sets it can see, so the axiom holds whichever module is loaded.
from rdflib import BNode as _B
from rdflib.collection import Collection as _Col
def _closure(m):  # the module and every crgo module it imports, directly or not (0.10.0: computed, was a hand list)
    out = {m}
    for i in MODULES[m][3]:
        if not i.startswith("IMPORT:"): out |= _closure(i)
    return out
SEES = {m: sorted(_closure(m), key=list(MODULES).index) for m in MODULES}
for m, seen in SEES.items():
    vs = [iri(v[0]) for v in VALUE_SETS if v[1] in seen]
    if len(vs) > 1:
        ax, lst = _B(), _B()
        graphs[m].add((ax, RDF.type, OWL.AllDisjointClasses)); graphs[m].add((ax, OWL.members, lst))
        _Col(graphs[m], lst, vs)
graphs["core"].add((iri("LibraryScenario"), OWL.disjointWith, iri("AssessmentScenario")))
MODULE_OF = {c[0]: c[1] for c in CLASSES}
ORDER = list(MODULES)
for a, b in V9.DISJOINT_09 + VG.DISJOINT_GRCA + VP.DISJOINT_PCA + VS.DISJOINT_SECOPS:  # stated in the module that sees both
    ma, mb = MODULE_OF[a], MODULE_OF[b]
    home = ma if mb in SEES[ma] else mb if ma in SEES[mb] else next((m for m in MODULES if ma in SEES[m] and mb in SEES[m]), None)
    assert home, "no module sees both %s and %s" % (a, b)
    graphs[home].add((iri(a), OWL.disjointWith, iri(b)))
# SKOS mapping relations are the super-properties of the typed correspondences (no SKOS import)
for p in (SKOS.relatedMatch, SKOS.closeMatch, SKOS.broadMatch, SKOS.narrowMatch):
    graphs["mapping"].add((p, RDF.type, OWL.ObjectProperty))

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

# ---------------------------------------------------------------- change notes (decision D9, 0.10.0)
graphs["gov"].add((SKOS.changeNote, RDF.type, OWL.AnnotationProperty))
for k, note in CHANGE_NOTES.items():
    s = iri(k)
    home = next(gg for gg in graphs.values() if (s, RDFS.label, None) in gg)
    home.add((s, SKOS.changeNote, Literal(note, lang="en")))
graphs["gov"].add((SKOS.editorialNote, RDF.type, OWL.AnnotationProperty))
for k, note in EDITORIAL_0101.items():  # 0.10.1: e.g. a retired alternative label (the spec format has no hidden labels)
    s = iri(k)
    home = next(gg for gg in graphs.values() if (s, RDFS.label, None) in gg)
    home.add((s, SKOS.editorialNote, Literal(note, lang="en")))

# ---------------------------------------------------------------- ontology headers and output
os.makedirs(os.path.join(ROOT, "ontology"), exist_ok=True)
DESC_FR = ("Ontologie formelle OWL 2 DL pour identifier, analyser et traiter le risque de cybersécurité à l'aide de scénarios de risque, "
           "alignée sur BFO-2020 (ISO/IEC 21838-2), les Common Core Ontologies et la méthode CyberRiskGuardian. "
           "Chaque élément porte son propre statut de gouvernance; les nouveaux éléments restent proposés jusqu'à leur approbation par l'expert du domaine.")
ABSTRACT = ("The CyberRiskGuardian Ontology (CRGO) gives a formal, reasoner-checked meaning to cybersecurity risk assessment data: "
            "assets, threat sources and events, vulnerabilities, risk scenarios, controls, frameworks and legal obligations, the "
            "CyberRiskGuardian quantitative model with the risk indices computed from it, and key risk indicators for monitoring. It is published with SKOS "
            "vocabularies for NIST CSF 2.0, NIST SP 800-53, ISO/IEC 27002:2022, COBIT 2019, MITRE ATT&CK, Québec Law 25 and the "
            "Québec health-information act, and with a library of about 1,900 generic risk scenarios linked to them.")
ABSTRACT_FR = ("L'ontologie CyberRiskGuardian (CRGO) donne un sens formel, vérifié par raisonneur, aux données d'appréciation du risque "
               "de cybersécurité : actifs, sources et événements de menace, vulnérabilités, scénarios de risque, mesures de sécurité, "
               "référentiels et obligations légales, modèle quantitatif CyberRiskGuardian avec les indices de risque qui en découlent, et indicateurs clés de risque pour la surveillance. "
               "Elle est publiée avec des vocabulaires SKOS pour le NIST CSF 2.0, le NIST SP 800-53, l'ISO/IEC 27002:2022, COBIT 2019, "
               "MITRE ATT&CK, la Loi 25 et la loi québécoise sur les renseignements de santé, et avec une bibliothèque d'environ "
               "1 900 scénarios de risque génériques liés à ces vocabulaires.")
SCHEMA = Namespace("https://schema.org/"); BIBO = Namespace("http://purl.org/ontology/bibo/")
REPO = "https://github.com/ITriskMgr/cyberriskguardian-ontology"

def header(g, o, name):
    """FAIR ontology metadata (WIDOCO and FOOPS! read these)."""
    g.bind("schema", SCHEMA); g.bind("bibo", BIBO)
    g.add((o, DCTERMS.description, Literal(DESC_FR, lang="fr")))
    g.add((o, DCTERMS.abstract, Literal(ABSTRACT, lang="en"))); g.add((o, DCTERMS.abstract, Literal(ABSTRACT_FR, lang="fr")))
    g.add((o, DCTERMS.contributor, Literal("Claude (Anthropic), AI drafting assistant; every element approved by the creator")))
    g.add((o, DCTERMS.publisher, Literal("ITriskMgr")))
    g.add((o, DCTERMS.modified, Literal(ISSUED, datatype=XSD.date)))
    g.add((o, DCTERMS.issued, Literal(ISSUED, datatype=XSD.date)))
    g.add((o, OWL.priorVersion, URIRef("%s%s/%s" % (BASE, PRIOR, name))))
    g.add((o, BIBO.status, Literal("draft" if "-" in VERSION else "released")))
    g.add((o, DCTERMS.bibliographicCitation, Literal("Léger, Marc-André (2026). CyberRiskGuardian Ontology (CRGO), version %s. %s" % (VERSION, REPO))))
    g.add((o, SCHEMA.codeRepository, URIRef(REPO)))
    g.add((o, FOAF.homepage, URIRef(BASE + "crgo")))
    g.add((o, DCTERMS.source, URIRef("https://github.com/ITriskMgr/CyberRiskGuardian")))

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
    g.add((o, DCTERMS.created, Literal("2026-10-08", datatype=XSD.date)))
    header(g, o, name)
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
u.add((o, DCTERMS.created, Literal("2026-10-08", datatype=XSD.date))); header(u, o, "crgo")
for m in MODULES.values():
    u.add((o, OWL.imports, URIRef(BASE + m[0])))
write_commented(u, os.path.join(ROOT, "ontology", "crgo.ttl"), "CyberRiskGuardian Ontology - umbrella (imports all modules)")

os.makedirs(os.path.join(ROOT, "build"), exist_ok=True)
json.dump(terms, open(os.path.join(ROOT, "build", "terms.json"), "w", encoding="utf-8"), ensure_ascii=False, indent=1)
counts = {}
for t in terms:
    counts[t["kind"]] = counts.get(t["kind"], 0) + 1
print("terms:", len(terms), counts)
