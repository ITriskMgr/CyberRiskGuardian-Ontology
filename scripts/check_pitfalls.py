# -*- coding: utf-8 -*-
"""Local scan for OOPS! pitfalls (catalogue: https://oops.linkeddata.es/catalogue.jsp); the OOPS! web service is
not reachable from the build environment. Critical pitfalls fail the check; the others are reported for review.
Input: build/crgo-full-merged.ttl. Output: build/pitfalls.md."""
import os, re, sys
from collections import Counter, defaultdict
import rdflib
from rdflib.namespace import RDF, RDFS, OWL, DCTERMS, SKOS

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
g = rdflib.Graph(); g.parse(os.path.join(ROOT, "build", "crgo-full-merged.ttl"))
CRGO = "https://w3id.org/crgo/CRGO_"
mine = lambda x: str(x).startswith(CRGO)
lab = lambda x: next((str(l) for l in g.objects(x, RDFS.label) if getattr(l, "language", None) == "en"), str(x))
classes = set(g.subjects(RDF.type, OWL.Class))
oprops = set(g.subjects(RDF.type, OWL.ObjectProperty)); dprops = set(g.subjects(RDF.type, OWL.DatatypeProperty))
aprops = set(g.subjects(RDF.type, OWL.AnnotationProperty))
declared_props = oprops | dprops | aprops | set(g.subjects(RDF.type, RDF.Property))
res, critical = [], 0

def report(code, name, items, crit=False, note=""):
    global critical
    status = "ok" if not items else ("CRITICAL" if crit else "review")
    if items and crit:
        critical += 1
    res.append((code, name, status, len(items), items[:15], note))

# P04 unconnected elements: own classes with no superclass and no use as domain/range/type
used = set(g.objects(None, RDFS.domain)) | set(g.objects(None, RDFS.range)) | set(g.objects(None, RDF.type))
report("P04", "Unconnected ontology elements", [lab(c) for c in classes if mine(c) and not list(g.objects(c, RDFS.subClassOf)) and c not in used])
# P07 merging different concepts in one class ("and"/"or" in class labels)
report("P07", "Merging different concepts in the same class", [lab(c) for c in classes if mine(c) and re.search(r"\b(and|or)\b", lab(c))],
       note="Review: a class named 'X and Y' may hide two concepts.")
# P08 missing annotations: own terms without label or definition (also enforced by check_metadata.py)
report("P08", "Missing annotations", [lab(t) for t in classes | declared_props if mine(t) and (not list(g.objects(t, RDFS.label)) or not list(g.objects(t, SKOS.definition)))], crit=True)
# P10 missing disjointness among own sibling classes (informational)
sib = defaultdict(list)
for c in classes:
    if mine(c):
        for p in g.objects(c, RDFS.subClassOf):
            if isinstance(p, rdflib.URIRef): sib[p].append(c)
disj = {frozenset((a, b)) for a, b in g.subject_objects(OWL.disjointWith)}
for ax in g.subjects(RDF.type, OWL.AllDisjointClasses):
    members = list(rdflib.collection.Collection(g, g.value(ax, OWL.members)))
    disj |= {frozenset((a, b)) for a in members for b in members if a != b}
nodisj = [lab(p) for p, cs in sib.items() if len(cs) > 1 and not any(frozenset((a, b)) in disj for a in cs for b in cs if a != b)]
report("P10", "Missing disjointness between sibling classes", nodisj,
       note="Most CRGO siblings inherit disjointness from BFO/CCO categories; same-category siblings (for example the CRG parameters) are left open on purpose.")
# P11 missing domain or range
report("P11", "Missing domain or range in properties", [lab(p) for p in oprops | dprops if mine(p) and (not list(g.objects(p, RDFS.domain)) or not list(g.objects(p, RDFS.range)))],
       note="Open on purpose where the specification says so (for example weaknessOf, mapsToRequirement, hasOwner); SHACL constrains the values instead.")
# P13 inverse relationships not declared
report("P13", "Inverse relationships not explicitly declared", [], note="By design: CRGO declares no inverse properties to stay within OWL 2 EL where possible.")
# P19 multiple domains or ranges (intersection semantics)
report("P19", "Multiple domains or ranges in properties", [lab(p) for p in oprops | dprops if mine(p) and (len(list(g.objects(p, RDFS.domain))) > 1 or len(list(g.objects(p, RDFS.range))) > 1)], crit=True)
# P21 miscellaneous class
report("P21", "Using a miscellaneous class", [lab(c) for c in classes if mine(c) and re.search(r"(?i)\b(other|misc|miscellaneous|various)\b", lab(c))])
# P22 inconsistent naming: English labels should be lower case (except proper names and acronyms)
report("P22", "Using different naming conventions", [lab(t) for t in classes | oprops | dprops if mine(t) and lab(t)[:1].isupper() and not re.match(r"^[A-Z]{2,}|^CRG|^CVSS|^IT\b", lab(t))])
# P24 recursive definitions
report("P24", "Using recursive definitions", [lab(c) for c in classes if (c, RDFS.subClassOf, c) in g or (c, OWL.equivalentClass, c) in g], crit=True)
# P25/P26/P28 symmetric/inverse misuse
report("P28", "Defining wrong symmetric relationships", [lab(p) for p in g.subjects(RDF.type, OWL.SymmetricProperty) if mine(p) and g.value(p, RDFS.domain) != g.value(p, RDFS.range)], crit=True)
# P29 wrongly defined transitive relationships: domain and range must match
report("P29", "Defining wrong transitive relationships", [lab(p) for p in g.subjects(RDF.type, OWL.TransitiveProperty) if mine(p) and g.value(p, RDFS.domain) != g.value(p, RDFS.range)], crit=True)
# P32 several classes with the same label
cnt = Counter(lab(c).lower() for c in classes if mine(c))
report("P32", "Several classes with the same label", [k for k, v in cnt.items() if v > 1], crit=True)
# P34 untyped class / P35 untyped property (in the whole merged graph, own namespace)
cls_used = {o for o in g.objects(None, RDF.type) if mine(o)} | {o for o in g.objects(None, RDFS.subClassOf) if mine(o)}
report("P34", "Untyped class", [str(c) for c in cls_used if c not in classes], crit=True)
props_used = {p for p in g.predicates() if mine(p)}
report("P35", "Untyped property", [str(p) for p in props_used if p not in declared_props], crit=True)
# P36 URI contains file extension
onts = set(g.subjects(RDF.type, OWL.Ontology))
report("P36", "URI contains file extension", [str(t) for t in classes | declared_props | onts if mine(t) and re.search(r"\.(owl|ttl|rdf|xml)$", str(t))], crit=True)
# P38 no OWL ontology declaration / P41 no licence declared (CRGO ontologies and vocabularies)
own_onts = [o for o in onts if str(o).startswith("https://w3id.org/crgo/")]
report("P41", "No license declared", [str(o) for o in own_onts if not list(g.objects(o, DCTERMS.license)) and not list(g.objects(o, DCTERMS.rights))], crit=True)
# P40 namespace hijacking: CCO and OBO terms used must be declared in the imports
ext = {t for t in set(g.subjects()) | set(g.objects()) if isinstance(t, rdflib.URIRef) and re.match(r"https://www.commoncoreontologies.org/ont\d+|http://purl.obolibrary.org/obo/BFO_\d+", str(t))}
report("P40", "Namespace hijacking", [str(t) for t in ext if not (t, RDF.type, None) in g], crit=True)

out = ["# Ontology pitfall scan (OOPS! catalogue, local implementation)", "",
       "The OOPS! web service is not reachable from the build environment, so the pitfalls that can be checked mechanically were implemented locally. Pitfalls that need human judgement (P02 synonyms as classes, P03 'is' relationships, P05 wrong inverses, P06 cycles in hierarchies beyond self-loops, P09 missing domain information, P12, P30, P31) are not covered.", "",
       "| Pitfall | Name | Result | Count | Note |", "|---|---|---|---|---|"]
for code, name, status, n, items, note in res:
    out.append("| %s | %s | %s | %d | %s |" % (code, name, status, n, note))
out.append("")
for code, name, status, n, items, note in res:
    if items:
        out += ["## %s %s (%d)" % (code, name, n), ""] + ["- " + i for i in items] + ([("- … %d more" % (n - 15))] if n > 15 else []) + [""]
open(os.path.join(ROOT, "build", "pitfalls.md"), "w", encoding="utf-8").write("\n".join(out) + "\n")
for code, name, status, n, items, note in res:
    print("   %-4s %-48s %-8s %d" % (code, name, status, n))
sys.exit(1 if critical else 0)
