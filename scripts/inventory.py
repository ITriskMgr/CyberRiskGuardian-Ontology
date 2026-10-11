"""Stage 0 baseline inventory: counts every ontology module, vocabulary, mapping group, library dataset, shape and test
from the repository files, and writes docs/baseline/metrics.json. Run from the repository root."""
import glob, json, os, re, subprocess, collections
from rdflib import Graph, RDF, RDFS, OWL, URIRef, Literal, Namespace
SKOS = Namespace("http://www.w3.org/2004/02/skos/core#"); SH = Namespace("http://www.w3.org/ns/shacl#")
T = Namespace("https://w3id.org/crgo/")
out = {"commit": subprocess.run(["git", "rev-parse", "--short", "HEAD"], capture_output=True, text=True).stdout.strip(),
       "branch": subprocess.run(["git", "branch", "--show-current"], capture_output=True, text=True).stdout.strip()}

mods = {}
for f in sorted(glob.glob("ontology/crgo-*.ttl")):
    g = Graph().parse(f); o = next(g.subjects(RDF.type, OWL.Ontology))
    mods[os.path.basename(f)] = {"triples": len(g),
        "classes": len({c for c in g.subjects(RDF.type, OWL.Class) if isinstance(c, URIRef) and str(c).startswith(str(T))}),
        "object_properties": len(set(g.subjects(RDF.type, OWL.ObjectProperty))),
        "data_properties": len(set(g.subjects(RDF.type, OWL.DatatypeProperty))),
        "annotation_properties": len({p for p in g.subjects(RDF.type, OWL.AnnotationProperty) if str(p).startswith(str(T))}),
        "named_individuals": len(set(g.subjects(RDF.type, OWL.NamedIndividual))),
        "version": str(next(g.objects(o, OWL.versionInfo), "")), "imports": sorted(str(i) for i in g.objects(o, OWL.imports))}
out["modules"] = mods
ids = [l.split("\t") for l in open("src/ids.tsv", encoding="utf-8") if l.strip() and not l.startswith("#")]
out["term_ids_minted"] = len(ids)

vocab = {}
for f in sorted(glob.glob("ontology/vocab/*.ttl")):
    k = os.path.basename(f)[:-4]
    if k == "mappings": continue
    g = Graph().parse(f); s = next(g.subjects(RDF.type, SKOS.ConceptScheme))
    cs = set(g.subjects(SKOS.inScheme, s))
    dep = {c for c in cs if (c, OWL.deprecated, Literal(True)) in g}
    top = set(g.objects(s, SKOS.hasTopConcept))
    status = collections.Counter(str(o).rsplit("/", 1)[-1] for c in cs for o in g.objects(c, T.CRGO_0000003)) if False else None
    vocab[k] = {"concepts": len(cs), "deprecated": len(dep), "top_concepts": len(top),
                "with_fr_label": sum(1 for c in cs if any(getattr(l, "language", None) == "fr" for l in g.objects(c, SKOS.prefLabel))),
                "version": str(next(g.objects(s, OWL.versionInfo), ""))}
out["vocabularies"] = vocab

g = Graph().parse("ontology/vocab/mappings.ttl")
grp = collections.Counter(); preds = collections.Counter()
for ax in g.subjects(RDF.type, OWL.Axiom):
    p = g.value(ax, OWL.annotatedProperty); preds[str(p).rsplit("#", 1)[-1]] += 1
groups = collections.Counter()
# group is recorded in the comment or local annotation; count by predicate and confidence
conf = collections.Counter(str(g.value(ax, T.CRGO_0000004) or g.value(ax, URIRef(str(T) + "CRGO_0000004"))) for ax in g.subjects(RDF.type, OWL.Axiom))
pairs = {(g.value(ax, OWL.annotatedSource), g.value(ax, OWL.annotatedProperty), g.value(ax, OWL.annotatedTarget)) for ax in g.subjects(RDF.type, OWL.Axiom)}
out["mappings"] = {"annotation_records": sum(preds.values()), "distinct_correspondences": len(pairs), "by_predicate": dict(preds)}

lib = Graph().parse("data/abox/crgo-library.ttl")
types = collections.Counter(str(o).rsplit("/", 1)[-1] for o in lib.objects(None, RDF.type))
out["library"] = {"triples": len(lib), "types_top": dict(types.most_common(25))}

sh = Graph().parse("shapes/crgo-shapes.ttl")
out["shacl"] = {"node_shapes": len(set(sh.subjects(RDF.type, SH.NodeShape))), "property_constraints": len(set(sh.objects(None, SH.property)))}
out["tests"] = {"competency_questions": len(glob.glob("tests/cq/CQ*.rq")), "owl_fixtures": len(glob.glob("tests/fixtures/*.ttl")),
                "negative_fixtures": len(glob.glob("tests/fixtures/neg-*.ttl")), "shacl_fixtures": len(glob.glob("tests/shacl/*.ttl")),
                "identification_checks": len(re.findall(r"^\s*check\(", open("tests/identify/test_identify.py").read(), re.M))}
ap = [l.rstrip("\n").split("\t") for l in open("src/approvals.tsv", encoding="utf-8") if l.strip() and not l.startswith("#")]
out["approvals"] = {"rows": len(ap), "decisions": dict(collections.Counter(r[1] for r in ap if len(r) > 1))}
out["scripts"] = sorted(glob.glob("pipeline/**/*.py", recursive=True) + glob.glob("scripts/*") + glob.glob("src/*.py"))
json.dump(out, open("docs/baseline/metrics.json", "w"), indent=1, ensure_ascii=False)
print(json.dumps({k: v for k, v in out.items() if k != "scripts"}, indent=1, ensure_ascii=False))
