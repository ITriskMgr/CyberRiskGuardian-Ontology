# -*- coding: utf-8 -*-
"""Build PRIVATE companions of the licensed-standard vocabularies with the text of the documents the project owner
holds (decision R-d, 2026-10-11). Never committed: data/raw/ and ontology/vocab-private/ are in .gitignore.

For each concept of iia-gias, iia-tr, itaf and tsc, the private file adds a skos:scopeNote@en holding the text of the
source pages on which the item appears (from the page where its heading is found up to, but not including, the page of
the next item; at most three pages). The extract is page-based, so it can include neighbouring text; it is a reading aid
for the owner, not an authoritative copy. ISO previews and the COSO summary carry no body text and are skipped.

    output: ontology/vocab-private/<scheme>-text.ttl   (same concept IRIs as the public files)
Usage: python3 pipeline/vocab/build_licensed_private.py
"""
import csv, os, subprocess
from rdflib import Graph, Literal, Namespace
from rdflib.namespace import SKOS, RDF, OWL, DCTERMS

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
RAW = os.path.join(ROOT, "data", "raw", "external", "grca")
FW = os.path.join(ROOT, "data", "frameworks", "grca")
OUT = os.path.join(ROOT, "ontology", "vocab-private")
VOC = "https://w3id.org/crgo/vocab/"
JOBS = {"iia-gias": ("iia_gias.tsv", ["globalinternalauditstandards_2024january9_editable.pdf"]),
        "itaf": ("itaf.tsv", ["1_ITAF_5th_Edition.pdf", "2_ITAF_Companion_Performance_Guidelines.pdf"]),
        "tsc": ("tsc.tsv", ["Trust-services-criteria.pdf"]),
        "iia-tr": ("iia_topical.tsv", ["cybersecurity_topical_requirement.pdf", "third_party_topical_requirement_english.pdf", "org_behav_topical_requirement_en.pdf"])}

def pages(pdf):
    txt = subprocess.run(["pdftotext", "-layout", pdf, "-"], capture_output=True, text=True).stdout
    return txt.split("\f")

def main():
    os.makedirs(OUT, exist_ok=True)
    for key, (tsv, pdfs) in JOBS.items():
        if not all(os.path.exists(os.path.join(RAW, p)) for p in pdfs):
            print("%-9s skipped (source PDF not present)" % key); continue
        rows = list(csv.DictReader((l for l in open(os.path.join(FW, tsv), encoding="utf-8") if not l.startswith("#")), delimiter="\t"))
        docs = {p: pages(os.path.join(RAW, p)) for p in pdfs}
        g = Graph(); ns = Namespace(VOC + key + "/"); g.bind("skos", SKOS)
        o = Namespace(VOC)[key + "-text"]
        g.add((o, RDF.type, OWL.Ontology))
        g.add((o, DCTERMS.title, Literal("PRIVATE: text extracts for %s (licensed; do not publish)" % key, lang="en")))
        n = 0
        for i, r in enumerate(rows):
            doc = pdfs[0]
            if key == "itaf" and r["id"] == "ITAF-2208": doc = pdfs[1]
            if key == "iia-tr":
                doc = {"CYBER": pdfs[0], "THIRD": pdfs[1], "ORGBE": pdfs[2]}[r["id"].split("-")[1][:5]]
            pg = docs[doc]
            head = r["label_en"].lower()[:40]
            start = next((k for k in range(len(pg)) if head and head in pg[k].lower() and k > 1), None)
            if start is None:
                try: start = int(r["page"]) - 1
                except ValueError: continue
            nxt = rows[i + 1] if i + 1 < len(rows) else None
            end = start + 1
            if nxt:
                h2 = nxt["label_en"].lower()[:40]
                e = next((k for k in range(start, min(start + 3, len(pg))) if h2 and h2 in pg[k].lower() and k > start), None)
                end = e if e else min(start + 1, len(pg))
            text = "\n".join(pg[start:max(end, start + 1)]).strip()
            if text:
                g.add((ns[r["id"].replace(" ", "_")], SKOS.scopeNote, Literal(text, lang="en"))); n += 1
        g.serialize(os.path.join(OUT, key + "-text.ttl"), format="turtle")
        print("%-9s %d extracts -> ontology/vocab-private/%s-text.ttl" % (key, n, key))

if __name__ == "__main__":
    main()
