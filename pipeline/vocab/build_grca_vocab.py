# -*- coding: utf-8 -*-
"""0.9.0 GRCA sprint: SKOS vocabularies for assessment and assurance standards (decisions G4, G5, R-d).

Writes ontology/vocab/
  sp800-53a.ttl     NIST SP 800-53A Rev. 5 assessment objectives (all 3,715) and assessment methods with their objects,
                    from the SP 800-53 Rev. 5.2.0 OSCAL catalogue (U.S. government work: prose reproduced)
  iia-gias.ttl      IIA Global Internal Audit Standards 2024: domains, principles, standards
  iia-tr.ttl        IIA Topical Requirements: Cybersecurity, Third-Party, Organizational Behavior
  itaf.ttl          ISACA ITAF 5th edition: standards and guidelines (and guideline 2208)
  tsc.ttl           AICPA 2017 Trust Services Criteria: categories, groups, criteria
  coso-erm.ttl      COSO ERM 2017: components and principles
  iso19011.ttl, iso27007.ttl, iso27008.ttl, iso37301.ttl, iso37302.ttl: clause structure
and data/frameworks/grca/links.tsv: SP 800-53A objective -> SP 800-53 control links, which
pipeline/vocab/build_external.py turns into typed 'evaluates control' correspondences.

Licensed standards (everything except SP 800-53A): identifiers and official headings only, with CRGO's own
paraphrases as definitions (checked by script: no run of more than 6 consecutive words shared with the source).
Labels that are CRGO translations, or CRGO labels where the source has no heading, say so in a skos:note.
Run after build_vocab.py and before build_external.py (scripts/build_vocab.sh order).
"""
import csv, json, os, re, sys
from rdflib import Literal, URIRef
from rdflib.namespace import SKOS
HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, HERE)
import build_vocab as BV  # noqa: E402
INTRO = "0.9.0"
FW = os.path.join(ROOT, "data", "frameworks", "grca")
report = []

def rows(name):
    return list(csv.DictReader((l for l in open(os.path.join(FW, name), encoding="utf-8") if not l.startswith("#")), delimiter="\t"))

PARA = "Definitions are CRGO paraphrases written for this vocabulary; no text of the standard is reproduced. Obtain the standard from its publisher."

# ---------------------------------------------------------------- NIST SP 800-53A (OSCAL)
d = json.load(open(os.path.join(BV.RAW, "NIST_SP-800-53_rev5_catalog.json"), encoding="utf-8"))["catalog"]
s = BV.Scheme("sp800-53a", "NIST SP 800-53A Rev. 5 assessment objectives and methods", "Objectifs et méthodes d'évaluation NIST SP 800-53A rév. 5",
              "SP 800-53 Rev. 5 OSCAL catalogue %s" % d["metadata"].get("version"), "https://github.com/usnistgov/oscal-content/tree/main/nist.gov/SP800-53/rev5",
              None, "US Government work, not subject to copyright in the United States (17 U.S.C. 105). Credit: NIST.", "NIST",
              "Every assessment objective of SP 800-53A Rev. 5 as carried in the 5.2.0 catalogue, nested as in 800-53A (broader = parent objective; "
              "the top objective of each control or enhancement is linked to the 800-53 concept by 'evaluates control'), and the examine, interview "
              "and test methods with their assessment objects. Organisation-defined parameters are shown as [organization-defined: label].")
links, n_obj, n_meth, meth_count = [], 0, 0, {}

def label_of(x):
    return next((p["value"] for p in x.get("props", []) if p["name"] == "label"), None)

def ctl_label(x):  # the 800-53 label of a control (class-less label prop), e.g. AC-2(1)
    return next((p["value"] for p in x.get("props", []) if p["name"] == "label" and "class" not in p), x["id"].upper())

def resolve(text, params, depth=0):
    out = re.sub(r"\{\{\s*insert:\s*param,\s*([\w.\-]+)\s*\}\}", lambda m: "[organization-defined: %s]" % params.get(m.group(1), m.group(1)), text or "").strip()
    return resolve(out, params, depth + 1) if "{{" in out and depth < 3 else out  # parameter labels can themselves insert parameters

def objectives(part, parent, params):
    global n_obj
    lab, note = label_of(part), None
    if lab is None:  # two objectives of SI-2(7) carry no label in the 5.2.0 catalogue; derived from the parent as 800-53A numbers them
        lab = "%s[%02d]" % (parent, int(part["id"].rsplit("-", 1)[1]))
        note = "Identifier derived by CRGO from the parent objective and the OSCAL part id %s: the catalogue gives this objective no label." % part["id"]
    prose = resolve(part.get("prose"), params)
    s.concept(lab, (lab + " " + prose).strip() if prose else lab, broader=parent, definition_en=prose or None, note=note,
              source="NIST SP 800-53A Rev. 5 (SP 800-53 Rev. 5.2.0 OSCAL catalogue, part %s)" % part["id"], introduced=INTRO)
    n_obj += 1
    for sub in part.get("parts", []):
        if sub["name"] == "assessment-objective":
            objectives(sub, lab, params)
    return lab

def control(c):
    global n_meth
    params = {}
    for p in c.get("params", []):
        params[p["id"]] = p.get("label") or "; ".join(p.get("select", {}).get("choice", [])) or p["id"]
    for p in c.get("parts", []):
        if p["name"] == "assessment-objective":
            top = objectives(p, None, params)
            links.append((top, ctl_label(c)))
        elif p["name"] == "assessment-method":
            meth = next(x["value"] for x in p["props"] if x["name"] == "method")
            objs = "; ".join(" ".join(o.get("prose", "").split()) for o in p.get("parts", []) if o["name"] == "assessment-objects")
            # notation from the 800-53 control label: the catalogue's own method labels repeat for 7 enhancements (e.g. PL-08-Examine for PL-8 and PL-8(1))
            lab = "%s-%s" % (ctl_label(c), meth.capitalize())
            top = next((label_of(x) for x in c.get("parts", []) if x["name"] == "assessment-objective"), None)
            mc = s.concept(lab, "%s: %s" % (ctl_label(c), meth.lower()), broader=None, definition_en=("Assessment objects: " + objs) if objs else None,
                           source="NIST SP 800-53A Rev. 5 (SP 800-53 Rev. 5.2.0 OSCAL catalogue, part %s)" % p["id"], introduced=INTRO)
            if label_of(p): s.g.add((mc, SKOS.altLabel, Literal(label_of(p), lang="en")))
            # skos:topConceptOf is added for broader=None; methods are not top objectives, so record the method explicitly
            s.g.add((mc, BV.C("usesAssessmentMethod"), BV.C({"EXAMINE": "MethodExamine", "INTERVIEW": "MethodInterview", "TEST": "MethodTest"}[meth])))
            if top:
                s.g.add((mc, SKOS.related, s.ns[s.safe(top)]))
            n_meth += 1; meth_count[meth] = meth_count.get(meth, 0) + 1
    for e in c.get("controls", []):
        control(e)

for f in d["groups"]:
    for c in f["controls"]:
        control(c)
report.append(("sp800-53a", s.save(), "objectives %d, methods %d %s" % (n_obj, n_meth, meth_count)))
with open(os.path.join(FW, "links.tsv"), "w", encoding="utf-8") as out:
    out.write("group\tsubject_scheme\tsubject\tobject_scheme\tobject\n")
    for a, b in links:
        out.write("mappings/sp800-53a-controls\tsp800-53a\t%s\tsp800-53r5\t%s\n" % (a, b))

# ---------------------------------------------------------------- licensed standards: identifiers, headings, paraphrases
def licensed(key, title_en, title_fr, version, source, rights, publisher, note, data, en_official, fr_official, src_label):
    s = BV.Scheme(key, title_en, title_fr, version, source, None, rights, publisher, note + " " + PARA)
    for r in data:
        notes = []
        off = r.get("official_title", "y") != "n"
        if off and not en_official:
            notes.append("English label translated by CRGO; the official title is the French one.")
        if off and not fr_official:
            notes.append("French label translated by CRGO.")
        if not off:
            notes.append("Label written by CRGO: the source gives no heading for this item.")
        s.concept(r["id"], r["label_en"], r["label_fr"] or None, broader=r["parent"] or None, definition_en=r["definition_en"],
                  definition_fr=r["definition_fr"] or None, source="%s, %s %s (page %s)" % (src_label, r["kind"], r["id"], r["page"]),
                  note=" ".join(notes) or None, introduced=INTRO)
    report.append((key, s.save(), ""))

LR = lambda who: "Identifiers and headings (c) %s, cited for reference and mapping only under the project owner's licence to use the document; " \
                 "definitions are CRGO paraphrases. No text is reproduced." % who
licensed("iia-gias", "IIA Global Internal Audit Standards (2024): domains, principles and standards", "Normes internationales d'audit interne de l'IIA (2024) : domaines, principes et normes",
         "2024 (published 2024-01-09)", "IIA Global Internal Audit Standards, published 2024-01-09 (data/frameworks/grca/iia_gias.tsv)", LR("The Institute of Internal Auditors"),
         "The Institute of Internal Auditors", "The file held states no effective date; see the IIA for it.", rows("iia_gias.tsv"), True, False, "IIA GIAS 2024")
licensed("iia-tr", "IIA Topical Requirements: cybersecurity, third-party and organizational behavior", "Exigences thématiques de l'IIA : cybersécurité, tiers et comportement organisationnel",
         "Cybersecurity (2025-02), Third-Party (2025-09), Organizational Behavior (2025-12)", "IIA Topical Requirements and user guides (data/frameworks/grca/iia_topical.tsv)",
         LR("The Institute of Internal Auditors"), "The Institute of Internal Auditors",
         "Requirement areas carry official headings; lettered requirements carry CRGO labels. The files held state publication months, not effective dates.",
         rows("iia_topical.tsv"), True, False, "IIA Topical Requirements")
licensed("itaf", "ISACA ITAF 5th edition: standards and guidelines", "ITAF de l'ISACA, 5e édition : normes et lignes directrices", "5th edition (copyright 2026)",
         "ISACA ITAF 5th edition and companion performance guideline 2208 (data/frameworks/grca/itaf.tsv)", LR("ISACA"), "ISACA",
         "General, performance and reporting standards and their guidelines; numbered statements inside each standard are not included.", rows("itaf.tsv"), True, False, "ISACA ITAF 5th edition")
licensed("tsc", "AICPA 2017 Trust Services Criteria (revised points of focus, 2022)", "Critères des services de confiance 2017 de l'AICPA (points d'attention révisés, 2022)",
         "2017 (points of focus revised 2022)", "AICPA TSP section 100 (data/frameworks/grca/tsc.tsv)", LR("AICPA"), "AICPA",
         "Categories and criterion groups carry official headings; criteria carry CRGO labels. CC1-CC5 definitions name the COSO 2013 principle each criterion states it relates to. "
         "The common criteria (CC1-CC9) are placed under Security although they apply to every category.", rows("tsc.tsv"), True, False, "AICPA 2017 TSC")
licensed("coso-erm", "COSO Enterprise Risk Management (2017): components and principles", "COSO Gestion des risques de l'entreprise (2017) : composantes et principes",
         "2017", "COSO ERM 2017 French executive summary (data/frameworks/grca/coso_erm.tsv)", LR("COSO"), "COSO",
         "French titles are those of the French executive summary; English titles are CRGO translations, the official English list not being in the files held.",
         rows("coso_erm.tsv"), False, True, "COSO ERM 2017 (French summary)")
ISO = {"ISO 19011:2018": "iso19011", "ISO/IEC 27007:2020": "iso27007", "ISO/IEC TS 27008:2019": "iso27008", "ISO 37301:2021": "iso37301", "ISO 37302:2025": "iso37302"}
iso_rows = rows("iso_audit_compliance.tsv")
for std, key in ISO.items():
    rs = [r for r in iso_rows if r["standard"] == std]
    head = next(r for r in rs if r["kind"] == "standard")
    s = BV.Scheme(key, "%s %s: clause structure" % (std, head["label_en"]), "%s %s : structure des articles" % (std, head["label_fr"]), head["edition"],
                  "%s (publisher preview: cover, foreword, introduction, scope, table of contents)" % std, None,
                  "Clause numbers and headings (c) ISO%s, cited for reference and mapping only; definitions are CRGO paraphrases. No text is reproduced." % ("/IEC" if "IEC" in std else ""),
                  "ISO" + ("/IEC JTC 1/SC 27" if "IEC" in std else ""), "Clauses to two levels and annex headings. " + PARA)
    for r in rs:
        if r["kind"] == "standard":
            continue
        tl = r["title_language"]
        note = "French heading official; English heading translated by CRGO." if tl.startswith("fr (") else \
               "English heading official; French heading translated by CRGO." if tl.startswith("en (") else None
        s.concept(r["id"], r["label_en"], r["label_fr"], broader=None if r["parent"] == std else r["parent"], definition_en=r["definition_en"],
                  definition_fr=r["definition_fr"], source="%s, %s %s (page %s)" % (std, r["kind"], r["id"], r["page"]), note=note, introduced=INTRO)
    report.append((key, s.save(), ""))

for k, n, extra in report:
    print("%-10s %5d concepts %s" % (k, n, extra))
print("links.tsv: %d objective -> control links" % len(links))
