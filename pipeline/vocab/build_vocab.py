# -*- coding: utf-8 -*-
"""Build the SKOS vocabularies of CRGO (Phase 3) into ontology/vocab/.

Sources (nothing is typed in by hand except the scenario themes, which are CRGO's own list):
- NIST CSF 2.0 and SP 800-53 Rev. 5.2.0: OSCAL catalogues from github.com/usnistgov/oscal-content
  (fetched to data/raw/ by fetch_sources.sh).
- MITRE ATT&CK Enterprise: STIX bundle from github.com/mitre-attack/attack-stix-data.
- ISO/IEC 27002:2022, COBIT 2019, Loi 25, CSA CCM v4.1 domains: verified tables in data/frameworks/,
  each row with its sources.
Each scheme carries its version, source, retrieval date and licence; each concept its notation,
labels, broader concept, source and governance status (proposed).
"""
import csv, json, os, re, sys
from rdflib import Graph, Namespace, Literal, URIRef
from rdflib.namespace import RDF, RDFS, SKOS, DCTERMS, OWL, XSD

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(ROOT, "pipeline", "library"))
import themes as T  # noqa: E402

ids = dict(l.rstrip("\n").split("\t") for l in open(os.path.join(ROOT, "src", "ids.tsv"), encoding="utf-8"))
C = lambda k: URIRef("https://w3id.org/crgo/CRGO_%07d" % int(ids[k]))
VOC = "https://w3id.org/crgo/vocab/"
RAW = os.path.join(ROOT, "data", "raw")
FW = os.path.join(ROOT, "data", "frameworks")
OUT = os.path.join(ROOT, "ontology", "vocab")
RETRIEVED = "2026-10-08"
VERSION = "0.6.0"
CONF = {"H": C("ConfHigh"), "M": C("ConfMedium"), "L": C("ConfLow")}
APPROVALS = {}
for _l in open(os.path.join(ROOT, "src", "approvals.tsv"), encoding="utf-8"):
    if _l.strip() and not _l.startswith("#") and "/" in _l.split("\t")[0]:
        _k, _d, _who, _date, *_ = _l.rstrip("\n").split("\t")
        APPROVALS[_k] = (_d, _who, _date)

def safe(i):
    i = i.replace("&", "and").replace(" ", "_").replace("(", "_").replace(")", "")
    return re.sub(r"[^A-Za-z0-9._-]", "", i)

class Scheme:
    def __init__(self, key, title_en, title_fr, version, source, licence, rights, publisher, note_en=""):
        self.g = Graph(); self.key = key
        for p, n in [("skos", SKOS), ("dcterms", DCTERMS), ("crgo", "https://w3id.org/crgo/"), ("owl", OWL), (key, VOC + key + "/")]:
            self.g.bind(p, n)
        self.ns = Namespace(VOC + key + "/")
        s = self.s = URIRef(VOC + key)
        g = self.g
        g.add((s, RDF.type, OWL.Ontology)); g.add((s, RDF.type, SKOS.ConceptScheme))
        g.add((s, OWL.versionIRI, URIRef("%s%s/%s" % (VOC, VERSION, key))))
        g.add((s, DCTERMS.title, Literal(title_en, lang="en")))
        if title_fr:
            g.add((s, DCTERMS.title, Literal(title_fr, lang="fr")))
        g.add((s, OWL.versionInfo, Literal(version)))
        g.add((s, DCTERMS.source, Literal(source)))
        g.add((s, DCTERMS.publisher, Literal(publisher)))
        g.add((s, DCTERMS.date, Literal(RETRIEVED, datatype=XSD.date)))
        if licence:
            g.add((s, DCTERMS.license, URIRef(licence)))
        g.add((s, DCTERMS.rights, Literal(rights, lang="en")))
        if note_en:
            g.add((s, SKOS.scopeNote, Literal(note_en, lang="en")))
        self.n = 0

    def concept(self, notation, label_en, label_fr=None, broader=None, definition_en=None, definition_fr=None,
                source=None, conf="H", deprecated=False, see_also=None, note=None, introduced="0.2.0"):
        c = self.ns[safe(notation)]
        g = self.g
        g.add((c, RDF.type, SKOS.Concept)); g.add((c, SKOS.inScheme, self.s))
        g.add((c, SKOS.notation, Literal(notation)))
        g.add((c, SKOS.prefLabel, Literal(label_en, lang="en")))
        if label_fr:
            g.add((c, SKOS.prefLabel, Literal(label_fr, lang="fr")))
        if definition_en:
            g.add((c, SKOS.definition, Literal(definition_en, lang="en")))
        if definition_fr:
            g.add((c, SKOS.definition, Literal(definition_fr, lang="fr")))
        if broader is None:
            g.add((c, SKOS.topConceptOf, self.s)); g.add((self.s, SKOS.hasTopConcept, c))
        else:
            g.add((c, SKOS.broader, self.ns[safe(broader)]))
        if deprecated:
            g.add((c, OWL.deprecated, Literal(True)))
        if see_also:
            g.add((c, RDFS.seeAlso, URIRef(see_also)))
        if note:
            g.add((c, SKOS.note, Literal(note, lang="en")))
        a = APPROVALS.get("%s/%s" % (self.key, notation))
        if a and a[0] == "Approve":
            g.add((c, C("governanceStatus"), C("StatusApproved")))
            g.add((c, C("approvedBy"), C("Agent" + a[1])))
            g.add((c, C("approvalDate"), Literal(a[2], datatype=XSD.date)))
        else:
            g.add((c, C("governanceStatus"), C("StatusProposed")))
        g.add((c, C("confidence"), CONF[conf]))
        if source:
            g.add((c, C("evidenceSource"), Literal(source, lang="en")))
        g.add((c, C("proposedBy"), C("AgentClaude")))
        g.add((c, C("introducedIn"), Literal(introduced)))
        self.n += 1
        return c

    def save(self):
        os.makedirs(OUT, exist_ok=True)
        self.g.serialize(os.path.join(OUT, "%s.ttl" % self.key), format="turtle")
        return self.n

def tsv(name):
    return list(csv.DictReader(open(os.path.join(FW, name), encoding="utf-8"), delimiter="\t"))

def props(x):
    return {p["name"]: p["value"] for p in x.get("props", []) if "class" not in p or p.get("class") != "sp800-53a"}

report = []

# --- scenario themes (CRGO's own list)
s = Scheme("theme", "CRGO scenario themes", "Thèmes de scénarios CRGO", VERSION,
           "CRGO, pipeline/library/themes.py (decision Q-E)", "https://creativecommons.org/licenses/by-nc/4.0/",
           "CC BY-NC 4.0, Marc-André Léger.", "CyberRiskGuardian Ontology",
           "Controlled list that replaces the 225 free-text categories of the 2023 scenario library; see data/library/category_map.tsv.")
for key, en, fr, den, dfr, _ in T.THEMES:
    s.concept(key, en, fr, definition_en=den, definition_fr=dfr, source="Phase 3 category consolidation, data/library/category_map.tsv", conf="M")
report.append(("theme", s.save()))

# --- NIST CSF 2.0 (OSCAL)
d = json.load(open(os.path.join(RAW, "NIST_CSF_v2.0_catalog.json"), encoding="utf-8"))["catalog"]
m = d["metadata"]
s = Scheme("csf2", "NIST Cybersecurity Framework 2.0", "Cadre de cybersécurité du NIST 2.0", "2.0 (OSCAL catalogue %s)" % m.get("version"),
           "https://github.com/usnistgov/oscal-content/tree/main/nist.gov/CSF/v2.0 (NIST CSWP 29, 26 Feb 2024)",
           None, "US Government work, not subject to copyright in the United States (17 U.S.C. 105). Credit: NIST.", "NIST",
           "Functions, categories and subcategories. Items NIST withdrew from 2.0 are kept as deprecated concepts so that old mappings resolve.")
for f in d["groups"]:
    s.concept(f["id"], f["title"].capitalize(), source="NIST CSF 2.0 OSCAL catalogue")
    for c in f["controls"]:
        p = props(c); wd = p.get("status") == "withdrawn"
        st = next((x.get("prose") for x in c.get("parts", []) if x["name"] == "statement"), None)
        s.concept(c["id"], c["title"], broader=f["id"], definition_en=st, deprecated=wd, source="NIST CSF 2.0 OSCAL catalogue")
        for sc in c.get("controls", []):
            p = props(sc); wd = p.get("status") == "withdrawn"
            st = next((x.get("prose") for x in sc.get("parts", []) if x["name"] == "statement"), None)
            s.concept(sc["id"], st or sc["title"], broader=c["id"], definition_en=st, deprecated=wd, source="NIST CSF 2.0 OSCAL catalogue")
report.append(("csf2", s.save()))

# --- NIST SP 800-53 Rev. 5.2.0 (OSCAL)
d = json.load(open(os.path.join(RAW, "NIST_SP-800-53_rev5_catalog.json"), encoding="utf-8"))["catalog"]
m = d["metadata"]
s = Scheme("sp800-53r5", "NIST SP 800-53 Rev. 5 security and privacy controls", "Mesures de sécurité et de confidentialité NIST SP 800-53 rév. 5",
           m.get("version"), "https://github.com/usnistgov/oscal-content/tree/main/nist.gov/SP800-53/rev5",
           None, "US Government work, not subject to copyright in the United States (17 U.S.C. 105). Credit: NIST.", "NIST",
           "Control families, controls and control enhancements (titles only). Withdrawn controls are kept as deprecated concepts.")
def lab(x):
    ls = [p["value"] for p in x.get("props", []) if p["name"] == "label" and "class" not in p]
    return ls[0] if ls else x["id"].upper()
for f in d["groups"]:
    s.concept(f["id"].upper(), f["title"], source="NIST SP 800-53 Rev. 5 OSCAL catalogue")
    for c in f["controls"]:
        wd = props(c).get("status") == "withdrawn"
        s.concept(lab(c), c["title"], broader=f["id"].upper(), deprecated=wd, source="NIST SP 800-53 Rev. 5 OSCAL catalogue")
        for e in c.get("controls", []):
            wd = props(e).get("status") == "withdrawn"
            s.concept(lab(e), e["title"], broader=lab(c), deprecated=wd, source="NIST SP 800-53 Rev. 5 OSCAL catalogue")
report.append(("sp800-53r5", s.save()))

# --- ISO/IEC 27002:2022 (IDs and titles; decision Q6/Q-B)
s = Scheme("iso27002-2022", "ISO/IEC 27002:2022 information security controls (identifiers and titles)",
           "Mesures de sécurité de l'information ISO/IEC 27002:2022 (identifiants et titres)", "2022 (corrected 2022-03)",
           "ISO/IEC 27002:2022 table of contents, cross-checked against four public mappings; see data/frameworks/iso27002_2022.tsv",
           None, "Control identifiers and titles of ISO/IEC 27002:2022, (c) ISO/IEC, cited for reference and mapping only. "
           "No control text is reproduced; obtain the standard from ISO or a national standards body.", "ISO/IEC JTC 1/SC 27",
           "The same 93 identifiers number the controls of ISO/IEC 27001:2022 Annex A. No official French titles were found, so French labels are omitted.")
for th, en in [("5", "Organizational controls"), ("6", "People controls"), ("7", "Physical controls"), ("8", "Technological controls")]:
    s.concept(th, en, source="ISO/IEC 27002:2022 clause structure")
for r in tsv("iso27002_2022.tsv"):
    s.concept(r["id"], r["title_en"], broader=r["id"].split(".")[0], source=r["sources"].replace(";", " ; "),
              conf="H" if r["status"] == "verified" else "M", note=(r["note"] if r["status"] != "verified" else None))
report.append(("iso27002-2022", s.save()))

# --- COBIT 2019
s = Scheme("cobit2019", "COBIT 2019 governance and management objectives", "Objectifs de gouvernance et de gestion COBIT 2019", "2019",
           "ISACA COBIT 2019 Framework: Introduction and Methodology; see data/frameworks/cobit2019.tsv", None,
           "Objective identifiers and names of COBIT 2019, (c) ISACA, cited for reference and mapping only.", "ISACA",
           "COBIT 2019 is the version used by CRGO (decision D4, 2026-10-09). ISACA announced COBIT 7 for 27 October 2026.")
doms = {}
for r in tsv("cobit2019.tsv"):
    dk = re.match(r"[A-Z]+", r["id"]).group(0)
    if dk not in doms:
        doms[dk] = s.concept(dk, r["domain"], source="ISACA COBIT 2019")
    s.concept(r["id"], r["name_en"], broader=dk, source=r["sources"].replace(";", " ; "), conf="H" if r["status"] == "verified" else "M")
report.append(("cobit2019", s.save()))

# --- Loi 25
s = Scheme("loi25", "Québec Law 25: obligations under the private-sector privacy Act", "Loi 25 du Québec : obligations de la Loi sur le secteur privé",
           "S.Q. 2021, c. 25, as consolidated in LégisQuébec on %s" % RETRIEVED,
           "LégisQuébec, CQLR c. P-39.1 and c. C-1.1; see data/frameworks/loi25.tsv", None,
           "Labels and definitions are CRGO paraphrases; the official text is in LégisQuébec.", "Gouvernement du Québec (source text)",
           "One concept per obligation, identified by Act and section. Includes s. 10 (security measures), which Law 25 did not amend but made subject to monetary administrative penalties (s. 90.1).")
sys.path.insert(0, HERE)
from ids_loi25 import loi25_notation  # noqa: E402
for r in tsv("loi25.tsv"):
    note = "In force %s. Source text: %s s. %s." % (r["in_force"], r["act"], r["section"])
    s.concept(loi25_notation(r["act"], r["section"]), r["label_en"], r["label_fr"], definition_en=r["definition_en"], definition_fr=r["definition_fr"],
              source=r["sources"].replace(";", " ; "), conf="H" if r["status"] == "verified" else "M", note=note,
              introduced="0.3.0" if r["section"] == "10" else "0.2.0")
report.append(("loi25", s.save()))

# --- Québec Act respecting health and social services information (R-22.1) and its regulations
s = Scheme("lrsss", "Québec Act respecting health and social services information: obligations",
           "Loi sur les renseignements de santé et de services sociaux : obligations",
           "S.Q. 2023, c. 5 (CQLR c. R-22.1) and regulations r. 1 and r. 2, as consolidated in LégisQuébec on 2026-10-10",
           "LégisQuébec, CQLR c. R-22.1, R-22.1 r. 1, R-22.1 r. 2; see data/frameworks/lrsss.tsv and lrsss_scope.md", None,
           "Labels and definitions are CRGO paraphrases; the official text is in LégisQuébec.", "Gouvernement du Québec (source text)",
           "Applies to health and social services bodies, including private professional offices and specialised medical centres "
           "(s. 4 and Schedule II); for the health information they hold it replaces the private-sector Act (P-39.1 s. 3, para. 3).")
for r in tsv("lrsss.tsv"):
    s.concept("%s s. %s" % (r["act"], r["section"]), r["label_en"], r["label_fr"], definition_en=r["definition_en"], definition_fr=r["definition_fr"],
              source=r["sources"].replace(";", " ; "), conf="H" if r["status"] == "verified" else "M",
              note="In force: %s." % r["in_force"], introduced="0.4.0")
report.append(("lrsss", s.save()))

# --- CSA CCM v4.1: domains only (control titles are not licensed for redistribution)
s = Scheme("ccm41", "CSA Cloud Controls Matrix v4.1 domains", "Domaines de la Cloud Controls Matrix v4.1 de la CSA", "4.1 (January 2026)",
           "see data/frameworks/ccm41_domains.tsv", None,
           "Domain identifiers and names of the CSA Cloud Controls Matrix, (c) Cloud Security Alliance, cited for reference. "
           "Control titles are not included: the CCM terms do not allow redistribution.", "Cloud Security Alliance",
           "Domains only. Controls are built privately from a licensed copy (pipeline/vocab/build_ccm_private.py) and are not published.")
for r in tsv("ccm41_domains.tsv"):
    s.concept(r["id"], r["domain_name"], source=r["sources"], conf="M", note="CSA writes some names with '&' (for example 'Audit & Assurance').")
report.append(("ccm41", s.save()))

# --- MITRE ATT&CK Enterprise
bundle = json.load(open(os.path.join(RAW, "enterprise-attack.json"), encoding="utf-8"))
objs = [o for o in bundle["objects"] if not o.get("revoked") and not o.get("x_mitre_deprecated")]
coll = next(o for o in bundle["objects"] if o["type"] == "x-mitre-collection")
s = Scheme("attack", "MITRE ATT&CK Enterprise tactics and techniques", "Tactiques et techniques MITRE ATT&CK Enterprise",
           coll.get("x_mitre_version"), "https://github.com/mitre-attack/attack-stix-data (enterprise-attack.json)",
           None, "(c) The MITRE Corporation. Reproduced under the ATT&CK Terms of Use (https://attack.mitre.org/resources/legal-and-branding/terms-of-use/).",
           "The MITRE Corporation", "Tactics as top concepts; techniques narrower than their first tactic; sub-techniques narrower than their parent technique.")
ext = lambda o: next(r for r in o["external_references"] if r.get("source_name") == "mitre-attack")
tac = {}
for o in objs:
    if o["type"] == "x-mitre-tactic":
        e = ext(o); tac[o["x_mitre_shortname"]] = e["external_id"]
        s.concept(e["external_id"], o["name"], see_also=e["url"], source="MITRE ATT&CK Enterprise %s" % coll.get("x_mitre_version"))
for o in sorted([o for o in objs if o["type"] == "attack-pattern"], key=lambda o: ext(o)["external_id"]):
    e = ext(o); tid = e["external_id"]
    if "." in tid:
        b = tid.split(".")[0]
    else:
        phases = [p["phase_name"] for p in o.get("kill_chain_phases", []) if p["kill_chain_name"] == "mitre-attack"]
        b = tac.get(phases[0]) if phases else None
    c = s.concept(tid, o["name"], broader=b, see_also=e["url"], source="MITRE ATT&CK Enterprise %s" % coll.get("x_mitre_version"))
    if "." not in tid:
        for ph in [p["phase_name"] for p in o.get("kill_chain_phases", []) if p["kill_chain_name"] == "mitre-attack"][1:]:
            s.g.add((c, SKOS.related, s.ns[safe(tac[ph])]))
# revoked and deprecated techniques stay as deprecated concepts, pointing to their replacement (crosswalk for older tools)
byid = {o["id"]: o for o in bundle["objects"]}
revoked_by = {r_["source_ref"]: r_["target_ref"] for r_ in bundle["objects"] if r_["type"] == "relationship" and r_.get("relationship_type") == "revoked-by"}
active = {ext(o)["external_id"] for o in objs if o["type"] == "attack-pattern"}
for o in bundle["objects"]:
    if o["type"] != "attack-pattern" or not (o.get("revoked") or o.get("x_mitre_deprecated")):
        continue
    e = next((r_ for r_ in o.get("external_references", []) if r_.get("source_name") == "mitre-attack"), None)
    if not e or e["external_id"] in active:
        continue
    tgt = byid.get(revoked_by.get(o["id"], ""))
    new = next((r_["external_id"] for r_ in tgt.get("external_references", []) if r_.get("source_name") == "mitre-attack"), None) if tgt else None
    c = s.concept(e["external_id"], o["name"], broader=None if "." not in e["external_id"] else None, deprecated=True, see_also=e.get("url"),
                  source="MITRE ATT&CK Enterprise %s (revoked or deprecated)" % coll.get("x_mitre_version"),
                  note=("Revoked; replaced by %s." % new) if new else "Deprecated in this ATT&CK release; no replacement.", introduced="0.3.0")
    s.g.remove((c, SKOS.topConceptOf, s.s)); s.g.remove((s.s, SKOS.hasTopConcept, c))
    if new and new in active:
        s.g.add((c, DCTERMS.isReplacedBy, s.ns[safe(new)]))
report.append(("attack", s.save()))

for k, n in report:
    print("%-15s %5d concepts" % (k, n))
