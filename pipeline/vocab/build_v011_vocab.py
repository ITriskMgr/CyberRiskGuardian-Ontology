# -*- coding: utf-8 -*-
"""0.11.0: SKOS vocabularies added with CRGO 0.11 (CyberRiskGuardian 1.9.0 decision record, 2026-11-02).

Writes ontology/vocab/
  cis81.ttl               CIS Critical Security Controls v8.1: 18 controls and 153 safeguards (data/frameworks/cis81.tsv).
                          Identifiers, Implementation Group membership (a safeguard of IG1 is also in IG2 and IG3), asset
                          type and security function (a NIST CSF 2.0 function of vocab/csf2) as facts; labels are CRGO's
                          own paraphrases of at most eight words, never CIS wording (CC BY-NC-ND 4.0). Values the drafting
                          agent could not recall with confidence carry confidence Low and an editorial note "REVIEW: ...".
                          Typed correspondences ('partially overlaps', CRGO judgement): controls to NIST CSF 2.0 categories
                          and ISO/IEC 27002:2022 controls, safeguards to SP 800-53 Rev. 5 controls; rdfs:seeAlso from
                          safeguards to the crgo-iam and crgo-context classes that record them.
  owasp-top10-2025.ttl    OWASP Top 10:2025 category identifiers with CRGO labels  } data/frameworks/owasp_011.tsv; links to
  owasp-llm-2025.ttl      OWASP Top 10 for LLM Applications 2025                   } the crgo-context scenario patterns
  owasp-agentic-2026.ttl  OWASP Top 10 for Agentic Applications 2026               } ('partially overlaps')
  naics-sectors.ttl       NAICS Canada 2022 sectors (data/frameworks/naics_sectors.tsv), adapted from MOACCO's NAICS classes
  glossary.ttl            Cybersecurity terms adapted from MOACCO's Cybersecurity_Terms (data/frameworks/glossary_moacco.tsv):
                          CRGO definitions, 'derived from' the MOACCO class, rdfs:seeAlso to related CRGO terms
Independent of build_vocab.py (which needs data/raw); the Scheme class below writes concepts the same way.
Every concept is proposed (approval groups cis81/*, owasp-top10-2025/*, owasp-llm-2025/*, owasp-agentic-2026/*,
naics-sectors/*, glossary/* in src/approvals.tsv).
"""
import csv, os, re
from rdflib import Graph, Namespace, Literal, URIRef
from rdflib.namespace import RDF, RDFS, SKOS, DCTERMS, OWL, XSD

HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.dirname(os.path.dirname(HERE))
ids = dict(l.rstrip("\n").split("\t") for l in open(os.path.join(ROOT, "src", "ids.tsv"), encoding="utf-8"))
C = lambda k: URIRef("https://w3id.org/crgo/CRGO_%07d" % int(ids[k]))
VOC = "https://w3id.org/crgo/vocab/"
FW = os.path.join(ROOT, "data", "frameworks"); OUT = os.path.join(ROOT, "ontology", "vocab")
RETRIEVED = "2026-11-02"; VERSION = "0.11.0"; INTRO = "0.11.0"
CONF = {"H": C("ConfHigh"), "M": C("ConfMedium"), "L": C("ConfLow")}
APPROVALS = {}
for _l in open(os.path.join(ROOT, "src", "approvals.tsv"), encoding="utf-8"):
    if _l.strip() and not _l.startswith("#") and "/" in _l.split("\t")[0]:
        _k, _d, _who, _date, *_ = _l.rstrip("\n").split("\t"); APPROVALS[_k] = (_d, _who, _date)
tsv = lambda n: list(csv.DictReader(open(os.path.join(FW, n), encoding="utf-8"), delimiter="\t"))
safe = lambda i: re.sub(r"[^A-Za-z0-9._-]", "", i.replace(":", "-").replace(" ", "_"))

def notations(key):
    g = Graph().parse(os.path.join(OUT, key + ".ttl"))
    return {str(n): s for s, n in g.subject_objects(SKOS.notation)}

class Scheme:
    def __init__(self, key, title_en, title_fr, version, source, licence, rights, publisher, note_en="", imports=()):
        self.key, self.g, self.ns, self.s, self.n = key, Graph(), Namespace(VOC + key + "/"), URIRef(VOC + key), 0
        g, s = self.g, self.s
        for p, n in [("skos", SKOS), ("dcterms", DCTERMS), ("crgo", "https://w3id.org/crgo/"), ("owl", OWL), (key, VOC + key + "/")]:
            g.bind(p, n)
        g.add((s, RDF.type, OWL.Ontology)); g.add((s, RDF.type, SKOS.ConceptScheme))
        g.add((s, OWL.versionIRI, URIRef("%s%s/%s" % (VOC, VERSION, key))))
        g.add((s, DCTERMS.title, Literal(title_en, lang="en"))); g.add((s, DCTERMS.title, Literal(title_fr, lang="fr")))
        g.add((s, OWL.versionInfo, Literal(version))); g.add((s, DCTERMS.source, Literal(source)))
        g.add((s, DCTERMS.publisher, Literal(publisher))); g.add((s, DCTERMS.date, Literal(RETRIEVED, datatype=XSD.date)))
        if licence: g.add((s, DCTERMS.license, URIRef(licence)))
        g.add((s, DCTERMS.rights, Literal(rights, lang="en")))
        if note_en: g.add((s, SKOS.scopeNote, Literal(note_en, lang="en")))
        for i in imports: g.add((s, OWL.imports, URIRef(i)))

    def iri(self, notation):
        return self.ns[safe(notation)]

    def concept(self, notation, label_en, label_fr=None, broader=None, definition_en=None, definition_fr=None,
                source=None, conf="H", see_also=(), note=None, review=None, derived=()):
        c = self.iri(notation); g = self.g
        g.add((c, RDF.type, SKOS.Concept)); g.add((c, SKOS.inScheme, self.s)); g.add((c, SKOS.notation, Literal(notation)))
        g.add((c, SKOS.prefLabel, Literal(label_en, lang="en")))
        if label_fr: g.add((c, SKOS.prefLabel, Literal(label_fr, lang="fr")))
        if definition_en: g.add((c, SKOS.definition, Literal(definition_en, lang="en")))
        if definition_fr: g.add((c, SKOS.definition, Literal(definition_fr, lang="fr")))
        if broader is None:
            g.add((c, SKOS.topConceptOf, self.s)); g.add((self.s, SKOS.hasTopConcept, c))
        else:
            g.add((c, SKOS.broader, self.iri(broader)))
        for u in see_also: g.add((c, RDFS.seeAlso, URIRef(u)))
        if note: g.add((c, SKOS.note, Literal(note, lang="en")))
        if review: g.add((c, SKOS.editorialNote, Literal("REVIEW: " + review, lang="en")))
        for d in derived: g.add((c, C("derivedFrom"), URIRef(d)))
        a = APPROVALS.get("%s/%s" % (self.key, notation)) or APPROVALS.get("%s/*" % self.key)
        if a and a[0] == "Approve":
            g.add((c, C("governanceStatus"), C("StatusApproved"))); g.add((c, C("approvedBy"), C("Agent" + a[1])))
            g.add((c, C("approvalDate"), Literal(a[2], datatype=XSD.date)))
        else:
            g.add((c, C("governanceStatus"), C("StatusProposed")))
        g.add((c, C("confidence"), CONF[conf]))
        if review: g.add((c, C("confidenceRationale"), Literal("Flagged for review: " + review, lang="en")))
        if source: g.add((c, C("evidenceSource"), Literal(source, lang="en")))
        g.add((c, C("proposedBy"), C("AgentClaude"))); g.add((c, C("introducedIn"), Literal(INTRO)))
        self.n += 1
        return c

    def save(self):
        self.g.serialize(os.path.join(OUT, "%s.ttl" % self.key), format="turtle")
        return self.n

report = []
CSF, SP, ISO = notations("csf2"), notations("sp800-53r5"), notations("iso27002-2022")
PO = C("partiallyOverlaps")

# ---------------------------------------------------------------- CIS Controls v8.1
CIS_URL = "https://www.cisecurity.org/controls/v8-1"
s = Scheme("cis81", "CIS Critical Security Controls v8.1 (identifiers, groups, asset types and functions; CRGO labels)",
           "Contrôles de sécurité critiques du CIS v8.1 (identifiants, groupes, types d'actifs et fonctions; libellés CRGO)",
           "8.1 (June 2024)", CIS_URL, None,
           "CIS Critical Security Controls v8.1 (c) Center for Internet Security, licensed CC BY-NC-ND 4.0; commercial use needs CIS approval. "
           "CRGO holds only identifiers, Implementation Group membership, asset types and security functions, with its own paraphrased labels. "
           "No CIS text is reproduced; see " + CIS_URL + ".", "Center for Internet Security (identifiers); CRGO (labels)",
           "18 controls and 153 safeguards. Values not checked against the CIS v8.1 workbook; those the drafting agent could not recall with "
           "confidence carry confidence Low and an editorial note beginning 'REVIEW:'. Correspondences are CRGO judgements ('partially overlaps').",
           imports=[VOC + "csf2", "https://w3id.org/crgo/crgo-context"])
SRC = "CIS Critical Security Controls v8.1 (%s); identifier and attributes as published, label a CRGO paraphrase" % CIS_URL
ASSET = {"DEV": "AssetTypeDevices", "APP": "AssetTypeSoftware", "DATA": "AssetTypeData", "NET": "AssetTypeNetwork", "USERS": "AssetTypeUsers",
         "DOC": "AssetTypeDocumentation", "NA": "AssetTypeNone"}
FUNC = {"GV": "GV", "ID": "ID", "PR": "PR", "DE": "DE", "RS": "RS", "RC": "RC"}
CONTROL_CSF = {"1": ["ID.AM"], "2": ["ID.AM"], "3": ["PR.DS"], "4": ["PR.PS"], "5": ["PR.AA"], "6": ["PR.AA"], "7": ["ID.RA", "PR.PS"],
               "8": ["DE.CM", "PR.PS"], "9": ["PR.PS"], "10": ["DE.CM"], "11": ["PR.DS", "RC.RP"], "12": ["PR.IR"], "13": ["DE.CM"],
               "14": ["PR.AT"], "15": ["GV.SC"], "16": ["PR.PS"], "17": ["RS.MA"], "18": ["ID.IM"]}
CONTROL_ISO = {"1": ["5.9"], "2": ["5.9", "8.19"], "3": ["5.12", "8.12"], "4": ["8.9"], "5": ["5.16", "5.18"], "6": ["5.15", "5.18", "8.5"],
               "7": ["8.8"], "8": ["8.15"], "9": ["8.23"], "10": ["8.7"], "11": ["8.13"], "12": ["8.20", "8.22"], "13": ["8.16"],
               "14": ["6.3"], "15": ["5.19", "5.22"], "16": ["8.25", "8.28"], "17": ["5.24", "5.26"]}
n_map = 0
for r in tsv("cis81.tsv"):
    i = r["id"]
    if "." not in i:
        c = s.concept(i, r["label_en"], r["label_fr"], source=SRC, conf="M", see_also=[CIS_URL])
        for t in CONTROL_CSF.get(i, []): s.g.add((c, PO, CSF[t])); n_map += 1
        for t in CONTROL_ISO.get(i, []): s.g.add((c, PO, ISO[t])); n_map += 1
        continue
    review = r["review"] or None
    c = s.concept(i, r["label_en"], r["label_fr"], broader=i.split(".")[0], source=SRC, conf="L" if review else "M", review=review,
                  see_also=["https://w3id.org/crgo/CRGO_%07d" % int(ids[k.strip()]) for k in r["crgo_classes"].split(";") if k.strip()])
    for ig in range(int(r["ig"]), 4):
        s.g.add((c, C("inImplementationGroup"), C("IG%d" % ig)))
    s.g.add((c, C("hasSafeguardAssetType"), C(ASSET[r["asset"]])))
    s.g.add((c, C("hasSecurityFunction"), CSF[FUNC[r["function"]]]))
    for t in filter(None, (x.strip() for x in r["sp80053"].split(";"))):
        s.g.add((c, PO, SP[t])); n_map += 1
report.append(("cis81", s.save(), n_map))

# ---------------------------------------------------------------- OWASP lists
OW = {"owasp-top10-2025": ("OWASP Top 10:2025 (category identifiers; CRGO labels)", "OWASP Top 10:2025 (identifiants de catégories; libellés CRGO)",
                           "2025", "https://owasp.org/Top10/2025/", "OWASP Foundation"),
      "owasp-llm-2025": ("OWASP Top 10 for LLM Applications 2025 (identifiers; CRGO labels)", "OWASP Top 10 des applications de grands modèles de langage 2025 (identifiants; libellés CRGO)",
                         "2025", "https://genai.owasp.org/llm-top-10/", "OWASP GenAI Security Project"),
      "owasp-agentic-2026": ("OWASP Top 10 for Agentic Applications 2026 (identifiers; CRGO labels)", "OWASP Top 10 des applications agentiques 2026 (identifiants; libellés CRGO)",
                             "2026 (released 2025-12-09)", "https://genai.owasp.org/", "OWASP GenAI Security Project")}
rows = tsv("owasp_011.tsv")
for key, (ten, tfr, ver, url, pub) in OW.items():
    s = Scheme(key, ten, tfr, ver, url, None,
               "Identifiers (c) OWASP Foundation, CC BY-SA 4.0. CRGO holds only the identifiers, with its own labels; see %s for the published text." % url,
               pub + " (identifiers); CRGO (labels)",
               "Links to the crgo-context scenario patterns are CRGO judgements ('partially overlaps').", imports=["https://w3id.org/crgo/crgo-context"])
    n_map = 0
    for r in rows:
        if r["scheme"] != key: continue
        c = s.concept(r["id"], r["label_en"], r["label_fr"], source="%s (%s); label a CRGO paraphrase" % (ten.split(" (")[0], url),
                      conf="H" if key == "owasp-top10-2025" else "M", see_also=[url])
        for p in filter(None, (x.strip() for x in r["patterns"].split(";"))):
            s.g.add((c, PO, C(p))); n_map += 1
    report.append((key, s.save(), n_map))

# ---------------------------------------------------------------- NAICS Canada 2022 sectors (from MOACCO)
MO = "http://www.semanticweb.org/maleger/ontologies/2022/3/MOACCO#"
MO_NAICS = {"11": "NAIC_Agriculture_forestry_fishing_hunting", "21": "NAIC_Mining_quarrying_and_oil_and_gas_extraction", "22": "NAIC_Utilities",
            "23": "NAIC_Construction", "31-33": "NAIC_Manufacturing", "41": "NAIC_Wholesale_trade", "44-45": "NAIC_Retail_trade",
            "48-49": "NAIC_Transportation_warehousing", "51": "NAIC_Information_cultural_industries", "52": "NAIC_Finance_insurance",
            "53": "NAIC_Real_estate_rental_leasing", "54": "NAIC_Professional_scientific_technical_services", "55": "NAIC_Management",
            "56": "NAIC_Administrative_support_waste_management_remediation_services", "61": "NAIC_Educational_services",
            "62": "NAIC_Health_care_social_assistance", "71": "NAIC_Arts_entertainment_recreation", "72": "NAIC_Accommodation_food_services",
            "81": "NAIC_Other_services", "91": "NAIC_Public_administration"}
s = Scheme("naics-sectors", "NAICS Canada 2022 sectors", "Secteurs du SCIAN Canada 2022", "2022 Version 1.0",
           "https://www.statcan.gc.ca/en/subjects/standard/naics/2022/v1/index", None,
           "Sector codes and titles of the North American Industry Classification System (NAICS) Canada 2022, Statistics Canada (Statistics Canada Open Licence).",
           "Statistics Canada", "Two-digit sectors, adapted from the NAICS classes of MOACCO (the author's earlier ontology), with Canadian codes. "
           "Organisations point to a sector with 'in industry sector' (crgo-context).")
for r in tsv("naics_sectors.tsv"):
    s.concept(r["id"], r["label_en"], r["label_fr"], source="NAICS Canada 2022 (Statistics Canada); adapted from MOACCO 1.2a NAICS classes", conf="M",
              derived=[MO + MO_NAICS[r["id"]]])
report.append(("naics-sectors", s.save(), 0))

# ---------------------------------------------------------------- glossary (from MOACCO)
s = Scheme("glossary", "CRGO cybersecurity glossary (adapted from MOACCO)", "Glossaire de cybersécurité de CRGO (adapté de MOACCO)", VERSION,
           "github.com/ITriskMgr/MOACCO (MOACCO_1-2a.owl, class Cybersecurity_Terms)", "https://creativecommons.org/licenses/by-nc/4.0/",
           "CC BY-NC 4.0, Marc-André Léger. Term list adapted from MOACCO 1.2a (MIT licence); definitions written for CRGO.", "CyberRiskGuardian Ontology",
           "Cybersecurity terms that MOACCO listed and CRGO had no term for. Each concept keeps the MOACCO class it was adapted from ('derived from') "
           "and points to related CRGO terms with rdfs:seeAlso. Not a replacement for the CRGO classes.")
for r in tsv("glossary_moacco.tsv"):
    s.concept(r["id"], r["label_en"], r["label_fr"], definition_en=r["def_en"], definition_fr=r["def_fr"],
              source="Adapted from MOACCO 1.2a, class %s (term only; definition by CRGO)" % r["moacco"], conf="M",
              see_also=["https://w3id.org/crgo/CRGO_%07d" % int(ids[k.strip()]) for k in r["see"].split(";") if k.strip()], derived=[MO + r["moacco"]])
report.append(("glossary", s.save(), 0))

for k, n, m in report:
    print("   %-20s %4d concepts, %3d typed correspondences" % (k, n, m))
