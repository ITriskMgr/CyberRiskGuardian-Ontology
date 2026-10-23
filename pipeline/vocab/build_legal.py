# -*- coding: utf-8 -*-
"""0.9.0: legal instruments, applicability conditions and source records.

Writes
  ontology/vocab/legal.ttl    one LegalInstrument per row of data/frameworks/legal_instruments.tsv, with jurisdiction,
                              kind, citation, dates (OWL-Time in-force interval only where the text states the date),
                              'provision of' links from every concept of the legal vocabularies, and the applicability
                              conditions of data/frameworks/applicability_conditions.tsv
  ontology/vocab/sources.ttl  one SourceRecord per row of docs/baseline/source_registry.csv, and 'has source record'
                              links from each vocabulary (concept scheme), the mappings, the library and the instruments
Approval groups (src/approvals.tsv): legal/instruments, legal/conditions, sources/records.
Conditions are CRGO paraphrases and interpretations; they stay proposed until the project owner approves them, and an
interpretive condition can only yield 'potentially applicable' (pipeline/grc/applicability.py)."""
import csv, os, sys
from rdflib import Graph, Namespace, URIRef, Literal, BNode
from rdflib.namespace import RDF, RDFS, OWL, XSD, SKOS, DCTERMS

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
VERSION = "0.10.1"
BASE = "https://w3id.org/crgo/"
LEG = Namespace(BASE + "vocab/legal/"); SRC = Namespace(BASE + "vocab/sources/"); VOC = BASE + "vocab/"
TIME = Namespace("http://www.w3.org/2006/time#"); PROV = Namespace("http://www.w3.org/ns/prov#")
ids = dict(l.rstrip("\n").split("\t") for l in open(os.path.join(ROOT, "src", "ids.tsv"), encoding="utf-8"))
T = lambda k: URIRef(BASE + "CRGO_%07d" % int(ids[k]))
APPROVALS = {}
for l in open(os.path.join(ROOT, "src", "approvals.tsv"), encoding="utf-8"):
    if l.strip() and not l.startswith("#"):
        k, d, who, date, *_ = l.rstrip("\n").split("\t"); APPROVALS[k] = (d, who, date)
dt = lambda d: Literal(d + "T00:00:00", datatype=XSD.dateTime)
tsv = lambda f: list(csv.DictReader(open(os.path.join(ROOT, f), encoding="utf-8"), delimiter="\t"))

def gov(g, s, group, conf, source, introduced="0.9.0"):
    a = APPROVALS.get(group)
    if a and a[0] == "Approve":
        g.add((s, T("governanceStatus"), T("StatusApproved"))); g.add((s, T("approvedBy"), T("AgentMAL")))
        g.add((s, T("approvalDate"), Literal(a[2], datatype=XSD.date)))
    else:
        g.add((s, T("governanceStatus"), T("StatusProposed")))
    g.add((s, T("confidence"), T({"H": "ConfHigh", "M": "ConfMedium", "L": "ConfLow"}[conf])))
    g.add((s, T("proposedBy"), T("AgentClaude"))); g.add((s, T("evidenceSource"), Literal(source, lang="en")))
    g.add((s, T("introducedIn"), Literal(introduced)))

def header(g, name, title_en, title_fr, desc):
    g.bind("crgo", BASE); g.bind("time", TIME); g.bind("skos", SKOS); g.bind("dcterms", DCTERMS); g.bind("prov", PROV)
    o = URIRef(VOC + name)
    g.add((o, RDF.type, OWL.Ontology)); g.add((o, OWL.versionInfo, Literal(VERSION)))
    g.add((o, OWL.versionIRI, URIRef("%svocab/%s/%s" % (BASE, VERSION, name))))
    g.add((o, DCTERMS.title, Literal(title_en, lang="en"))); g.add((o, DCTERMS.title, Literal(title_fr, lang="fr")))
    g.add((o, DCTERMS.description, Literal(desc, lang="en")))
    g.add((o, DCTERMS.license, URIRef("https://creativecommons.org/licenses/by-nc/4.0/")))
    g.add((o, OWL.imports, URIRef(BASE + "crgo")))
    return o

# ---------------------------------------------------------------- sources.ttl
gs = Graph(); header(gs, "sources", "CRGO source records", "Notices de source de CRGO",
                     "One source record per dataset, publication or legal text CRGO content comes from (docs/baseline/source_registry.csv).")
SCHEME_SOURCES = {"a21": ["qc-a-2.1"], "attack": ["mitre-attack-19.2"], "capec": ["mitre-capec-3.9"], "ccm41": ["csa-ccm-4.1"],
                  "cobit2019": ["cobit-2019"], "csf2": ["nist-csf-2.0", "nist-csf-2.0-fr"], "cwe": ["mitre-cwe-via-d3fend"],
                  "d3fend": ["mitre-d3fend-1.6.0"], "gdpr": ["eu-gdpr"], "iso27002-2022": ["iso-iec-27002-2022"], "kev": ["cisa-kev"],
                  "loi25": ["qc-p-39.1"], "lrsss": ["qc-r-22.1"], "osfi-b13": ["osfi-b13"], "pipeda": ["ca-pipeda"],
                  "sp800-53r5": ["nist-sp800-53r5"], "sp800-53a": ["nist-sp800-53a-r5"], "iia-gias": ["iia-gias-2024"],
                  "iia-tr": ["iia-tr-cyber", "iia-tr-third-party", "iia-tr-orgbehav"], "itaf": ["isaca-itaf-5"], "tsc": ["aicpa-tsc-2017"],
                  "coso-erm": ["coso-erm-2017"], "iso19011": ["iso-19011-2018"], "iso27007": ["iso-iec-27007-2020"], "iso27008": ["iso-iec-ts-27008-2019"],
                  "iso37301": ["iso-37301-2021", "iso-37301-2021-amd1-2024"],
                  "attack-detection": ["mitre-attack-19.2"], "ocsf": ["ocsf-1.9.0"], "iso37302": ["iso-37302-2025"],
                  "mappings": ["ctid-mappings", "nist-cprt-csf", "nist-csf11-80053", "nist-olir-80053-27001", "mitre-capec-3.9", "cisa-kev", "mitre-d3fend-1.6.0", "nist-sp800-53a-r5"]}
LIB_SOURCES = ["crg-2023-scenarios", "teaching-cases", "first-epss", "vcdb", "leger-cyber-gov-3e-v2.51"]  # 0.10.1: the MediBec worked CRG assessment follows the textbook v2.51
ACCESS = {"VERIFIED": "AccessVerified", "PENDING_ACCESS": "AccessPendingAccess", "LICENSE_RESTRICTED": "AccessLicenceRestricted", "REJECTED": "AccessRejected"}
RECORDS_2026_10_11 = {"bfo-2020", "cco-2.2", "nist-csf-2.0", "nist-csf-2.0-fr", "nist-sp800-53r5", "nist-cprt-csf", "nist-csf11-80053", "nist-olir-80053-27001",
    "iso-iec-27002-2022", "cobit-2019", "csa-ccm-4.1", "mitre-attack-19.2", "mitre-capec-3.9", "mitre-d3fend-1.6.0", "mitre-cwe-via-d3fend", "cisa-kev",
    "ctid-mappings", "first-epss", "vcdb", "qc-p-39.1", "qc-a-2.1", "qc-r-22.1", "ca-pipeda", "osfi-b13", "eu-gdpr", "uk-gdpr", "crg-2023-scenarios",
    "teaching-cases", "iso-27005-31000-sp80030"}
RECORDS_PCA = {"iso-37301-2021-amd1-2024"}  # 0.10.0 (policy, compliance and audit management)
RECORDS_SECOPS = {"nist-sp800-61r3", "ocsf-1.9.0", "sigma-spec-2.1.0", "oasis-stix-2.1", "oasis-cacao-2.0", "first-tlp-2.0", "otel-logs"}  # 0.10.0 SIEM/SOAR
RECORDS_0101 = {"leger-cyber-gov-3e-v2.51"}  # 0.10.1: the textbook the CRG method follows (approved 2026-10-23)
reg = list(csv.DictReader(open(os.path.join(ROOT, "docs", "baseline", "source_registry.csv"), encoding="utf-8")))
known = set()
for r in reg:
    s = SRC[r["source_id"]]; known.add(r["source_id"])
    gs.add((s, RDF.type, OWL.NamedIndividual)); gs.add((s, RDF.type, T("SourceRecord")))
    gs.add((s, RDFS.label, Literal(r["title"], lang="en"))); gs.add((s, T("localIdentifier"), Literal(r["source_id"])))
    for col, key in (("issuer", "issuerName"), ("official_identifier_or_url", "officialIdentifier"), ("licence_or_terms", "licenceTerms"),
                     ("redistribution_in_crgo", "redistributionTerms"), ("verification_status", "verificationNote")):
        if r[col]: gs.add((s, T(key), Literal(r[col])))
    if r["version_used"]: gs.add((s, T("sourceVersion"), Literal(r["version_used"])))
    if r["retrieved_on"]: gs.add((s, T("retrievedOn"), dt(r["retrieved_on"])))
    for h in filter(None, r["sha256"].split(";")): gs.add((s, T("checksumSha256"), Literal(h)))
    if r["notes"]: gs.add((s, RDFS.comment, Literal(r["notes"], lang="en")))
    if r.get("access_status"):
        gs.add((s, T("hasAccessStatus"), T(ACCESS[r["access_status"]])))
    # the group approval sources/records of 2026-10-11 covers the 29 records that existed then; later records have their own group
    group = ("sources/records" if r["source_id"] in RECORDS_2026_10_11 else "sources/records-pca" if r["source_id"] in RECORDS_PCA
             else "sources/records-secops" if r["source_id"] in RECORDS_SECOPS else "sources/records-0101" if r["source_id"] in RECORDS_0101
             else "sources/records-grca")
    gov(gs, s, group, "H", "docs/baseline/source_registry.csv (Stage 0, GRCA sprint and 0.10.0)",
        "0.10.1" if r["source_id"] in RECORDS_0101 else "0.10.0" if r["source_id"] in RECORDS_PCA | RECORDS_SECOPS else "0.9.0")
for k, srcs in SCHEME_SOURCES.items():
    for sid in srcs:
        assert sid in known, sid
        gs.add((URIRef(VOC + k), T("hasSourceRecord"), SRC[sid]))
for sid in LIB_SOURCES:
    gs.add((URIRef(BASE + "data/library"), T("hasSourceRecord"), SRC[sid]))

# ---------------------------------------------------------------- legal.ttl
gl = Graph(); header(gl, "legal", "CRGO legal instruments and applicability conditions", "Instruments juridiques et conditions d'applicabilité de CRGO",
                     "Legal instruments behind the CRGO legal vocabularies, their provisions and the conditions under which they apply. "
                     "Conditions are CRGO paraphrases for evaluation over an organisation profile; they are not legal advice.")
gl.add((URIRef(VOC + "legal"), OWL.imports, URIRef(VOC + "sources")))
inst = {}
for r in tsv("data/frameworks/legal_instruments.tsv"):
    s = LEG[r["id"]]; inst[r["id"]] = s
    gl.add((s, RDF.type, OWL.NamedIndividual)); gl.add((s, RDF.type, T("LegalInstrument")))
    gl.add((s, RDFS.label, Literal(r["title_en"], lang="en"))); gl.add((s, RDFS.label, Literal(r["title_fr"], lang="fr")))
    gl.add((s, T("officialCitation"), Literal(r["citation"]))); gl.add((s, T("hasJurisdiction"), T(r["jurisdiction"])))
    gl.add((s, T("hasInstrumentKind"), T(r["kind"]))); gl.add((s, T("hasSourceRecord"), SRC[r["source_id"]]))
    for col, key in (("published", "publishedOn"), ("applies_from", "appliesFrom"), ("last_amended", "lastAmendedOn"), ("consolidated_to", "consolidatedTo")):
        if r[col]: gl.add((s, T(key), dt(r[col])))
    if r["in_force_from"]:  # OWL-Time interval, open-ended while not repealed
        iv, b = LEG[r["id"] + "-in-force"], LEG[r["id"] + "-in-force-start"]
        gl.add((iv, RDF.type, OWL.NamedIndividual)); gl.add((iv, RDF.type, TIME.ProperInterval)); gl.add((iv, TIME.hasBeginning, b))
        gl.add((b, RDF.type, OWL.NamedIndividual)); gl.add((b, RDF.type, TIME.Instant))
        gl.add((b, TIME.inXSDDateTimeStamp, Literal(r["in_force_from"] + "T00:00:00Z", datatype=XSD.dateTimeStamp)))
        gl.add((s, T("hasInForcePeriod"), iv))
    if r["note"]: gl.add((s, RDFS.comment, Literal(r["note"], lang="en")))
    gov(gl, s, "legal/instruments", "H", "data/frameworks/legal_instruments.tsv; dates as printed in the source PDFs (data/raw/external/legal)")
# provisions: every concept of a legal vocabulary belongs to the instrument its notation names
PREFIX = sorted(((r["prefix"], r["id"]) for r in tsv("data/frameworks/legal_instruments.tsv") if r["prefix"]), key=lambda x: -len(x[0]))
n_prov = 0
extra = {}  # Loi 25 obligations also made under a regulation (data/frameworks/loi25.tsv, column act)
for r in tsv("data/frameworks/loi25.tsv"):
    for a in [x.strip() for x in r["act"].split(";")][1:]:
        extra.setdefault(r["key"], []).append({"A-2.1, r. 3.1": "A-2.1-r3.1", "A-2.1, r. 0.1": "A-2.1-r0.1"}[a])
sys.path.insert(0, os.path.join(ROOT, "pipeline", "vocab")); from ids_loi25 import loi25_notation  # noqa: E402
extra_by_notation = {}
for r in tsv("data/frameworks/loi25.tsv"):
    if r["key"] in extra: extra_by_notation[loi25_notation(r["act"], r["section"])] = extra[r["key"]]
for k in ("loi25", "a21", "lrsss", "pipeda", "gdpr", "osfi-b13"):
    v = Graph().parse(os.path.join(ROOT, "ontology", "vocab", k + ".ttl"))
    for c, n in v.subject_objects(SKOS.notation):
        n = str(n)
        target = "OSFI-B-13" if k == "osfi-b13" else next((i for p, i in PREFIX if n == p or n.startswith(p + " ")), None)
        assert target, (k, n)
        gl.add((c, T("provisionOf"), inst[target])); n_prov += 1
        for t in extra_by_notation.get(n, []):
            gl.add((c, T("provisionOf"), inst[t])); n_prov += 1
# applicability conditions
n_cond = 0
for r in tsv("data/frameworks/applicability_conditions.tsv"):
    s = LEG["condition/" + r["id"]]
    gl.add((s, RDF.type, OWL.NamedIndividual)); gl.add((s, RDF.type, T("ApplicabilityCondition")))
    gl.add((s, RDFS.label, Literal(r["label_en"], lang="en"))); gl.add((s, RDFS.label, Literal(r["label_fr"], lang="fr")))
    gl.add((s, T("conditionOf"), inst[r["instrument"]])); gl.add((s, T("hasConditionKind"), T(r["kind"])))
    gl.add((s, T("conditionTest"), Literal("%s|%s|%s" % (r["role"], r["test"], "interpretive" if r["interpretive"] == "y" else "plain"))))
    gl.add((s, T("localIdentifier"), Literal(r["id"]))); gl.add((s, SKOS.note, Literal("Citation: " + r["citation"], lang="en")))
    gov(gl, s, "legal/conditions", "M" if r["interpretive"] == "y" else "H",
        "CRGO paraphrase of %s (data/frameworks/applicability_conditions.tsv); interpretation, not legal advice" % r["citation"])
    n_cond += 1
for g, name in ((gs, "sources"), (gl, "legal")):
    g.serialize(os.path.join(ROOT, "ontology", "vocab", name + ".ttl"), format="turtle")
print("sources: %d records; legal: %d instruments, %d provision links, %d conditions" % (len(reg), len(inst), n_prov, n_cond))
