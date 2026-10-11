# -*- coding: utf-8 -*-
"""0.7.0: vocabularies and cross-references imported from public sources (nothing typed by hand).

Vocabularies (ontology/vocab/):
- cwe:    MITRE CWE weaknesses, as carried by D3FEND 1.6.0 (labels, definitions, CWE hierarchy).
- d3fend: MITRE D3FEND 1.6.0 defensive techniques (broader = parent technique).
- capec:  MITRE CAPEC attack patterns (STIX bundle from github.com/mitre/cti; broader = ChildOf).
- kev:    CISA Known Exploited Vulnerabilities catalogue (github.com/cisagov/kev-data).
Cross-references (ontology/vocab/mappings.ttl), each an annotated assertion with its source, confidence and status:
- CAPEC -> ATT&CK and CAPEC -> CWE (CAPEC's own references), confidence H;
- ATT&CK -> SP 800-53 "mitigated by" (MITRE CTID Mappings Explorer, ATT&CK 16.1), confidence H;
- KEV CVE -> ATT&CK (CTID KEV mapping) and KEV CVE -> CWE (CISA's own field), confidence H;
- ATT&CK -> D3FEND for the 212 techniques the scenario library uses, judged by Claude (data/library/d3fend_judged.jsonl,
  prompt d3fend_judged_prompt.md) with confidence H/M/L. D3FEND's digital-artifact relations served only as hints:
  matching on shared artifacts alone was tried twice and rejected after independent review (40-link samples: 14 correct,
  15 weak, 11 wrong; then 16 correct, 12 weak, 12 wrong). The judged links scored 28 correct, 16 weak, 1 wrong on 45.
ATT&CK identifiers revoked after 16.1 are translated to their 19.2 replacements.
"""
import json, os, re, sys, collections
import rdflib
from rdflib import Graph, Literal, URIRef, BNode, Namespace
from rdflib.namespace import RDF, RDFS, OWL, SKOS, DCTERMS, XSD
HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, HERE)
import build_vocab as BV  # noqa: E402  (Scheme, C, safe, approvals); importing rebuilds the base vocabularies
X = os.path.join(ROOT, "data", "raw", "external")
D3 = "http://d3fend.mitre.org/ontologies/d3fend.owl#"
d3 = Graph(); d3.parse(os.path.join(X, "d3fend-1.6.0.ttl"))
P = lambda n: URIRef(D3 + n)
lab = lambda c: next((str(l) for l in d3.objects(c, RDFS.label)), None)
val = lambda c, p: next((str(l) for l in d3.objects(c, P(p))), None)
INTRO = "0.7.0"

# --- CWE (from D3FEND) -----------------------------------------------------------------------------------------------
cwe = BV.Scheme("cwe", "MITRE CWE weaknesses (as carried by D3FEND)", "Faiblesses MITRE CWE (telles que reprises par D3FEND)", "D3FEND 1.6.0",
                "https://github.com/d3fend/d3fend-ontology (src/ontology/d3fend-protege.ttl, 2026-10-08)", None,
                "CWE (c) The MITRE Corporation, used under the CWE Terms of Use (https://cwe.mitre.org/about/termsofuse.html); D3FEND (c) The MITRE Corporation, MIT licence.",
                "The MITRE Corporation", "Weaknesses as structured in D3FEND 1.6.0; broader = parent weakness.")
cwes = {}
for c in set(d3.subjects(P("cwe-id"), None)):
    cwes[c] = val(c, "cwe-id")
for c, n in sorted(cwes.items(), key=lambda x: int(x[1].split("-")[1])):
    par = next((cwes[p] for p in d3.objects(c, RDFS.subClassOf) if p in cwes), None)
    cwe.concept(n, lab(c) or n, broader=par, definition_en=val(c, "definition"), see_also="https://cwe.mitre.org/data/definitions/%s.html" % n.split("-")[1],
                source="MITRE CWE via D3FEND 1.6.0", introduced=INTRO)
# --- D3FEND defensive techniques ---------------------------------------------------------------------------------------
dfd = BV.Scheme("d3fend", "MITRE D3FEND defensive techniques", "Techniques défensives MITRE D3FEND", "1.6.0",
                "https://github.com/d3fend/d3fend-ontology (src/ontology/d3fend-protege.ttl, 2026-10-08)", "https://opensource.org/licenses/MIT",
                "D3FEND (c) The MITRE Corporation, MIT licence.", "The MITRE Corporation", "Defensive techniques; broader = parent technique; top concepts are D3FEND's tactics.")
def _desc(root):
    out, st = set(), [root]
    while st:
        x = st.pop()
        for k in d3.subjects(RDFS.subClassOf, x):
            if k not in out: out.add(k); st.append(k)
    return out
# defensive techniques only (D3FEND also gives ids to its catalogue of analytic algorithms, "D3A-", which are not defences)
_dt = _desc(P("DefensiveTechnique"))
defs = {c: val(c, "d3fend-id") for c in set(d3.subjects(P("d3fend-id"), None)) if c in _dt and val(c, "d3fend-id").startswith("D3-")}
for c, n in sorted(defs.items(), key=lambda x: x[1]):
    par = next((defs[p] for p in d3.objects(c, RDFS.subClassOf) if p in defs), None)
    dfd.concept(n, lab(c) or n, broader=par, definition_en=val(c, "definition"), see_also="https://d3fend.mitre.org/technique/d3f:%s/" % str(c).split("#")[1],
                source="MITRE D3FEND 1.6.0", introduced=INTRO)
# --- CAPEC -----------------------------------------------------------------------------------------------------------
bundle = json.load(open(os.path.join(X, "capec-stix.json")))
cap = BV.Scheme("capec", "MITRE CAPEC attack patterns", "Patrons d'attaque MITRE CAPEC", next((o.get("x_capec_version") for o in bundle["objects"] if o.get("x_capec_version")), "3.9"),
                "https://github.com/mitre/cti (capec/2.1/stix-capec.json)", None,
                "CAPEC (c) The MITRE Corporation, used under the CAPEC Terms of Use (https://capec.mitre.org/about/termsofuse.html).",
                "The MITRE Corporation", "Attack patterns; broader = ChildOf parent pattern.")
byid = {o["id"]: o for o in bundle["objects"]}
cext = lambda o: next((r for r in o.get("external_references", []) if r.get("source_name") == "capec"), None)
patterns = [o for o in bundle["objects"] if o["type"] == "attack-pattern" and not o.get("revoked") and not o.get("x_capec_status") == "Deprecated" and cext(o)]
active_cap = {cext(o)["external_id"] for o in patterns}
cap_map_attack, cap_map_cwe = [], []
for o in sorted(patterns, key=lambda o: int(cext(o)["external_id"].split("-")[1])):
    cid = cext(o)["external_id"]
    par = next((cext(byid[r])["external_id"] for r in o.get("x_capec_child_of_refs", []) if r in byid and cext(byid[r]) and cext(byid[r])["external_id"] in active_cap), None)
    desc = re.sub(r"\s+", " ", o.get("description", "")).strip()
    cap.concept(cid, o["name"], broader=par, definition_en=desc[:1200] or None, see_also=cext(o).get("url"), source="MITRE CAPEC", introduced=INTRO)
    for r in o.get("external_references", []):
        if r.get("source_name") == "ATTACK" and r.get("external_id"):
            cap_map_attack.append((cid, "T" + r["external_id"].lstrip("T")))
        if r.get("source_name") == "cwe" and r.get("external_id"):
            cap_map_cwe.append((cid, r["external_id"]))
_ids = dict(l.rstrip("\n").split("\t") for l in open(os.path.join(ROOT, "src", "ids.tsv"), encoding="utf-8"))
TERM = lambda k: URIRef("https://w3id.org/crgo/CRGO_%07d" % int(_ids[k]))
# --- KEV -------------------------------------------------------------------------------------------------------------
kevd = json.load(open(os.path.join(X, "cisa_kev.json")))
kev = BV.Scheme("kev", "CISA Known Exploited Vulnerabilities", "Vulnérabilités exploitées connues (CISA)", kevd["catalogVersion"],
                "https://github.com/cisagov/kev-data (known_exploited_vulnerabilities.json)", None,
                "Published by the U.S. Cybersecurity and Infrastructure Security Agency (CISA); U.S. government work.", "CISA",
                "Vulnerabilities with evidence of active exploitation. Used as exploitation evidence for ATT&CK techniques and CWE weaknesses, not as an inventory of an organisation's vulnerabilities.")
kev_cwe = []
for v in kevd["vulnerabilities"]:
    note = "Added to KEV %s; known ransomware campaign use: %s." % (v["dateAdded"], v.get("knownRansomwareCampaignUse", "Unknown"))
    kc = kev.concept(v["cveID"], v["vulnerabilityName"], definition_en=v.get("shortDescription"), note=note,
                see_also="https://nvd.nist.gov/vuln/detail/%s" % v["cveID"], source="CISA KEV catalogue %s" % kevd["catalogVersion"], introduced=INTRO)
    # 0.9.0: KEV date and ransomware use as typed data (gap G7); the note is kept for readers
    kev.g.add((kc, TERM("kevDateAdded"), Literal(v["dateAdded"] + "T00:00:00", datatype=XSD.dateTime)))
    kev.g.add((kc, TERM("knownRansomwareUse"), Literal(v.get("knownRansomwareCampaignUse", "Unknown"))))
    for w in v.get("cwes") or []:
        kev_cwe.append((v["cveID"], w))
NCON = {sc.key: sc.save() for sc in (cwe, dfd, cap, kev)}
# --- mappings --------------------------------------------------------------------------------------------------------
att = Graph(); att.parse(os.path.join(ROOT, "ontology", "vocab", "attack.ttl"))
rep = {str(att.value(s, SKOS.notation)): str(att.value(o, SKOS.notation)) for s, o in att.subject_objects(DCTERMS.isReplacedBy)}
att_ids = {str(o) for o in att.objects(None, SKOS.notation)}
def norm_t(t):
    seen = set()
    while t in rep and t not in seen:
        seen.add(t); t = rep[t]
    return t
VOC = BV.VOC
m = Graph(); mo = URIRef(VOC + "mappings")
for p, n in [("skos", SKOS), ("dcterms", DCTERMS), ("crgo", "https://w3id.org/crgo/"), ("owl", OWL)]:
    m.bind(p, n)
m.add((mo, RDF.type, OWL.Ontology)); m.add((mo, OWL.versionIRI, URIRef(VOC + BV.VERSION + "/mappings")))
m.add((mo, DCTERMS.title, Literal("CRGO cross-references between framework vocabularies", lang="en")))
m.add((mo, DCTERMS.title, Literal("Correspondances CRGO entre vocabulaires de référentiels", lang="fr")))
m.add((mo, OWL.versionInfo, Literal(BV.VERSION)))
m.add((mo, DCTERMS.license, URIRef("https://creativecommons.org/licenses/by-nc/4.0/")))
m.add((mo, DCTERMS.rights, Literal("Cross-references compiled by CRGO from the sources named on each assertion: MITRE CAPEC references, MITRE CTID Mappings Explorer (Apache 2.0), CISA KEV, D3FEND (MIT).", lang="en")))
m.add((mo, OWL.imports, URIRef("https://w3id.org/crgo/crgo-mapping")))
# 0.9.0: proposed correspondences are kept apart, in mappings-proposed.ttl, which crgo-full does not import (gap G5)
mp = Graph(); mpo = URIRef(VOC + "mappings-proposed")
for p_, n_ in m.namespaces(): mp.bind(p_, n_)
mp.add((mpo, RDF.type, OWL.Ontology)); mp.add((mpo, OWL.versionIRI, URIRef(VOC + BV.VERSION + "/mappings-proposed")))
mp.add((mpo, OWL.versionInfo, Literal(BV.VERSION))); mp.add((mpo, OWL.imports, URIRef("https://w3id.org/crgo/crgo-mapping")))
mp.add((mpo, DCTERMS.title, Literal("CRGO proposed cross-references (not approved; not imported by crgo-full)", lang="en")))
mp.add((mpo, DCTERMS.title, Literal("Correspondances proposées par CRGO (non approuvées; non importées par crgo-full)", lang="fr")))
mp.add((mpo, DCTERMS.license, URIRef("https://creativecommons.org/licenses/by-nc/4.0/")))
# 0.9.0: each meaning has its own relation, a sub-property of the SKOS one (decision D3); keyed by approval group
TYPED = {"capec-attack": "attackPatternRelatedToTechnique", "capec-cwe": "attackPatternExploitsWeakness",
         "ctid-attack-800-53": "mitigatedByControl", "ctid-kev-attack": "vulnerabilityAssociatedWithTechnique",
         "kev-cwe": "vulnerabilityInstanceOfWeakness", "d3fend-judged": "counteredByDefensiveTechnique",
         "loi25-a21": "sameObligationOtherRegime", "loi25-pipeda": "comparableObligation", "loi25-gdpr": "comparableObligation",
         "b13-csf2": "principleAddressedByCategory", "nist-csf2-800-53-derived": "subcategorySupportedByControl",
         "nist-olir-800-53-iso27002": "controlCorrespondsToControl"}
cnt = collections.Counter()
valid = {k: {str(o) for o in Graph().parse(os.path.join(ROOT, "ontology", "vocab", k + ".ttl")).objects(None, SKOS.notation)} for k in ("cwe", "capec", "sp800-53r5", "d3fend", "kev")}
valid["attack"] = att_ids
def link(s_scheme, s_id, p, o_scheme, o_id, source, conf, kind, group, note=None):
    if s_id not in valid[s_scheme] or o_id not in valid[o_scheme]:
        cnt["skipped (identifier not in vocabulary): " + group] += 1; return
    s = URIRef(VOC + s_scheme + "/" + BV.safe(s_id)); o = URIRef(VOC + o_scheme + "/" + BV.safe(o_id))
    ok = BV.APPROVALS.get(group)
    tg = m if ok and ok[0] == "Approve" else mp  # proposed correspondences go to the proposal file
    tp = TERM(TYPED[group.split("/")[1]])
    tg.add((s, p, o)); tg.add((s, tp, o)); a = BNode()
    for t in [(a, RDF.type, OWL.Axiom), (a, OWL.annotatedSource, s), (a, OWL.annotatedProperty, p), (a, OWL.annotatedTarget, o),
              (a, BV.C("confidence"), BV.CONF[conf]), (a, BV.C("proposedBy"), BV.C("AgentClaude")),
              (a, BV.C("evidenceSource"), Literal(source, lang="en")), (a, RDFS.comment, Literal(kind + ((": " + note) if note else ""), lang="en")),
              (a, BV.C("governanceStatus"), BV.C("StatusApproved" if ok and ok[0] == "Approve" else "StatusProposed"))]:
        tg.add(t)
    if ok and ok[0] == "Approve":
        tg.add((a, BV.C("approvedBy"), BV.C("Agent" + ok[1]))); tg.add((a, BV.C("approvalDate"), Literal(ok[2], datatype=XSD.date)))
    cnt[group] += 1
for c, t in sorted(set(cap_map_attack)):
    link("capec", c, SKOS.relatedMatch, "attack", norm_t(t), "MITRE CAPEC (ATT&CK reference)", "H", "CAPEC pattern related to ATT&CK technique", "mappings/capec-attack")
for c, w in sorted(set(cap_map_cwe)):
    link("capec", c, SKOS.relatedMatch, "cwe", w, "MITRE CAPEC (related weakness)", "H", "attack pattern exploits weakness", "mappings/capec-cwe")
ctid = json.load(open(os.path.join(X, "ctid_nist_800_53-rev5_attack-16.1.json")))
seen = set()
for x in ctid["mapping_objects"]:
    if x["mapping_type"] != "mitigates": continue
    t, c = norm_t(x["attack_object_id"]), re.sub(r"-0*(\d+)", r"-\1", x["capability_id"])
    if (t, c) in seen: continue
    seen.add((t, c))
    link("attack", t, SKOS.relatedMatch, "sp800-53r5", c, "MITRE CTID Mappings Explorer, NIST SP 800-53 Rev. 5 to ATT&CK 16.1 (last update 2025-04-16)", "H", "technique mitigated by control", "mappings/ctid-attack-800-53")
kctid = json.load(open(os.path.join(X, "ctid_kev_attack-16.1.json")))
for x in kctid["mapping_objects"]:
    if x.get("mapping_type") and x.get("attack_object_id") and x.get("capability_id"):
        link("kev", x["capability_id"], SKOS.relatedMatch, "attack", norm_t(x["attack_object_id"]), "MITRE CTID Mappings Explorer, KEV to ATT&CK 16.1 (2025-07-28)", "H",
             "vulnerability %s technique" % x["mapping_type"].replace("_", " "), "mappings/ctid-kev-attack")
for v, w in sorted(set(kev_cwe)):
    link("kev", v, SKOS.relatedMatch, "cwe", w, "CISA KEV catalogue (cwes field)", "H", "vulnerability is an instance of weakness", "mappings/kev-cwe")
# ATT&CK -> D3FEND, judged (see module docstring)
for l in open(os.path.join(ROOT, "data", "library", "d3fend_judged.jsonl"), encoding="utf-8"):
    x = json.loads(l)
    for it in x["d3fend"]:
        link("attack", norm_t(x["technique"]), SKOS.relatedMatch, "d3fend", it["id"], "Judged by Claude against MITRE D3FEND 1.6.0 (2026-10-11)", it["c"],
             "technique countered by defensive technique", "mappings/d3fend-judged/" + it["c"])
# Québec public-sector Act (A-2.1) <-> private-sector Act (Loi 25): same duty under the other regime (0.8.0)
import csv as _csv
for r in _csv.DictReader(open(os.path.join(ROOT, "data", "frameworks", "a21.tsv"), encoding="utf-8"), delimiter="\t"):
    for eq in filter(None, r["loi25_equivalent"].split("|")):
        if "a21" not in valid:
            valid["a21"] = {str(o) for o in Graph().parse(os.path.join(ROOT, "ontology", "vocab", "a21.ttl")).objects(None, SKOS.notation)}
            valid["loi25"] = {str(o) for o in Graph().parse(os.path.join(ROOT, "ontology", "vocab", "loi25.ttl")).objects(None, SKOS.notation)}
        link("loi25", eq, SKOS.closeMatch, "a21", "A-2.1 s. " + r["section"], "CRGO correspondence between CQLR c. P-39.1 and c. A-2.1 (texts verified on LégisQuébec, 2026-10-11)",
             "H", "same obligation for a public body", "mappings/loi25-a21")
# PIPEDA <-> Loi 25 (comparable obligation under federal law) and OSFI B-13 principle <-> CSF 2.0 category (0.8.0)
for k in ("pipeda", "osfi-b13", "csf2"):
    valid[k] = {str(o) for o in Graph().parse(os.path.join(ROOT, "ontology", "vocab", k + ".ttl")).objects(None, SKOS.notation)}
for r in _csv.DictReader(open(os.path.join(ROOT, "data", "frameworks", "pipeda.tsv"), encoding="utf-8"), delimiter="\t"):
    for eq in filter(None, r["loi25_equivalent"].split("|")):
        link("loi25", eq, SKOS.relatedMatch, "pipeda", "PIPEDA " + r["provision"], "CRGO correspondence between CQLR c. P-39.1 and PIPEDA (texts verified, 2026-10-11)",
             "M", "comparable obligation under federal private-sector law", "mappings/loi25-pipeda")
# GDPR <-> Loi 25 (comparable obligation under EU law), 0.9.0
valid["gdpr"] = {str(o) for o in Graph().parse(os.path.join(ROOT, "ontology", "vocab", "gdpr.ttl")).objects(None, SKOS.notation)}
for r in _csv.DictReader(open(os.path.join(ROOT, "data", "frameworks", "gdpr.tsv"), encoding="utf-8"), delimiter="\t"):
    for eq in filter(None, r["loi25_equivalent"].split("|")):
        link("loi25", eq, SKOS.relatedMatch, "gdpr", "GDPR " + r["provision"], "CRGO correspondence between CQLR c. P-39.1 and Regulation (EU) 2016/679 (OJ text read 2026-10-11)",
             r["match_conf"], "comparable obligation under EU law" if r["match_conf"] == "M" else "partly comparable obligation under EU law (differences in scope or trigger)",
             "mappings/loi25-gdpr/" + r["match_conf"])
for r in _csv.DictReader(open(os.path.join(ROOT, "data", "frameworks", "osfi_b13.tsv"), encoding="utf-8"), delimiter="\t"):
    for c in filter(None, r["csf2"].split("|")):
        link("osfi-b13", r["id"], SKOS.relatedMatch, "csf2", c, "CRGO correspondence between OSFI B-13 principles and NIST CSF 2.0 categories (judged, 2026-10-11)",
             "M", "principle addressed by CSF category", "mappings/b13-csf2")
# NIST crosswalks supplied by the project owner (0.8.0; pipeline/external/nist_crosswalks.py)
valid["iso27002-2022"] = {str(o) for o in Graph().parse(os.path.join(ROOT, "ontology", "vocab", "iso27002-2022.ttl")).objects(None, SKOS.notation)}
for r in _csv.DictReader(open(os.path.join(ROOT, "data", "library", "nist_csf2_80053.csv"), encoding="utf-8")):
    link("csf2", r["csf2"], SKOS.relatedMatch, "sp800-53r5", r["sp80053r5"], "Derived by CRGO from NIST's CSF 1.1 to SP 800-53r5 mapping and the CSF 2.0 withdrawal records (NIST CPRT export, 2026-10-11)",
         "M", "subcategory supported by control" + ("" if r["basis"] == "kept" else " (" + r["basis"] + ")"), "mappings/nist-csf2-800-53-derived")
for r in _csv.DictReader(open(os.path.join(ROOT, "data", "library", "nist_80053_iso27002.csv"), encoding="utf-8")):
    link("sp800-53r5", r["sp80053r5"], SKOS.relatedMatch, "iso27002-2022", r["iso27002"], "NIST OLIR mapping of SP 800-53r5 to ISO/IEC 27001:2022 (updated 2023-10-12), Annex A controls",
         "H", "control related to ISO/IEC 27002 control", "mappings/nist-olir-800-53-iso27002")
m.serialize(os.path.join(ROOT, "ontology", "vocab", "mappings.ttl"), format="turtle")
mp.serialize(os.path.join(ROOT, "ontology", "vocab", "mappings-proposed.ttl"), format="turtle")
for k, n in NCON.items():
    print("%-8s %5d concepts" % (k, n))
for k, v in sorted(cnt.items()): print("  %-50s %d" % (k, v))
