# -*- coding: utf-8 -*-
"""Build contracts/library-proposal/v1/examples/golden-grouping.json: inputs and expected outputs of crgo-grouping/1 and
crgo-validation/1 on the 0.11.2 export, shared with CyberRiskGuardian's browser port (js/crgo_group.js).

Run only when the rules or the export change on purpose (and then bump ALGORITHM_* in grouping.py if the rules changed):
    python3 tests/grouping/make_golden.py --write
Without --write it prints whether the committed golden file is current.

The MediBec cases use the 45 screening candidates of the fictional MediBec teaching case (CyberRiskGuardian
examples/medibec/source/data.py, CANDIDATES: ref, name, threat source, assets). Their free-text fields were mapped to
CRGO vocabulary by hand for this test (MAPPING below, recorded in the golden file): crown jewels and asset words to asset
categories, threat-source words to threat-source types, and a few ATT&CK techniques per candidate name (analyst mapping
for test purposes, not CRGO links). Themes are left empty so that the theme rules infer them.
"""
import json, os, sys
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "pipeline", "query"))
sys.path.insert(0, os.path.join(ROOT, "pipeline", "contracts"))
import grouping as G  # noqa: E402
import proposals as P  # noqa: E402

OUT = os.path.join(ROOT, "contracts", "library-proposal", "v1", "examples", "golden-grouping.json")

# ref, name, threat source (free text), assets (free text) — MediBec screening candidates C01-C45
MEDIBEC = [
 ("C01", "Phishing-led compromise of clinic administrator credentials", "Cybercriminal", "CJ5 / CJ1"),
 ("C02", "Ransomware encrypting EHR support systems, shared folders and scheduling", "Ransomware group", "CJ1 / CJ3 / CJ6"),
 ("C03", "Backup environment compromised before encryption, recovery fails", "Ransomware group / privileged attacker", "CJ6"),
 ("C04", "Cloud medical-image transfer storage exposed or accessed externally", "Opportunistic actor / cybercriminal", "CJ7"),
 ("C05", "API key committed to a code repository enables data access", "Opportunistic actor", "CJ1 / CJ7"),
 ("C06", "Clinic Wi-Fi compromise or rogue access point", "Local attacker", "Clinic LAN"),
 ("C07", "Exploitation of unpatched internet-facing or end-of-life systems", "Cybercriminal / state-linked actor", "CJ5 / CJ6"),
 ("C08", "Intrusion goes undetected because monitoring and triage are insufficient", "Any external actor", "All"),
 ("C09", "Connected medical device used as network foothold", "Cybercriminal", "CJ8"),
 ("C10", "DDoS against patient-facing online services", "Hacktivist / extortionist", "CJ3"),
 ("C11", "Staff member exports health or billing records for unauthorized purposes", "Malicious or curious insider", "CJ1 / CJ4"),
 ("C12", "Alteration of patient, medication or billing records", "Attacker or insider", "CJ1 / CJ2"),
 ("C13", "Compromise of a vendor with remote access to MediBec systems", "Supply-chain attacker", "CJ1 / CJ2 / CJ8"),
 ("C14", "Untested incident response plan causes poor coordination", "Any incident", "All"),
 ("C15", "Over-privileged service account (ehr-sync-svc) abused for mass extraction", "External attacker or insider", "CJ1"),
 ("C16", "Montreal data centre or WAN outage isolates all clinics", "Accidental / environmental", "CJ6"),
 ("C17", "Unmanaged copies on local clinic storage units exposed", "Theft / insider", "Clinic storage"),
 ("C18", "Business e-mail compromise diverts billing payments", "Fraudster", "CJ4"),
 ("C19", "Lost or stolen tablet or handheld with patient data", "Opportunistic thief", "Endpoints"),
 ("C20", "MFA push-fatigue bypass of remote access", "Cybercriminal", "CJ5"),
 ("C21", "Authorization flaw in patient portal exposes other patients' records", "External actor / patient", "CJ3 / CJ1"),
 ("C22", "Trojanized software update from a supplier", "Supply-chain actor", "Many hosts"),
 ("C23", "Cloud tenant takeover via token theft or consent phishing", "Cybercriminal", "CJ5 / CJ7"),
 ("C24", "Misdirected e-mail/fax or wrong-patient disclosure", "Negligent insider", "CJ1"),
 ("C25", "Teleconsultation or clinical messaging intercepted", "Opportunistic intruder", "Communications"),
 ("C26", "Exposed admin interfaces attacked with stuffed/default credentials", "Cybercriminal", "CJ6"),
 ("C27", "Malware on patient-supplied imaging media", "Commodity malware", "CJ2 / CJ8"),
 ("C28", "Data left on disposed devices and leased equipment", "Downstream buyer", "Retired assets"),
 ("C29", "Patient data pasted into public generative-AI tools", "Well-intentioned insider", "CJ1"),
 ("C30", "Help-desk vishing leads to MFA reset", "Social engineer", "CJ5"),
 ("C31", "Malicious or departing IT admin sabotage", "Privileged insider", "CJ5 / CJ6"),
 ("C32", "Interception/tampering of HL7/DICOM traffic", "Attacker with internal position", "CJ2"),
 ("C33", "Look-alike domains and smishing targeting patients", "Fraud group", "Patient trust"),
 ("C34", "Mass encryption of hypervisors", "Ransomware group", "CJ6"),
 ("C35", "Active Directory misconfiguration enables domain takeover", "Any intruder", "CJ5"),
 ("C36", "End-of-support workstation operating systems in clinics", "Cybercriminal", "Endpoints"),
 ("C37", "Cryptomining on cloud or server resources", "Cybercriminal", "Cloud"),
 ("C38", "Skimming on online payment page", "Fraudster", "Online payments"),
 ("C39", "Physical intrusion into clinic server closet", "Thief / intruder", "Clinic equipment"),
 ("C40", "Insufficient logs to prove breach scope", "Any incident", "All"),
 ("C41", "Clinician mailbox compromise used to harvest PHI", "Cybercriminal", "Mail"),
 ("C42", "AI scribe SaaS mishandles recordings", "Third party", "CJ1"),
 ("C43", "Building IoT or CCTV used as foothold", "Cybercriminal", "Clinic LAN"),
 ("C44", "Excessive data retention amplifies breach size", "N/A (amplifier)", "All data"),
 ("C45", "Firewall single point of failure", "Accidental / attacker", "CJ6"),
]
MAPPING = {
 "assets": {"CJ1 (EHR and clinical record data)": ["CatApplication", "CatInformation"],
            "CJ2 (radiology, laboratory, pharmacy systems)": ["CatApplication"],
            "CJ3 (scheduling and patient online services)": ["CatApplication"],
            "CJ4 (billing and administrative systems)": ["CatApplication", "CatInformation"],
            "CJ5 (identity, remote access and cloud access)": ["CatIdentity"],
            "CJ6 (data centre, WAN and backups)": ["CatInfrastructure", "CatNetwork"],
            "CJ7 (cloud storage for image transfer)": ["CatCloud", "CatInformation"],
            "CJ8 (connected medical equipment and IoT)": ["CatOTIoT"],
            "Clinic LAN": ["CatNetwork"], "Clinic storage": ["CatInfrastructure", "CatInformation"], "Endpoints": ["CatEndpoint"],
            "Many hosts": ["CatEndpoint", "CatInfrastructure"], "Communications": ["CatNetwork"], "Retired assets": ["CatEndpoint", "CatInformation"],
            "Mail": ["CatApplication"], "Cloud": ["CatCloud"], "Online payments": ["CatApplication"], "Clinic equipment": ["CatFacility", "CatInfrastructure"],
            "All data": ["CatInformation"], "All": [], "Patient trust": []},
 "threat_sources": {"Accidental / environmental": ["SrcAccidental", "SrcEnvironmental"], "Accidental / attacker": ["SrcAccidental", "SrcAdversarial"],
                    "Negligent insider": ["SrcAccidental"], "Well-intentioned insider": ["SrcAccidental"],
                    "Any incident": [], "N/A (amplifier)": [], "(any other source)": ["SrcAdversarial"]},
 "techniques": {"C01": ["T1566"], "C02": ["T1486"], "C03": ["T1490", "T1486"], "C04": ["T1530"], "C05": ["T1552"], "C06": ["T1557"],
                "C07": ["T1190"], "C09": ["T1210"], "C10": ["T1498"], "C11": ["T1005"], "C12": ["T1565"], "C13": ["T1199", "T1133"],
                "C15": ["T1078"], "C18": ["T1566"], "C20": ["T1621"], "C21": ["T1190"], "C22": ["T1195"], "C23": ["T1528", "T1550"],
                "C25": ["T1557"], "C26": ["T1110", "T1078"], "C27": ["T1091"], "C30": ["T1566.004"], "C31": ["T1485"], "C32": ["T1557"],
                "C33": ["T1583.001", "T1566"], "C34": ["T1486"], "C35": ["T1558.003", "T1484"], "C36": ["T1203"], "C37": ["T1496"],
                "C38": ["T1059.007"], "C41": ["T1114", "T1566"], "C43": ["T1210"]},
 "note": "Analyst mapping of the MediBec screening's free text to CRGO vocabulary, for this test only; themes left empty (inferred).",
}
CJ = {k.split(" ")[0]: v for k, v in MAPPING["assets"].items() if k.startswith("CJ")}

def medibec_candidates():
    out = []
    for ref, name, src, assets in MEDIBEC:
        cats = []
        for a in [x.strip() for x in assets.split("/")]:
            for c in CJ.get(a, MAPPING["assets"].get(a, [])):
                if c not in cats: cats.append(c)
        ts = MAPPING["threat_sources"].get(src, MAPPING["threat_sources"]["(any other source)"])
        c = {"ref": ref, "name": name, "asset_categories": cats, "threat_source_types": ts}
        if ref in MAPPING["techniques"]: c["techniques"] = MAPPING["techniques"][ref]
        out.append(c)
    return out

# proposals approved into the golden local extension: two with the same name (tie on everything but the id)
PROPOSALS = [
 {"name": "Zorblax telemetry relay hijacked by a rogue drone fleet", "statement": "A rogue drone fleet hijacks the Zorblax telemetry relay of the organisation's logistics yard, sending false positions to dispatch.",
  "themes": ["ThemeMedicalIoT"], "asset_categories": ["CatOTIoT"], "threat_source_types": ["SrcAdversarial"], "techniques": [["T1557", "M"]],
  "proposed_by": "Analyst A", "proposed_on": "2026-11-12", "anonymized": True},
 {"name": "Quillon ledger forged by a payroll robot", "statement": "A payroll robot forges entries in the Quillon ledger so that payments go to accounts it controls.",
  "themes": ["ThemeIntegrity"], "asset_categories": ["CatApplication"], "threat_source_types": ["SrcAdversarial"], "techniques": [["T1565", "M"]],
  "proposed_by": "Analyst A", "proposed_on": "2026-11-12", "anonymized": True},
 {"name": "Quillon ledger forged by a payroll robot", "statement": "A payroll robot alters Quillon ledger balances overnight; the second wording of the same scenario.",
  "themes": ["ThemeIntegrity"], "asset_categories": ["CatApplication"], "threat_source_types": ["SrcAdversarial"], "techniques": [["T1565", "H"]],
  "proposed_by": "Analyst B", "proposed_on": "2026-11-12", "anonymized": True},
]

def local_extension(ref):
    recs = [G.local_record(P.proposal_id(p), p, ref, "Admin", "2026-11-12") for p in PROPOSALS]
    return {"schema": "crgo-local-extension/1", "release_built_against": ref.release, "scenarios": G.local_clusters(recs, ref)}

SYNTH = [
 {"ref": "S-REVOKED", "name": "Attackers disable endpoint security tools before deploying ransomware", "techniques": ["T1562", "T1486"], "asset_categories": ["CatEndpoint"]},
 {"ref": "S-UNKNOWN", "name": "Ransomware encrypts the file servers", "techniques": ["T9999", "t1486"], "asset_categories": ["CatNope", "infrastructure"],
  "threat_source_types": ["SrcMartian", "adversarial"], "themes": ["ThemeNope"], "cwe": ["CWE-0", "79"]},
 {"ref": "S-GAP-1", "name": "Zorblax telemetry relay hijacked by rogue drones", "themes": ["ThemeMedicalIoT"], "techniques": ["T1557"], "asset_categories": ["CatOTIoT"]},
 {"ref": "S-GAP-2", "name": "Frobnicated telemetry relay of the yard", "themes": ["ThemeMedicalIoT"], "techniques": ["T1557.002"], "asset_categories": ["CatOTIoT"]},
 {"ref": "S-OWN", "name": "Wibble wobble glorp", "statement": "Wibble wobble glorp snark."},
 {"ref": "S-TIE-1", "name": "Quillon ledger forged by payroll robot", "themes": ["ThemeIntegrity"]},
 {"ref": "S-TIE-2", "name": "Quillon ledger forged by a payroll robot", "themes": ["ThemeIntegrity"]},
 {"ref": "S-KEPT-LIB", "name": "Anything at all", "crgo_id": "LIB-F1353"},
 {"ref": "S-KEPT-CASE", "name": "Our firewall case", "crgo_id": "ACRB/ACRB-A1"},
 {"ref": "S-BADID", "name": "Phishing of clinic staff credentials", "crgo_id": "LIB-F999999"},
 {"ref": "S-NFC", "name": "Phishing attack on healthcare staff   réseau", "statement": "Café staff are phished."},
]
VALIDATE = [
 ("v-revoked", {"name": "Attackers disable endpoint security tools before deploying ransomware", "techniques": ["T1562", "T1486"], "asset_categories": ["CatEndpoint"]}),
 ("v-cwe-unlinked", {"name": "Phishing of clinic staff credentials", "techniques": ["T1566"], "cwe": ["CWE-89"], "asset_categories": ["CatIdentity"]}),
 ("v-cwe-consistent", {"name": "Cross-site scripting in the patient portal", "techniques": ["T1190"], "cwe": ["CWE-79"], "asset_categories": ["CatApplication"]}),
 ("v-cwe-no-reference", {"name": "Cross-site scripting in the patient portal", "techniques": ["T1190"], "cwe": ["CWE-1037"], "asset_categories": ["CatApplication"]}),
 ("v-outside", {"name": "Wibble wobble glorp", "statement": "Wibble wobble glorp snark."}),
 ("v-facet-match", {"name": "Glorp exfiltration of patient records", "techniques": ["T1048"], "asset_categories": ["CatInformation"]}),
 ("v-unknown-vocab", {"name": "Ransomware encrypts the file servers", "techniques": ["T9999"], "asset_categories": ["CatNope"], "threat_source_types": ["SrcMartian"],
                      "themes": ["ThemeNope"], "cwe": ["CWE-0"], "crgo_id": "LIB-F999999"}),
 ("v-kept-case", {"name": "Our firewall case", "crgo_id": "ACRB/ACRB-A1"}),
 ("v-local", {"name": "Zorblax telemetry relay hijacked by rogue drones", "themes": ["ThemeMedicalIoT"], "techniques": ["T1557"], "asset_categories": ["CatOTIoT"]}),
]

def build():
    ref = G.load_reference()
    for c in medibec_candidates():
        for t in c.get("techniques", []): assert t in ref.active, t
    ext = local_extension(ref)
    local = ext["scenarios"]
    data = {"grouping": json.load(open(os.path.join(ROOT, "data", "export", "crgo-identification.json"), encoding="utf-8"))["grouping"],
            "records": sorted([r["id"], r["cluster"], r["primary_theme"]] for r in ref.records)}
    cases = []
    def add(cid, tool, inp, use_local, conf="M"):
        L = local if use_local else []
        exp = G.group(inp, ref, L, conf) if tool == "crgo_group_candidates" else G.validate(inp, ref, L, conf)
        cases.append({"id": cid, "tool": tool, "local": use_local, "min_confidence": conf, "input": inp, "expected": exp})
    mb = medibec_candidates()
    add("medibec-45", "crgo_group_candidates", mb, False)
    add("medibec-45-confidence-L", "crgo_group_candidates", mb, False, "L")
    add("synthetic-edge-cases", "crgo_group_candidates", SYNTH, False)
    add("synthetic-edge-cases-with-local", "crgo_group_candidates", SYNTH, True)
    for cid, s in VALIDATE:
        add("validate-" + cid, "crgo_validate_scenario", s, cid == "v-local")
    add("validate-v-local-without-local", "crgo_validate_scenario", dict(VALIDATE[-1][1]), False)
    return {"schema": "crgo-grouping-golden/1", "algorithms": [G.ALGORITHM_GROUP, G.ALGORITHM_VALID], "release": ref.release,
            "data_fingerprint": __import__("hashlib").sha256(G.canonical(data).encode("utf-8")).hexdigest(),
            "data_fingerprint_note": "sha256 of the canonical JSON of {grouping: the export's grouping block, records: sorted [id, cluster, primary_theme] of every scenario}; equal on the snapshot when it carries the same data",
            "how_to_replay": "For each case, call the tool (or its offline port) with input (a list of candidates, or one scenario), min_confidence, and the local records local_extension.scenarios when local is true (else none); the result must deep-equal expected.",
            "medibec_source": "CyberRiskGuardian examples/medibec/source/data.py CANDIDATES (fictional teaching case): ref, name, threat source, assets",
            "medibec_mapping": MAPPING, "local_extension": ext, "local_proposals": PROPOSALS, "cases": cases}

if __name__ == "__main__":
    g = build()
    text = json.dumps(g, ensure_ascii=False, indent=1, sort_keys=True) + "\n"
    if "--write" in sys.argv:
        open(OUT, "w", encoding="utf-8").write(text); print("written", OUT, len(text), "bytes")
    else:
        cur = open(OUT, encoding="utf-8").read() if os.path.isfile(OUT) else ""
        print("golden file is current" if cur == text else "golden file differs (run with --write after checking the change)")
        sys.exit(0 if cur == text else 1)
