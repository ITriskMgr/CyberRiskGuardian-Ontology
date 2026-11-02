# CRGO 0.11.0: review for the project owner

Prepared 2026-11-02 under the CyberRiskGuardian 1.9.0 decision record (section "CRGO 0.11", binding). Everything listed here is
**proposed**: nothing in 0.11.0 is approved until the project owner records it in `src/approvals.tsv`. Approval keys are given
per group. Earlier approved terms are unchanged (no definition, label or axiom of an approved term was modified); only the module
headers (version 0.11.0) changed.

## 1. Groups to approve

| Key in `src/approvals.tsv` | What | Size |
|---|---|---|
| `terms/iam` | Module crgo-iam: identities, accounts, roles, entitlements, SoD, access lifecycle, privileged access, credentials (metadata only), emergency access, findings, configuration items, snapshots, baseline versions and requirements, deviations, change records, deployment gates, build attestations, service impact, outcome metrics, coverage observations, the seven register classes | 55 classes, 6 value sets (31 values), 61 object and 31 data properties |
| `terms/context` | Module crgo-context: AI systems and agents, model artefacts, certificates, cryptographic inventory, scenario patterns, technology in use, CIS implementation groups and asset types, MOACCO-derived organisation size, legal form, standard origin and obligation source; the added values *designated operator* (organisation type) and *technology condition* (condition kind) | 6 classes, 9 value sets (45 values), 16 object and 2 data properties |
| `legal/instruments-0110` | Critical Cyber Systems Protection Act (Bill C-8) | 1 instrument |
| `legal/standards-0110` | ISO/IEC 27701:2025, ISO/IEC 42001:2023, OWASP Top 10:2025, OWASP LLM 2025, OWASP Agentic 2026, CIS Controls v8.1 as Framework individuals | 6 |
| `legal/conditions-0110` | Six interpretive applicability conditions (CCSPA designated operator; 27701 personal information; 42001 AI systems; OWASP web, generative AI, AI agents) | 6 |
| `sources/records-0110` | Nine source records (MOACCO, CIS v8.1, OWASP x3, ISO x2, CCSPA, NAICS Canada 2022) | 9 |
| `cis81/*` | CIS v8.1 vocabulary: 18 controls, 153 safeguards, 170 typed correspondences | 171 concepts |
| `owasp-top10-2025/*`, `owasp-llm-2025/*`, `owasp-agentic-2026/*` | OWASP identifiers with CRGO labels, 13 links to scenario patterns | 30 concepts |
| `naics-sectors/*`, `glossary/*` | NAICS Canada 2022 sectors; 35 glossary terms adapted from MOACCO | 20 + 35 concepts |
| `tests/0.11.0` | Test expectation: CMP CQ1 now lists ISO/IEC 27701:2025 (potentially applicable) for Nordelle | 1 check |

## 2. Design choices to confirm

1. **Registers are counts, not people.** The register classes are *populations* (sub-classes of `population`, CRGO_0000528) or
   summary records; a SHACL shape rejects an account population that lists individual accounts. Individual identity, account,
   lease and session classes exist (spec v1.1 section 9.2) for organisations that need them, but CyberRiskGuardian stores none.
2. **Superclasses** (decision record): identities and accounts are information assets; identity sources, IdPs and vaults are
   software assets; roles, entitlements, permissions and leases are directives; SoD rule is a `control`; access policy and
   authoritative-source policy are technical standards; identity, privilege, SoD and configuration findings are `control gap
   finding`s (CRGO_0000018), not control deficiencies, because a deficiency needs an assessed control measure; baseline version is
   a `directive version` of a `configuration baseline` (CRGO_0000501), so approved versions need an approval decision and an
   effective date; configuration exceptions are `policy exception`s (CRGO_0000502); outcome metric is a `key risk indicator`
   (CRGO_0000034); authenticator assurance evidence is configuration evidence (`evidence`, CRGO_0000036).
3. **Not every deviation is a deficiency.** Baseline deviation is a description with one of the six drift classes of spec v1.1
   section 6.4; only degradation, functional, strengthening and unknown count against the baseline; a compensated deviation
   needs an exception that has not expired when the deviation was last checked (SHACL), so an expired exception never counts.
4. **Voluntary standards are never 'applicable'.** Their conditions are interpretive, so the evaluator returns at most
   *potentially applicable*; binding force comes from adoption (framework adoption) or a contract.
5. **CCSPA**: Royal Assent was announced on 2026-06-16 (Public Safety Canada); the Act comes into force in phases, so no in-force
   date is asserted and the designated-operator condition is interpretive. The enacted text, chapter number and section numbers
   were not read.
6. **CIS v8.1**: identifiers and attributes are recalled facts, not checked against the CIS workbook (no network access to it).
   39 safeguards carry confidence Low and a `REVIEW:` note: the v8.1 *Govern* function and *Documentation* asset type that the
   drafting agent recalls for process and policy safeguards (3.1, 4.1, 6.1, 6.2, 7.1, 7.2, 8.1, 11.1, 14.1, 15.2, 16.1, 17.3,
   17.4, 18.1; possibly 4.2, 12.2, 12.4, 16.2), the v8 "N/A" asset types of controls 14, 15, 17 and 18, and the function of 16.4.
   Implementation Group counts (56 / 130 / 153) match the published totals. Labels are CRGO's own, at most eight words.
7. **CIS ↔ other frameworks**: 'partially overlaps' only (CRGO judgement), at control level to CSF 2.0 categories and ISO/IEC
   27002:2022, at safeguard level to SP 800-53 Rev. 5; links to crgo-iam classes are `rdfs:seeAlso`, not mappings.
8. **Security function** of a CIS safeguard is given as the CSF 2.0 function concept (vocab/csf2 GV, ID, PR, DE, RS, RC) rather
   than a new value set.

## 3. MOACCO review (step 1 of the 0.11 work)

Source: `github.com/ITriskMgr/MOACCO`, file `MOACCO_1-2a.owl.zip` (86.9 MB RDF/XML, 590,874 triples, dated 2022-11-01).
Licence: repository `LICENSE` is MIT (© 2022 Marc-André Léger); the ontology header says `dc:rights` CC BY 3.0; the README says the
project "claim[s] no ownership of the material" it gathered. Recorded as source record `moacco-1.2a`. CRGO already cited MOACCO
1.2a (Herzog et al. Security.owl concepts) for threat source role and vulnerability since 0.1.0.

Inventory (owl:Class by namespace): 221,541 classes of a WebProtégé project, 221,539 of them CVE records modelled as classes;
8,843 WebProtégé classes (CWE research/software/hardware views, NICE NCWF 2017 tasks, knowledge, skills and abilities, ATT&CK
techniques, Immersive Labs course titles, ACFE fraud-examiner topics, CISSP domains, university course structures, compliance
categories and requirement kinds), 3,499 classes and 3,904 individuals of the US DoD JP 1-02 dictionary (Muninn project), 1,945
MOACCO classes, 997 classes and 1,148 individuals of an older D3FEND, 453 classes of the Linköping security ontology (Herzog),
79 classes of a security-metrics ontology, 42 classes of the ITSM ontology (ITSMO); 230 object and 48 data properties, mostly
D3FEND, ITSMO and Security.owl. The MOACCO classes are: a glossary of 229 cybersecurity terms (names only, no definitions),
NIST SP 800-53 families and controls (rev. 5 structure), ISO/IEC 27002:2013 clauses **with the standard's control text in
dc:description**, PCI DSS 3.x requirements, Common Criteria protection-profile categories, NAICS sectors, organisation size and
legal structure, standards typology, and laws and regulations by jurisdiction.

Brought into CRGO (re-identified as CRGO terms or vocabulary concepts, redefined in CRGO's words, aligned to BFO/CCO through the
existing classes, EN/FR labels, provenance by `derived from` (CRGO_0000287) to the MOACCO IRI and the evidence source "Adapted from
MOACCO ..."):
- organisation size (3 values), legal form (6), standard origin (5), obligation source (4: from the author's compliance-requirement
  classes), with properties *has organisation size*, *has legal form*, *in industry sector*, *has standard origin*, *has obligation
  source*;
- NAICS sectors as vocab/naics-sectors (20 sectors, Canadian NAICS 2022 codes and French SCIAN titles);
- 35 glossary terms CRGO lacked (attack surface, attack path, air gap, allow/block lists, APT, botnet, rootkit, spyware, trojan,
  worm, spoofing, data spill, digital forensics, red/blue/white team, tabletop exercise, penetration testing, moving target defence,
  security by design, SCRM, authenticity, non-repudiation, digital signature, (a)symmetric cryptography, hashing, PKI, work factor,
  situational awareness, information sharing, ICS, critical infrastructure, security automation) as vocab/glossary.

Not brought, and why:
- ISO/IEC 27002:2013 clauses: superseded by the 2022 edition already in CRGO, and MOACCO holds licensed ISO text that CRGO must
  not redistribute. **Author's judgement needed:** the public MOACCO repository itself redistributes that text.
- PCI DSS 3.x requirements: superseded (PCI DSS v4.0.1) and PCI SSC licence terms; a v4.0.1 identifier vocabulary could follow.
- NIST SP 800-53, ATT&CK, CWE, CVE, D3FEND copies: CRGO holds current versions from the publishers (5.2.0, ATT&CK 19.2, D3FEND 1.6.0,
  KEV); CVE records are not a vocabulary by design (roadmap).
- NICE NCWF 2017 tasks/knowledge/skills: superseded by the NICE Framework components v1.0+ (2024); a workforce vocabulary from the
  current NIST release is a candidate for a later version.
- Immersive Labs, ACFE, CISSP, GIAC, university course material: third-party or curricular, outside an ontology of risk.
- JP 1-02 military dictionary, Herzog's Security.owl, the metrics ontology and ITSMO: third-party ontologies with unclear terms;
  Security.owl concepts were already used as sources in 0.1.0; ITSMO's configuration item corroborates the crgo-iam class but
  nothing was derived from it.
- Common Criteria protection-profile categories (13): small and factual but marginal for CRG; candidate for later.
- Laws and regulations by jurisdiction, compliance categories: covered better by crgo-grc instruments and jurisdictions.
- Glossary terms already covered by CRGO classes or vocabularies (asset, threat, vulnerability, risk assessment, incident,
  phishing, malware, ransomware, encryption, firewall and so on), or too vague to define (analyze, investigate, targets).

## 4. Validation and what remains

`scripts/check.sh` with `WITH_LIBRARY=1` and ROBOT 1.9.11: see the release check paragraph of `CHANGELOG.md` (all checks pass
except the release gate CQ17, which waits for these approvals). Not done, needing the owner: WIDOCO documentation (`scripts/make_docs.py`
with `WIDOCO_JAR`; not run in this build), the library ABox and EPSS/KEV refresh, the
regenerated compliance and secops contract examples (no change of contract was needed), the w3id pull request (no new rule is
needed: `crgo-[a-z]+` and `vocab/[a-z0-9-]+` already cover the new IRIs), and the native French read-through.
