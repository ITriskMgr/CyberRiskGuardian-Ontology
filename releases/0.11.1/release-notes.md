# CRGO 0.11.1 release notes

Patch release of the CyberRiskGuardian Ontology for CyberRiskGuardian 1.9.2 (findings NV-C01 to NV-C08 of the test campaign of 8 November 2026). The full list of changes is in `CHANGELOG.md`; the term-level change report is `change-report.md` beside this file.

## What changed, in short

- **Input validation (NV-C01, NV-C02, NV-C03).** `pipeline/query/identify.py` validates every argument before it reaches a SPARQL query (ATT&CK ids, requirement ids, scenario ids, IRIs, filter values, confidence); `pipeline/mcp/crgo_server.py` returns error documents (`INVALID_ARGUMENT`, `UNKNOWN_ID`, and the contract codes) instead of a bare "Error executing tool". Result bounds (`limit`, `top`, `per_theme`, `max_total`) are clamped to 1..200; list arguments take at most 50 values of at most 100 characters; unknown ATT&CK ids are reported in `unknown_techniques`.
- **Write-back path (NV-C04).** `crgo_submit_assessment` validates the document before anything else, resolves symlinks and refuses any path inside the repository except `build/` with the new code `REPOSITORY_PATH`; missing or unreadable organisation graph files give `INVALID_ARGUMENT`; a malformed `as_of` gives `SCHEMA_INVALID` in all three contracts.
- **CIS Controls v8.1 in `crgo_scenarios_for_control` (NV-C06).** `framework='cis81'` reaches library scenarios through the requirements the safeguard partially overlaps (`via`, `through_parent` for an enhancement's base control); unknown frameworks list the allowed ones.
- **`check.sh` (NV-C07, NV-C08).** The SHACL shapes are generated to `build/` and compared with the tracked file; the README documents the prerequisites (ROBOT 1.9.6 from GitHub releases, pySHACL, about 35 minutes with the library).
- **Content review (NV-C05).** Eleven library families and the ACRB-A1 case scenario re-themed; seven family names without their trailing colon; four CIS v8.1 French labels corrected (14.2, 14.6, 14.7 « Enseigner à ... », 17.9 without « de sécurité »). No value, estimate or risk index changed.
- **French terminology of CyberRiskGuardian 1.9.2 (decisions FR-2, FR-3).** « probabilité » instead of « vraisemblance » (class *likelihood*, « vraisemblance » kept as alternative label; four French definitions) and « élément(s) probant(s) » instead of « preuve(s) » on 37 evidence terms. IRIs, meanings and English wording unchanged; each term carries a `skos:changeNote`.

## CIS Controls v8.1 safeguards still flagged `REVIEW:` (39)

These safeguards were accepted as delivered in 0.11.0 **without verification against the CIS v8.1 workbook** (project owner, 2026-11-02) and stay so in 0.11.1: confidence Low, `skos:editorialNote` `REVIEW:`, status approved. The labels are CRGO paraphrases, never CIS text; cite CIS by identifier. Checking them against the CIS publication stays on the roadmap. The spot check of the campaign (`crgo-spotcheck.log`) found no problem in a sample of 30 scenarios and lists these 39.

| Safeguard | IG | CRGO label (en) | CRGO label (fr) | What to verify |
|---|---|---|---|---|
| 3.1 | 123 | Run a documented data management process | Appliquer un processus documenté de gestion des données | v8.1 Govern/Documentation recalled (v8: Data, Identify); verify |
| 4.1 | 123 | Run a secure configuration process | Appliquer un processus de configuration sécuritaire | v8.1 Govern/Documentation recalled (v8: Applications, Protect); verify |
| 4.2 | 123 | Securely configure network infrastructure | Configurer l'infrastructure réseau de façon sécuritaire | v8.1 may classify as Govern/Documentation; verify |
| 6.1 | 123 | Run a process to grant access | Appliquer un processus d'octroi des accès | v8.1 Govern/Documentation recalled (v8: Users, Protect); verify |
| 6.2 | 123 | Run a process to revoke access | Appliquer un processus de révocation des accès | v8.1 Govern/Documentation recalled (v8: Users, Protect); verify |
| 7.1 | 123 | Run a vulnerability management process | Appliquer un processus de gestion des vulnérabilités | v8.1 Govern/Documentation recalled (v8: Applications, Protect); verify |
| 7.2 | 123 | Run a remediation process | Appliquer un processus de correction | v8.1 Govern/Documentation recalled (v8: Applications, Respond); verify |
| 8.1 | 123 | Run an audit log management process | Appliquer un processus de gestion des journaux | v8.1 Govern/Documentation recalled (v8: Network, Protect); verify |
| 11.1 | 123 | Run a data recovery process | Appliquer un processus de récupération des données | v8.1 Govern/Documentation recalled (v8: Data, Recover); verify |
| 12.2 | 23 | Maintain a secure network architecture | Maintenir une architecture réseau sécuritaire | v8.1 may classify as Govern/Documentation; verify |
| 12.4 | 23 | Keep network architecture diagrams | Tenir des schémas d'architecture réseau | v8.1 may classify as Documentation; verify |
| 14.1 | 123 | Run a security awareness programme | Mener un programme de sensibilisation | v8.1 Govern/Documentation recalled (v8: N/A, Protect); verify |
| 14.2 | 123 | Teach recognising social engineering | Enseigner à reconnaître l'ingénierie sociale | asset type (v8: N/A) to verify for v8.1 |
| 14.3 | 123 | Teach good authentication habits | Enseigner les bonnes pratiques d'authentification | asset type (v8: N/A) to verify for v8.1 |
| 14.4 | 123 | Teach safe data handling | Enseigner la manipulation sécuritaire des données | asset type (v8: N/A) to verify for v8.1 |
| 14.5 | 123 | Teach causes of accidental data exposure | Enseigner les causes d'exposition accidentelle | asset type (v8: N/A) to verify for v8.1 |
| 14.6 | 123 | Teach spotting and reporting incidents | Enseigner à repérer et signaler les incidents | asset type (v8: N/A) to verify for v8.1 |
| 14.7 | 123 | Teach reporting missing security updates | Enseigner à signaler les mises à jour manquantes | asset type (v8: N/A) to verify for v8.1 |
| 14.8 | 123 | Teach risks of insecure networks | Enseigner les risques des réseaux non sécurisés | asset type (v8: N/A) to verify for v8.1 |
| 14.9 | 23 | Give role-specific security training | Offrir une formation adaptée aux fonctions | asset type (v8: N/A) to verify for v8.1 |
| 15.1 | 123 | Keep an inventory of service providers | Tenir un inventaire des fournisseurs de services | asset type (v8: N/A) to verify for v8.1 |
| 15.2 | 23 | Set a service provider management policy | Établir une politique de gestion des fournisseurs | v8.1 Govern/Documentation recalled (v8: N/A, Identify); verify |
| 15.3 | 23 | Tier service providers by risk | Classer les fournisseurs selon le risque | asset type (v8: N/A) to verify for v8.1 |
| 15.4 | 23 | Put security terms in provider contracts | Inclure des exigences de sécurité aux contrats | asset type (v8: N/A) to verify for v8.1 |
| 15.5 | 3 | Evaluate service providers' security | Évaluer la sécurité des fournisseurs | asset type (v8: N/A) to verify for v8.1 |
| 16.1 | 23 | Run a secure development process | Appliquer un processus de développement sécuritaire | v8.1 Govern/Documentation recalled (v8: Applications, Protect); verify |
| 16.2 | 23 | Run a process for reported software flaws | Traiter les vulnérabilités logicielles signalées | v8.1 may classify as Govern/Documentation; verify |
| 16.4 | 23 | Inventory third-party software components | Inventorier les composants logiciels de tiers | security function (Protect or Identify) to verify |
| 17.1 | 123 | Name people to manage incidents | Désigner les responsables de la gestion des incidents | asset type (v8: N/A) to verify for v8.1 |
| 17.2 | 123 | Keep incident reporting contacts current | Tenir à jour les contacts de signalement | asset type (v8: N/A) to verify for v8.1 |
| 17.3 | 123 | Run a process to report incidents | Appliquer un processus de signalement des incidents | v8.1 Govern/Documentation recalled (v8: N/A, Respond); verify |
| 17.4 | 23 | Run an incident response process | Appliquer un processus de réponse aux incidents | v8.1 Govern/Documentation recalled (v8: N/A, Respond); verify |
| 17.5 | 23 | Assign incident response roles | Attribuer les rôles de réponse aux incidents | asset type (v8: N/A) to verify for v8.1 |
| 17.6 | 23 | Set communication means for incidents | Prévoir les moyens de communication en incident | asset type (v8: N/A) to verify for v8.1 |
| 17.7 | 23 | Exercise incident response regularly | Exercer régulièrement la réponse aux incidents | asset type (v8: N/A) to verify for v8.1 |
| 17.8 | 23 | Review incidents afterwards | Revoir les incidents après coup | asset type (v8: N/A) to verify for v8.1 |
| 17.9 | 3 | Set incident thresholds | Fixer les seuils d'incident | asset type (v8: N/A) to verify for v8.1 |
| 18.1 | 23 | Run a penetration testing programme | Mener un programme de tests d'intrusion | v8.1 Govern/Documentation recalled (v8: N/A, Identify); verify |
| 18.5 | 3 | Penetration-test from inside regularly | Effectuer des tests d'intrusion internes réguliers | asset type (v8: N/A) to verify for v8.1 |

## Check results

Release check (`scripts/check.sh`, `WITH_LIBRARY=1`, ROBOT 1.9.6, pySHACL 0.40.2, Java 21, 8 November 2026, about 35 minutes): **all checks passed**: HermiT and ELK consistent with no unsatisfiable classes; OWL 2 DL (modules and crgo-full); 1 positive and 16 negative OWL fixtures; 1,598 of 1,598 terms approved with complete metadata and unique labels; 41 SKOS vocabularies; MediBec round trip 84,305 / 41,023 with 10 sensitivity cases (CRG_CALC not set: the committed graph was checked); SHACL conforms with the three deliberate warnings (640 s) and 90 negative shapes tests, the tracked shapes found current (isomorphic); no critical pitfalls; store 1,013,623 asserted + 317,770 inferred triples; 27 CQs and the identification tests (33 checks); 27 specification, 57 GRCA, 91 policy/compliance/audit/SIEM/SOAR and 25 IAM checks; Nordelle samples consistent and in OWL 2 DL; 45,972 w3id IRIs resolved; tenants separated; 36 DSS and 31 read-contract checks. `tests/mcp/test_mcp_errors.py`: 44 calls, all as expected, repository unchanged outside `build/`.
