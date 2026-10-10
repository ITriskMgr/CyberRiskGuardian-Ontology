# CRGO identification interface: blind end-to-end evaluation on MediBec

Evaluator role: CyberRiskGuardian (CRG) using `pipeline/query/identify.py`. Date: 2026-10-09.
Profile source: `/home/claude/cases/raw/medibec.txt` (MediBec v2.0b; no file has "v2" in its name, this is the v2.0b text), sections 1-12 only (student narrative, technology environment, threat context, injects T-10 to T+30, audit universe, student-facing scenario list MED-CYR-01..15, Appendices A-F). Instructor Annexes A and B were not read. `tests/crg/medibec30.json` and `data/library/case_scenarios.json` were opened only after the candidate list was fixed.

All calls used `include_cases=False` so that the interface could not return MediBec's own case scenarios (see finding L1: with the default `include_cases=True`, a ransomware query returns `MediBec-CRG/S2`, which is the expert answer itself).

## 1. Calls made (step 1, blind)

| # | Profile driver | Call (all with `include_cases=False`) | Matches |
|---|---|---|---|
| C01 | Ransomware / EHR outage inject (T-0) | `identify(themes=["ThemeRansomware"], sector="health", limit=10)` | 77 |
| C02 | Phishing inject (T-10), Appendix A | `identify(themes=["ThemeSocialEng"], limit=10)` | 129 |
| C03 | MFA push approved, unusual login (T-5) | `identify(themes=["ThemeAccess"], keywords=["mfa","credential","authentication","password"], limit=10)` | 59 |
| C04 | Cloud image-transfer storage downloads (T-3) | `identify(themes=["ThemeCloud"], keywords=["misconfig","storage","bucket","exposed","public"], limit=10)` | 26 |
| C05 | API key / repositories (audit universe) | `identify(keywords=["api key","api","secret","repository"], limit=10)` | 24 |
| C06 | Clinic Wi-Fi | `identify(keywords=["wireless","wi-fi","wifi","rogue access"], limit=10)` | 33 |
| C07 | Patch delays, device constraints | `identify(themes=["ThemeVulnMgmt"], keywords=["patch","unpatched","outdated","legacy"], limit=10)` | 53 |
| C08 | Backup failures (T-1) | `identify(keywords=["backup"], limit=10)` | 33 |
| C09 | Alert closed as low, IDS/IPS | `identify(keywords=["intrusion detection","ids","monitoring","logging","siem","detect"], limit=10)` | 55 |
| C10 | Interconnected medical equipment | `identify(themes=["ThemeMedicalIoT"], limit=10)` | 136 |
| C11 | Online booking / patient services | `identify(themes=["ThemeDoS"], keywords=["ddos","denial"], limit=10)` | 21 |
| C12 | Insider export of records | `identify(themes=["ThemeInsider"], keywords=["insider","exfiltrat","employee","staff"], limit=10)` | 173 |
| C13 | Record integrity | `identify(themes=["ThemeIntegrity"], limit=10)` | 139 |
| C14 | EHR, cloud, device vendors | `identify(themes=["ThemeThirdParty"], limit=10)` | 100 |
| C15 | Untested IR plan | `identify(themes=["ThemeContinuity"], keywords=["incident response","plan","tabletop","recovery"], limit=10)` | 23 |
| C16 | ATT&CK from injects | `identify(techniques=["T1566","T1059","T1078","T1486","T1567","T1490","T1530","T1621"], limit=15)` | 424 |
| C17 | Privacy / notification | `identify(themes=["ThemeCompliance","ThemeDataBreach"], sector="health", keywords=["privacy","health","patient","breach","notification"], limit=10)` | 121 |
| C18 | Remote access | `identify(themes=["ThemeNetwork"], keywords=["remote access","vpn","segmentation"], limit=10)` | 30 |
| C19 | Over-privileged `ehr-sync-svc` (App. B) | `identify(keywords=["privilege","service account","admin"], limit=10)` | 68 |
| C20 | Tablets, handhelds | `identify(themes=["ThemeEndpoint"], keywords=["tablet","mobile","endpoint","device","lost"], limit=10)` | 55 |
| C21 | Sweep over health information | `identify(asset_categories=["CatInformation"], sector="health", limit=15)` | 851 |
| C22 | Journalist inject, trust | `identify(themes=["ThemeReputation"], limit=6)` | 28 |
| C23 | Voice/video/messaging systems | `identify(keywords=["email","voice","video","messaging","telehealth","telemedicine"], limit=8)` | 93 |
| C24 | 2-person security team | `identify(themes=["ThemeITGov"], keywords=["staff","skill","budget","governance","shortage"], limit=8)` | 13 |
| C25 | Backup isolation / recovery | `identify(keywords=["backup server","exposed backup","immutable","offline backup","recovery"], limit=8)` | 9 |
| C26 | MFA fatigue | `identify(keywords=["mfa fatigue","push","session hijack","token"], limit=8)` | 5 |
| C27 | Macro to PowerShell | `identify(techniques=["T1059","T1204"], limit=8)` | 49 |
| C28 | Encrypted storage | `identify(themes=["ThemeCrypto"], keywords=["encrypt"], limit=8)` | 30 |
| C29 | Awareness | `identify(keywords=["awareness","training"], limit=8)` | 28 |
| C30 | Local clinic storage (physical) | `identify(themes=["ThemePhysical"], sector="health", limit=8)` | 138 |
| C31 | Segmentation / lateral movement | `identify(keywords=["segmentation","lateral movement","flat network"], limit=8)` | 9 |
| C32 | EHR access | `identify(keywords=["ehr","electronic health record"], limit=10)` | 6 |
| C33 | Radiology, lab, pharmacy | `identify(keywords=["radiology","pacs","imaging","laboratory","pharmacy"], limit=10)` | 20 |
| C34 | Clinic outages | `identify(themes=["ThemeContinuity","ThemeDoS"], sector="health", keywords=["outage","downtime","unavailab","failure"], limit=8)` | 30 |

Step 3 calls: `scenario()` on LIB-F1461, F0613, F1194, F0196, F1003 (and F0111).

## 2. Candidate list (40)

| # | Library id | Name | Why (profile evidence) |
|---|---|---|---|
| 1 | LIB-F1461 | Ransomware attack encrypting patient medical records for extortion | T-0 ransom note, EHR and shared folders unavailable |
| 2 | LIB-F1436 | Combined phishing and ransomware attack targeting healthcare IS | Phishing (T-10) leading to ransomware (T-0) chain |
| 3 | LIB-F1522 | Phishing attacks targeting administrative staff | Lure sent to clinic administrators and billing staff |
| 4 | LIB-F1604 | Phishing: credential theft from healthcare providers | Credential-harvest link in Appendix A |
| 5 | LIB-F0116 | Lack of multi-factor authentication | MFA push approved for an unusual login; risk appetite requires MFA |
| 6 | LIB-F0122 | Stolen administrative credentials | Valid clinical administrator account used remotely (T-5) |
| 7 | LIB-F0130 | Credential stuffing | Rising attack attempts against remote and cloud access |
| 8 | LIB-F0613 | Data breach via misconfigured cloud storage | Medical-image cloud store, unusual external downloads (T-3) |
| 9 | LIB-F0196 | API key exposure in code repositories | Audit universe: secure development and API key management |
| 10 | LIB-F0667 | Insecure APIs exposing patient records | EHR and cloud integrations |
| 11 | LIB-F1302 | Unauthorized wireless network access | 10 clinics with Wi-Fi and guest networks |
| 12 | LIB-F1318 | Unauthorized wireless access point (rogue AP) | Audit universe: rogue AP scans |
| 13 | LIB-F1789 | Exploitation of unpatched vulnerabilities | Patch delays because of uptime and vendor constraints |
| 14 | LIB-F1786 | Inadequate security patch management | Same, process side |
| 15 | LIB-F0111 | Unauthorized access to backups | Backup jobs fail (T-1); backup isolation questioned |
| 16 | LIB-F0283 | Compromise of cloud-based backup systems | Off-site and cloud backups |
| 17 | LIB-F0441 | Inadequate data backup and recovery | Untested restores, RTO/RPO evidence asked |
| 18 | LIB-F1094 | Insufficient logging and monitoring to identify incidents | PowerShell alert closed as low; can logs prove attempts failed? |
| 19 | LIB-F1263 | Inadequate intrusion detection and prevention | Outdated IDS/IPS risk |
| 20 | LIB-F1194 | Exploitation of vulnerabilities in networked medical devices | Interconnected medical equipment |
| 21 | LIB-F1168 | Insecure IoT devices as a gateway to internal networks | Device foothold to EHR network |
| 22 | LIB-F1175 | Failure to isolate medical devices on dedicated networks | Segmentation of device networks unknown |
| 23 | LIB-F0674 | DDoS attack on hospital website | Online appointments, records access, communications |
| 24 | LIB-F1003 | Insider threat: exfiltration of patient records | Staff export of health or billing data |
| 25 | LIB-F0998 | Insider threat: privileged snooping | EHR access reviews |
| 26 | LIB-F1133 | Data integrity attack on EHR | Altered patient or billing records |
| 27 | LIB-F1692 | Vendor compromise | EHR, cloud, device and support vendors |
| 28 | LIB-F1665 | Unauthorized remote access by suppliers | Vendor remote support paths |
| 29 | LIB-F0430 | Inadequate incident response planning | IR plan never tested across clinics |
| 30 | LIB-F0410 | Inadequate testing of disaster recovery plans | Clinic recovery and workaround procedures |
| 31 | LIB-F1806 | Vulnerabilities in remote access infrastructure | Remote access for staff and clinicians |
| 32 | LIB-F1266 | Lack of network segmentation: lateral movement | Central hub with WAN to clinics |
| 33 | LIB-F0995 | Insider threat: inappropriate use of admin privileges | Over-privileged `ehr-sync-svc` service account |
| 34 | LIB-F0103 | Unauthorized access to electronic health records | EHR is the central crown jewel |
| 35 | LIB-F0967 | Ineffective employee security awareness training | Clinicians and admin staff targeted |
| 36 | LIB-F1418 | Mobile device theft: personal health information | Tablets and handhelds used for EHR |
| 37 | LIB-F0089 | Unauthorized access to medical imaging systems | Radiology systems and image export |
| 38 | LIB-F0827 | Ineffective governance structures for cybersecurity | Security treated as an IT task; steering committee is new |
| 39 | LIB-F0488 | Failure to encrypt sensitive data at rest | Local clinic storage, exports |
| 40 | LIB-F0413 | Lack of an emergency communication plan | Journalist and public communication injects |

## 3. Coverage of the 30 expert scenarios (step 2)

Legend: covered = a candidate addresses the same threat event against the same kind of asset; partly = related but different event or asset; missed = no candidate. For misses and partials, "Library best match" is the closest library scenario found afterwards with targeted `identify(keywords=...)` searches, plus where it stood in step 1.

| Expert | Scenario (short) | Verdict | My matching candidate | Library best match / note |
|---|---|---|---|---|
| S1 | Phishing + MFA fatigue against clinical admin accounts | covered | F1604, F0116, F0122 | No library scenario names MFA push fatigue (`keywords=["mfa fatigue","push"]` returns 0 relevant) |
| S2 | Ransomware disrupting EHR and clinics | covered | F1461, F1436 | |
| S3 | Backup environment compromised, recovery prevented | covered | F0111, F0283 | F0111 statement: attacker deletes or encrypts backups |
| S4 | Cloud medical-image storage exposed, bulk exfiltration | covered | F0613 | |
| S5 | Misuse of clinical, privileged or service-account access to extract records | covered | F1003, F0995 | |
| S6 | Exploitation of unpatched internet-facing or EOL systems | covered | F1789 | |
| S7 | Medical device foothold to EHR network | covered | F1194, F1168 | |
| S8 | Detection and response gaps let an intrusion persist | covered | F1094, F1263, F0430 | |
| S9 | Compromise of a critical vendor with remote access | covered | F1665, F1692 | |
| S10 | Manipulation of patient, medication or billing records | covered | F1133 | |
| S11 | API key or secret exposed | covered | F0196 | |
| S12 | Clinic Wi-Fi compromise or rogue AP | covered | F1302, F1318 | |
| S13 | DDoS on booking, portal, communications | covered | F0674 | |
| S14 | BEC diverts vendor or billing payments | missed | - | F1612, F1520, F1586. F1586 came back in C23 but I did not select it; C02 (phishing theme) did not show any BEC in its top 10 |
| S15 | Lost or stolen tablet exposes patient data | covered | F1418 | |
| S16 | Loss of Montreal hub or WAN isolates clinics | missed | (F0410 only touches DR) | F0706 power outage, F1768 single point of failure, F0696 ISP outage. All came back in C34; I did not select them |
| S17 | Unmanaged patient data on local clinic storage | partly | F0488 (data at rest) | Nothing on branch or local storage; closest is F0052 (NAS). Library gap |
| S18 | Web application flaw in the patient portal | missed | - | F1796 "Web Application Vulnerability - Patient Portal". Not surfaced by any profile-driven call |
| S19 | Trojanized software update from a supplier | partly | F1692 | F1696, F0170. F1696 came back at rank 7 in C14 |
| S20 | Cloud tenant takeover through token theft or OAuth consent | missed | - | Only approximate: F0033 (cloud management consoles), F0057 (federated identities). No token-theft or consent-phishing scenario. Library gap |
| S21 | Accidental disclosure of patient information by staff | missed | - | F0997, F0542, F1011. Not surfaced: C12 ranked malicious insiders first among 173 matches |
| S22 | Interception of teleconsultations and clinical messaging | missed | - | F0112 eavesdropping on telemedicine came back in C17 and C23; I did not select it |
| S23 | Brute force or credential stuffing against exposed admin interfaces | partly | F0130 | F0125, F1287, F0269 (web admin panel). Nothing on hypervisor or firewall management interfaces |
| S24 | Malware from patient imaging media or USB | missed | - | F1485, F1498. F1498 came back in C27; I did not select it |
| S25 | Retired devices released with recoverable data | missed | - | F1377, F0525, F1734. Not surfaced by any profile-driven call |
| S26 | Staff paste patient data into unapproved GenAI tools | missed | - | No GenAI scenario (`keywords=["generative","chatgpt","llm","ai tool"]` returns 0). Closest is F0918 (unauthorized cloud services). Library gap |
| S27 | Help-desk impersonation leads to MFA reset and account takeover | missed | - | F1622, F1620, F1528. F1622 came back at rank 7 in C02; I did not select it |
| S28 | Malicious or departing IT admin sabotage | partly | F0995 | F0959, F1014. F1014 came back in C12 |
| S29 | Interception or tampering of HL7/DICOM interface traffic | missed | - | Only approximate: F1227 (MitM on treatment plans, came back in C13), F1668, F1230. Nothing names HL7 or DICOM |
| S30 | Criminals impersonate MediBec to phish or defraud patients | missed | - | F1598 "Phishing Attack Targeting Patients", F1581, F1606. Not surfaced; C22 returned F1546 (fraudulent fundraising) |

### Recall

- Covered: 14 (S1-S13, S15)
- Partly: 4 (S17, S19, S23, S28)
- Missed: 12

**Recall = (14 + 0.5 x 4) / 30 = 16 / 30 = 0.53**

Library ceiling, if every best library match above had been picked: about (25 + 0.5 x 4) / 30 = 0.90. The weakest parts of the library are S17, S20, S23 and S29 (approximate matches only) and S26 (nothing).

### Why the 12 misses happened

| Cause | Count | Scenarios |
|---|---|---|
| Interface returned a match, but it was buried among near-duplicates or ranked low, and I did not select it | 6 | S14, S16, S22, S24, S27, S29 (approximate) |
| Interface did not surface it from profile-driven queries, although the library has it | 4 | S18, S21, S25, S30 |
| Not in the library (or approximate only) | 2 | S20, S26 |

So the library holds a usable match for 10 of the 12 misses. Counting "returned but buried" as an interface failure, the interface split is 10 "interface did not surface (effectively)" and 2 "not in library".

## 4. Validity warning: the test leaks the answer (important)

- **L1, case scenarios returned by default.** `identify()` defaults to `include_cases=True`. With that default, `identify(themes=["ThemeRansomware"], sector="health")` returns `MediBec-CRG/S2` (the expert S2) at rank 5. Any MediBec run with default settings is reading the answer key.
- **L2, ranking uses the expert's own calibration.** 20 of my 40 candidates carry `case_calibrated` estimates whose evidence is `CASE-MediBec-CRG`, which is the expert assessment being tested. `identify()` ranks case-calibrated scenarios first, and `scenario()` shows `refined_by: [<expert scenario name>]`. Re-ranking the same result sets on library-2023 risk alone moves the exact library ids the expert picked a long way down:

  | Scenario | Rank with calibration | Rank without |
  |---|---|---|
  | F1461 (ransomware theme) | 1 | 48 |
  | F1194 (medical IoT theme) | 1 | 70 |
  | F1604 (social engineering theme) | 4 | 56 |
  | F1665 (third-party theme) | 1 | 41 |
  | F1133 (integrity theme) | 6 | 30 |

  Coverage was judged by topic, and topical siblings (other ransomware or device scenarios) would still have ranked high, so the 0.53 figure is probably only mildly optimistic. The ranking itself, however, is not blind for MediBec.

## 5. Quality of five candidates (step 3)

| Scenario | ATT&CK | Controls | Loi 25 (P-39.1) | Misleading points |
|---|---|---|---|---|
| **F1461** Ransomware on patient records | T1486 (H), T1566.001 (M): sensible. Missing for MediBec: T1204.002 and T1059.001 (macro to PowerShell), T1490 (backup failures), T1567/T1041 (double extortion), T1078 (valid account) | Backup, malware protection, IR and recovery are right. No identity/MFA, segmentation or EDR controls, which are the MediBec root causes | s.10, 3.5 para 1, 3.7, 3.8 at M. Notification (s.3.5 para 2) is missing, although F0613 and F1003 include it at H. Inconsistent across scenarios | No statement and no weaknesses. Two estimate sets contradict each other (resilience Th 0.35 case vs 0.8 library) with no explanation. Case-calibrated set is labelled confidence "M" with n = 1 and no bounds. `estimated_risk` 7893 has no unit, and MediBec uses a 0-1 scale with 0.40 tolerance. Five ransomware scenarios share exactly the same 7893.48, which looks like propagated calibration but reads as independent evidence |
| **F0613** Misconfigured cloud storage | T1530: right for the T-3 inject | PR.AA-05, PR.PS-01, CM-6, ISO 5.23 and 8.9: good | Notification H, s.10, 3.7, 3.8: good | CVSS 8.35/8.7 given for a scenario (the case itself warns CVSS is not enterprise risk). Calibration pools a retail case (CanaRetail) with MediBec. Statement says "the hospital" while MediBec is a private clinic network |
| **F1194** Medical device exploitation | T1210 fine. T1190 (public-facing application) is doubtful for internal clinical devices. Nothing ICS/medical-specific | RA-5, SI-2, SC-7, ISO 8.22 fine. Device inventory (ID.AM / CM-8) is missing, though it is MediBec's first stated gap | **None**, although devices store and transmit health data (s.10 at minimum) | No statement or weaknesses. Patient-safety dimension not flagged |
| **F0196** API key exposure | T1552.001, T1213.003: good | Secret management (PR.PS-06, IA-5, ISO 5.17 and 8.28): good | **None**, although a leaked key gives direct access to EHR and cloud health data | Threat source types empty. No statement |
| **F1003** Insider exfiltration of patient records | T1078, T1213 good. Exfiltration technique missing (T1567/T1048/T1052) | DLP 8.12, AC-6, PM-12, AU-6: good | Notification H, 3.7 H, s.10, 3.8: good | Statement frames a disgruntled seller only. MediBec's service-account abuse (`ehr-sync-svc`) is not represented |

Cross-cutting issues:

- The caveat appears once per response, at the top level and at the end of `scenario()`. Each entry returned by `identify()` carries a bare `estimated_risk` with no caveat and no n, so a downstream report can quote it as a fact.
- Only P-39.1 (the private-sector privacy act) is mapped. For a private medical centre, applicability of Quebec's 2023 health and social services information act should at least be raised as "verify with counsel". The interface gives no such hint.
- 11 of 40 candidates have no ATT&CK link and 19 of 40 have no Loi 25 obligation. Many control-gap scenarios lack statements.

## 6. Interface behaviour observed

- **Near-duplicates crowd the result limit.** Six "MitM on Wi-Fi" variants filled the first six slots of C06. Five ransomware variants with identical risk filled C01. Four help-desk social-engineering variants appeared in C02. No family clustering or de-duplication.
- **Theme tags are noisy.** ThemePhysical with sector health returns five firewall-misconfiguration scenarios first. ThemeIntegrity returns logging and monitoring first.
- **Keyword matching is too literal.**
  - Plain substring match: "ids" and "cd" match inside unrelated words.
  - Ranking ignores weaknesses, threat events and techniques: it uses only name and statement, and many scenarios (F1461, F1194, F0196) have no statement.
  - No synonyms or stemming: "generative" vs "AI", "teleconsultation" vs "telemedicine".
- **Large match sets are unordered by fit.** For example, 851 matches for the information-asset sweep. With no profile, ranking falls back to calibrated risk, so broad sweeps return only the same top ransomware and phishing items.

## 7. Suggestions

**Interface**

1. **Remove answer leakage.**
   - Make `include_cases=False` the default.
   - Add `exclude_case="MediBec"` (or `holdout=`) that drops that case's calibration sets, `refined_by` labels and case scenarios.
   - Rank by profile fit, not by calibrated risk.
2. **Add `identify_profile(profile)`, a coverage sweep.**
   - Take a structured profile (asset categories, technologies, sector, observed techniques, injects).
   - Return one representative per threat-event x asset-type family, with siblings as "see also".
   - Guarantee at least k results per theme and per asset category.
   - Report empty themes as explicit gaps.

   This would have surfaced BEC, help-desk reset, USB media, telemedicine, disposal, patient-portal and WAN-outage scenarios, which were 9 of the 12 misses.
3. **Improve matching.**
   - Match on word boundaries.
   - Add a synonym and stem map (telehealth/teleconsultation/telemedicine, GenAI/LLM/ChatGPT, HL7/DICOM/clinical interface).
   - Search weaknesses and threat-event labels as well as name and statement.
   - Add an `exclude_ids` / `diversify=True` option.
4. **Make estimates safer to present.**
   - Return per-scenario `estimate_status: "analyst estimate - validation required"`, n, source case and sector in every `identify()` entry.
   - Normalise or label the risk scale (the raw 7893 vs a 0-1 tolerance).
   - Flag contradictory estimate sets.
   - Do not label n = 1 instructor values confidence "M".

**Library**

5. **Add missing scenarios:**
   - GenAI or unapproved AI tool disclosure of health data
   - cloud tenant takeover through token theft or OAuth consent phishing
   - MFA push-fatigue
   - HL7/DICOM interface interception or tampering
   - unmanaged local or branch clinic storage
   - brand impersonation phishing aimed at patients (a health-specific variant of F1598)
   - management-plane brute force (hypervisor, firewall, storage)
6. **Fill metadata gaps and fix tagging.**
   - Add statements, weaknesses and threat sources (F1461, F1194, F0196 have none).
   - Add data-protection obligations wherever health data is reachable (F1194, F0196, F0111).
   - Make notification (s.3.5 para 2) consistent across confidentiality scenarios.
   - Add exfiltration techniques to extortion and insider scenarios.
   - Fix the theme mis-tags (Physical, Integrity).
   - Merge or cluster the many near-duplicate families.
7. **Add a jurisdiction note.** Add an optional health-sector obligation set, or at least a "verify applicability" note, for Quebec health-information legislation alongside P-39.1.
