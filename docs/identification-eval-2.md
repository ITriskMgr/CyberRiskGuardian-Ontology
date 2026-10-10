# Identification evaluation 2: MediBec, blind run (CRGO `identify.py`)

Date: 2026-10-09. Evaluator role: CyberRiskGuardian using the CRGO identification interface.
Blind rule: every call passed `holdout=["MediBec-CRG","MediBec"]`. The ground truth (`tests/crg/medibec30.json`) was opened only after the candidate list below was fixed. Profile source: `/home/claude/cases/raw/medibec.txt`, sections 1 to 12 only.

**Result: recall = (14 + 0.5 × 3) / 30 = 15.5 / 30 = 0.52** (14 covered, 3 partly, 13 missed). Of the 13 misses, 10 have a matching scenario in the library (4 of them appeared in tool output but I did not select them, 6 never appeared) and 3 have no match in the library.

**Blind-integrity warning (most important finding).** The holdout does not hide the MediBec expert assessment scenarios. `S1`, `S2`, `S5` and `S29` (IRIs `https://w3id.org/crgo/data/medibec/scenario-Sx`, kind "assessment scenario") came back from `sweep` and `identify` even with the holdout set. The cause is in `identify._allowed()`, which filters only IRIs that contain `/C-`. I left these out of the candidate list so they do not inflate recall. `scenario("S1")` also shows a `refines` link to `LIB-candidate-C01`, but `scenario("LIB-candidate-C01")` raises "unknown scenario".

---

## 1. Calls

Sweep calls (all with `sector="Healthcare"` and the holdout):

| # | Call | Result |
|---|---|---|
| W1 | `sweep(asset_categories=[9 categories, all except Facility], themes=[19 themes], techniques=[T1566.001, T1566.002, T1204.002, T1059.001, T1078, T1621, T1133, T1530, T1567, T1490, T1486, T1078.003, T1498, T1552.001], keywords=[EHR, MFA, ransomware, backup, cloud storage, API key, wireless, patch, IDS, medical device, DDoS, insider, phishing, vendor, incident response, service account, medical imaging, PowerShell], per_theme=2, max_total=60)` | 1815 candidates, 46 returned, no theme gaps. Many off-profile picks: XSS, defacement, software licensing (×2), R&D documents, cognitive computing, decentralised integrity. Leaked `S1` and `S5`. |
| W2 | Same as W1 but with no asset categories, 14 themes, keyword "intrusion detection", `per_theme=3`, `max_total=60` | 1606 candidates, 60 returned. More focused: backups, phishing, ransomware, vendors, medical devices, Wi-Fi, API key. Still off-profile items: quantum, augmented reality, 3D designs, ERP, edge nodes. Leaked `S1` and `S5`. |

Targeted `identify` calls (keyword or technique, sometimes with a theme filter). The results that matter are noted; "∅" means nothing came back.

| Query | Notable results |
|---|---|
| kw "MFA fatigue" | ∅ |
| kw "MFA" + ThemeAccess | F0116, F0018, F0036, F0145 |
| kw "adaptive authentication" | ∅ |
| tech T1059.001 / kw "PowerShell" | F1449 Fileless malware (the only hit) |
| kw "macro" | only the leaked `S1` and `S2` |
| kw "service account" | only the leaked `S5` |
| kw "privileged" + ThemeAccess | F0062 |
| kw "medical image", "radiology" | ∅ |
| kw "PACS" | only the leaked `S29` |
| kw "credential" + ThemeAccess | F0122, F1287, F0130, F1424 |
| kw "remote access", "VPN" | F1287, F1294, F1800, F1770 |
| kw "ransomware" (Healthcare) | F1501, F1468, F1472, F0111 |
| kw "EHR" / "electronic health record" | F0656, F0103, F1133, F1062, F0979 |
| kw "backup" + Ransomware/Continuity | F1007, F0440, F0111, F0421, F1490 |
| kw "exfiltration" + ThemeCloud | F0918, F0307 |
| kw "intrusion detection" | F1263 |
| kw "monitoring" / "logging" | F1078, F1094, F1110, F1084, F1261 |
| kw "incident response" | F1095, F0868, F0430, F0877, F0438 |
| kw "wireless", "Wi-Fi" | F0110, F1306, F1753, F1286, F0493 |
| kw "rogue access point" | ∅ |
| kw "patch" | F1786, F1741, F1749, F1802 |
| kw "medical device" / "IoT" | F1203, F1196, F1206, F1202, F1213, F1694 |
| kw "segmentation" | F1266, F1170 |
| kw "DDoS" / "appointment" / "patient portal" | F0699, F0701, F0694; F1600; **F1796 Patient Portal web app** (not selected) |
| kw "insider" + ThemeDataBreach | F0640, F0996, F0935, F0890 |
| kw "billing", "laboratory", "pharmacy" | F0618; F0891, F1063, F0220; F0971 |
| kw "API key" | F0196 |
| kw "cloud storage" / "misconfiguration" + ThemeCloud | F0613, F0359, F0355, F0281 |
| kw "data residency", "local storage", "asset inventory" | ∅ |
| kw "vendor" + ThemeThirdParty | F1698, F1692, F1632, F1473, F1703 |
| kw "video conferencing", "messaging", "VoIP" | F1246, F0853, F1274 |
| kw "staffing" / "governance" / "breach notification" / "privacy" | F0848; F0827; F0557; F0554 |
| tech T1566.001, T1486, T1490, T1530, T1078 | F1603, F1469, F1501, F0111, F0283, F0613, F0122, F1582 |
| tech T1621 (MFA request generation) | ∅ |
| kw "endpoint" + ThemeEndpoint | F0785, F0786 |
| kw "tablet", "mobile device" | F0635, F1423, F1430 |
| kw "encryption" + DataBreach/Crypto | F0444, F0478 |
| kw "media" + ThemeReputation | ∅ |
| kw "integrity" + ThemeIntegrity | F1133, F0642 |
| kw "interface", "integration" + IoT/Network/Integrity | ∅ |

## 2. Candidate list (fixed before Step 2)

42 scenarios. W = surfaced by a sweep, T = surfaced by a targeted call.

| # | ID | Name | Why (profile evidence) | Src |
|---|---|---|---|---|
| 1 | LIB-F1603 | Spear Phishing Attack: Credential Compromise | T-10 phishing of clinic admins and billing staff (App. A) | T |
| 2 | LIB-F1469 | Malware Infection via Email Attachment | `.docm` attachment spawned PowerShell | T |
| 3 | LIB-F1582 | Phishing Attack on Healthcare Staff | Clinical staff targeted (MED-CYR-12) | T |
| 4 | LIB-F0122 | Stolen Administrative Credentials | Valid clinical admin account used from unusual location | T |
| 5 | LIB-F0018 | Inadequate multi-factor authentication implementation | MFA push approved (MFA fatigue) | T |
| 6 | LIB-F1294 | Unsecured Remote Access | Remote and cloud access for clinicians | T |
| 7 | LIB-F1449 | Fileless malware that evades traditional antivirus | Encoded PowerShell from WINWORD | T |
| 8 | LIB-F0786 | Lack of EDR capabilities | EDR alert closed as low severity | T |
| 9 | LIB-F1501 | Ransomware Attack on Healthcare Information Systems | Ransom note, EHR and shared folders down | W/T |
| 10 | LIB-F0111 | Unauthorized Access to Backups | Backup failures at T-1, MED-CYR-07 | W |
| 11 | LIB-F0441 | Inadequate Data Backup and Recovery | Recovery and restore testing unknown | W |
| 12 | LIB-F0421 | Failure to periodically test disaster recovery procedures | Tested recovery required by appetite | T |
| 13 | LIB-F0613 | Data Breach via Misconfigured Cloud Storage | Medical-image transfer bucket, large downloads | W |
| 14 | LIB-F0478 | Lack of encryption in cloud-based file storage | Cloud data access, encryption assumptions | W |
| 15 | LIB-F0196 | API key exposure in code repositories | MED-CYR-04, secure dev audit area | W |
| 16 | LIB-F0110 | Unauthorized Access to Hospital Wi-Fi Network | Clinic Wi-Fi, MED-CYR-05 | T |
| 17 | LIB-F1753 | Insecure Wi-Fi configurations | WPA settings, guest segmentation | T |
| 18 | LIB-F1786 | Inadequate Security Patch Management | MED-CYR-06 | T |
| 19 | LIB-F1749 | Inability to patch known vulnerabilities in legacy systems | Uptime and vendor constraints | T |
| 20 | LIB-F1263 | Inadequate intrusion detection and prevention | MED-CYR-08, outdated IDS/IPS | T |
| 21 | LIB-F1094 | Insufficient logging and monitoring to identify incidents | Logs may not prove attempts failed | T |
| 22 | LIB-F1196 | Medical Device Vulnerability Exploitation | Interconnected medical equipment | T |
| 23 | LIB-F1202 | Insecure IoT Devices in the Hospital Network | MED-CYR-09 building IoT | T |
| 24 | LIB-F1266 | Lack of Network Segmentation, Lateral Movement | Segmentation flagged in the network row | T |
| 25 | LIB-F1170 | Insufficient network segmentation for IoT devices | Devices sharing the EHR network | T |
| 26 | LIB-F0694 | DDoS Attack on Hospital Website | MED-CYR-10 online appointments | T |
| 27 | LIB-F0103 | Unauthorized Access to Electronic Health Records | EHR access control audit area | T |
| 28 | LIB-F0935 | Insider using privileged access to exfiltrate sensitive data | MED-CYR-11 | T |
| 29 | LIB-F0062 | Inadequate monitoring of privileged user activity | ehr-sync-svc unusual query volume | T |
| 30 | LIB-F1133 | Data Integrity Attack, Electronic Health Records | MED-CYR-13 | T |
| 31 | LIB-F1063 | Alteration of laboratory results affecting patient treatment | Lab system, clinical decisions | T |
| 32 | LIB-F1692 | Vendor Compromise | MED-CYR-14 | T |
| 33 | LIB-F1698 | Data Breach via Weak Vendor Security | Vendor assurance gaps | T |
| 34 | LIB-F1665 | Unauthorized remote access by suppliers | Vendor support access | W |
| 35 | LIB-F1707 | Supply Chain Attack, Compromised Medical Equipment Vendor | Medical-device vendors | W |
| 36 | LIB-F0430 | Inadequate incident response planning | MED-CYR-15 untested plan | T |
| 37 | LIB-F0877 | Inadequate incident response training for medical staff | Clinic crisis roles | T |
| 38 | LIB-F0848 | Inadequate staffing causing security oversight | 2-person cyber team, 15 IT staff | T |
| 39 | LIB-F0827 | Ineffective governance structures for cybersecurity | Cyber treated as IT-operational | T |
| 40 | LIB-F0557 | Non-compliance with data breach notification laws | Quebec/PIPEDA notification | T |
| 41 | LIB-F0853 | Insecure instant messaging among hospital staff | Voice, video and messaging systems | T |
| 42 | LIB-F0635 | Physical Security Breach: Theft of Mobile Devices | Tablets and handhelds for EHR access | T |

## 3. Coverage of the 30 expert scenarios

| ID | Expert scenario | Verdict | Matching candidates / note |
|---|---|---|---|
| S1 | Credential compromise via phishing and MFA fatigue | covered | 1, 4, 5 |
| S2 | Ransomware disrupting EHR and clinics | covered | 9, 2, 24 |
| S3 | Backup environment compromised | covered | 10, 11 |
| S4 | Cloud medical-image storage exposed, bulk exfiltration | covered | 13 |
| S5 | Misuse of clinical, privileged or service-account access | covered | 28, 29, 27 |
| S6 | Exploitation of unpatched internet-facing or EOL systems | covered | 18, 19 (6) |
| S7 | Medical device foothold | covered | 22, 25, 23 |
| S8 | Detection and response gaps | covered | 20, 21, 36, 38 |
| S9 | Critical vendor with remote access compromised | covered | 34, 32 |
| S10 | Manipulation of patient, medication or billing records | covered | 30, 31 |
| S11 | API key or secret exposed | covered | 15 |
| S12 | Clinic Wi-Fi or rogue AP | covered | 16, 17 |
| S13 | DDoS on booking, portal and communications | covered | 26 |
| S14 | Business e-mail compromise diverts payments | **missed** | |
| S15 | Lost or stolen tablet | covered | 42 |
| S16 | Loss of Montreal hub or WAN | **missed** | |
| S17 | Unmanaged data on local clinic storage | **missed** | |
| S18 | Patient-portal web application flaw | **missed** | |
| S19 | Trojanized software update from a supplier | partly | 32, 35: vendor and device-vendor compromise, but not the update channel |
| S20 | Cloud tenant takeover (token theft or consent phishing) | **missed** | |
| S21 | Accidental disclosure by staff | **missed** | |
| S22 | Interception of teleconsultations and clinical messaging | partly | 41 covers messaging, not teleconsultations |
| S23 | Brute force or credential stuffing on exposed admin interfaces | partly | 6, 4: remote access and stolen admin credentials, but not the brute-force event |
| S24 | Malware via patient imaging media or USB | **missed** | |
| S25 | Retired devices released with recoverable data | **missed** | |
| S26 | Patient data pasted into generative-AI tools | **missed** | |
| S27 | Help-desk impersonation leads to MFA reset | **missed** | |
| S28 | Malicious or departing IT administrator sabotages systems | **missed** | 28 is exfiltration, a different threat event |
| S29 | Interception or tampering of HL7/DICOM traffic | **missed** | |
| S30 | Criminals impersonate MediBec to phish patients | **missed** | |

Totals: covered 14, partly 3, missed 13. **Recall = (14 + 1.5) / 30 = 0.517.**

The profile's own 15-item scenario library (MED-CYR-01 to 15) maps to S1 through S13. All of those are covered. Every miss is one of the expert's Annex-B-derived additions (S14 to S30), which the profile text only hints at.

## 4. Misses: what the library holds

Checked with `identify` keyword calls, still with the holdout.

### 4a. Not surfaced (a matching scenario is in the library)

Surfaced by a tool call but not selected by me (analyst or ranking miss):

| Miss | Library match | Where it appeared |
|---|---|---|
| S16 Hub/WAN loss | LIB-F0702 DoS, Telecommunications Outage; F0696 ISP outage; F1768 single point of failure | F0702 appeared in W1 |
| S18 Portal web-app flaw | LIB-F1796 Web Application Vulnerability, Patient Portal; F1792 | kw "patient portal" |
| S24 USB or imaging media | LIB-F1476 Malware Infection via USB; F1464 Malware-infected External Media; F0803 USB Drop | F0803 appeared in W1 |
| S28 Admin sabotage | LIB-F1007 Insider Attack, Sabotage of Backup Systems; F1014 Disgruntled Employee Sabotage | F1007 ranked first in W2 |

Never surfaced by my profile-driven calls (found only by keywords taken from the expert list):

| Miss | Library match |
|---|---|
| S14 BEC | LIB-F1612 Business Email Compromise (BEC) Scam |
| S17 Local clinic storage | LIB-F0052 Unauthorized access to NAS systems (approximate) |
| S21 Accidental disclosure | LIB-F0997 Insider Threat: Accidental Data Disclosure |
| S25 Disposal | LIB-F1377 Insecure disposal of hardware containing sensitive data; F1734 |
| S27 Help desk | LIB-F1622 Social Engineering Attack on IT Help Desk; F1528; F0858 |
| S30 Impersonating the organisation to patients | LIB-F1581 Social Engineering Attack on Patients; F1606; pharming F1462 |

Library matches for the partly-covered items: S19 → LIB-F1696 Software Supply Chain Attack, Compromised Software Update (and F0170); S22 → LIB-F0112 Eavesdropping on Telemedicine Sessions; S23 → LIB-F1287 Brute Force Attack on Remote Access Systems.

### 4b. Not in the library

| Miss | Nearest analogue | Gap |
|---|---|---|
| S20 Cloud tenant takeover via token theft or app consent | F0033/F0053 cloud console access, F0041 session hijacking | No token-theft or OAuth-consent scenario. The keyword "consent" matches psychiatric-records consent instead. |
| S26 Generative-AI data leakage | none ("generative", "LLM", "AI", "chatbot" all return nothing) | Missing family |
| S29 HL7/DICOM interception or tampering | F1291 Wi-Fi interception, F1668 lab transmission (third-party) | No clinical-interface protocol scenario. "HL7", "DICOM", "PACS" match only the leaked `S29`. |

If the 4 surfaced-but-not-selected and the 3 partly items had been taken, recall would reach about 0.75. If all 10 library matches had surfaced and been taken, the ceiling is about 0.90 (27/30).

## 5. Remaining problems and suggestions

1. **The holdout leaks the expert assessment.** `_allowed()` checks only for `/C-` in the IRI, so `data/medibec/scenario-S*` assessment scenarios pass through. `sweep` returned `S1` and `S5`; `identify` returned `S1`, `S2`, `S5` and `S29`. A careless blind run would pick them up and inflate recall.
   *Fix:* decide holdout by the case key derived for every non-library IRI, including assessment scenarios under `data/<case>/`. Add a regression test that `sweep(..., holdout=["MediBec-CRG","MediBec"])` returns no IRI containing `medibec`. Also fix the dangling `refines` → `LIB-candidate-C01`.

2. **Sweep dilution and blind spots.** With a full profile, the sweep scores 1600 to 1800 candidates. The guaranteed per-theme slots and the near-tie `fit` scores fill the 60 places with off-profile items: licensing, R&D documents, quantum, augmented reality, 3D designs, cognitive computing, ThemeEmerging and ThemePhysical, even when those themes were not requested. Meanwhile, common healthcare families that the expert always includes never appear: BEC, help-desk social engineering, accidental disclosure, disposal, removable media, impersonation of the organisation to patients, and hub/WAN outage.
   *Fix:* (a) do not give guaranteed slots to themes that were not requested; (b) weight sector-typical families with a "baseline healthcare checklist" pass that always returns one representative per common family; (c) penalise items whose only match is a broad asset category; (d) return a short "commonly assessed but not matched" list so the analyst is prompted.

3. **Keyword and technique matching is brittle.** These return nothing: "MFA fatigue", "adaptive authentication", "medical image", "radiology", "rogue access point", "local storage", "data residency", "asset inventory", "WAN", "media" with ThemeReputation, and "interface/integration". T1621 has no linked scenarios, and T1059.001 links to only one. The synonym expansion adds noise ("consent" → psychiatric consent, "token" → MRI images).
   *Fix:* use stemmed or phrase-partial matching (image/imaging, radiology→PACS/imaging); add domain synonyms (WAN↔network outage, local storage↔NAS/file share, rogue AP↔wireless); add ATT&CK links for T1621, T1059.x, T1566.x and T1078.x; review synonym pairs that produce false positives.

Further points:

- **Library gaps to fill:** cloud identity or tenant takeover (token theft, consent phishing), generative-AI data leakage, and HL7/DICOM/clinical-interface interception or tampering.
- **Missing risk estimates:** many returned scenarios have `estimated_risk = None`, which weakens ranking among near-duplicates.
- **Ranking:** `fit` is the same value (2) for most single-keyword hits, so ranking falls back to risk. Weighting matched profile elements by specificity (for example, a technique from the incident timeline outweighs a generic category) would help.
