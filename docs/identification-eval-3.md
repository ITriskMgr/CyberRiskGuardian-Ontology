# Identification evaluation 3: MediBec, blind, end to end

Evaluator: an independent agent acting as CyberRiskGuardian. It had not seen evaluations 1 or 2, and did not read them.
Interface: `pipeline/query/identify.py`. Every call passed `holdout=["MediBec-CRG", "MediBec"]`.
Input: `/home/claude/cases/raw/medibec.txt`, sections 1 to 12 only.
Reference: `tests/crg/medibec30.json` → `SCEN` (30 expert scenarios). This file was opened only after the candidate list was fixed.

## Result

| Measure | Value |
|---|---|
| Candidates selected | 45 |
| Covered | 16 |
| Partly covered | 5 |
| Missed | 9 |
| **Recall** = (16 + 0.5 × 5) / 30 | **0.617** |
| Misses not surfaced (the library has a match) | 2 (S21, S24) |
| Misses surfaced but not picked | 5 (S20, S22, S25, S28, S30) |
| Misses not in the library | 2 (S26, S29) |

## 1. Calls

### 1.1 Profile sweep (one call)

```
I.sweep(asset_categories=[CatIdentity, CatCloud, CatInformation, CatOTIoT, CatNetwork, CatEndpoint, CatApplication, CatInfrastructure],
        themes=[ThemeAccess, ThemeRansomware, ThemeCloud, ThemeDataBreach, ThemeMedicalIoT, ThemeNetwork, ThemeVulnMgmt, ThemeThirdParty,
                ThemeSocialEng, ThemeInsider, ThemeIntegrity, ThemeContinuity, ThemeDoS, ThemeAppSec, ThemeCompliance, ThemeCrypto],
        sector="health", techniques=[T1566, T1078, T1486, T1059.001, T1621, T1530, T1490, T1567, T1552, T1498],
        keywords=[mfa, adaptive authentication, ransomware, backup, cloud, wireless, rogue access point, api key, patch, intrusion detection,
                  medical device, ddos, insider, phishing, data integrity, vendor, incident response, ehr, radiology, wan, local storage,
                  service account, mfa fatigue, patient portal, asset inventory, segmentation, logging, encryption],
        per_theme=3, max_total=70, holdout=[...])
```

The sweep returned 70 candidates from a pool of 1,767, which collapsed to 1,330 distinct representatives. It reported no theme gaps and no baseline gaps.

**Useful picks:**
- Ransomware Attack on Hospital Systems
- Cloud Storage Misconfiguration
- Unauthorized Access to Backups
- Inadequate Data Backup and Recovery
- Unauthorized Wireless Access (rogue AP)
- Weak Wi-Fi encryption
- Unauthorized Access to Medical Device Systems
- Data Integrity Attack on the EHR
- Third-Party Vendor Breach
- API key exposure
- DDoS
- BEC
- Phishing / credential theft
- Web Application Vulnerability in the Patient Portal
- Telecom outage
- Help-desk-adjacent social engineering (in `see_also`)
- Data leakage from decommissioned devices (baseline)

**Noise:**
- Pharming appears six times, as representatives for Insider, Integrity, Ransomware, Network and SocialEng.
- Zero-days and RCE on CRM systems appear under AppSec.
- Licensing compliance scenarios appear.
- A "Zero-Day Exploit" with risk 1530 is returned.

**Missing despite being explicit in the profile:**
- MFA or adaptive authentication
- IDS/IPS detection gaps
- Patch delay as a primary scenario
- Exposed backup servers
- Insider exfiltration of patient records
- Untested incident response plan
- IoT network foothold

### 1.2 Targeted `identify` calls (about 80, all with the holdout)

Each call is listed with its keyword or filter and the number of matches.

**Identity and access:**
- `adaptive authentication` (1)
- `mfa` (7)
- `mfa fatigue` (0)
- `two-factor` (7)
- `password` (40)
- `brute force` (26)
- `credential stuffing` (9)
- `privileged access` (14)
- `service account` (0)
- `token theft` (5)
- `session hijacking` (4)
- `single sign-on` (0)

**Detection, response and governance:**
- `intrusion detection` (3)
- `ids` (2)
- `logging` (6)
- `endpoint`+`detection` (35)
- `powershell` (1)
- `fileless` (1)
- `macro` (0)
- `incident response` (10)
- ThemeContinuity+`incident response plan` (2)
- `disaster recovery` (7)
- `training` (22)
- `awareness` (9)
- `governance` (2)
- `staff shortage` (0)

**Patching, backup and insider:**
- `delayed patch` (0)
- ThemeVulnMgmt+`patch` (14)
- `backup`+`exposed` (59)
- `backup server` (0)
- ThemeAccess+`backup` (1)
- ThemeDataBreach+`backup` (13)
- `insider`+`exfiltration` (126)

**Medical devices and IoT:**
- ThemeMedicalIoT+`network` (0)
- ThemeMedicalIoT+`iot` (31)
- ThemeMedicalIoT+`patch` (0)
- ThemeMedicalIoT+`outdated` (3)
- ThemeMedicalIoT+`unpatched` (1)
- ThemeMedicalIoT+`lateral movement` (0)

**Network, remote access and availability:**
- `segmentation` (7)
- `lateral movement` (5)
- `remote access` (12)
- `wan` (0)
- ThemeDoS+`outage` (0)
- ThemeDoS+`website` (7)
- `ddos`+`patient portal` (19)
- ThemeNetwork+`wireless` (32)
- ThemeNetwork+`monitoring` (7)
- ThemeNetwork+`outdated` (0)
- ThemeAPT+`network` (0)

**Applications, data and clinical systems:**
- `api` (21)
- `secret` (2)
- `local storage` (1)
- `billing` (9)
- `ehr` (5)
- `ransomware`+`ehr` (30)
- ThemeIntegrity+`patient record` (2)
- ThemeIntegrity+`financial` (10)
- `radiology` (8)
- `medical image` (8)
- `laboratory` (13)
- `pharmacy` (2)
- `encryption`+`data at rest` (36)
- `key management` (3)
- CatCloud+`exfiltration` (9)

**Endpoints, communications and vendors:**
- `vendor`+`access` (85)
- `mobile device` (24)
- `tablet` (8)
- `video` (11)
- `messaging` (2)

**Other:**
- `spoofed domain` (0)
- `internet-facing` (0)
- `detect` (0)
- `undetected` (4)
- `dll` (0; see section 6)

## 2. Candidate list (fixed before Step 2)

| # | ID | Name | Why (profile evidence) |
|---|---|---|---|
| 1 | LIB-F0116 | Lack of Multi-Factor Authentication (MFA) | MED-CYR-01; risk appetite says privileged and clinical admin accounts need MFA; MFA push approved from unusual geography |
| 2 | LIB-F0158 | Lack of contextual access controls in zero trust architectures | Adaptive authentication named in IAM capability and MED-CYR-01 |
| 3 | LIB-F0662 | Data Exfiltration - Healthcare Provider Credential Theft | Valid clinical admin account used remotely to reach EHR |
| 4 | LIB-F0130 | Credential Stuffing | Weak or non-adaptive authentication; password policy |
| 5 | LIB-F1604 | Phishing Attack: Credential Theft from Healthcare Providers | MED-CYR-12; EHR-themed phishing lure (Appendix A) |
| 6 | LIB-F1489 | Malware-infected Email Attachments | `.docm` attachment spawned PowerShell |
| 7 | LIB-F1612 | Business Email Compromise (BEC) Scam | Billing staff targeted; vendor impersonation (baseline) |
| 8 | LIB-F1618 | Social Engineering Attack - Impersonation of IT Support | MED-CYR-12 "impersonate IT"; help-desk baseline |
| 9 | LIB-F1468 | Ransomware Attack on Hospital Systems | MED-CYR-02; ransom note in Module A |
| 10 | LIB-F0441 | Inadequate Data Backup and Recovery | Failed clinic backups; untested restore |
| 11 | LIB-F0111 | Unauthorized Access to Backups | MED-CYR-07; backups in same admin domain |
| 12 | LIB-F0601 | Data Leakage from Unsecured Backup Systems | MED-CYR-07 confidentiality side |
| 13 | LIB-F0359 | Cloud Storage Misconfiguration | MED-CYR-03; medical-image cloud storage downloads |
| 14 | LIB-F0444 | Inadequate encryption of sensitive data in the cloud | Cloud data access; encryption claims |
| 15 | LIB-F0196 | API key exposure in code repositories | MED-CYR-04 |
| 16 | LIB-F0667 | Insecure APIs exposing patient records | API logs, EHR integration |
| 17 | LIB-F1306 | Unauthorized Wireless Access (see_also Rogue AP) | MED-CYR-05 |
| 18 | LIB-F0493 | Weak Wi-Fi encryption protocols | WPA settings in audit universe |
| 19 | LIB-F1786 | Inadequate Security Patch Management | MED-CYR-06 |
| 20 | LIB-F1749 | Inability to patch known vulnerabilities in legacy systems | Uptime and vendor constraints |
| 21 | LIB-F1263 | Inadequate intrusion detection and prevention measures | MED-CYR-08; outdated IDS/IPS |
| 22 | LIB-F1084 | Insufficient logging and alerting | Log coverage; closed PowerShell alert |
| 23 | LIB-F0786 | Lack of endpoint detection and response (EDR) | EDR alert triaged as low |
| 24 | LIB-F1449 | Fileless malware that evades traditional antivirus | Encoded PowerShell |
| 25 | LIB-F1202 | Insecure IoT Devices in the Hospital Network | MED-CYR-09 |
| 26 | LIB-F1203 | Unauthorized Access to Medical Device Systems | Medical equipment interconnected with EHR |
| 27 | LIB-F1170 | Insufficient network segmentation for IoT devices | Segmentation of device networks |
| 28 | LIB-F1266 | Lack of Network Segmentation - Lateral Movement Attack | Ransomware spread; segmentation assessment |
| 29 | LIB-F0694 | DDoS Attack on Hospital Website | MED-CYR-10 |
| 30 | LIB-F1003 | Insider Threat - Exfiltration of Patient Records | MED-CYR-11 |
| 31 | LIB-F1036 | Insider Threat - Misuse of Privileged Access | Over-privileged `ehr-sync-svc` service account |
| 32 | LIB-F1133 | Data Integrity Attack - Electronic Health Records | MED-CYR-13 |
| 33 | LIB-F1134 | Data Tampering in Financial Management System | MED-CYR-13 billing records |
| 34 | LIB-F1703 | Third-Party Vendor Breach - Healthcare Information Systems | MED-CYR-14 |
| 35 | LIB-F1707 | Supply Chain Attack - Compromised Medical Equipment Vendor | Medical-device vendors |
| 36 | LIB-F0431 | Inadequate incident response testing | MED-CYR-15 |
| 37 | LIB-F0868 | Ineffective incident response training for staff | Clinic-level coordination |
| 38 | LIB-F0967 | Ineffective Employee Security Awareness Training | Awareness capability; phishing clicks |
| 39 | LIB-F0702 | Denial-of-Service - Telecommunications Outage | Central Montreal hub; WAN dependency |
| 40 | LIB-F0827 | Ineffective governance structures for cybersecurity | Cyber treated as IT-operational; governance audit area |
| 41 | LIB-F1294 | Unsecured Remote Access | Remote access login anomaly |
| 42 | LIB-F0118 | Unauthorized Access - Stolen or Lost Devices | Tablets and handhelds for EHR access |
| 43 | LIB-F0052 | Unauthorized access to network attached storage (NAS) | Local clinic storage units |
| 44 | LIB-F0012 | Advanced Persistent Threat | Sustained, increasing attempts since 2020 |
| 45 | LIB-F1796 | Web Application Vulnerability - Patient Portal | Online access and booking services |

Considered but not picked:
- F0525 (decommissioned devices, a sweep baseline pick)
- F1007 (insider sabotage of backups)
- F1293 (Wi-Fi MitM)
- F0283 (cloud backup compromise)
- F0933 (IT staff training)
- F1539 and F1462 (patient-targeted fraud and pharming)

## 3. Coverage against the 30 expert scenarios

| Expert | Name (short) | Verdict | Matching candidate(s) / comment |
|---|---|---|---|
| S1 | Credential compromise via phishing + MFA fatigue | covered | F0116, F1604, F0662. MFA fatigue itself has no library scenario: `mfa fatigue` returned 0 matches. |
| S2 | Ransomware on EHR and clinics | covered | F1468 (+F1489, F1266) |
| S3 | Backup environment compromised, no recovery | covered | F0111, F0441, F0601 |
| S4 | Cloud medical-image storage exposed | covered | F0359 |
| S5 | Misuse of clinical, privileged or service-account access | covered | F1003, F1036 |
| S6 | Exploitation of unpatched internet-facing / EOL systems | covered | F1786, F1749. Both are generic patch-management scenarios and do not name an internet-facing gateway. |
| S7 | Medical device foothold | covered | F1202, F1203, F1170 |
| S8 | Detection and response gaps | covered | F1263, F1084, F0431 |
| S9 | Critical vendor with remote access compromised | covered | F1703 |
| S10 | Manipulation of patient / medication / billing records | covered | F1133, F1134 |
| S11 | API key / secret exposure | covered | F0196 |
| S12 | Clinic Wi-Fi / rogue AP | covered | F1306, F0493 |
| S13 | DDoS on booking / portal | covered | F0694 |
| S14 | BEC diverting payments | covered | F1612 |
| S15 | Lost / stolen tablet | covered | F0118 |
| S16 | Loss of Montreal hub / WAN | partly | F0702 covers a telecom outage, but not the single-hub, no-redundancy failure. F1768 (single point of failure in redundant network) and F0696 (ISP outage) exist; neither was picked. |
| S17 | Unmanaged data on local clinic storage | partly | F0052 (NAS access) covers exposure, but not the unmanaged accumulation or loss without backup. |
| S18 | Patient-portal web flaw | covered | F1796 |
| S19 | Trojanized software update | partly | F1707 is a supply-chain attack through a device vendor, not the update channel. F1632 surfaced in the vendor+access call and was not picked. F1696 (Compromised Software Update) exists but was not surfaced. |
| S20 | Cloud tenant takeover via token theft / app consent | missed | Surfaced, not picked: F0297 (Man-in-the-Cloud token theft, from the `token theft` call). Better matches F0033 and F0053 (cloud management console access) were never surfaced. |
| S21 | Accidental disclosure by staff | missed | **Not surfaced.** F0997 (Accidental Data Disclosure) exists. The sweep's "accidental disclosure" baseline slot was filled by Cloud Storage Misconfiguration. |
| S22 | Interception of teleconsultations / clinical messaging | missed | Surfaced, not picked: F0101, F1246, F0853 (`video` and `messaging` calls). The library also holds F0112 and F0026. |
| S23 | Brute force / stuffing on exposed admin interfaces | partly | F0130 (credential stuffing on user accounts), F1294. F1287 and F1800 (brute force on remote access, RDP) surfaced and were not picked. |
| S24 | Malware via patient imaging media / USB | missed | **Not surfaced.** F1476 and F1464 exist. The sweep's "removable media" baseline slot was filled by Malware Infection via Third-Party Contractor. |
| S25 | Retired devices with recoverable data | missed | Surfaced, not picked: F0525 (sweep baseline pick). |
| S26 | Staff paste patient data into generative AI | missed | **Not in library.** The genAI synonym group, `artificial intelligence` and `chatbot` all return 0. The nearest is F0918 (unauthorized cloud services by staff). The profile itself does not mention AI. |
| S27 | Help-desk impersonation → MFA reset | partly | F1618 has the impersonation in the reverse direction (attacker poses as IT). F1622 (Social Engineering Attack on IT Help Desk) appeared in F1618's `see_also` and was not picked. |
| S28 | Malicious / departing IT admin sabotage | missed | Surfaced, not picked: F1007, F0983, F0955 (sweep). |
| S29 | HL7/DICOM interface traffic interception | missed | **Not in library.** The hl7/dicom synonym group returns 0. The generic proxy F0492 (Data Interception - Unencrypted Communications) exists but was not surfaced. |
| S30 | Criminals impersonate MediBec to phish patients | missed | Surfaced, not picked: F1581 (in `see_also`), F1539, F1462 (sweep). |

### Misses by cause

- **Not surfaced (the library has a match):**
  - S21: F0997
  - S24: F1476 / F1464

  In both cases the baseline mechanism was satisfied by an unrelated scenario (section 5, problem 2).
- **Surfaced but not picked:**
  - S20: F0297, a weak match
  - S22: F0101 / F1246 / F0853
  - S25: F0525
  - S28: F1007 / F0955
  - S30: F1581 / F1539

  These are analyst-selection misses. Most concern risks the profile mentions only indirectly:
  - S22: "voice, video and messaging services"
  - S30: a newly registered look-alike domain in Appendix A
  - S28: a small IT team with concentrated privileges
- **Not in library:**
  - S26: generative AI
  - S29: HL7/DICOM interface traffic; only the generic proxy F0492 exists

Partial matches have the same split:
- **Surfaced but not picked:** S19, S23, S27
- **Weak or absent in the library:** S16, S17

## 4. Observations on the interface

**Strengths:**
- With a broad profile, the sweep covers the core MediBec case-library scenarios well. About 11 of the 15 MED-CYR items have a direct representative in the sweep output.
- `see_also` exposed good alternatives: F1622 for the help desk, F1581 for patients, F1318 for rogue APs.

**Weaknesses:**
- Explicit profile items still needed targeted calls to surface: MFA, adaptive authentication, IDS, insider exfiltration, IR testing and the IoT foothold.
- The sweep's per-theme slots are filled by token overlap and risk value, not by fit to the profile. This explains the repeated Pharming picks and the CRM zero-days.
- Many library scenarios have no estimated risk, so they sort below weaker scenarios that do have one.

## 5. Top problems

### Problem 1: synonym expansion swallows generic keywords

`_expand` maps a single word to a synonym group whenever that word appears as a token inside one of the group's phrases. The original word is then dropped. Examples:

| Keyword | Replaced by group |
|---|---|
| `network`, `outage` | WAN group |
| `insider` | sabotage group |
| `access` | OAuth/token group |
| `device` | asset-inventory group |
| `storage` | NAS group |

Effects:
- `network outage` returns 0 matches.
- ThemeDoS+`outage` returns 0, although F0702 "Telecommunications Outage" exists.
- ThemeMedicalIoT+`network` returns 0.
- ThemeAPT+`network` returns 0.
- The sweep keyword `insider` searched only for sabotage words.

Plural handling is suffix-only. Phrase variants therefore fail:
- "telecommunication outage" does not match "telecommunications outage".
- "data centre" returns 0, while "data center" returns 12.

Fix: always keep the literal keyword in its group, and expand only on exact phrase membership.

### Problem 2: baseline slots are filled by incidental keyword hits, and the reason is hidden

`_baseline_hits` uses loose substrings: "lost", "accidental", "brand", "usb" in any statement. As a result:

| Baseline risk | Satisfied by |
|---|---|
| accidental disclosure | Cloud Storage Misconfiguration |
| removable media | Malware Infection via Third-Party Contractor |
| lost or stolen device | External Vendor Breach / Pharming Attack on Website |
| impersonation of the organisation | IT-support impersonation |
| privileged account misuse | Insider Threat Leakage |

When the representative is already chosen, `take()` keeps the earlier reason, so the analyst never sees which baseline risk it stands for. The sweep then reports `baseline_gaps: []` although no dedicated scenario was returned.

This directly caused both not-surfaced misses: S21 (F0997) and S24 (F1476).

Fix: match baseline patterns against the scenario name or primary threat event only. Add the dedicated representative even when the bucket is "covered" by an existing pick. Add the baseline label to `selected_because` as well.

### Problem 3: sweep ranking noise and gaps for explicit profile items, plus a vocabulary leak

Slots go to off-target representatives:
- Pharming appears six times.
- CRM RCE and zero-days appear.
- Software licensing compliance appears.

Meanwhile, risks the profile states verbatim (MFA, adaptive authentication, IDS/IPS, delayed patching, exposed backups, insider exfiltration, IR testing) are absent until targeted `identify` calls are made.

Separately, the hand-written `SYNONYMS` and `BASELINE` vocabularies mirror the held-out expert list almost item by item:

| Vocabulary entry | Expert scenario |
|---|---|
| hub / WAN | S16 |
| local storage / NAS | S17 |
| OAuth / app consent / token theft | S20 |
| accidental disclosure | S21 |
| telehealth | S22 |
| removable media | S24 |
| disposal | S25 |
| generative AI | S26 |
| help desk | S27 |
| departing employee | S28 |
| HL7 / DICOM | S29 |
| impersonation of the organisation | S30 |
| MFA fatigue | S1 |
| patient portal | S18 |

Unless this vocabulary was derived from other cases, it was tuned on the MediBec answer key. That tuning would inflate any "blind" MediBec score, and the inflation would mostly appear in recall from baseline and keyword hits. See section 6.

## 6. Held-out data leakage check

**Data paths: no leak observed.**
- No `MediBec-CRG/*` or `MediBec/*` scenario was returned by any call.
- `_allowed` filters all 20 MediBec case scenarios that are present in the search index.
- With the holdout, `scenario()` hides `refined_by` labels. Without the holdout, F1468 shows "Ransomware disrupting EHR access and clinic operations across the network", which is S2's name. With the holdout it shows nothing.
- `scenario()` also hides `case_calibrated` estimates under the holdout.
- `_library_risk` with the holdout differs from the unheld version for 92 scenarios, so held-out calibrations are being removed. 62 scenarios keep case-calibrated values from other cases.

**Design leak: likely.** The `SYNONYMS` and `BASELINE` vocabularies match the expert-only additions in `SCEN` (Annex B items S14 to S30) very closely. Several of these concepts never appear in sections 1 to 12 of the profile:
- generative AI
- HL7/DICOM
- telehealth
- disposal
- help desk
- removable media

**Evaluator exposure.**
- The first `grep` of section headings in `medibec.txt` displayed the table-of-contents and annex headings at lines 516 to 1450. These headings included Instructor Annex A scenario names such as "DLL Hijacking at MediBec (64)". The annex bodies were not read.
- One resulting query, `dll`, returned 0 matches and added nothing to the list.
- No annex-derived scenario was added. The Annex A headings seen (adaptive authentication, 2FA, API key, cloud misconfiguration, wireless, DDoS, patching, backup) duplicate the section 9 library anyway.
