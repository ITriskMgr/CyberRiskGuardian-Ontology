# Blind identification evaluation: ACRB (Atlantic Canada Regional Bank, v2.0b)

Date: 2026-10-09. Interface: `pipeline/query/identify.py` (sweep / identify). Every call used `holdout=["ACRB"]`.
Role played: CyberRiskGuardian building a candidate scenario list from the organisation profile only.

## Blind protocol

- Step 1 used only `acrb.txt` lines 1-383 (sections 1-8: narrative, business profile, governance/technology, 2022 incident, Module A injects, Module B audit universe and prior findings IA-21-01..05, Module C appetite and scoring). Reading stopped at "# 9. Scenario Library" (line 384). The instructor annex (line 593 onward), Appendix F and `cases_extract.json` were not opened until Step 2.
- I wrote down the candidate list before opening the reference sections and did not change it afterwards. Two drafted items (LIB-F1795, LIB-F0421) were dropped as redundant before Step 2, which left 40.
- `sector` was never used as a filter. Note: `list_values("sector")` includes "Banking", but `identify(sector="Banking", holdout=["ACRB"])` returns 0 matches, so the only banking-tagged scenarios are ACRB's own.

## Step 1: calls

1. `sweep(...)` over the whole profile:
   - assets: 9 categories (everything except OT/IoT)
   - themes: 20 (every theme except MedicalIoT, Integrity and Other)
   - techniques: T1566, T1204, T1059, T1078, T1021, T1486, T1041, T1074, T1003, T1133, T1190
   - keywords: 44 profile terms (spear-phishing, ransomware, exfiltration, core banking, legacy, ATM, POS terminal, mobile/online banking, API, AWS, Azure, VPN, segmentation, backup, DR, asset inventory, patch, SIEM, SOC, privileged access, MFA, vendor, customer data, notification, Exchange/Teams/SharePoint, VoIP, CRM, analytics, AI, marketing, branch, call center, fraud, DDoS, incident response, governance, encryption, ...)
   - settings: `per_theme=2`, `max_total=60`
   - result: 1854 candidates, 1405 distinct, 60 returned, no theme or baseline gaps.
2. `identify(keywords=..., limit=8)` follow-ups, one call per profile element. Matches in brackets:
   - ATM [**0**]
   - POS/skimming [1]
   - mobile banking [13]
   - online banking/portal [11]
   - core banking/legacy [5]
   - SOC/SIEM/alert/logging with themes [17]
   - VPN/stolen credentials [29]
   - incident response/tabletop [10]
   - notification/communication [107]
   - firewall [16]
   - AWS/Azure/cloud storage [69]
   - analytics/marketing/AI [35]
   - Exchange/SharePoint/Teams [11]
   - VoIP/IVR/call center/vishing [7]
   - fraud/account takeover [24]
   - branch/physical access [32]
   - network outage/WAN [4]
   - DR/failover [12]
   - asset inventory [2, both false positives: compliance inventory, pharmacy inventory]
   - governance/board [12]
   - staffing/hiring [5]
   - encryption/obsolete/TLS [50]
   - regulatory [35]
   - ransom/extortion [29]
   - API [23]
   - patch [32]
   - privileged access [14]
   - lateral movement/PowerShell [6]
   - exfiltration/staging [89]
   - customer data/SIN [26]
   - DNS/spoofing/impersonation [46]
   - SDLC [5]
   - vendor (ThemeThirdParty) [73]
   - awareness [30]
   - ransomware+backup [70]
   - insider [231]
   - misconfiguration/change [58]
   - DDoS [35]
3. Further `identify` calls:
   - terminal/kiosk/jackpotting/card [9]
   - OT+payment [2]
   - payment/transaction [32]
   - email gateway/DMARC/spear-phishing [7]
   - malicious attachment/macro [2]
   - DLP/classification [4]
   - MFA [12]
   - reputation [46]
   - sector=Banking [0]

## Step 1: candidate list (40, frozen before Step 2)

| # | ID | Name | Why (profile evidence) |
|---|---|---|---|
| 1 | LIB-F1603 | Spear Phishing Attack: Credential Compromise | 2022 entry vector: vendor/regulator-themed spear-phish, T-14 AML-template lure |
| 2 | LIB-F1489 | Malware-infected Email Attachments | malicious attachment executed (PowerShell alert T-13) |
| 3 | LIB-F1463 | Ransomware Infection | ransomware encrypted critical systems, one week outage |
| 4 | LIB-F0650 | Data Exfiltration | staging of customer exports, 100k customers incl. SIN |
| 5 | LIB-F1537 | Advanced phishing attack followed by lateral movement | two-week dwell, credential harvesting, lateral movement |
| 6 | LIB-F1266 | Lack of Network Segmentation - Lateral Movement Attack | segmentation in audit universe; ransomware spread across branches/DCs |
| 7 | LIB-F1110 | Inadequate monitoring and logging, affecting incident response capabilities | SOC auto-closed alert; two-week dwell |
| 8 | LIB-F0431 | Inadequate incident response testing | IA-21-04: ransomware tabletop postponed twice |
| 9 | LIB-F0441 | Inadequate Data Backup and Recovery | IA-21-05: only file-level restores tested; RTO/RPO |
| 10 | LIB-F0111 | Unauthorized Access to Backups | backup isolation question |
| 11 | LIB-F1749 | Inability to patch known vulnerabilities in legacy systems | 1970s core banking; IA-21-03 exceptions |
| 12 | LIB-F1786 | Inadequate Security Patch Management | inconsistent patching, IA-21-03 |
| 13 | LIB-F1777 | Exploitation of vulnerabilities in legacy systems no longer supported | legacy core banking; proxy for legacy ATM/POS platforms (no ATM scenario) |
| 14 | LIB-F0145 | Inadequate multi-factor authentication for VPN access | T-10 VPN login from unusual geography with valid account |
| 15 | LIB-F0130 | Credential Stuffing | online banking/mobile login of customers |
| 16 | LIB-F1036 | Insider Threat - Misuse of Privileged Access | privileged access in appetite statement and audit universe |
| 17 | LIB-F1008 | Insider Threat - Unauthorized Access and Data Theft | ~500 client-facing staff with access to customer records |
| 18 | LIB-F1399 | Misconfiguration of Network Firewall | Cisco firewalls, configuration management |
| 19 | LIB-F0510 | Data breaches due to misconfigured cloud permissions | AWS/Azure, shared responsibility |
| 20 | LIB-F0497 | Data leakage through insecure APIs | digital banking API security |
| 21 | LIB-F0571 | Mobile application vulnerability exposing patient data | mobile banking app (healthcare wording) |
| 22 | LIB-F1788 | Web Application Vulnerability Exploitation | online banking portal |
| 23 | LIB-F0707 | DDoS Attack | online banking availability |
| 24 | LIB-F0216 | Skimming attacks on point-of-sale terminals | ~700 POS terminals, ~800 ATMs |
| 25 | CanaRetail/CR-S5 | CanaRetail Credit Crunch: POS Malware Infiltration | POS terminals (cross-case analog) |
| 26 | LIB-F1708 | Data Exfiltration via Third-Party Vendor | third-party exposure, critical suppliers |
| 27 | LIB-F0670 | Data loss due to cloud service outages | cloud/vendor dependency |
| 28 | LIB-F0524 | Data leakage due to weak encryption | appetite: encryption of high-risk data stores |
| 29 | LIB-F0557 | Non-compliance with data breach notification laws | slow notification criticised; PIPEDA/OSFI reporting |
| 30 | LIB-F0413 | Lack of an emergency communication plan | poor customer communication, media pressure |
| 31 | LIB-F0827 | Ineffective governance structures for cybersecurity | pre-incident governance failure, CEO/CIO suspended |
| 32 | LIB-F0900 | Inability to recruit IT staff | team growing from 20 to 39, hiring capacity |
| 33 | LIB-F0967 | Ineffective Employee Security Awareness Training | IA-21-02 |
| 34 | MediBec-CRG/S16 | Loss of the hub or WAN isolates clinics from central systems | 30 branches depend on central connectivity |
| 35 | LIB-F0305 | Lack of data governance in data lakes | analytics/AI marketing on customer data |
| 36 | LIB-F0632 | Physical Security Breach | branches, data centres |
| 37 | LIB-F1612 | Business Email Compromise (BEC) Scam | payment fraud against bank/finance staff |
| 38 | LIB-F1565 | VoIP phishing (vishing) attacks | call centre/IVR, Cisco VoIP |
| 39 | LIB-F1541 | Fraudulent transactions using stolen payment data | fraud monitoring in digital banking |
| 40 | MediBec-CRG/S30 | Criminals impersonate the organisation to defraud or phish clients | customer-targeted phishing after public breach (cross-case analog) |

## Step 2: reference list (author's expected scenarios)

Sources:
- the 15 Scenario Library items (CYR-01..15)
- the 10 instructor annex scenarios (A1..A10)
- `cases_extract.json`, which also lists ACRB-INC-2022 (the 2022 incident itself)

After merging duplicates, N = 19.

| Ref | Source IDs merged | Risk (threat event against asset) |
|---|---|---|
| R1 | CYR-01, A8, INC-2022 | Spear-phishing/malicious attachment, then credential harvesting, ransomware on core/shared systems and customer data exfiltration |
| R2 | CYR-02 | Compromised privileged admin account (external use from unusual location), then lateral movement and disabling of security tools |
| R3 | CYR-03, A10 | Exploitation of an unpatched (legacy) core banking component |
| R4 | CYR-04 | Cloud storage misconfiguration exposes marketing analytics customer data |
| R5 | CYR-05, A6 | Third-party payment processor breach exposes ACRB customer financial data |
| R6 | CYR-06 | Mobile banking API account enumeration (no rate limiting) feeding fraud |
| R7 | A3 | Mobile app encryption flaw enables MITM interception of credentials/transactions |
| R8 | CYR-07 | Departing disgruntled insider exports customer records |
| R9 | A2 | Disgruntled insider manipulates transaction data to divert funds (insider fraud) |
| R10 | CYR-08 | SOC alert fatigue: kill-chain alerts closed, detection missed |
| R11 | CYR-09 | Backups reachable from compromised admin domain, so ransomware recovery is delayed |
| R12 | CYR-10 | ATM or merchant POS malware compromises transaction integrity |
| R13 | CYR-11 | DDoS against online banking during a public incident |
| R14 | CYR-12, A7 | Compromised personal (BYOD) tablet gives a foothold in the internal network |
| R15 | CYR-13, A5 | Certificate/encryption lifecycle failure: expired certificate causes an outage; obsolete crypto on online banking enables interception |
| R16 | CYR-14, A4 | Tailgating into data centre; rogue device or direct data theft |
| R17 | CYR-15 | Vendor remote-support tool compromised and used to access ACRB after hours |
| R18 | A1 | Outdated or misconfigured firewall misses malicious traffic |
| R19 | A9 | Ineffective incident response (no plan) during malware exfiltration from mainframe |

Merging decisions:
- A2 and CYR-07 were kept apart: A2 is funds diversion (fraud), CYR-07 is data theft.
- A3 and CYR-06 were kept apart: they are different threat events.
- A5 was merged into CYR-13, whose text includes obsolete encryption configuration.
- The Appendix F "sample top risks" are themes already covered by R1, R2, R4, R5, R10 and R11, so they were not counted again.

## Step 3: coverage

| Ref | Verdict | Candidate(s) | Note / cause |
|---|---|---|---|
| R1 | covered | F1603, F1489, F1463, F0650, F1537 | full chain represented, but split over 5 entries |
| R2 | partly | F1266, F0145, F1036 | lateral movement and VPN MFA present. F1036 is an insider, not an external party using a stolen privileged account. LIB-F0122 "Stolen Administrative Credentials" and MediBec-CRG/S1 were **surfaced but not picked** |
| R3 | covered | F1749, F1786, F1777 | |
| R4 | covered | F0510 | (marketing-data specificity left to the analyst) |
| R5 | covered | F1708 | vendor breach exposing customer data; "payment processor" not in library wording |
| R6 | partly | F0497, F0571 | API leakage, but not enumeration/automation. LIB-F0164 "Inadequate API rate limiting" exists, **not surfaced** |
| R7 | covered | F0571 | LIB-F1252 (insecure mobile transmission) also exists |
| R8 | covered | F1008 | |
| R9 | partly | F1036 | privileged misuse only. LIB-F1009 / F1066 (unauthorised modification of financial records, embezzlement) **exist, surfaced but not picked**: F1009 was top of the insider query |
| R10 | covered | F1110 | detection failure (alert fatigue as cause not explicit) |
| R11 | covered | F0111, F0441 | |
| R12 | partly | F0216, CanaRetail/CR-S5 | POS covered. **ATM absent** from library (0 matches for ATM / automated teller / cash dispenser) |
| R13 | covered | F0707 | |
| R14 | **missed** | none | LIB-F1794 "BYOD Vulnerability" and LIB-F1474 "Malware Infection via Employee's Personal Device" **exist, not surfaced**: the sweep's BYOD representative was F0793 (operational instability, wrong risk), and the profile never mentions BYOD |
| R15 | partly | F0524 | obsolete encryption covered. Certificate-expiry outage **absent** (only F0490 "time-bound security certificates", weak). LIB-F0448 "deprecated cryptographic algorithms" surfaced, not picked |
| R16 | covered | F0632 | LIB-F0623 "Physical Security Breach - Data Center" is closer, surfaced |
| R17 | **missed** | none | LIB-F1665 "Unauthorized remote access by suppliers" and MediBec-CRG/S9 "Compromise of a critical vendor with remote access" **exist, not surfaced**: they only appear when vendor and remote access are queried together (`themes=[ThemeThirdParty], keywords=[remote access]`) |
| R18 | covered | F1399 | |
| R19 | covered | F0431, F1110 | |

**Counts (N = 19):** covered 12, partly 5, missed 2.

**Recall = (12 + 0.5 × 5) / 19 = 14.5 / 19 = 0.76.**

Precision indication: 26 of the 40 candidates map to a reference item. The other 14 are plausible risks the author did not list:
- governance and staffing
- breach notification and crisis communication
- BEC, vishing and impersonation
- WAN outage and cloud outage
- analytics data governance
- web application vulnerabilities
- credential stuffing
- payment fraud
- awareness training

## Misses and partial misses by cause

| Cause | Items |
|---|---|
| Library has it, not surfaced by sweep or follow-ups | R14 BYOD (F1794, F1474); R17 vendor remote access (F1665, MediBec-CRG/S9); R6 API rate limiting (F0164) |
| Surfaced, not picked (analyst/selection) | R2 stolen admin credentials (F0122, MediBec-CRG/S1); R9 insider financial-record manipulation (F1009, F1066); R15 deprecated crypto (F0448) |
| Absent from library | R12 ATM malware (POS only); R15 certificate-expiry outage |

## Observations specific to a non-healthcare organisation

1. **Banking vocabulary is missing.** "ATM" returns 0 scenarios. Core banking, mobile banking, online banking, payment processor and account enumeration only match generic or healthcare-worded items such as "Mobile application vulnerability exposing patient data" and "Web Application Vulnerability - Patient Portal". `SYNONYMS` has no banking or payment groups (for example ATM/teller/cash machine, POS/payment terminal/card, core banking/mainframe, online banking/e-banking/customer portal). The analyst has to translate every hit.
2. **The healthcare framing leaks into ranking and names.** The sweep's top 60 includes:
   - "Ransomware Attack on Hospital Systems"
   - "APT on Hospital Network"
   - "Data Exfiltration - Healthcare Provider Credential Theft"
   - "multi-stage attack ... laboratory systems"
   - several healthcare-irrelevant fillers (software licensing compliance, "Users cannot use new application software", "Pharming Attack" filed under insider)

   The sweep is usable as a theme checklist, but only about half of its picks were usable directly.
3. **The sweep's breadth hides specific risks.** With 9 asset categories, 20 themes and 44 keywords, almost the whole library matches (1854 candidates). Selection then falls back on per-theme representatives and "commonly assessed" names. The BYOD slot went to the wrong scenario (F0793), and neither the vendor-remote-access nor the insider-fraud representative surfaced. Combined-concept risks (vendor × remote access, insider × transaction manipulation, API × enumeration) only appear with targeted AND queries, which the analyst has to think of.
4. **Cross-case scenarios helped.** MediBec-CRG/S16 (WAN hub isolating sites) and CanaRetail/CR-S5 (POS malware) were the best available analogs for the branch network and POS terminals. MediBec-CRG/S9 would have covered R17. Retail and hospitality cases partly fill the payment gap that the healthcare library leaves.
5. **Keyword false positives.** "asset inventory" matched "compliance requirements inventory" and "pharmacy inventory", and the actual risk (IA-21-01, incomplete inventory of ATMs, POS and cloud workloads) has no scenario. "notification/communication" returned 107 matches, mostly noise.
6. **Duplicate-heavy library.** Several near-identical ransomware, insider, pharming and DDoS variants were returned, and the near-duplicate merge in the sweep only works within one theme.
7. **The reference contains no governance or people risks** (staffing, governance, notification compliance, communication), although the profile emphasises them. A profile-driven list will produce extras the author did not list, so precision against this reference understates usefulness.

## Recommendations

- Add a banking/payments synonym set and generic scenarios that are currently absent: ATM malware/jackpotting, certificate-expiry outage, incomplete asset inventory.
- In `sweep`, add combination probes (third-party × remote access, insider × financial manipulation, API × rate limiting, BYOD × malware) to the BASELINE list. BYOD should map to F1794/F1474, not F0793.
- Down-weight healthcare-specific names when the profile has no healthcare terms.
