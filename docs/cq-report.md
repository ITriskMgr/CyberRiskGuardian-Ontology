# Competency questions: results

## CQ01 — pass

Which library scenarios affect a given asset category (here: OT, IoT and connected devices)?

Expected: min_rows 50. Rows: 105. Time: 0.02 s.

| scenario | name |
|---|---|
| data/library/F1160 | Bypassing authentication in IoT devices |
| data/library/F1188 | Compromise of Building Management Systems (BMS) |
| data/library/F1163 | Compromise of IoT sensors used in patient care, leading to false readi |
| data/library/F1167 | Compromise of smart HVAC systems |
| data/library/F1219 | Compromise of wearable device leading to false health alerts |
| data/library/F1141 | Counterfeiting of medical equipment through 3D printing |
| data/library/F1429 | Cyber-Physical Attack on Medical Devices |
| data/library/F1205 | Cyberattack on Medical Devices |

## CQ02 — pass

For a scenario theme (here: ransomware), which scenarios belong to it and what kinds of threat source do they involve?

Expected: min_rows 30; contains type=adversarial. Rows: 99. Time: 0.02 s.

| scenario | name | type |
|---|---|---|
| data/library/F1446 | 1502  Regularly, there is infection of laptops with malware | adversarial |
| data/library/F1434 | Use of unauthorized external storage devices, leading to data exfiltra | accidental |
| data/library/F1434 | Use of unauthorized external storage devices, leading to data exfiltra | adversarial |
| data/library/F1442 | Industrial espionage takes place | adversarial |
| data/library/F1462 | Pharming Attack Redirecting Patients' Online Activities | adversarial |
| data/library/F1435 | Outdated antivirus software |  |
| data/library/F1495 | Malware Infection Through Vulnerable Software | adversarial |
| data/library/F1487 | Zero-day Exploit on Hospital Systems | adversarial |

## CQ03 — pass

Which ATT&CK techniques does a scenario's threat event use, with the confidence and approval status of each link?

Expected: min_rows 1; contains notation=T1486. Rows: 2. Time: 0.00 s.

| notation | technique | confidence | approved |
|---|---|---|---|
| T1486 | Data Encrypted for Impact | high confidence | true |
| T1078 | Valid Accounts | medium confidence | true |

## CQ04 — pass

Given an ATT&CK technique and its sub-techniques (here: T1566 Phishing), which library scenarios use it?

Expected: min_rows 20. Rows: 122. Time: 0.00 s.

| scenario | name | notation |
|---|---|---|
| data/library/F0259 | Pharming Attack on Website | T1566 |
| data/library/F0113 | Email Account Compromise | T1566 |
| data/library/F0108 | Social Media Account Takeover | T1566 |
| data/library/F1535 | 1504  Company data are stolen through unauthorized access gained by a  | T1566 |
| data/library/F0109 | Unauthorized Access to Healthcare Information System | T1566 |
| data/library/F1625 | Social Engineering and Phishing Attack on Employee Credentials | T1566 |
| data/library/F1542 | Phishing attacks targeting employees to gain unauthorized access | T1566 |
| data/library/F1520 | Business Email Compromise (BEC) attacks | T1566 |

## CQ05 — pass

Which control requirements (CSF 2.0, SP 800-53, ISO/IEC 27002) are relevant to a scenario, highest confidence first, approved links only?

Expected: min_rows 3; contains scheme=https://w3id.org/crgo/vocab/sp800-53r5. Rows: 11. Time: 0.00 s.

| scheme | notation | title | confidence |
|---|---|---|---|
| vocab/csf2 | PR.DS-11 | Backups of data are created, protected, maintained, and tested | high confidence |
| vocab/iso27002-2022 | 8.13 | Information backup | high confidence |
| vocab/sp800-53r5 | CP-9 | System Backup | high confidence |
| vocab/csf2 | PR.AA-05 | Access permissions, entitlements, and authorizations are defined in a  | medium confidence |
| vocab/csf2 | RC.RP-01 | The recovery portion of the incident response plan is executed once in | medium confidence |
| vocab/csf2 | RS.MI-01 | Incidents are contained | medium confidence |
| vocab/iso27002-2022 | 5.26 | Response to information security incidents | medium confidence |
| vocab/iso27002-2022 | 8.7 | Protection against malware | medium confidence |

## CQ06 — pass

Which scenarios does a given control address (here: SP 800-53 SI-4 System Monitoring), grouped by theme?

Expected: min_rows 10. Rows: 22. Time: 0.01 s.

| theme | scenarios |
|---|---|
| data breach and exfiltration | 57 |
| networks and remote access | 48 |
| IoT, OT and medical devices | 37 |
| phishing and social engineering | 37 |
| denial of service and availability | 32 |
| legacy, patch and configuration management | 27 |
| malware and ransomware | 23 |
| identity and access | 21 |

## CQ07 — pass

Which scenarios can trigger the Loi 25 duty to notify the Commission and the persons concerned (P-39.1 s. 3.5, 2nd paragraph)?

Expected: min_rows 100. Rows: 426. Time: 0.01 s.

| scenario | name |
|---|---|
| data/library/F1621 | Zero-Day Exploit on CRM System |
| data/library/F1690 | Zero-day Exploit on Healthcare Information Systems |
| data/library/F0262 | SQL Injection Attack on Website Database |
| data/library/F1382 | Physical theft of backup storage devices |
| data/library/F1668 | Insecure data transmission between third-party labs and hospital labor |
| data/library/F0719 | Unauthorized access to augmented reality healthcare platforms |
| data/library/F0552 | Failure to report a data breach within stipulated timeframes |
| data/library/F0659 | Data Breach through Unencrypted Backup Tapes |

## CQ08 — pass

Which vulnerabilities (weaknesses) are described for scenarios affecting a given asset category (here: cloud and third-party services)?

Expected: min_rows 10. Rows: 40. Time: 0.01 s.

| weakness | scenario |
|---|---|
| Insecure data transmission between third-party labs and hospital labor | data/library/F1668 |
| Insufficient application of security controls to cloud-based assets | data/library/F0296 |
| Insecure vendor platforms | data/library/F1629 |
| Inadequate vetting of vendor security policies | data/library/F1630 |
| Unsecured Cloud Storage | data/library/F0599 |
| Insecure cloud data storage | data/library/F0285 |
| Insecure cloud resource provisioning | data/library/F0286 |
| Lack of third-party verification in audits | data/library/F1628 |

## CQ09 — pass

For a sector (here: healthcare), which case scenarios exist and which generic library scenarios do they refine?

Expected: min_rows 20. Rows: 196. Time: 0.01 s.

| case | caseName | family | familyName |
|---|---|---|---|
| data/library/C-MediBec-CRG-S18 | Web application flaw in the patient portal exposes other patients' rec | data/library/F1796 | Web Application Vulnerability - Patient Portal |
| data/library/C-MediBec-CRG-S18 | Web application flaw in the patient portal exposes other patients' rec | data/library/F0263 | SQL Injection Attack on Healthcare Information System |
| data/library/C-MediBec-CRG-S18 | Web application flaw in the patient portal exposes other patients' rec | data/library/F1792 | Web Application Vulnerability - Healthcare Information System |
| data/library/C-MediBec-CRG-S18 | Web application flaw in the patient portal exposes other patients' rec | data/library/F0182 | Unauthorized direct object reference attacks on databases |
| data/library/C-MediBec-CRG-S18 | Web application flaw in the patient portal exposes other patients' rec | data/library/F0616 | Data Leakage via Vulnerable Web Application |
| data/library/C-MediBec-CRG-S20 | Takeover of cloud tenant administration through token theft or malicio | data/library/F0033 | Unauthorized access to cloud management consoles |
| data/library/C-MediBec-CRG-S20 | Takeover of cloud tenant administration through token theft or malicio | data/library/F0041 | Session hijacking attacks |
| data/library/C-MediBec-CRG-S26 | Staff paste patient data into unapproved generative-AI tools | data/library/F0653 | Data Leakage through Unauthorized Cloud Storage Usage |

## CQ10 — pass

What estimates does a library scenario have, from which source, with what confidence and spread?

Expected: min_rows 8; contains confidence=low confidence. Rows: 24. Time: 0.00 s.

| parameter | value | low | high | n | confidence | evidence |
|---|---|---|---|---|---|---|
| probability of exploitation Pb(ψ,A) | 0.45 | 0.4 | 0.5 | 2 | low confidence | CASE-ACRB |
| probability of exploitation Pb(ψ,A) | 0.45 | 0.4 | 0.5 | 2 | low confidence | CASE-CanaRetail |
| threat presence Pb(A) | 0.7 | 0.6 | 0.8 | 21 | low confidence | LIB-2023 |
| maximum damage δm | 0.925 | 0.9 | 0.95 | 2 | low confidence | CASE-ACRB |
| maximum damage δm | 0.925 | 0.9 | 0.95 | 2 | low confidence | CASE-CanaRetail |
| organisational resilience θ | 0.6 | 0.4 | 0.7 | 21 | low confidence | LIB-2023 |
| expected damage δe | 0.8 | 0.5 | 0.9 | 21 | low confidence | LIB-2023 |
| probability of exploitation Pb(ψ,A) | 0.7 | 0.6 | 0.8 | 21 | low confidence | LIB-2023 |

## CQ11 — pass

Rank the scenarios of a theme (here: ransomware) by CRG estimated risk, preferring case-calibrated values.

Expected: min_rows 3. Rows: 15. Time: 0.02 s.

| scenario | name | estimatedRisk | caseCalibrated |
|---|---|---|---|
| data/library/F1481 | Targeted Malware Attack on CRM System | 8806 | false |
| data/library/F1473 | Malware Infection via Third-Party Supplier | 7908.75 | false |
| data/library/F1436 | A combined phishing and ransomware attack targeting healthcare informa | 7893.482143 | true |
| data/library/F1461 | Ransomware attack encrypting patient medical records for extortion | 7893.482143 | true |
| data/library/F1501 | Ransomware Attack on Healthcare Information Systems | 7893.482143 | true |
| data/library/F1472 | Ransomware Attack on Patient Records | 7893.482143 | true |
| data/library/C-MediBec-CRG-S2 | Ransomware disrupting EHR access and clinic operations across the netw | 7893.482143 | false |
| data/library/F1468 | Ransomware Attack on Hospital Systems | 7893.482143 | true |

## CQ12 — pass

What is the threat landscape of healthcare case scenarios: which ATT&CK techniques appear most often in the library scenarios they refine?

Expected: min_rows 5. Rows: 15. Time: 0.02 s.

| notation | technique | scenarios |
|---|---|---|
| T1078 | Valid Accounts | 35 |
| T1190 | Exploit Public-Facing Application | 17 |
| T1557 | Adversary-in-the-Middle | 13 |
| T1485 | Data Destruction | 9 |
| T1040 | Network Sniffing | 9 |
| T1498 | Network Denial of Service | 8 |
| T1530 | Data from Cloud Storage | 8 |
| T1565.001 | Stored Data Manipulation | 8 |

## CQ13 — pass

Which current ATT&CK technique replaces a revoked identifier used by older tools (here: T1562 Impair Defenses)?

Expected: rows 1; contains new=T1685. Rows: 1. Time: 0.00 s.

| old | new | name |
|---|---|---|
| T1562 | T1685 | Disable or Modify Tools |

## CQ14 — pass

In the MediBec assessment, which scenarios are above tolerance, with estimated and residual risk and the ratio?

Expected: min_rows 10; sum est=84491 over all. Rows: 30. Time: 0.02 s.

| id | name | est | res | ratio | class |
|---|---|---|---|---|---|
| S19 | Trojanized software update from a clinical or IT software supplier | 2235.044642857 | 1653.933035714 | 1.911666667 | above tolerance |
| S28 | Malicious or departing IT administrator sabotages systems | 1685.957142857 | 1129.591285714 | 1.730833333 | above tolerance |
| S9 | Compromise of a critical vendor with remote access to MediBec systems | 4057.232142857 | 2495.197767857 | 1.5375 | above tolerance |
| S7 | Connected medical device used as a foothold to disrupt clinical equipm | 3775.178571429 | 2189.603571429 | 1.45 | above tolerance |
| S16 | Loss of the Montreal hub or WAN isolates clinics from central clinical | 2959.25 | 1612.79125 | 1.271666667 | above tolerance |
| S27 | Help-desk impersonation leads to MFA reset and account takeover | 3940.1484375 | 2048.8771875 | 1.256666667 | above tolerance |
| S5 | Misuse of legitimate clinical, privileged or service-account access to | 2811.6 | 1715.076 | 1.22 | above tolerance |
| S2 | Ransomware disrupting EHR access and clinic operations across the netw | 7893.482142857 | 3453.3984375 | 1.203125 | above tolerance |

## CQ15 — pass

For an assessment scenario, which estimates rest on which evidence, and what kind of evidence is it?

Expected: min_rows 6. Rows: 9. Time: 0.00 s.

| parameter | value | evidence | basis |
|---|---|---|---|
| organisational resilience θ | 0.4 | E3 | documented evidence |
| organisational resilience θ | 0.4 | E6 | exercise or simulation evidence |
| probability of exploitation Pb(ψ,A) | 0.55 | E6 | exercise or simulation evidence |
| threat presence Pb(A) | 0.85 | E4 | documented evidence |
| threat presence Pb(A) | 0.85 | E6 | exercise or simulation evidence |
| expected damage δe | 0.55 | E1 | documented evidence |
| expected damage δe | 0.55 | E6 | exercise or simulation evidence |
| maximum damage δm | 0.85 | E1 | documented evidence |

## CQ16 — pass

Which links are still proposed (awaiting approval), by framework?

Expected: min_rows 1. Rows: 7. Time: 0.17 s.

| scheme | proposedLinks |
|---|---|
| vocab/attack | 521 |
| vocab/csf2 | 274 |
| vocab/iso27002-2022 | 387 |
| vocab/loi25 | 213 |
| vocab/lrsss | 2298 |
| vocab/sp800-53r5 | 403 |
| vocab/theme | 822 |

## CQ17 — pass

Which ontology terms are not yet approved?

Expected: rows 0. Rows: 0. Time: 0.02 s.

## CQ18 — pass

Which library scenarios have no control requirement link? (should be none)

Expected: rows 0. Rows: 0. Time: 0.01 s.

## CQ19 — pass

Which controls address the most themes (cross-cutting controls worth prioritising)?

Expected: min_rows 10. Rows: 15. Time: 0.04 s.

| notation | title | themes | scenarios |
|---|---|---|---|
| 8.16 | Monitoring activities | 22 | 367 |
| 8.8 | Management of technical vulnerabilities | 21 | 226 |
| 6.3 | Information security awareness, education and training | 21 | 212 |
| 8.3 | Information access restriction | 21 | 157 |
| 8.22 | Segregation of networks | 20 | 162 |
| 5.15 | Access control | 20 | 135 |
| 8.5 | Secure authentication | 19 | 223 |
| 8.20 | Networks security | 19 | 156 |

## CQ20 — pass

Which scenarios match free-text keywords (here: 'backup') together with their theme, as a starting point for an analyst?

Expected: min_rows 10. Rows: 39. Time: 0.02 s.

| scenario | name | theme |
|---|---|---|
| data/library/F1382 | Physical theft of backup storage devices | physical and environmental |
| data/library/F0659 | Data Breach through Unencrypted Backup Tapes | data breach and exfiltration |
| data/library/F0439 | Insufficient data backup locations | continuity and incident response |
| data/library/F0658 | Data Leakage via Unencrypted Backup Tapes | data breach and exfiltration |
| data/library/F1386 | Theft of backup drives from secured storage | physical and environmental |
| data/library/F0437 | Backup media is lost or backups are not checked for effectiveness | continuity and incident response |
| data/library/F0441 | Inadequate Data Backup and Recovery | malware and ransomware |
| data/library/F0441 | Inadequate Data Backup and Recovery | continuity and incident response |

