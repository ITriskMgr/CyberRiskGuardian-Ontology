# Spot check: scenario-family links to frameworks (links.csv)

- Reviewer: independent expert review (cyber risk, ATT&CK, CSF 2.0, SP 800-53r5, ISO/IEC 27002:2022, Loi 25). I did not see how the links were produced.
- Date: 2026-10-09
- Population: 1,811 families, 18,948 links (attack 1,973 · csf2 5,045 · sp80053r5 5,479 · iso27002 5,028 · loi25 1,422).
- Sample: 50 families drawn with `random.seed(11); random.sample(sorted(family_ids), 50)`, using every family id in `work/linking/batch_*.jsonl`. The sample holds **510 links**.
- Grading scale: **correct** means a risk analyst would cite it. **Acceptable** means it is defensible but not the best item. **Wrong** means it does not address the scenario or misreads it. Each link was judged against the family name, narrative, events, consequences and mitigations, and against the item title in `reference.md`.
- Sampled families: F0031 F0062 F0074 F0086 F0122 F0130 F0186 F0193 F0291 F0323 F0379 F0382 F0389 F0390 F0496 F0622 F0812 F0915 F0926 F0927 F0928 F0954 F0975 F1041 F1049 F1083 F1104 F1147 F1203 F1220 F1229 F1258 F1261 F1277 F1290 F1300 F1332 F1340 F1421 F1514 F1594 F1600 F1625 F1647 F1659 F1704 F1752 F1755 F1774 F1802

## 1. Results by scheme

| Scheme | Links | Correct | Acceptable | Wrong | % correct | % correct+acceptable |
|---|---|---|---|---|---|---|
| attack | 53 | 39 | 13 | 1 | 73.6% | 98.1% |
| csf2 | 136 | 110 | 25 | 1 | 80.9% | 99.3% |
| sp80053r5 | 147 | 128 | 19 | 0 | 87.1% | 100.0% |
| iso27002 | 134 | 114 | 19 | 1 | 85.1% | 99.3% |
| loi25 | 40 | 32 | 7 | 1 | 80.0% | 97.5% |
| **All** | **510** | **423** | **83** | **4** | **82.9%** | **99.2%** |

## 2. Precision by confidence level

| Confidence | Links | Correct | Acceptable | Wrong | % correct | % correct+acceptable |
|---|---|---|---|---|---|---|
| H | 194 | 189 | 5 | 0 | 97.4% | 100.0% |
| M | 281 | 225 | 56 | 0 | 80.1% | 100.0% |
| L | 35 | 9 | 22 | 4 | 25.7% | 88.6% |

The confidence levels are well calibrated and point the right way.
- **H** can be trusted. The only 5 H links I downgraded to acceptable (F1600: PR.AA-05, 5.15, AC-3; F0975: AC-3; F0954: 8.13) are generic access-control or backup controls that are relevant but not the main control for the scenario.
- **M** links are all at least defensible.
- **L** links are best read as "suggestions". All 4 wrong links in the sample are L, and only about a quarter of L links are the item an analyst would pick first.

## 3. Wrong links

| Family | Scheme | ID | Why it is wrong |
|---|---|---|---|
| F0186 Unauthorized document deletion | iso27002 | 8.10 Information deletion (L) | 8.10 covers *secure deletion* of information that is no longer needed. It is the opposite concern, not a safeguard against unauthorized deletion. The right controls (8.3, 8.13, 5.15) are already linked. |
| F0496 Acoustic data exfiltration | attack | T1011 Exfiltration Over Other Network Medium (L) | T1011 covers an alternative *network* medium such as Wi-Fi, Bluetooth or cellular. An acoustic covert channel is not a network medium, and ATT&CK Enterprise has no acoustic technique. Leaving ATT&CK blank, with SC-31 and PE-19 carrying the scenario, is better than a misleading technique. |
| F0915 Scams mimicking employee benefit programs | csf2 | DE.CM-09 (L) | Monitoring of computing hardware, software and runtime environments does not address a social-engineering or fraud scenario. DE.CM-03 or DE.AE-02 would fit better. |
| F1220 Inadequate data encryption on wearables | loi25 | P-39.1 s. 3.5 (1st para.) (L) | This is a post-incident obligation (reasonable measures after a confidentiality incident) attached to a preventive *vulnerability* scenario. The right Loi 25 hook is s. 10 (security measures proportionate to sensitivity), which is **not in the reference list** (see problem 2). |

## 4. Notable omissions (clear cases only, at most 2 per family)

| Family | Missing | Why |
|---|---|---|
| F0122 Stolen administrative credentials | attack T1566 Phishing; PR.AT-01 / AT-2 / 6.3 awareness | Event 1 says the credentials were obtained through a phishing email. The initial-access step and its main control are both missing. |
| F1600 Social engineering targeting appointment system | attack T1566 Phishing (+ T1204 User Execution); 8.7 / SI-3 malware protection | The events are phishing, then malware download, then access. T1078 was linked instead, which misreads the access path. |
| F1203 Unauthorized access to medical device systems | PR.IR-01 / 8.22 / SC-7 segmentation; attack T1210 | Segmenting medical devices is the first mitigation listed, and the events describe exploiting device vulnerabilities, not valid accounts. |
| F1421 Physical intrusion: theft of hardware with sensitive data | loi25 s. 3.5 (2nd para.) / 3.8; 7.10 or SC-28 (protection of stored data) | Theft of hardware holding patient data is a confidentiality incident (loss) under Loi 25, yet the family has no Loi 25 link at all. |
| F0622 Breach of healthcare information system | attack T1041 (exfiltration); T1657 (extortion / financial theft) | Events 4 and 6 describe exfiltration and a ransom demand. Only initial access (T1190) is mapped. |
| F1594 Social engineering phishing | attack T1684.001 Impersonation | The narrative is about impersonating staff and vendors by phone and email. Phishing is mapped, but impersonation is not. |
| F1704 Third-party software vulnerabilities | ID.RA-10 / 5.21 / SR-6 supplier assessment | The narrative says the hospital *purchases* software with known vulnerabilities. Only technical vulnerability management is linked, not the supply-chain side. |
| F0927 Critical servers damaged | PE-13 Fire Protection | Fire suppression is listed as a mitigation. Coverage through PE-14 and 7.5 is partial. |
| F0031 Inadequate cloud IAM | loi25 incident or governance link | The family is tagged DimPrivacy and the text mentions medical records, but it has no Loi 25 link. |

Population check: **176 of 554 families tagged `DimPrivacy` (32%) have no Loi 25 link**. **153 of 984 `SrcAdversarial` families (16%) have no ATT&CK link**. Some of these are legitimate, for example purely physical or insider-procedural scenarios. Many are not.

## 5. Main problems

1. **Coverage is weaker than precision, especially for ATT&CK.** Families have only 1.8 techniques on average, and the techniques tend to be either the initial-access step or the impact step. Explicit chain steps in the events are skipped: phishing in F0122 and F1600, exfiltration and extortion in F0622. T1078 Valid Accounts is used as a generic fallback (270 links, the most common technique). In F1600, F1203 and F0074 it stands in for the real access vector. ATT&CK also has the lowest strict precision (74%).
2. **Loi 25 linking is formulaic and missing a key article.** The incident triad s. 3.5 (2nd para.), s. 3.7 and s. 3.8 makes up 1,137 of 1,422 Loi 25 links (80%). It is correct for breach scenarios but tells them apart poorly. The reference list has **no s. 10** (security measures appropriate to the sensitivity of the information), which is the obligation most vulnerability and control-weakness scenarios engage. Those scenarios therefore get a post-incident article (F1220) or nothing. Meanwhile 32% of privacy-impact families have no Loi 25 link at all (F1421 is a clear case), while some families get the triad on implied personal information only (F1774, F1203).
3. **The L tier and generic controls need filtering.** L links are only 26% strictly correct and hold every wrong link in the sample. The most frequent controls (PR.AA-05 in 421 families, SI-4 in 299, 8.16 in 366, DE.CM-09 in 309) are sometimes added as tangential fillers, a few of them with H confidence (F1600, F0975). Together this inflates control lists and makes families look alike.

Item to verify (not counted as an error): the ATT&CK reference is labelled "Enterprise 19.2" and uses IDs and tactics that differ from widely deployed ATT&CK versions: T1684 Social Engineering / T1684.001 Impersonation, T1685.xxx Disable or Modify Tools / Clear Windows Event Logs under a "defense-impairment" tactic, and "stealth" in place of defense-evasion. T1656, T1562 and T1070.001 do not appear in the reference. Before publishing, confirm these IDs against the official MITRE STIX release, and provide a crosswalk for tools still on older ATT&CK versions.

Data-quality note (scenario text, not the links): several families have no narrative or events, and their "mitigations" field holds leaked prompt text or methodology text instead of mitigations (e.g. F0001, F0291, F1229, F1258, F1340). Their links were evidently inferred from the family name alone. They are still mostly correct, but they are necessarily generic.

## 6. Verdict

**Usable for threat, vulnerability and control identification with human review.** In the sample, 99% of links are at least defensible and 83% are the item an analyst would cite. H links are 97% correct, so they can be accepted with light review. M links should be reviewed. L links should be treated as suggestions.

The human review should focus on **completeness**, not correctness:
- Add the missing ATT&CK chain steps (initial access, exfiltration, impact) from each family's events.
- Add Loi 25 links for privacy-impact families, and add s. 10, and arguably s. 3.2, to the reference list for preventive scenarios.
- Prune generic L and M filler controls.

The control mappings (CSF 2.0, SP 800-53r5, ISO 27002) are the strongest part and are fit to seed control identification as they stand. ATT&CK and Loi 25 are fit as a starting point, not as a complete threat or obligation inventory.
