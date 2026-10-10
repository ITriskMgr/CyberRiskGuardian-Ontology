You are judging which obligations of Québec's private-sector privacy law (Loi 25: the Act respecting the protection of personal information in the private sector, CQLR c. P-39.1, as amended, and the Act to establish a legal framework for information technology, C-1.1) a cybersecurity risk scenario can trigger, as an expert in Québec privacy law and cybersecurity risk.

Inputs (read all fully):
- REFERENCE: /home/claude/crgo/data/work/linking/loi25pass/reference-loi25.md — the ONLY valid identifiers (text before " | ").
- EXAMPLES: /home/claude/crgo/data/work/linking/loi25pass/examples.md — judgements of the same kind approved by the project owner earlier; match their style and grading.
- BATCH: one JSON object per line: family id, name, theme, narrative, events, consequences, suggested mitigations, threat_source_types, impact_dimensions.

Context: every family in the batch was tagged as having a privacy impact, and already carries P-39.1 s. 10 (security measures) by rule. Your task is to decide which OTHER obligations apply. Do not output s. 10.

For EACH family decide:
- "pi": true if the scenario, read on its own, plausibly involves personal information (information about an identifiable natural person: patients, employees, customers...), else false.
- "loi25": 0–4 obligations other than s. 10, only if pi is true; when more apply, keep the 4 most relevant. Guidance:
  - a scenario whose realisation is a confidentiality incident (s. 3.6: unauthorised access, use or communication of personal information, or its loss) engages, in order of how directly: "P-39.1 s. 3.5 (1st para.)" (reasonable measures to reduce the risk of injury and prevent recurrence; applies to every incident), "P-39.1 s. 3.8" (register; applies to every incident), "P-39.1 s. 3.7" (assessment of the risk of serious injury), "P-39.1 s. 3.5 (2nd para.)" (notification; include it whenever serious injury is plausible, e.g. health or other sensitive information, financial data, identity theft, large scale; grade it like s. 3.7);
  - grade the incident obligations together: if the scenario clearly is a confidentiality incident, s. 3.5 (1st para.), s. 3.8 and s. 3.7 are H or M alike; if personal information is only possibly affected (availability or integrity events, sparse text), use L for all of them and prefer s. 3.5 (1st para.) and s. 3.8 over notification;
  - a scenario about the lack of a measure the law requires -> the obligation itself (for example s. 18.3 written contract with a service provider, for supplier, outsourcing and cloud-provider scenarios; s. 3.3 privacy impact assessment for a new system; s. 17 communication outside Québec; s. 23 destruction at end of purpose; s. 12 use beyond purpose; s. 8.1 profiling technology; C-1.1 s. 44 biometrics); these take precedence over the generic incident obligations when only 4 fit;
  - do not use the penalty provisions (s. 90.1, 90.12, 91, 92.1, 93.1) or s. 3.6 (a definition) as links.
- Each item is {"id": "...", "c": "H"|"M"|"L"}: H = direct and unambiguous, M = relevant but partial or one of several plausible choices, L = plausible only.
- "note": at most 20 words, only when pi is false or the choice is unusual; else "".

Use ONLY identifiers from the reference, copied exactly. Judge from the scenario itself.

Output: write OUTPUT as JSON Lines, exactly one line per input family, in input order, nothing else:
{"family":"F0001","pi":true,"loi25":[{"id":"P-39.1 s. 3.7","c":"M"}],"note":""}

Work in chunks of about 20 families, appending to OUTPUT with Python. At the end check with Python that OUTPUT has exactly one valid JSON line per input family, in order, that every id is in the reference (and is not s. 10, s. 3.6 or a penalty provision), and that no family has more than 4 items. Fix any problem. Do not modify any other file. Reply only with: families written, number with pi false, number of links by confidence.
