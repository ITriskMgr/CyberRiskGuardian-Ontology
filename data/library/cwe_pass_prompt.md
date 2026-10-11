You are linking generic cybersecurity risk scenarios to MITRE CWE weaknesses, as an expert in software and system security.

Inputs (read both fully):
- REFERENCE: /home/claude/crgo/data/work/linking/cwe/reference-cwe.md — the ONLY valid CWE identifiers (ID | name | parent).
- BATCH: one JSON object per line: family id, name, theme, narrative, events, consequences, suggested mitigations, the ATT&CK techniques already linked, and "cwe_candidates": weaknesses reached from those techniques through CAPEC and the CISA KEV catalogue. Candidates are hints only; they are often too generic or off-target.

For EACH family decide:
- "cwe": 0–3 CWE weaknesses that the scenario's threat event exploits or that the scenario describes as the flaw. Rules:
  - CWE covers weaknesses in software, hardware and system configuration. Use none for scenarios about people, process, governance, physical events or accidents unless a technical weakness is named or clearly implied (for example "default credentials" -> CWE-1392/CWE-798 family, "unpatched system" -> CWE-1104 or the specific weakness if named, "misconfigured cloud storage" -> CWE-732 or CWE-284 family).
  - Prefer the most specific weakness that the scenario's wording supports; use a broader class (for example CWE-284, CWE-287, CWE-20) only when the scenario is generic.
  - Each item is {"id": "CWE-n", "c": "H"|"M"|"L"}: H = the scenario names or unambiguously implies this weakness; M = relevant but one of several plausible; L = plausible only.
- "note": at most 15 words, only when you chose none for a technical scenario or the choice is unusual; else "".

Use ONLY identifiers from the reference, copied exactly. Judge from the scenario itself.

Output: write OUTPUT as JSON Lines, exactly one line per input family, in input order:
{"family":"F0001","cwe":[{"id":"CWE-798","c":"H"}],"note":""}

Work in chunks of about 25 families, appending to OUTPUT with Python. At the end check with Python that OUTPUT has exactly one valid JSON line per input family in order, every id is in the reference, and no family has more than 3 items. Fix any problem. Do not modify any other file. Reply only with: families written, families with no CWE, links by confidence.
