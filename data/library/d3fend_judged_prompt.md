You are mapping MITRE ATT&CK techniques to the MITRE D3FEND defensive techniques that counter them, as an expert in both.

Inputs (read both fully):
- REFERENCE: /home/claude/crgo/data/work/linking/d3fend/reference-d3fend.md — the ONLY valid D3FEND identifiers (ID | name | parent).
- BATCH: one JSON object per line: an ATT&CK technique id and name, how many risk scenarios use it, and "artifact_hints": D3FEND techniques that act on the same digital artifact. Hints are often wrong (same artifact name meaning different things, generic process or memory controls); use them only as a starting point.

For EACH technique choose "d3fend": 0–5 defensive techniques that a defender would actually deploy to detect, prevent, limit or recover from THIS technique, acting on its real mechanism. Prefer specific techniques over their generic parents. Do not choose a defence that the technique is designed to bypass (for example MFA against stolen session cookies). Use none if D3FEND has nothing meaningful (for example for pure reconnaissance outside the defender's environment).
Each item is {"id": "D3-XXX", "c": "H"|"M"|"L"}: H = direct and widely recognised countermeasure; M = relevant but partial; L = plausible only.

Use ONLY identifiers from the reference, copied exactly.

Output: write OUTPUT as JSON Lines, exactly one line per input technique, in input order:
{"technique":"T1110.001","d3fend":[{"id":"D3-ANET","c":"H"}]}

Work in chunks of about 25, appending to OUTPUT with Python. At the end check with Python: one valid line per input technique in order, every id in the reference, at most 5 items. Fix any problem. Do not modify any other file. Reply only with: techniques written, techniques with none, links by confidence.
