# -*- coding: utf-8 -*-
"""Content review of the scenario library for CRGO 0.11.1 (test campaign of 2026-11-08, finding NV-C05).

Applies a small, listed set of corrections to the library data files AND to the committed ABox
data/abox/crgo-library.ttl, by targeted text edits. The ABox is not rebuilt: pipeline/library/build_abox.py needs the
KEV/EPSS downloads that are not committed, and rebuilding reorders 500,000 triples. Every edit is asserted to match
exactly once, so the script fails loudly rather than guessing.

Corrections
1. Theme fit. The theme rule for 'physical and environmental' matched 'fire' inside 'firewall' (pipeline/library/themes.py,
   now \\bfire\\b), so ten firewall families and the ACRB-A1 case scenario that refines five of them were filed under
   ThemePhysical. They move to the theme the family review had already proposed as second theme (ThemeNetwork for most,
   ThemeAppSec for the WAF bypass); ThemePhysical is removed. The 'advanced and multi-vector attacks' rule matched
   'evolution' in F0006 (enterprise architecture complexity): F0006 moves to ThemeITGov, its proposed second theme.
2. Malformed names. Seven family names ended with ':' (LIB-F1022, F1023, F1024, F1497, F1613, F1614, F1801).
3. Library header version 0.11.1 with a change note.

Run once from the repository root: python3 pipeline/library/content_review_0111.py  (idempotent: a second run finds nothing to do)
"""
import csv, io, json, os, re, sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
LIB = os.path.join(ROOT, "data", "library")
ABOX = os.path.join(ROOT, "data", "abox", "crgo-library.ttl")

# family -> (old primary theme, new primary theme). The new theme was the review's proposed second theme, so the
# annotated second-theme axiom for it is dropped; a different proposed second theme (ThemeVulnMgmt) is kept.
THEME = {"F1346": ("ThemePhysical", "ThemeNetwork"), "F1347": ("ThemePhysical", "ThemeNetwork"), "F1352": ("ThemePhysical", "ThemeNetwork"),
         "F1353": ("ThemePhysical", "ThemeNetwork"), "F1371": ("ThemePhysical", "ThemeNetwork"), "F1399": ("ThemePhysical", "ThemeNetwork"),
         "F1404": ("ThemePhysical", "ThemeNetwork"), "F1405": ("ThemePhysical", "ThemeNetwork"), "F1407": ("ThemePhysical", "ThemeNetwork"),
         "F1422": ("ThemePhysical", "ThemeAppSec"), "F0006": ("ThemeAPT", "ThemeITGov")}
CASE_THEME = {"C-ACRB-ACRB-A1": ("ThemePhysical", "ThemeNetwork")}   # refines F1353, F1371, F1399, F1405, F1407: all ThemeNetwork now
COLON = {"F1022": "Insider Theft", "F1023": "Lack of User Training", "F1024": "Insider Data Leakage", "F1497": "USB Drive Malware Infection",
         "F1613": "Social Engineering", "F1614": "Phishing Campaign", "F1801": "Outdated Software Vulnerability"}
NOTE = "content review 0.11.1 (NV-C05)"
changed = 0

def csv_edit(path, key_col, edit):
    """Edit rows of a CSV in place; the csv module round-trips these files byte for byte (checked)."""
    global changed
    raw = open(path, encoding="utf-8", newline="").read()
    rows = list(csv.reader(io.StringIO(raw)))
    head = rows[0]
    n = 0
    for r in rows[1:]:
        n += edit(dict(zip(head, r)), r, head)
    buf = io.StringIO(); csv.writer(buf, lineterminator="\n").writerows(rows)
    if buf.getvalue() != raw:
        open(path, "w", encoding="utf-8", newline="").write(buf.getvalue()); changed += n
    print("   %-22s %d row(s) edited" % (os.path.basename(path), n))
    return rows

def set_col(r, head, col, value):
    if r[head.index(col)] == value: return 0
    r[head.index(col)] = value; return 1

# 1-2. families.csv
rows_of = {}
def fam_edit(d, r, head):
    n = 0
    f = d["family"]
    rows_of[f] = d["rows"].split()
    if f in THEME and d["theme"] == THEME[f][0]: n += set_col(r, head, "theme", THEME[f][1])
    if f in COLON and d["name"].rstrip().endswith(":"): n += set_col(r, head, "name", COLON[f])
    return n
csv_edit(os.path.join(LIB, "families.csv"), "family", fam_edit)
# the rows the families were merged from (rows.csv, rows.jsonl) carry the same theme and name
row_theme = {rid: THEME[f] for f, rids in rows_of.items() if f in THEME for rid in rids}
row_name = {rid: COLON[f] for f, rids in rows_of.items() if f in COLON for rid in rids}
def row_edit(d, r, head):
    n = 0
    rid = d["row"]
    if rid in row_theme and d["theme"] == row_theme[rid][0]:
        n += set_col(r, head, "theme", row_theme[rid][1]); set_col(r, head, "theme_basis", NOTE)
    if rid in row_name and d["name"].rstrip().endswith(":"): n += set_col(r, head, "name", row_name[rid])
    return n
csv_edit(os.path.join(LIB, "rows.csv"), "row", row_edit)
p = os.path.join(LIB, "rows.jsonl"); out, n = [], 0
for line in open(p, encoding="utf-8").read().split("\n"):
    if line:
        d = json.loads(line); rid = d.get("row")
        if rid in row_theme and d.get("theme") == row_theme[rid][0]: d["theme"], d["theme_basis"] = row_theme[rid][1], NOTE; n += 1
        if rid in row_name and str(d.get("name", "")).rstrip().endswith(":"): d["name"] = row_name[rid]; n += 1
        line = json.dumps(d, ensure_ascii=False)
    out.append(line)
if n: open(p, "w", encoding="utf-8").write("\n".join(out)); changed += n
print("   %-22s %d field(s) edited" % ("rows.jsonl", n))

# 3. the committed ABox: targeted text edits, each asserted
t = open(ABOX, encoding="utf-8").read()
orig = t

def block(text, start_rx):
    """(start, end) of the Turtle block that starts with start_rx at a line start and ends at the next blank line."""
    m = re.search(start_rx, text, re.M)
    if not m: return None
    e = text.find("\n\n", m.start())
    return m.start(), (e if e >= 0 else len(text))

def set_theme(text, subject, old, new):
    b = block(text, r"^%s a crgo:CRGO_0000024 ;" % re.escape(subject))
    if b is None: raise SystemExit("subject not found: " + subject)
    s, e = b; blk = text[s:e]
    m = re.search(r"crgo:CRGO_0000246 ((?:theme:\w+,\s*)*theme:\w+) ;", blk)
    if not m: raise SystemExit("no theme statement for " + subject)
    themes = [x.strip() for x in m.group(1).replace("\n", " ").split(",")]
    if "theme:" + old not in themes:
        return text, 0     # already done
    themes = [x for x in themes if x != "theme:" + old]
    if "theme:" + new not in themes: themes.append("theme:" + new)
    repl = "crgo:CRGO_0000246 " + ",\n        ".join(sorted(themes)) + " ;"
    return text[:s] + blk[:m.start()] + repl + blk[m.end():] + text[e:], 1

def drop_axiom(text, subject, prop, target):
    """Remove the owl:Axiom block annotating (subject prop target); 0 or 1 block."""
    rx = re.compile(r"\n\[\] a owl:Axiom ;\n(?:    [^\n]*\n)*?    owl:annotatedProperty %s ;\n    owl:annotatedSource %s ;\n    owl:annotatedTarget %s ;\n(?:    [^\n]*\n)*?    [^\n]*\.\n"
                    % (re.escape(prop), re.escape(subject), re.escape(target)))
    ms = list(rx.finditer(text))
    if len(ms) > 1: raise SystemExit("several axioms for %s %s %s" % (subject, prop, target))
    if not ms: return text, 0
    m = ms[0]
    return text[:m.start()] + text[m.end() - 1:], 1   # keep one newline (the blank line that followed)

def retarget_axiom(text, subject, prop, old, new):
    rx = re.compile(r"(\n\[\] a owl:Axiom ;\n(?:    [^\n]*\n)*?    owl:annotatedProperty %s ;\n    owl:annotatedSource %s ;\n    owl:annotatedTarget )%s( ;)"
                    % (re.escape(prop), re.escape(subject), re.escape(old)))
    ms = list(rx.finditer(text))
    if len(ms) > 1: raise SystemExit("several axioms for %s %s %s" % (subject, prop, old))
    if not ms: return text, 0
    m = ms[0]
    return text[:m.start()] + m.group(1) + new + m.group(2) + text[m.end():], 1

n = 0
for f, (old, new) in THEME.items():
    t, k = set_theme(t, "lib:" + f, old, new); n += k
    if k:   # the new primary theme was the proposed second theme: its 'second theme' axiom no longer applies
        t, k2 = drop_axiom(t, "lib:" + f, "crgo:CRGO_0000246", "theme:" + new); n += k2
        if not k2: print("   note: %s had no second-theme axiom for %s" % (f, new))
for c, (old, new) in CASE_THEME.items():
    t, k = set_theme(t, "lib:" + c, old, new); n += k
    t, k2 = retarget_axiom(t, "lib:" + c, "crgo:CRGO_0000246", "theme:" + old, "theme:" + new); n += k2
    if k and not k2: raise SystemExit("case theme axiom not found for " + c)
for f, name in COLON.items():
    for old, new in (('rdfs:label "%s:"@en' % name, 'rdfs:label "%s"@en' % name),
                     ('rdfs:label "suggested treatment for %s:"@en' % name, 'rdfs:label "suggested treatment for %s"@en' % name),
                     ('rdfs:label "Weakness exploited in: %s:"@en' % name, 'rdfs:label "Weakness exploited in: %s"@en' % name)):
        k = t.count(old)
        if k > 2: raise SystemExit("unexpected count %d for %r" % (k, old))
        t = t.replace(old, new); n += k
# header: version and change note
hdr = block(t, r"^<https://w3id.org/crgo/data/library> a owl:Ontology ;")
if hdr is None: raise SystemExit("library header not found")
s, e = hdr; blk = t[s:e]
if 'owl:versionInfo "0.11.1"' not in blk:
    blk2 = re.sub(r'owl:versionInfo "[0-9.]+"', 'owl:versionInfo "0.11.1"', blk)
    blk2 = blk2.replace(" a owl:Ontology ;\n", " a owl:Ontology ;\n    <http://www.w3.org/2004/02/skos/core#changeNote> \"0.11.1 content review (NV-C05): eleven families and the ACRB-A1 case scenario re-themed (firewall scenarios were filed under 'physical and environmental' because 'fire' matched 'firewall'; F0006 under 'advanced attacks' because of 'evolution'); seven family names lost a trailing colon. No value changed.\"@en ;\n", 1)
    t = t[:s] + blk2 + t[e:]; n += 1
if t != orig:
    open(ABOX, "w", encoding="utf-8").write(t); changed += n
print("   %-22s %d edit(s)" % ("crgo-library.ttl", n))
print("content review 0.11.1: %d change(s) applied" % changed if changed else "content review 0.11.1: nothing to do (already applied)")
