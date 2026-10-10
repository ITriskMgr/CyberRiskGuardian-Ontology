# -*- coding: utf-8 -*-
"""Run the competency questions (tests/cq/CQnn.rq) against the CRGO store and check their expectations.

Each file has a header:  # Question: ...   # Expect: clause; clause
Clauses: "rows N", "min_rows N", "contains var=value" (some row's value equals, or ends with, value),
"sum var=X over all" (sum of the column, rounded, equals X).
In the query, {{Key}} stands for the CRGO term with that key in src/ids.tsv.
Writes build/cq-report.md with the answers (first rows) and exits non-zero if any expectation fails.
"""
import glob, os, re, sys, time
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(ROOT, "pipeline", "query"))
import store  # noqa: E402

ids = dict(l.rstrip("\n").split("\t") for l in open(os.path.join(ROOT, "src", "ids.tsv"), encoding="utf-8"))
PREFIX = """PREFIX owl: <http://www.w3.org/2002/07/owl#>
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
PREFIX skos: <http://www.w3.org/2004/02/skos/core#>
PREFIX dcterms: <http://purl.org/dc/terms/>
PREFIX theme: <https://w3id.org/crgo/vocab/theme/>
"""

def expand(q):
    return PREFIX + re.sub(r"\{\{(\w+)\}\}", lambda m: "<https://w3id.org/crgo/CRGO_%07d>" % int(ids[m.group(1)]), q)

def val(t):
    return "" if t is None else t.value

def check(expect, cols, rows):
    fails = []
    for clause in [c.strip() for c in expect.split(";") if c.strip()]:
        m = re.match(r"(min_rows|rows)\s+(\d+)$", clause)
        if m:
            n = int(m.group(2))
            if (m.group(1) == "rows" and len(rows) != n) or (m.group(1) == "min_rows" and len(rows) < n):
                fails.append("%s (got %d)" % (clause, len(rows)))
            continue
        m = re.match(r"contains\s+(\w+)=(.+)$", clause)
        if m:
            v, x = m.group(1), m.group(2).strip()
            if not any(val(r[v]) == x or val(r[v]).endswith(x) for r in rows):
                fails.append(clause)
            continue
        m = re.match(r"sum\s+(\w+)=([\d.]+)\s+over all$", clause)
        if m:
            continue  # checked by the caller with the unfiltered sum query
        fails.append("unknown clause: " + clause)
    return fails

def main():
    st = store.open_store()
    out, failed = ["# Competency questions: results", ""], 0
    for f in sorted(glob.glob(os.path.join(HERE, "CQ*.rq"))):
        text = open(f, encoding="utf-8").read()
        q = re.search(r"# Question: (.*)", text).group(1)
        exp = re.search(r"# Expect: (.*)", text).group(1)
        t0 = time.time()
        res = st.query(expand(text))
        cols = [v.value for v in res.variables]
        rows = list(res)
        dt = time.time() - t0
        fails = check(exp, cols, rows)
        m = re.search(r"sum\s+(\w+)=([\d.]+)\s+over all", exp)
        if m:
            allq = re.sub(r"ORDER BY.*$", "", text.strip(), flags=re.S)
            total = sum(float(val(r[m.group(1)])) for r in st.query(expand(allq)))
            if round(total) != round(float(m.group(2))):
                fails.append("sum %s = %.0f, expected %s" % (m.group(1), total, m.group(2)))
        name = os.path.basename(f)[:-3]
        ok = not fails
        failed += not ok
        print("%s %-5s %4d rows %6.2f s  %s" % (name, "PASS" if ok else "FAIL", len(rows), dt, "; ".join(fails)))
        out += ["## %s — %s" % (name, "pass" if ok else "FAIL: " + "; ".join(fails)), "", q, "", "Expected: %s. Rows: %d. Time: %.2f s." % (exp, len(rows), dt), ""]
        if rows:
            out += ["| " + " | ".join(cols) + " |", "|" + "---|" * len(cols)]
            for r in rows[:8]:
                out.append("| " + " | ".join(val(r[c]).replace("|", "/").replace("https://w3id.org/crgo/", "")[:70] for c in cols) + " |")
            out.append("")
    os.makedirs(os.path.join(ROOT, "build"), exist_ok=True)
    open(os.path.join(ROOT, "build", "cq-report.md"), "w", encoding="utf-8").write("\n".join(out) + "\n")
    print("%d of %d competency questions pass" % (len(glob.glob(os.path.join(HERE, "CQ*.rq"))) - failed, len(glob.glob(os.path.join(HERE, "CQ*.rq")))))
    sys.exit(1 if failed else 0)

if __name__ == "__main__":
    main()
