# -*- coding: utf-8 -*-
"""Repair and consolidate the 2023 scenario library (decision Q-E, option 3).

Input : data/raw/combined_file.xlsx (2,158 rows, 2023 generator; not committed)
Output: data/library/rows.jsonl       one repaired record per usable row
        data/library/rows.csv         the same, without long text
        data/library/families.csv     duplicate rows merged into scenario families
        data/library/category_map.tsv the 225 source categories -> scenario themes
        data/library/REPAIR_REPORT.md counts and rules

Rules
1. Values are re-read from the raw LLM answer (detailed_scenarios). A value the answer does not
   state stays empty; the spreadsheet value (often a block mean filled in by the notebook) is kept
   only in a legacy column and flagged.
2. Rows with no LLM answer are dropped.
3. Risk is recomputed with CyberRiskGuardian v1.0c (crg_calc.py, appetite 0.30, factor 1000) only
   when all eight parameters and a CVSS score are stated. CVSS values are LLM estimates of v3.1
   scores, not v4.0 base scores.
4. Duplicate rows are merged into families (same theme, Jaccard >= 0.8 on name tokens).
5. Each row gets a theme from a controlled list (themes.py): from the scenario name when it matches,
   otherwise from the 225 source categories (mapping in category_map.tsv) or, for 'Undetermined', the narrative.
6. Causal fields (threat source type, asset categories, impact dimensions, mitigations) are
   extracted with keyword rules: low confidence, for review.
7. The organisation name is replaced by a sector tag (healthcare).
8. All numbers are low-confidence priors (AI estimates requiring validation).
"""
import collections, csv, json, os, re, statistics, sys
import pandas as pd

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, HERE)
import parse_llm as P  # noqa: E402
import themes as T     # noqa: E402

APPETITE, FACTOR = 0.30, 1000
PARAMS = {"PbA": "Pb_Threat", "Pbx": "Pb_Exploitation", "De": "Exp_Damages", "Dm": "Max_Damages",
          "Th": "Resilience", "Mu": "Exp_Utility", "red_p": "Pb_Reduction", "red_i": "Imp_Reduction"}
LEGACY = ["CVSS_Score", "Mitigation_Cost", "MonteCarlo_Damages", "MonteCarlo_Mitigated", "KRI_Estimate", "KRI_Max",
          "KRI_Tolerate", "KRI_Mitigated", "KRI_Residual", "KRI_Ratio"]
SECTOR = "healthcare"

def anonymise(t):
    if t is None or (isinstance(t, float) and pd.isna(t)):
        return ""
    t = str(t).replace("\xa0", " ")
    t = re.sub(r"(?i)\b(?:the )?montr[eé]al regional hospital", "the organisation", t)
    t = re.sub(r"(?i)\bmontr[eé]al\b", "the city", t)
    t = re.sub(r"(?i)\bthe the organisation", "the organisation", t)
    return t

def crg(p, cvss):
    """CyberRiskGuardian Excel Guide v1.0c, identical to crg_calc.calc()."""
    base = p["PbA"] * p["Pbx"] * cvss * p["Mu"] / p["Th"] * FACTOR
    est = base * (p["De"] + p["Dm"]) / 2
    tol = base * APPETITE
    mit = est * p["red_p"] * p["red_i"]
    res = est - mit
    ratio = res / tol
    cls = "below" if ratio < 0.90 else ("at" if ratio <= 1.10 else "above")
    return dict(est=est, tol=tol, mit=mit, res=res, ratio=ratio, pre_ratio=est / tol, cls=cls)

# --- keyword rules for causal fields (low confidence) ---
SRC = {
    "SrcAdversarial": r"compromis|forg|clon|eavesdrop|intercept|spoof|tamper|hijack|inject|malware|breach|impersonat|skimm|attack|hacker|cybercrimin|malicious|adversar|threat actor|ransom|phish|nation[- ]state|criminal|fraud|exploit|steal|theft|sabotag|espionage|disgruntled|unauthori[sz]ed",
    "SrcAccidental": r"accident|unintentional|inadvertent|human error|mistake|negligen|misconfigur|careless|by mistake|erroneous",
    "SrcStructural": r"failure|malfunction|outage|obsolete|legacy|end[- ]of[- ]life|bug|crash|hardware fault|degrad|capacity|incompatib",
    "SrcEnvironmental": r"\bfire\b|\bflood(?:s|ing)?\b(?!\s+(?:of|the|with|its)\b)|earthquake|storm|hurricane|natural disaster|acts of nature|weather|pandemic|heat ?wave|power (outage|failure|cut)",
}
CAT = {
    "CatInformation": r"data|record|information|database|file|document|phi|personal",
    "CatIdentity": r"identity|authenticat|credential|password|access control|active directory|\bsso\b|account",
    "CatApplication": r"application|software|\bapi\b|website|web |erp|\bemr\b|\behr\b|portal|e-?mail|system",
    "CatEndpoint": r"laptop|workstation|endpoint|mobile|device|tablet|smartphone|printer|usb",
    "CatInfrastructure": r"server|data center|storage|infrastructure|virtual|operating system|backup",
    "CatNetwork": r"network|wi-?fi|wireless|vpn|firewall|router|telecom|dns|internet",
    "CatCloud": r"cloud|saas|vendor|third[- ]party|supplier|outsourc|provider",
    "CatOTIoT": r"iot|medical device|medical equipment|imaging|infusion|wearable|sensor|operational technology|building|hvac|robot|3d print",
    "CatFacility": r"facility|building|premises|data center|physical|room",
    "CatPeople": r"employee|staff|personnel|user|clinician|physician|nurse|contractor|human",
}
DIM = {
    "DimConfidentiality": r"confidential|disclos|leak|exfiltrat|unauthori[sz]ed access|breach|exposure|stolen data",
    "DimIntegrity": r"integrity|tamper|alter|manipulat|corrupt|falsif|modif",
    "DimAvailability": r"unavailab|downtime|outage|disrupt|denial|inaccessib|interrupt|delay",
    "DimPrivacy": r"privacy|personal (data|information)|patient (data|records?|information)|medical records?|phi\b|identity theft",
    "DimSafety": r"patient safety|safety|harm to patients|adverse health|life[- ]threatening|injur|death",
    "DimFinancial": r"financial|revenue|cost|fine|ransom payment|monetary|lost income|expens",
    "DimLegal": r"legal|regulat|lawsuit|litigation|compliance|penalt|fine",
    "DimReputation": r"reputation|trust|public image|brand|media",
    "DimOperational": r"operation|workflow|service delivery|productivity|treatment plans?|clinical",
    "DimStrategic": r"strategic|competitive|market|mission",
}

def tags(text, rules):
    t = text.lower()
    return [k for k, pat in rules.items() if re.search(pat, t)]

def section(text, start, stops):
    m = re.search(r"(?is)(?:" + start + r")\s*:?(.*?)(?=" + "|".join(stops) + r"|$)", text)
    return m.group(1) if m else ""

def mitigations(raw):
    s = section(raw, r"(?:proposed )?mitigation measures|proposed mitigations(?:_costs)?",
                [r"mitigation costs?", r"mitigations_costs", r"impact reduction", r"estimated mitigation"])
    items = [re.sub(r"\s+", " ", i).strip(" .;:-") for i in re.split(r"(?:^|\n|\s)(?:\d{1,2}[.)]|[-*•])\s+", s)]
    items = [i for i in items if 8 <= len(i) <= 300 and not re.match(r"(?i)(the following|to mitigate|here are)", i)]
    return items[:12]

def tokens(name):
    stop = {"the", "a", "an", "of", "to", "and", "or", "in", "on", "for", "by", "with", "due", "from", "at", "through", "via",
            "leading", "resulting", "causing", "organisation", "organisation's", "s", "risk", "risks", "scenario", "into", "its"}
    return frozenset(w for w in re.findall(r"[a-z0-9]+", anonymise(name).lower()) if w not in stop)

def main():
    src = os.path.join(ROOT, "data", "raw", "combined_file.xlsx")
    out = os.path.join(ROOT, "data", "library"); os.makedirs(out, exist_ok=True)
    df = pd.read_excel(src)
    n_in = len(df)
    df["row"] = ["R%04d" % (i + 1) for i in range(len(df))]  # position in combined_file.xlsx
    dropped = df[df.detailed_scenarios.isna()]
    df = df[df.detailed_scenarios.notna()].copy()

    recs, flags = [], collections.Counter()
    for _, r in df.iterrows():
        raw = str(r.detailed_scenarios)
        cat = T.norm_category(r.Category)
        und = cat == "Undetermined"
        name = anonymise(r.NAME).strip()
        narrative = anonymise(r.query).strip() if und else ""
        rec = dict(row=r.row, source=r.Source, category_raw=cat, sector=SECTOR, name=name, narrative=narrative,
                   theme=T.theme_of(name, True) if T.theme_of(name, True) != "ThemeOther" else (T.theme_of(narrative, True) if und else T.theme_of(cat)),
                   theme_basis="inferred from name" if T.theme_of(name, True) != "ThemeOther" else ("inferred from narrative" if und else "mapped from category"),
                   generator="2023 notebook, Detailed_Metrics version" if und else "2023 notebook v2-1b")
        params = {}
        for k, col in PARAMS.items():
            v, ev = P.unit_param(raw, k)
            sheet = float(r[col]) if pd.notna(r[col]) else None
            if v is None:
                basis = "not stated" + ("; source value %.4g was filled in by the notebook" % sheet if sheet is not None else "")
                flags["%s not stated" % k] += 1
            elif sheet is not None and abs(v - sheet) > 0.005:
                one_dec = abs(sheet * 10 - round(sheet * 10)) < 1e-9
                basis = ("stated; source value %.4g differs (%s)" % (sheet, "conflict, review" if one_dec else "notebook fill"))
                flags["%s %s" % (k, "conflict" if one_dec else "repaired from text")] += 1
            else:
                basis = "stated"
            params[k] = v
            rec[k], rec[k + "_basis"], rec[k + "_evidence"] = v, basis, ev if v is not None else ""
        c, cev = P.cvss(raw)
        if c == 0:
            c, cev = None, "stated as 0, treated as not stated"
            flags["cvss stated as 0"] += 1
        rec["cvss"], rec["cvss_version"] = c, "3.1 (LLM estimate)" if c is not None else ""
        rec["cvss_basis"] = "stated" if c is not None else "not stated"
        rec["cvss_evidence"] = cev if c is not None else ""
        if c is None:
            flags["cvss not stated"] += 1
        cv, lo, hi, cbasis, cev = P.cost(raw)
        rec.update(cost=cv, cost_low=lo, cost_high=hi, cost_basis=cbasis, cost_evidence=cev)
        if cv is None:
            flags["cost not stated"] += 1
        if params["De"] is not None and params["Dm"] is not None and params["Dm"] < params["De"]:
            flags["maximum damage below expected damage"] += 1
            rec["warning"] = "maximum damage below expected damage"
        if all(params[k] is not None for k in PARAMS) and c is not None and min(params[k] for k in ("PbA", "Pbx", "Mu", "Th")) > 0:
            k = crg(params, c)
            rec.update({"crg_" + a: b for a, b in k.items()})
            if cv:
                rec["crg_cost_effectiveness"] = (k["est"] - k["res"]) / cv * 1000
            flags["CRG recomputed"] += 1
        for col in LEGACY:
            rec["legacy_" + col] = float(r[col]) if pd.notna(r[col]) else None
        for k, col in PARAMS.items():
            rec["legacy_" + col] = float(r[col]) if pd.notna(r[col]) else None
        cause_text = name + " " + narrative + " " + section(raw, r"event sequence", [r"consequences"])
        rec["threat_source_types"] = tags(cause_text, SRC)
        rec["asset_categories"] = tags(name + " " + narrative, CAT)
        cons = section(raw, r"consequences", [r"historical data", r"threat (?:estimate|probability)", r"metrics"])
        rec["impact_dimensions"] = tags(name + " " + narrative + " " + cons, DIM)
        rec["mitigations"] = [anonymise(m) for m in mitigations(raw)]
        rec["text"] = raw
        for k, v in rec.items():  # every text field, evidence spans included
            if isinstance(v, str):
                rec[k] = anonymise(v)
        recs.append(rec)

    # --- families: same theme, Jaccard >= 0.8 on name tokens (union-find)
    parent = list(range(len(recs)))
    def find(i):
        while parent[i] != i:
            parent[i] = parent[parent[i]]; i = parent[i]
        return i
    toks = [tokens(x["name"]) for x in recs]
    by_theme = collections.defaultdict(list)
    for i, x in enumerate(recs):
        by_theme[x["theme"]].append(i)
    for idx in by_theme.values():
        for a in range(len(idx)):
            for b in range(a + 1, len(idx)):
                i, j = idx[a], idx[b]
                A, B = toks[i], toks[j]
                if A and B and len(A & B) / len(A | B) >= 0.8:
                    parent[find(i)] = find(j)
    groups = collections.defaultdict(list)
    for i in range(len(recs)):
        groups[find(i)].append(i)
    ordered = sorted(groups.values(), key=lambda g: (recs[g[0]]["theme"], min(recs[i]["row"] for i in g)))
    fams = []
    for n, g in enumerate(ordered, 1):
        fid = "F%04d" % n
        members = [recs[i] for i in g]
        for m in members:
            m["family"] = fid
        names = collections.Counter(m["name"].rstrip(".") for m in members)
        top = max(names.items(), key=lambda kv: (kv[1], -len(kv[0])))[0]
        f = dict(family=fid, name=top, theme=members[0]["theme"], n_rows=len(members),
                 rows=" ".join(m["row"] for m in members), sources=" ".join(sorted({m["source"] for m in members})))
        med = {}
        for k in list(PARAMS) + ["cvss", "cost"]:
            vals = [m[k] for m in members if m.get(k) is not None]
            f[k] = statistics.median(vals) if vals else None
            f[k + "_n"] = len(vals)
            f[k + "_min"] = min(vals) if vals else None
            f[k + "_max"] = max(vals) if vals else None
            med[k] = f[k]
        if all(med[k] is not None for k in PARAMS) and med["cvss"] and min(med[k] for k in ("PbA", "Pbx", "Mu", "Th")) > 0:
            f.update({"crg_" + a: b for a, b in crg(med, med["cvss"]).items()})
        for key in ("threat_source_types", "asset_categories", "impact_dimensions"):
            c = collections.Counter(t for m in members for t in m[key])
            f[key] = " ".join(t for t, k in c.most_common() if k * 2 >= len(members))
        mit = collections.Counter(x for m in members for x in m["mitigations"])
        f["mitigations"] = " | ".join(x for x, _ in mit.most_common(6))
        narr = [m["narrative"] for m in members if m["narrative"]]
        f["narrative"] = narr[0] if narr else ""
        fams.append(f)

    # --- write
    with open(os.path.join(out, "rows.jsonl"), "w", encoding="utf-8") as fh:
        for x in recs:
            fh.write(json.dumps(x, ensure_ascii=False) + "\n")
    flat = [{k: (" ".join(v) if isinstance(v, list) else v) for k, v in x.items() if k not in ("text", "mitigations")} for x in recs]
    pd.DataFrame(flat).to_csv(os.path.join(out, "rows.csv"), index=False)
    pd.DataFrame(fams).to_csv(os.path.join(out, "families.csv"), index=False)
    cats = collections.Counter(x["category_raw"] for x in recs)
    with open(os.path.join(out, "category_map.tsv"), "w", encoding="utf-8") as fh:
        fh.write("source_category\trows\ttheme\n")
        for c_, n in sorted(cats.items()):
            fh.write("%s\t%d\t%s\n" % (c_, n, "(per row, inferred from name)" if c_ == "Undetermined" else T.theme_of(c_)))

    # --- report
    th = collections.Counter(x["theme"] for x in recs)
    fth = collections.Counter(f["theme"] for f in fams)
    comp = sum(1 for f in fams if f.get("crg_est") is not None)
    cls = collections.Counter(f.get("crg_cls") for f in fams if f.get("crg_cls"))
    L = ["# Scenario library repair report", "",
         "Source: `combined_file.xlsx`, %d rows. Generated by `pipeline/library/repair.py`; rules are in its docstring." % n_in, "",
         "## Counts", "",
         "| Step | Rows |", "|---|---|",
         "| Input rows | %d |" % n_in,
         "| Dropped: no LLM answer | %d (%s) |" % (len(dropped), ", ".join(dropped.row)),
         "| Usable rows | %d |" % len(recs),
         "| Rows with CRG v1.0c risk recomputed (all eight parameters and CVSS stated) | %d |" % flags["CRG recomputed"],
         "| Scenario families after merging duplicates | %d |" % len(fams),
         "| Families with CRG risk computable from member medians | %d |" % comp, "",
         "Family tolerance classes at appetite 0.30: " + ", ".join("%s %d" % kv for kv in sorted(cls.items())) + ".", "",
         "## Value repair", "",
         "| Finding | Rows |", "|---|---|"]
    for k, v in sorted(flags.items()):
        if k != "CRG recomputed":
            L.append("| %s | %d |" % (k, v))
    L += ["", "\"repaired from text\": the spreadsheet held a notebook fill (non-round block mean) but the LLM answer states a value, which is used. "
          "\"conflict\": the spreadsheet holds a different round value; the value read from the answer is used and the row is flagged for review. "
          "\"not stated\": the answer gives no value; the field is left empty and the notebook fill is kept only as a legacy column.", "",
          "## Themes", "", "| Theme | Rows | Families |", "|---|---|---|"]
    for key, en, *_ in T.THEMES:
        L.append("| %s | %d | %d |" % (en, th[key], fth[key]))
    L += ["", "## Caveats", "",
          "- All values are AI estimates produced by gpt-3.5-turbo in 2023 for a fictitious hospital. They are calibration priors, not organisational evidence.",
          "- CVSS values are LLM-estimated v3.1 scores; CyberRiskGuardian uses v4.0 base scores computed from vectors.",
          "- Causal fields (threat source types, asset categories, impact dimensions) come from keyword rules and need review.",
          "- Theme is inferred from the scenario name when the name matches a theme; otherwise from the narrative ('Undetermined' rows) or the source category (%d rows have category 'Undetermined')." % cats.get("Undetermined", 0)]
    open(os.path.join(out, "REPAIR_REPORT.md"), "w", encoding="utf-8").write("\n".join(L) + "\n")
    print("\n".join(L[:20]))

if __name__ == "__main__":
    main()
