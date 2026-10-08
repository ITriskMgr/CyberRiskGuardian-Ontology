# -*- coding: utf-8 -*-
"""Re-read the CRG-style parameters from the raw LLM answers of the 2023 scenario generator.

Each extractor returns (value, evidence) where evidence is the text span the value was read from,
or (None, reason) when the answer does not state the value. Nothing is filled in or averaged here.
"""
import re

NUM = r"(\d{1,3}(?:[ ,]\d{3})+(?:\.\d+)?|\d+(?:\.\d+)?)"

def _clean(t):
    t = str(t).replace("\xa0", " ").replace("–", "-").replace("—", "-").replace("−", "-")
    # Remove CVSS version tokens so that "CVSS Version 3.1 Score: 7.5" does not yield 3.1.
    t = re.sub(r"(?i)\b(cvss\s*)?(v(?:ersion)?\s*)(3\.[01]|4\.0|2\.0)\b", r"\1", t)
    t = re.sub(r"(?i)\bcvss\s*(3\.[01]|4\.0)\b", "cvss", t)
    t = re.sub(r"(?i)\bcvssv?(3\.[01]|4\.0)\b", "cvss", t)
    return t

# Labels for the unit-interval parameters, most specific first. Group 'lab' is the label.
PROB_LABELS = {
    "PbA": [r"threat probability", r"probability of (?:the )?threat(?: occurring| occurrence)?", r"threat estimate", r"threat likelihood"],
    "Pbx": [r"probability of exploitation", r"exploitation estimate", r"exploitation probability", r"vulnerability exploitation probability", r"likelihood of exploitation"],
    "De": [r"expected damages?", r"estimated expected damages?"],
    "Dm": [r"maxim(?:al|um) damages?", r"worst[- ]case damages?"],
    "Th": [r"organi[sz]ational resilience", r"resilience"],
    "Mu": [r"expected utility(?: of (?:the )?assets?(?: at risk)?)?"],
    "red_i": [r"(?:total )?impact reduction"],
    "red_p": [r"(?:total )?probability reduction"],
}

REFUSAL = r"(?i)cannot|can ?not|not (?:be )?(?:possible|provided|available|determined)|unable|insufficient|requires? (?:more|additional)|\bn/?a\b|not applicable"
SCALE_AFTER = r"\s*(?:to|and|-|–)\s*1(?:\.0)?\b"
EXAMPLE_BEFORE = r"(?i)(?:e\.g\.,?|for example,?|for instance,?|such as|scale of|range of|between|from|ranging from)\s*\(?\s*$"

def _values(seg):
    """Numbers in a paragraph that can be an estimate: not scale bounds, not examples, not years."""
    for n in re.finditer(r"(?<![\w.])(\d+(?:\.\d+)?)\s*(%|percent)?", seg):
        if re.match(SCALE_AFTER, seg[n.end():]):
            continue
        if re.search(EXAMPLE_BEFORE, seg[max(0, n.start() - 30):n.start()]):
            continue
        if re.search(r"(?i)(?:e\.g\.|for example|for instance)[^)]*$", seg[max(0, n.start() - 40):n.start()]):
            continue  # inside an example: "(e.g., 0.7 for a 70% chance)"
        if re.search(r"\d\s*(?:to|and|-|–)\s*$", seg[max(0, n.start() - 12):n.start()]):
            continue  # upper bound of "0 to 1"
        if re.search(r"(?i)where\s*$", seg[max(0, n.start() - 8):n.start()]) or \
           re.match(r"(?i)\s*(?:represents|means|indicates|denotes|signifies|=|being the|is (?:the|no|very|low|high|least|most|minimal|maximum|a (?:certain|complete)))\b", seg[n.end():]):
            continue  # scale explanation: "where 0 represents ..."
        before = seg[max(0, n.start() - 60):n.start()]
        if re.search(r"(?i)(?:\bwith|\bfrom)\s*$|\)\s*(?:to|and)\s*$|(?:represents?|means|indicates|denotes|being)[^.;]{0,50}(?:and|to|,)\s*$", before):
            continue  # "with 0 being ...", "from 0 (none) to 1", "0 represents none and 1 ..."
        if n.group(2) and re.match(r"(?i)\s*(?:attacks?|majority)\b", seg[n.end():]):
            continue  # "51% attack" is a technique name, not an estimate
        v = float(n.group(1))
        if v > 100 or (v > 1 and not n.group(2) and v != int(v)):
            continue
        yield n

def _paragraph(text, start, limit=500):
    seg = text[start:start + limit]
    return re.split(r"\n\s*\n|\n(?=[\-\*\d\.#\s]*\**[A-Za-z][A-Za-z /()_]{2,50}\**\s*:)|(?i:(?:proposed )?mitigations?(?:_| )(?:measures|costs?)[^.\n]{0,30}:)", seg)[0]

def _first_value(text, labels):
    strict = r"(?im)^[\s\-\*\d\.#]*\**(?:estimated )?(?:%s)\**\s*(?:\([^)\n]{0,40}\))?\s*[:=-]"
    for mode in ("strict", "loose"):
        for lab in labels:
            pat = strict % lab if mode == "strict" else r"(?i)\b" + lab + r"\b"
            for m in re.finditer(pat, text):
                seg = _paragraph(text, m.end())
                n = next(_values(seg), None)
                if n is None:
                    continue  # nothing usable in this paragraph (refusal or scale only)
                if re.search(REFUSAL, seg[:n.start()]) and not re.search(r"(?i)however|but|estimat|approximat|assum|would be|around|roughly", seg[:n.start()]):
                    continue
                if re.match(r"(?i)\s*(?:by|reduced|reduction)\b", seg):
                    continue
                return float(n.group(1)), bool(n.group(2)), (m.group(0).strip() + " " + seg[:n.end()]).strip()
    return None

def unit_param(raw, key):
    t = _clean(raw)
    r = _first_value(t, PROB_LABELS[key])
    if not r:
        return None, "not stated in answer"
    v, pct, ev = r
    if pct or 1 < v <= 100:
        v = v / 100
    if not (0 <= v <= 1):
        return None, "out of range: %s" % ev
    return v, ev

CVSS_LABELS = [r"base score", r"overall (?:cvss )?score", r"estimated cvss(?:_| )score", r"calculated cvss score", r"cvss(?:_| )score",
               r"cvss score \(estimated\)", r"cvss cvss_score", r"cvss\b(?! vector)(?: [a-z]+){0,3}"]

def cvss(raw):
    t = _clean(raw)
    # ignore lines about temporal / environmental / sub-scores
    t2 = re.sub(r"(?im)^.*(temporal|environmental|subscore|sub-score|exploitability score|impact score).*$", "", t)
    for lab in CVSS_LABELS:
        for m in re.finditer(r"(?i)\b" + lab, t2):
            seg = t2[m.end():m.end() + 120]
            seg = re.split(r"\n\s*\n|(?i:mitigation)|\(", seg)[0]
            if re.match(r"(?is)[^0-9]{0,80}(cannot|can ?not|not (?:be )?(?:possible|provided|available|determined)|unable|insufficient|requires? (?:more|additional)|additional information)", seg):
                continue
            n = re.search(r"(?<![\w./])(\d{1,2}(?:\.\d)?)(?![\d/])", seg)
            if n and 0 <= float(n.group(1)) <= 10:
                return float(n.group(1)), (m.group(0) + seg[:n.end()]).strip()
    return None, "not stated in answer"

COST_LABELS = [r"total (?:estimated )?(?:mitigation(?:s_| )costs?|cost)", r"(?:estimated )?mitigation(?:s_| )costs?(?: in dollars)?(?: \(estimated\))?",
               r"total mitigations_costs"]

def _money(s):
    s = s.lower().replace(",", "").replace(" ", "")
    m = re.match(r"\$?(\d+(?:\.\d+)?)(k|m|million|thousand)?", s)
    if not m:
        return None
    v = float(m.group(1)); u = m.group(2)
    if u in ("k", "thousand"): v *= 1e3
    if u in ("m", "million"): v *= 1e6
    return v

MONEY = r"\$\s?\d[\d,]*(?:\.\d+)?\s?(?:k\b|m\b|million|thousand)?|\d[\d,]*(?:\.\d+)?\s?(?:usd|dollars|k\b|million|thousand)|(?<=: )\d{4,}[\d,]*"

def cost(raw):
    """Mitigation cost in dollars. A stated total wins; one amount gives itself; a range gives its midpoint;
    itemised amounts on separate list lines are summed; repeated mentions of the same amount count once."""
    t = _clean(raw)
    for lab in COST_LABELS:
        for m in re.finditer(r"(?i)\b" + lab + r"\b[^:\n]{0,30}:", t):
            seg = t[m.end() - 1:m.end() + 1500]  # keep the colon: bare amounts are recognised after ": "
            seg = re.split(r"(?i)impact reduction|probability reduction", seg)[0]
            head = seg[:160]
            if re.search(r"(?i)cannot|can ?not|not (?:be )?(?:possible|provided|available|determined)|unable|insufficient|requires? (?:more|additional)|additional information", head) and not re.search(MONEY, head):
                continue
            tot = re.search(r"(?i)total[^$\d\n]{0,60}(" + MONEY + r")(?:\s*(?:-|to)\s*(" + MONEY + r"))?", seg)
            if tot and _money(tot.group(1)) and _money(tot.group(1)) >= 100:
                lo = _money(tot.group(1)); hi = _money(tot.group(2)) if tot.group(2) else None
                return (lo + hi) / 2 if hi else lo, lo, hi or lo, "total", tot.group(0).strip()
            amounts = [a for a in re.finditer(r"(" + MONEY + r")(?:\s*(?:-|to)\s*(" + MONEY + r"))?", seg)
                       if _money(a.group(1)) is not None and _money(a.group(1)) >= 100]
            if not amounts:
                continue
            pair = lambda a: (_money(a.group(1)), _money(a.group(2)) if a.group(2) else _money(a.group(1)))
            vals = [pair(a) for a in amounts]
            item = lambda a: re.search(r"(?m)^\s*(?:[-*•]|\d{1,2}[.)])\s", seg[seg.rfind("\n", 0, a.start()) + 1:a.start()] or "") is not None
            items = [pair(a) for a in amounts if item(a)]
            if len(items) >= 2:
                lo = sum(v[0] for v in items); hi = sum(v[1] for v in items)
                if len(set(items)) == 1:
                    lo, hi = items[0]
                return (lo + hi) / 2, lo, hi, "sum of %d items" % len(items), (m.group(0) + seg[:amounts[-1].end()]).strip()[:300]
            lo, hi = vals[0]
            return (lo + hi) / 2, lo, hi, "range" if hi != lo else "single", (m.group(0) + seg[:amounts[0].end()]).strip()[:300]
    # prose fallback: "we estimate the mitigation costs to be around $100,000"
    for lab in COST_LABELS:
        for m in re.finditer(r"(?i)\b" + lab + r"\b", t):
            seg = t[m.end():m.end() + 150]
            if re.search(r"(?i)impact reduction|probability reduction", seg):
                seg = re.split(r"(?i)impact reduction|probability reduction", seg)[0]
            a = re.search(r"(\$\s?\d[\d,]*(?:\.\d+)?\s?(?:k\b|m\b|million|thousand)?)(?:\s*(?:-|to)\s*(\$\s?\d[\d,]*(?:\.\d+)?\s?(?:k\b|m\b|million|thousand)?))?", seg)
            if a and _money(a.group(1)) and _money(a.group(1)) >= 100:
                lo = _money(a.group(1)); hi = _money(a.group(2)) if a.group(2) else lo
                return (lo + hi) / 2, lo, hi, "stated in prose", (m.group(0) + seg[:a.end()]).strip()
    return None, None, None, "not stated in answer", ""
