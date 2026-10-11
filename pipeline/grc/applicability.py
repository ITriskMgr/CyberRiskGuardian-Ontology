# -*- coding: utf-8 -*-
"""Evaluate the applicability of CRGO's legal instruments to an organisation (specification section 9; ADR-004).

Input: an RDF graph holding the organisation profile (crgo-org terms) and ontology/vocab/legal.ttl (instruments and
conditions). Output: one ApplicabilityAssessment per instrument that has conditions, with its state and the
conditions met, not met or undetermined.

Facts read from the profile. A value the profile lists makes a condition met. A value it does not list makes the
condition *not met* only when the profile declares that property complete ('profile complete for' <key>);
otherwise the fact is missing and the condition is undetermined. Missing data therefore never yields
'not applicable' (independent review 2026-10-11).

  orgType=X              organisation 'has organisation type' X                           (complete key: hasOrganisationType)
  orgTypeIn=X,Y          one of the listed types                                            (hasOrganisationType)
  establishedIn=J        organisation 'established in' J                                    (establishedIn)
  offersServicesIn=J     'offers goods or services to persons in' J                         (offersServicesIn)
  monitorsBehaviourIn=J  'monitors behaviour of persons in' J                               (monitorsBehaviourIn)
  activeIn=J             offers services to, or has data subjects in, J                     (offersServicesIn and dataSubjectsIn)
  processesPersonalInfo  a processing activity is 'carried out by' the organisation         (carriedOutBy)
  processesData=C        one of its processing activities 'processes data category' C       (processesDataCategory)
  transfersOutside=J     data subjects in, or transfers to, a jurisdiction other than J     (dataSubjectsIn and transfersDataTo)

Rules per instrument: before the date it applies from (or comes into force), not applicable; an exception met ->
not applicable (potentially applicable when the exception is interpretive); a required condition not met -> not
applicable; no 'any of' condition met while all are evaluated -> not applicable; otherwise a missing fact ->
unknown; otherwise applicable, or potentially applicable when a condition relied on is marked interpretive
(qualified review needed). Instruments without conditions (regulations that follow their Act) are not assessed.

Usage: python3 pipeline/grc/applicability.py PROFILE.ttl ORG_IRI DATE ASSESSOR_IRI OUT.ttl
"""
import os, sys
from rdflib import Graph, Namespace, URIRef, Literal
from rdflib.namespace import RDF, RDFS, OWL, XSD
TIME = Namespace("http://www.w3.org/2006/time#")

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
BASE = "https://w3id.org/crgo/"
ids = dict(l.rstrip("\n").split("\t") for l in open(os.path.join(ROOT, "src", "ids.tsv"), encoding="utf-8"))
T = lambda k: URIRef(BASE + "CRGO_%07d" % int(ids[k]))
KEY_OF = {T(k): k for k in ids}
MET, NOT, UNK = "met", "not met", "undetermined"
ASSUMPTION = ("Organisation profile read as given: a listed value is a fact; an unlisted value counts as absent only for the properties "
              "the profile declares complete (profile complete for); otherwise it is unknown.")


def facts(g, org):
    vals = lambda p: {KEY_OF.get(o, str(o)) for o in g.objects(org, T(p))}
    acts = set(g.subjects(T("carriedOutBy"), org))
    act_vals = lambda p: {KEY_OF.get(o, str(o)) for a in acts for o in g.objects(a, T(p))}
    return {"hasOrganisationType": vals("hasOrganisationType"), "establishedIn": vals("establishedIn"), "offersServicesIn": vals("offersServicesIn"),
            "monitorsBehaviourIn": vals("monitorsBehaviourIn"), "carriedOutBy": acts, "processesDataCategory": act_vals("processesDataCategory"),
            "dataSubjectsIn": act_vals("dataSubjectsIn"), "transfersDataTo": act_vals("transfersDataTo"),
            "complete": {str(v) for v in g.objects(org, T("profileCompleteFor"))}}


def _member(f, props, wanted):
    """met if any wanted value is listed under any of props; not met if none is and every prop is declared complete."""
    listed = set().union(*[f[p] for p in props])
    if listed & set(wanted): return MET
    return NOT if all(p in f["complete"] for p in props) else UNK


def test(f, expr):
    name, _, arg = expr.partition("=")
    if name == "orgType": return _member(f, ["hasOrganisationType"], [arg])
    if name == "orgTypeIn": return _member(f, ["hasOrganisationType"], arg.split(","))
    if name in ("establishedIn", "offersServicesIn", "monitorsBehaviourIn"): return _member(f, [name], [arg])
    if name == "activeIn": return _member(f, ["offersServicesIn", "dataSubjectsIn"], [arg])
    if name == "processesPersonalInfo":
        return MET if f["carriedOutBy"] else (NOT if "carriedOutBy" in f["complete"] else UNK)
    if name == "processesData": return _member(f, ["processesDataCategory"], [arg])
    if name == "transfersOutside":
        places = f["dataSubjectsIn"] | f["transfersDataTo"]
        if places - {arg}: return MET
        return NOT if {"dataSubjectsIn", "transfersDataTo"} <= f["complete"] else UNK
    raise ValueError("unknown condition test: " + expr)


def starts(g, inst):
    """Date from which an instrument applies: 'applies from' if given, else the beginning of its in-force interval."""
    d = g.value(inst, T("appliesFrom"))
    if d is None:
        iv = g.value(inst, T("hasInForcePeriod")); b = g.value(iv, TIME.hasBeginning) if iv is not None else None
        d = g.value(b, TIME.inXSDDateTimeStamp) if b is not None else None
    return str(d)[:10] if d is not None else None


def evaluate(g, org, date, assessor, out_base):
    """Return a graph of ApplicabilityAssessment individuals for org at date (YYYY-MM-DD)."""
    f = facts(g, org)
    out = Graph(); out.bind("crgo", BASE)
    conds = {}
    for c in g.subjects(RDF.type, T("ApplicabilityCondition")):
        role, expr, kind = str(g.value(c, T("conditionTest"))).split("|")
        for inst in g.objects(c, T("conditionOf")):
            conds.setdefault(inst, []).append((c, role, expr, kind == "interpretive"))
    results = {}
    for inst, cs in sorted(conds.items()):
        ev = [(c, role, interp, test(f, expr)) for c, role, expr, interp in cs]
        req = [e for e in ev if e[1] == "required"]; any_ = [e for e in ev if e[1] == "anyof"]; exc = [e for e in ev if e[1] == "exception"]
        st = starts(g, inst)
        if st and date < st:
            state = "AppNotApplicable"  # not yet applicable at the assessment date
        elif any(e[3] == MET and not e[2] for e in exc) or any(e[3] == NOT for e in req) or (any_ and all(e[3] == NOT for e in any_)):
            state = "AppNotApplicable"
        elif any(e[3] == MET for e in exc):
            state = "AppPotentiallyApplicable"  # an interpretive exception may exclude it: qualified review
        elif any(e[3] == UNK for e in req + exc) or (any_ and not any(e[3] == MET for e in any_)):
            state = "AppUnknown"
        else:
            relied = [e for e in req if e[3] == MET]
            plain_any = [e for e in any_ if e[3] == MET and not e[2]]
            relied += plain_any or [e for e in any_ if e[3] == MET]
            state = "AppPotentiallyApplicable" if any(e[2] for e in relied) else "AppApplicable"
        a = URIRef("%sapplicability/%s-%s" % (out_base, str(inst).rsplit("/", 1)[1], date))
        out.add((a, RDF.type, OWL.NamedIndividual)); out.add((a, RDF.type, T("ApplicabilityAssessment")))
        out.add((a, T("applicabilityOf"), inst)); out.add((a, T("concernsOrganisation"), org))
        out.add((a, T("hasApplicabilityState"), T(state))); out.add((a, T("assessedOn"), Literal(date + "T00:00:00", datatype=XSD.dateTime)))
        out.add((a, T("assessedBy"), assessor))
        for j in g.objects(inst, T("hasJurisdiction")): out.add((a, T("hasJurisdiction"), j))
        for c, role, interp, r in ev:
            out.add((a, T({MET: "conditionMet", NOT: "conditionNotMet", UNK: "conditionUndetermined"}[r]), c))
        asm = URIRef(out_base + "assumption/profile-reading")
        out.add((asm, RDF.type, OWL.NamedIndividual)); out.add((asm, RDF.type, T("Assumption")))
        out.add((asm, RDFS.label, Literal("Reading of the organisation profile", lang="en")))
        out.add((asm, RDFS.comment, Literal(ASSUMPTION, lang="en"))); out.add((a, T("dependsOnAssumption"), asm))
        out.add((a, RDFS.label, Literal("Applicability of %s, %s: %s" % (str(g.value(inst, RDFS.label) or inst), date, state[3:]), lang="en")))
        results[str(inst).rsplit("/", 1)[1]] = state
    return out, results


if __name__ == "__main__":
    prof, org, date, assessor, dest = sys.argv[1:6]
    g = Graph().parse(prof); g.parse(os.path.join(ROOT, "ontology", "vocab", "legal.ttl"))
    org = URIRef(org); base = str(org).rstrip("/") + "/"
    out, res = evaluate(g, org, date, URIRef(assessor), base)
    out.serialize(dest, format="turtle")
    for k, v in res.items(): print("   %-12s %s" % (k, v[3:]))
