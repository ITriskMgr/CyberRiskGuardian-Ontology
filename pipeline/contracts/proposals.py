# -*- coding: utf-8 -*-
"""Contract library-proposal/v1 (0.11.2): library-scenario proposals, their approval or rejection, this installation's
ontology additions and public contribution files. See contracts/library-proposal/v1/README.md.

Everything is written under a store folder chosen by the caller (CyberRiskGuardian's helper: the installation folder
<org root>/_installation/crgo-local/), never inside the CRGO repository (REPOSITORY_PATH, build/ included):

  <store>/proposals/LOC-xxxxxxxxxx.json          one proposal and its history (proposed -> approved | rejected; public)
  <store>/approved/crgo-local-extension.json     approved additions, export-shaped records loaded beside the library
  <out_dir>/crgo-contribution-LOC-xxxxxxxxxx.json a public contribution for ITriskMgr/CyberRiskGuardian-Ontology

CRGO records who approved and when; it does not check roles (the application restricts approval to administrators).
A proposal stays 'proposed' until approved; an approval adds the scenario to this installation only. A contribution
file is a suggestion to the CRGO project owner, status 'proposed', who assigns the F-id and the approval as before.
"""
import datetime, json, os, re, sys, tempfile
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(ROOT, "pipeline", "query"))
sys.path.insert(0, HERE)
import grouping as G  # noqa: E402
import dss  # noqa: E402

SCHEMAS = os.path.join(ROOT, "contracts", "library-proposal", "v1")
RX_LOC = re.compile(r"^LOC-[0-9a-f]{10}$")
RX_DATE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}$")
CONTENT_KEYS = ("name", "statement", "themes", "asset_categories", "threat_source_types", "impact_dimensions", "weaknesses",
                "techniques", "cwe", "csf2", "sp80053r5", "iso27002", "loi25")
STATUSES = ("proposed", "approved", "rejected")
EXTENSION = os.path.join("approved", "crgo-local-extension.json")


class ProposalError(ValueError):
    def __init__(self, code, message, details=None):
        super().__init__(message)
        self.code, self.message, self.details = code, message, details

    def document(self):
        d = {"error": True, "code": self.code, "message": self.message}
        if self.details: d["details"] = [str(x) for x in self.details]
        return d


# ---------------------------------------------------------------- paths and files
def store_path(store_dir, required=True):
    """The store folder: an absolute path to an existing folder outside the CRGO repository. '' -> None when not required."""
    if store_dir is None or str(store_dir).strip() == "":
        if required:
            raise ProposalError("INVALID_ARGUMENT", "store_dir is required: the installation's folder for ontology proposals (outside the CRGO repository).")
        return None
    p = str(store_dir).strip()
    if len(p) > 1000 or "\x00" in p or not os.path.isabs(p):
        raise ProposalError("INVALID_ARGUMENT", "store_dir must be an absolute path.")
    if dss.repository_path(p, allow_build=False):
        raise ProposalError("REPOSITORY_PATH", "store_dir is inside the CRGO repository; proposals are kept in the installation's own folder.")
    if not os.path.isdir(p):
        raise ProposalError("INVALID_ARGUMENT", "store_dir is not an existing folder.", [p])
    return os.path.realpath(p)

def _out_dir(out_dir):
    p = str(out_dir or "").strip()
    if not p or len(p) > 1000 or "\x00" in p or not os.path.isabs(p):
        raise ProposalError("INVALID_ARGUMENT", "out_dir must be the absolute path of the folder for ontology proposals.")
    if dss.repository_path(p, allow_build=False):
        raise ProposalError("REPOSITORY_PATH", "out_dir is inside the CRGO repository; contribution files go to the folder for ontology proposals.")
    if not os.path.isdir(p):
        raise ProposalError("INVALID_ARGUMENT", "out_dir is not an existing folder.", [p])
    return os.path.realpath(p)

def _write(path, obj):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path), prefix=".tmp-", suffix=".json")
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(obj, fh, ensure_ascii=False, indent=1, sort_keys=True)
        fh.write("\n")
    os.replace(tmp, path)

def _date(date):
    d = str(date or "").strip() or datetime.date.today().isoformat()
    try:
        if not RX_DATE.match(d): raise ValueError
        datetime.date.fromisoformat(d)
    except ValueError:
        raise ProposalError("INVALID_ARGUMENT", "date must be written yyyy-mm-dd.")
    return d

def _who(name, what):
    n = G.nfc(name).strip() if isinstance(name, str) else ""
    if not n or len(n) > 200:
        raise ProposalError("INVALID_ARGUMENT", "%s is required (a name of at most 200 characters)." % what)
    return n

def _pid(proposal_id):
    p = str(proposal_id or "").strip()
    if not RX_LOC.match(p):
        raise ProposalError("INVALID_ARGUMENT", "proposal_id must look like 'LOC-' followed by 10 hexadecimal digits.")
    return p

def _load(store, pid):
    path = os.path.join(store, "proposals", pid + ".json")
    if not os.path.isfile(path):
        raise ProposalError("UNKNOWN_ID", "unknown proposal: %s" % pid)
    return json.load(open(path, encoding="utf-8")), path

def load_local(store_dir):
    """Approved local records of a store ([] without a store or before the first approval)."""
    store = store_path(store_dir, required=False)
    if store is None: return []
    path = os.path.join(store, EXTENSION)
    if not os.path.isfile(path): return []
    doc = json.load(open(path, encoding="utf-8"))
    return list(doc.get("scenarios", []))


# ---------------------------------------------------------------- proposal content
def _nfc(x):
    if isinstance(x, str): return G.nfc(x).strip()
    if isinstance(x, list): return [_nfc(v) for v in x]
    if isinstance(x, dict): return {k: _nfc(v) for k, v in x.items()}
    return x

def proposal_id(proposal):
    """LOC- + the first 10 hex digits of the SHA-256 of the canonical JSON of the scenario content (CONTENT_KEYS present):
    the same content proposed twice, by anyone, has the same id."""
    return "LOC-" + G.sha10(G.canonical({k: proposal[k] for k in CONTENT_KEYS if k in proposal}))

def check_proposal(proposal, ref, id_exists=None):
    """Schema first (SCHEMA_INVALID), then vocabulary and identifiers (INVALID_ARGUMENT, never invent ids)."""
    if not isinstance(proposal, dict):
        raise ProposalError("SCHEMA_INVALID", "proposal must be a JSON object valid against proposal.schema.json.")
    errs = dss.validate_doc(proposal, "proposal.schema.json", SCHEMAS)
    if errs:
        raise ProposalError("SCHEMA_INVALID", "The proposal does not conform to library-proposal/v1 (no parameters, estimates or organisation figures).", errs)
    bad = []
    for field, kind in (("themes", "theme"), ("asset_categories", "asset_category"), ("threat_source_types", "threat_source_type"), ("impact_dimensions", "impact_dimension")):
        bad += ["%s: unknown %s %s" % (field, kind, v) for v in proposal.get(field, []) if v not in ref.labels[kind]]
    for t, _c in proposal.get("techniques", []):
        if t in ref.replaced: bad.append("techniques: %s is revoked, use %s" % (t, ref.successor(t)))
        elif t in ref.deprecated: bad.append("techniques: %s is deprecated and has no successor" % t)
        elif t not in ref.active: bad.append("techniques: unknown ATT&CK id %s" % t)
    bad += ["cwe: unknown %s" % w for w, _c in proposal.get("cwe", []) if w not in ref.cwe_ids]
    if id_exists is not None:
        for field, fw in (("csf2", "csf2"), ("sp80053r5", "sp800-53r5"), ("iso27002", "iso27002-2022"), ("loi25", "loi25")):
            bad += ["%s: unknown requirement %s" % (field, i) for i, _c in proposal.get(field, []) if not id_exists(fw, i)]
    for field in ("techniques", "cwe", "csf2", "sp80053r5", "iso27002", "loi25"):
        ids = [i for i, _c in proposal.get(field, [])]
        bad += ["%s: %s listed twice" % (field, i) for i in sorted({i for i in ids if ids.count(i) > 1})]
    if bad:
        raise ProposalError("INVALID_ARGUMENT", "The proposal uses identifiers CRGO does not hold (CRGO never invents identifiers).", bad)


# ---------------------------------------------------------------- operations
def propose(proposal, store_dir, ref, id_exists=None):
    """Store a proposal (status 'proposed'). Idempotent: the same content returns the existing proposal and its status."""
    store = store_path(store_dir)
    proposal = _nfc(proposal) if isinstance(proposal, dict) else proposal
    check_proposal(proposal, ref, id_exists)
    pid = proposal_id(proposal)
    path = os.path.join(store, "proposals", pid + ".json")
    if os.path.isfile(path):
        doc = json.load(open(path, encoding="utf-8"))
        return {"id": pid, "status": doc["status"], "path": path, "existing": True}
    doc = {"schema": "crgo-library-proposal/1", "id": pid, "status": "proposed", "crgo_release": ref.release, "proposal": proposal,
           "history": [{"status": "proposed", "by": proposal["proposed_by"], "on": proposal["proposed_on"]}]}
    _write(path, doc)
    return {"id": pid, "status": "proposed", "path": path, "existing": False}

def _summary(doc):
    p = doc["proposal"]
    s = {"id": doc["id"], "status": doc["status"], "name": p["name"], "proposed_by": p["proposed_by"], "proposed_on": p["proposed_on"]}
    dec = [h for h in doc.get("history", []) if h.get("status") in ("approved", "rejected")]
    if dec:
        s["decided_by"], s["decided_on"] = dec[-1]["by"], dec[-1]["on"]
        if dec[-1].get("reason"): s["reason"] = dec[-1]["reason"]
    pub = [h for h in doc.get("history", []) if "public" in h]
    if pub: s["public"] = pub[-1]["public"]
    elif p.get("public"): s["public"] = "requested"
    return s

def list_proposals(store_dir, status=""):
    store = store_path(store_dir)
    status = str(status or "").strip()
    if status and status not in STATUSES:
        raise ProposalError("INVALID_ARGUMENT", "status must be one of %s or empty." % ", ".join(STATUSES), list(STATUSES))
    folder = os.path.join(store, "proposals")
    out = []
    for f in sorted(os.listdir(folder)) if os.path.isdir(folder) else []:
        if RX_LOC.match(f[:-5]) and f.endswith(".json"):
            doc = json.load(open(os.path.join(folder, f), encoding="utf-8"))
            if not status or doc["status"] == status: out.append(_summary(doc))
    return {"proposals": sorted(out, key=lambda s: s["id"]), "count": len(out)}

def approve(store_dir, proposal_id_, approver, date, ref):
    """proposed -> approved; the scenario joins this installation's ontology (approved/crgo-local-extension.json)."""
    store, pid = store_path(store_dir), _pid(proposal_id_)
    approver, date = _who(approver, "approver"), _date(date)
    doc, path = _load(store, pid)
    if doc["status"] != "proposed":
        raise ProposalError("STATUS_NOT_PROPOSED", "proposal %s is already %s." % (pid, doc["status"]))
    local = [r for r in load_local(store) if r["id"] != pid]
    local.append(G.local_record(pid, doc["proposal"], ref, approver, date))
    local = G.local_clusters(local, ref)
    _write(os.path.join(store, EXTENSION), {"schema": "crgo-local-extension/1", "release_built_against": ref.release, "scenarios": local})
    doc["status"] = "approved"
    doc["history"].append({"status": "approved", "by": approver, "on": date})
    _write(path, doc)
    rec = next(r for r in local if r["id"] == pid)
    return {"id": pid, "status": "approved", "path": path, "local_extension": os.path.join(store, EXTENSION),
            "primary_theme": rec["primary_theme"], "cluster": rec["cluster"]}

def reject(store_dir, proposal_id_, approver, date, reason):
    store, pid = store_path(store_dir), _pid(proposal_id_)
    approver, date = _who(approver, "approver"), _date(date)
    reason = G.nfc(reason).strip() if isinstance(reason, str) else ""
    if not reason or len(reason) > 1000:
        raise ProposalError("INVALID_ARGUMENT", "reason is required to reject a proposal (at most 1,000 characters).")
    doc, path = _load(store, pid)
    if doc["status"] != "proposed":
        raise ProposalError("STATUS_NOT_PROPOSED", "proposal %s is already %s." % (pid, doc["status"]))
    doc["status"] = "rejected"
    doc["history"].append({"status": "rejected", "by": approver, "on": date, "reason": reason})
    _write(path, doc)
    return {"id": pid, "status": "rejected", "path": path}

def contribution(doc, action, date, tool, release):
    p = doc["proposal"]
    return {"schema": "crgo-contribution/1", "for": "ITriskMgr/CyberRiskGuardian-Ontology", "crgo_release": release, "status": "proposed",
            "action": action, "key": "CONTRIB-" + doc["id"],
            "scenario": {"name": p["name"], "statement": p["statement"], "theme": p["themes"][0],
                         "asset_categories": p.get("asset_categories", []), "threat_source_types": p.get("threat_source_types", []),
                         "impact_dimensions": p.get("impact_dimensions", []), "weaknesses": p.get("weaknesses", []),
                         "attack": p.get("techniques", []), "csf2": p.get("csf2", []), "sp80053r5": p.get("sp80053r5", []),
                         "iso27002": p.get("iso27002", []), "loi25": p.get("loi25", []), "cwe": p.get("cwe", [])},
            "provenance": {"tool": tool, "anonymized": True, "submitted_on": date}}

def export_contribution(store_dir, proposal_id_, out_dir, ref, action="add", date="", tool=""):
    """Write the public contribution file of an APPROVED proposal into out_dir (the folder for ontology proposals)."""
    store, pid = store_path(store_dir), _pid(proposal_id_)
    out = _out_dir(out_dir)
    action = str(action or "add").strip()
    if action not in ("add", "withdraw"):
        raise ProposalError("INVALID_ARGUMENT", "action must be 'add' or 'withdraw'.", ["add", "withdraw"])
    date = _date(date)
    tool = G.nfc(tool).strip() if isinstance(tool, str) and tool.strip() else "CRGO %s crgo_export_contribution" % ref.release
    if len(tool) > 100: raise ProposalError("INVALID_ARGUMENT", "tool: at most 100 characters.")
    doc, path = _load(store, pid)
    if doc["status"] != "approved":
        raise ProposalError("STATUS_NOT_PROPOSED", "only an approved proposal can be made public (%s is %s)." % (pid, doc["status"]))
    c = contribution(doc, action, date, tool, ref.release)
    errs = dss.validate_doc(c, "contribution.schema.json", SCHEMAS)
    if errs:
        raise ProposalError("SCHEMA_INVALID", "The contribution does not conform to contribution.schema.json.", errs)
    f = os.path.join(out, "crgo-contribution-%s%s.json" % (pid, "-withdraw" if action == "withdraw" else ""))
    _write(f, c)
    doc["history"].append({"public": "submitted" if action == "add" else "withdrawn", "on": date, "file": os.path.basename(f)})
    _write(path, doc)
    return {"id": pid, "action": action, "path": f}
