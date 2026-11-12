# Contract library-proposal/v1 (CRGO 0.11.2)

Candidate grouping, scenario validation, library-scenario proposals, their approval in one installation, and public
contribution files. Built for CyberRiskGuardian Desktop 1.9.3 (spec section 4, workstream W2). Reference implementation:
`pipeline/query/grouping.py` (rules, store-free) and `pipeline/contracts/proposals.py` (files); MCP tools in
`pipeline/mcp/crgo_server.py`. The desktop's offline port (`js/crgo_group.js`) must give **identical** results; it is
tested against `examples/golden-grouping.json`.

| File | Purpose |
|---|---|
| `candidate.schema.json` | candidate / scenario descriptor (input of grouping and validation) |
| `proposal.schema.json` | proposal (input of `crgo_propose_library_scenario`) |
| `local-extension.schema.json` | `approved/crgo-local-extension.json`, this installation's ontology additions |
| `contribution.schema.json` | public contribution file for ITriskMgr/CyberRiskGuardian-Ontology |
| `error.schema.json` | error document |
| `examples/golden-grouping.json` | inputs and expected outputs shared with the desktop port (built by `tests/grouping/make_golden.py`) |
| `examples/*.json`, `examples/invalid/*.json` | valid and invalid examples (tests: `tests/contracts/test_library_proposal_contract.py`) |

Nothing here carries risk parameters, estimates, figures or organisation names: every input schema has
`additionalProperties: false`.

## Tools

| Tool | Writes | Arguments | Result |
|---|---|---|---|
| `crgo_group_candidates` | no | `candidates` (1..200), `store_dir` = "", `min_confidence` = "M" | grouping result |
| `crgo_validate_scenario` | no | `scenario`, `store_dir` = "", `min_confidence` = "M" | validation result |
| `crgo_propose_library_scenario` | proposals/ | `proposal`, `store_dir` | `{id, status: "proposed", path, existing}` |
| `crgo_list_proposals` | no | `store_dir`, `status` = "" (`proposed`, `approved`, `rejected`) | `{proposals: [{id, status, name, proposed_by, proposed_on, decided_by?, decided_on?, reason?, public?}], count}` sorted by id; `public`: `requested` (ticked on the proposal), `submitted`, `withdrawn` |
| `crgo_approve_proposal` | proposals/, approved/ | `store_dir`, `proposal_id`, `approver`, `date` = today | `{id, status: "approved", path, local_extension, primary_theme, cluster}` |
| `crgo_reject_proposal` | proposals/ | `store_dir`, `proposal_id`, `approver`, `reason`, `date` = today | `{id, status: "rejected", path}` |
| `crgo_export_contribution` | out_dir | `store_dir`, `proposal_id`, `out_dir`, `action` = "add" \| "withdraw", `date` = today, `tool` = "" | `{id, action, path}` |

`crgo_scenario` also takes `store_dir` (0.11.2): `scenario_id` `LOC-xxxxxxxxxx` returns the approved local record.

### Errors

`{"error": true, "code", "message", "details"?}` (`error.schema.json`), never a bare tool error:

| Code | When |
|---|---|
| `INVALID_ARGUMENT` | grouping/validation input of the wrong shape (not a list, 0 or more than 200 candidates, missing or malformed `ref`, duplicate `ref`, no `name` and no `statement`, a field not in the schema, list over 50 values or string over its length), unknown `min_confidence`; for the write tools: empty, relative or missing `store_dir` / `out_dir`, malformed `proposal_id`, empty `approver`, bad `date`, empty `reason`, unknown `status` filter or `action`; a proposal using vocabulary or identifiers CRGO does not hold (themes, categories, ATT&CK, CWE, CSF 2.0, SP 800-53, ISO 27002, Loi 25), a revoked technique (the successor is in `details`), an identifier listed twice |
| `UNKNOWN_ID` | no proposal with this id in the store; `crgo_scenario` with an unknown `LOC-` id |
| `SCHEMA_INVALID` | a proposal that is not an object or fails `proposal.schema.json` (extra field such as `estimates`, `anonymized` not true, ...) |
| `REPOSITORY_PATH` | `store_dir` or `out_dir` inside the CRGO repository (real path, symlinks resolved, `build/` included) |
| `STATUS_NOT_PROPOSED` | approve or reject a proposal already decided; export a proposal that is not approved |

Unknown vocabulary in a **candidate or scenario descriptor** is never an error: grouping reports it, validation turns it
into findings.

## Data

Both paths read the same data: the server reads `data/export/crgo-identification.json`; the desktop reads its snapshot,
built from that export, which must keep per scenario `id`, `name`, `statement`, `kind`, `themes`, `asset_categories`,
`attack_techniques`, `controls`, `obligations`, `estimates`, `refines`, **`primary_theme`**, **`cluster`**, and the
export's top-level **`values`** and **`grouping`** block:

| `grouping` key | Content |
|---|---|
| `attack.active` | ATT&CK ids (techniques, sub-techniques, tactics) not deprecated |
| `attack.replaced` | revoked id -> final successor (chains already followed), e.g. `T1562` -> `T1685` |
| `attack.deprecated` | deprecated ids without a successor |
| `cwe_ids` | CWE ids CRGO holds |
| `cwe_broader` | CWE id -> parent CWE ids (`skos:broader`) |
| `cwe_techniques` | CWE id -> base ATT&CK ids referenced for it: CAPEC patterns and KEV entries related to both, and library co-occurrence (approved H/M links of the same scenario); successors applied |
| `theme_rules` | `[theme key, regex]` in the effective (event-first) order; `event_first` lists the keys tried first |
| `stop_words` | the token stop list |

`examples/golden-grouping.json` has `data_fingerprint` = sha256 of the canonical JSON (below) of
`{"grouping": <grouping block>, "records": sorted [id, cluster, primary_theme] of every scenario}`.

## Normalisation (both paths)

- **Text** `norm(s)`: Unicode NFC, then lower case (`str.lower()` / `toLowerCase()`), then every run of
  `[ \t\n\r\f\v ]` replaced by one space, trimmed.
- **Tokens** of a name: the `[a-z0-9]+` runs of `norm(name)`, minus `stop_words`, as a set.
- **Vocabulary** (`asset_categories`, `threat_source_types`, `themes`): a value equal to a key, or whose `norm` equals the
  `norm` of an English label or of a key, gives that key; otherwise it is unknown (reported, not used). Duplicates are
  dropped, first occurrence kept.
- **Techniques**: trimmed, upper case. Known = in `active`, `replaced` or `deprecated`; unknown ones are reported and not
  used. A replaced id becomes its successor and is reported in `replaced_techniques` `{original: successor}`. The
  **base** id is the part before the first `.`; matching uses base ids.
- **CWE**: trimmed, upper case, a bare number `79` becomes `CWE-79`; known = matches `^CWE-[0-9]{1,6}$` and is in
  `cwe_ids`.
- **Primary theme** of a candidate: its first known theme; with none, inferred: the first rule of `theme_rules` whose
  regex matches `norm(name)` (or `norm(statement)` when the name is empty), else `ThemeOther`. Regexes run with ASCII
  semantics: Python `re.ASCII`, JavaScript `new RegExp(pattern)` without the `u` flag. `theme_inferred` says which.
  The candidate's theme set = its known themes plus the primary theme.
- **Record risk** (ordering only): `estimates.case_calibrated.risk.estimated`, else `estimates.case.risk.estimated`, else
  `estimates.library_2023.risk.estimated`, else 0 (compare the JSON numbers as they are; no rounding).
- **Record techniques** for a confidence level: base ids (after successor) of `attack_techniques` whose `confidence` is
  allowed (`H`: H; `M`: H, M; `L`: H, M, L). **Record categories**: `asset_categories` labels mapped to keys as above.
- **Comparisons and sorts**: identifiers and refs compare by code point (`<` in JavaScript, never `localeCompare`);
  every sort ends on an identifier.
- **Canonical JSON**: keys sorted recursively, no whitespace, non-ASCII characters not escaped (Python
  `json.dumps(sort_keys=True, separators=(",", ":"), ensure_ascii=False)`; JavaScript `JSON.stringify` of a key-sorted
  copy). Hashes are SHA-256 of its UTF-8 bytes, in lower-case hex.

## Static clusters (`cluster`, `primary_theme`; computed once at export)

Library scenarios only. Primary theme = the family's theme (`data/library/families.csv`) or the authored scenario's
theme (always one of the scenario's themes); for case scenarios the smallest theme key. Visit library scenarios in the
order (primary theme, -risk, id); a scenario joins the first **representative** already met with the same primary theme
and `5·|A∩B| >= 2·max(1, |A∪B|)` on name tokens, else it becomes a representative. `cluster` = the representative's
id. A case scenario's `cluster` = the cluster of the smallest id among its `refines` (null without one). The desktop
never recomputes them. This differs from `crgo_sweep`'s near-duplicate merging, which is query-dependent and unchanged.

**Local records** (approved additions) are clustered against the library representatives with the same rule, visited
after the library, in id order (they have no risk and `LOC-` sorts after `LIB-`); a local record that joins no
representative is its own representative.

## Matching one candidate (`match`)

The pool = library scenarios (`kind` = `library scenario`) and local records, prepared for `min_confidence`.

1. **kept**: `crgo_id` (trimmed, NFC) names a pool record -> that record. If it names a case scenario, the smallest id
   among its `refines` that is in the pool. Rule `kept`. An unknown `crgo_id` falls through to 2 and is reported.
2. Otherwise, for every pool record R, with `I` = |candidate tokens ∩ R tokens|, `U` = max(1, |candidate tokens ∪ R tokens|):
   - `near` = R's primary theme == the candidate's primary theme and `5·I >= 2·U`;
   - `facet` = R's primary theme ∈ the candidate's theme set, and they share a base technique, and they share an asset
     category.

   Records with neither are out. The best record is the greatest by: `near` (true first); then Jaccard `I/U`, compared
   by cross-multiplication `I1·U2` vs `I2·U1` (greater first); then `facet` (true first); then risk (greater first);
   then id (smaller first). Rule `near_duplicate` if the best is `near`, else `theme_technique_asset`.

## Grouping (`crgo-grouping/1`)

1. Match every candidate. Matched candidates with the same `cluster` (of the matched record) form one group.
2. Unmatched candidates: two are joined when they have the same primary theme, share a base technique and share an asset
   category; groups are the connected components (union-find; order-free).
3. Kinds: a cluster group with >= 2 members is `family`, with 1 member `unique`; both carry `representative` = the
   cluster's representative record. An unmatched component with >= 2 members is `family` with `representative: null`
   (the member with the smallest ref gives the starting text), with 1 member `own`; both carry `theme_gap` = their
   primary theme (the ontology holds no scenario like it). Matched groups have `theme_gap: null`.
4. Ids: a cluster group's `cluster_id` = the representative id. Other groups: `GRP-` + the first 10 hex digits of
   sha256 of the members' refs, sorted, joined by `\n`.
5. Order: groups by (`family` < `unique` < `own`, `cluster_id`); members by `ref`.

```json
{"algorithm": "crgo-grouping/1", "release": "0.11.2", "min_confidence": "M",
 "local": {"count": 0, "sha256": "<sha256 of the canonical JSON of the local records sorted by id; [] when none>"},
 "groups": [{"cluster_id": "LIB-F1582", "kind": "family|unique|own",
             "representative": {"id", "name", "statement" (null if none), "themes": [keys], "source": "library|local"} | null,
             "members": [{"ref", "match": {"id", "rule": "kept|near_duplicate|theme_technique_asset"} | null,
                          "primary_theme", "theme_inferred": bool, "replaced_techniques": {"T1562": "T1685"}}],
             "theme_gap": "ThemeX" | null}],
 "theme_gaps": [sorted distinct theme_gap values],
 "unknown_techniques": [sorted],
 "unknown_values": {"asset_categories"?, "threat_source_types"?, "themes"?, "cwe"?: [sorted]}   (only when some),
 "unknown_crgo_ids": [sorted]   (only when some: crgo_id given but not kept),
 "caveat": "..."}
```

## Validation (`crgo-validation/1`)

Input: one descriptor (candidate shape, `ref` optional). Match as above. **Theme match** when there is no match: a pool
record with the same primary theme sharing a base technique or an asset category.

Findings, in this order (values sorted within each line):

| Code | Severity | field | When | message (Python `%` template) |
|---|---|---|---|---|
| `LIBRARY_MATCH` | info | match | a match | `Matches CRGO scenario %s (%s).` (id, rule) |
| `THEME_MATCH_ONLY` | info | themes | no match, theme match | `No CRGO scenario matches; scenarios of the theme %s share a technique or an asset category (theme gap: own scenario).` |
| `OUTSIDE_ONTOLOGY` | attention | themes | no match, no theme match | `Outside the ontology: no CRGO scenario matches and no scenario of the theme %s shares a technique or an asset category (own scenario).` |
| `TECHNIQUE_UNKNOWN` | attention | techniques | unknown id | `ATT&CK technique %s is not in CRGO.` |
| `TECHNIQUE_REVOKED` | attention | techniques | replaced id; `suggestion` = successor | `ATT&CK technique %s is revoked; its successor is %s.` |
| `TECHNIQUE_DEPRECATED` | attention | techniques | deprecated, no successor | `ATT&CK technique %s is deprecated and has no successor.` |
| `CWE_UNKNOWN` | attention | cwe | unknown CWE | `%s is not in the CWE list CRGO holds.` |
| `CWE_NO_REFERENCE` | info | cwe | neither the CWE nor an ancestor has a `cwe_techniques` entry | `CRGO has no technique reference for %s or its parent weaknesses: consistency cannot be judged.` |
| `CWE_TECHNIQUE_UNLINKED` | attention | cwe | entries exist, the descriptor has known techniques, none is among them | `No technique of the scenario is linked to %s or its parent weaknesses (expected one of: %s).` (the first 10 sorted base ids joined by `, `, then ` ...` if more) |
| `ASSET_CATEGORY_UNKNOWN`, `THREAT_SOURCE_TYPE_UNKNOWN`, `THEME_UNKNOWN` | attention | the field | unknown value | `Asset category %s ...`, `Threat source type %s ...`, `Theme %s is not in the CRGO vocabulary.` |
| `CRGO_ID_UNKNOWN` | attention | crgo_id | `crgo_id` given and not kept | `CRGO scenario %s is unknown.` |

CWE references are gathered breadth first from the CWE through `cwe_broader` (parents visited in sorted order), as the
sorted union of the entries met. The desktop may show its own (French) wording by `code`; the `message` is English.

State: `outside_ontology` without match and theme match; else `needs_attention` if any finding is `attention`; else
`consistent`. Controls and obligations: with a match, the matched record's links allowed by `min_confidence`
(`{id, title, confidence, status}`, sorted by confidence H, M, L then id; `controls_basis: "match"`); without a match
but with known techniques, the 10 most frequent links among pool records sharing a base technique
(`{id, title, scenarios}`, sorted by count descending then id; `"techniques"`); otherwise empty (`"none"`).

```json
{"algorithm": "crgo-validation/1", "release", "min_confidence", "local": {...},
 "state": "consistent|needs_attention|outside_ontology",
 "match": {"id", "cluster_id", "rule"} | null, "theme_gap": "ThemeX" | null (null when matched),
 "primary_theme", "theme_inferred", "replaced_techniques": {...},
 "findings": [{"code", "severity", "field", "value", "message", "suggestion"?}],
 "controls_basis": "match|techniques|none",
 "controls": {"csf2": [...], "sp800-53r5": [...], "iso27002-2022": [...]}, "obligations": [...], "caveat": "..."}
```

## Store, proposals and approval

`store_dir` is chosen by the caller (CyberRiskGuardian's helper: `<org root>/_installation/crgo-local/`); it must be an
absolute path to an **existing** folder outside the CRGO repository. The tools never choose a default. The read tools
work without it (library only); with it, approved additions take part like library scenarios.

```
<store>/proposals/LOC-xxxxxxxxxx.json        {"schema": "crgo-library-proposal/1", "id", "status", "crgo_release", "proposal": {...},
                                              "history": [{"status": "proposed", "by", "on"}, {"status": "approved"|"rejected", "by", "on", "reason"?},
                                                          {"public": "submitted"|"withdrawn", "on", "file"}]}
<store>/approved/crgo-local-extension.json   {"schema": "crgo-local-extension/1", "release_built_against", "scenarios": [local records]}
```

- **Proposal id** = `LOC-` + the first 10 hex digits of sha256 of the canonical JSON of the proposal's content keys that
  are present (`name, statement, themes, asset_categories, threat_source_types, impact_dimensions, weaknesses,
  techniques, cwe, csf2, sp80053r5, iso27002, loi25`), after NFC and trimming of every string. Proposing the same
  content again (by anyone) returns the existing proposal (`existing: true`) and its status.
- **Checks**: schema first (`SCHEMA_INVALID`), then identifiers (`INVALID_ARGUMENT`, all problems in `details`):
  vocabulary keys, ATT&CK ids active (revoked: refused, successor named), CWE ids, requirement and obligation ids.
- **Approval** records `approver` and `date`; CRGO does not check roles (the application allows administrators only).
  The record added to the local extension is export-shaped: `{id, name, kind: "local scenario", source: "local",
  statement, themes [{key, label}], asset_categories [labels], threat_source_types [labels], impact_dimensions [labels],
  weaknesses, attack_techniques, controls {csf2, sp800-53r5, iso27002-2022}, obligations (Loi 25), cwe, primary_theme
  (= first theme), cluster, approved_by, approved_on}`; links are `{id, title (from the library, "" if none),
  confidence, status: "proposed"}`: approved for this installation, not reviewed by the CRGO project owner.
- A helper that writes these files itself (no server) must use the same shapes, ids and cluster rule.

## Contribution file

`crgo_export_contribution` writes `<out_dir>/crgo-contribution-<LOC-id>.json` (withdrawal:
`crgo-contribution-<LOC-id>-withdraw.json`) for an **approved** proposal; nothing is sent anywhere. Format
(`contribution.schema.json`): `{"schema": "crgo-contribution/1", "for": "ITriskMgr/CyberRiskGuardian-Ontology",
"crgo_release", "status": "proposed", "action": "add"|"withdraw", "key": "CONTRIB-<LOC-id>", "scenario": {name, statement,
theme (the first theme), asset_categories, threat_source_types, impact_dimensions, weaknesses, attack, csf2, sp80053r5,
iso27002, loi25, cwe}, "provenance": {"tool", "anonymized": true, "submitted_on"}}`: exactly a
`data/library/authored_scenarios.json` entry plus `cwe` (which the library build does not read yet). The proposer's
name, source refs and any figure stay in the installation. The CRGO project owner assigns the F-id and the approval
(`src/approvals.tsv`) as for any authored scenario; until then the scenario is *proposed*.
