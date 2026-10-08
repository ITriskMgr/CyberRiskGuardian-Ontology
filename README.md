# CyberRiskGuardian Ontology (CRGO)

**Status: draft 0.1.0, Phase 2 — every term is `proposed`; nothing is approved yet.**

CRGO is an OWL 2 ontology for cybersecurity risk assessment. It gives a formal,
reasoner-checked meaning to the data that [CyberRiskGuardian](https://github.com/ITriskMgr/CyberRiskGuardian)
(CRG) produces: assets, threat and vulnerability descriptions, risk scenarios,
controls, the CRG quantitative parameters and the key risk indicators computed
from them. It replaces the earlier MOACCO ontology, which is retired.

- Upper ontology: BFO-2020 (ISO/IEC 21838-2), with an extract of the Common Core Ontologies 2.2 for information content entities, artifacts, agents and plans.
- Labels and definitions in English and French for every term.
- Governance annotations on every term: source, confidence, status, proposer, version.
- Licence: CC BY-NC 4.0 (see `LICENSE`); third-party imports keep their own licences (see `NOTICE.md`).

## Modules

| Module | IRI | Contents |
|---|---|---|
| crgo-gov | `https://w3id.org/crgo/crgo-gov` | Governance annotation properties, status and confidence values |
| crgo-core | `https://w3id.org/crgo/crgo-core` | Assets, organisation, threats, weaknesses, controls, frameworks, scenarios, assessment and treatment |
| crgo-measure | `https://w3id.org/crgo/crgo-measure` | Generic estimates (likelihood, impact, risk level, control effectiveness) and scales |
| crgo-crg | `https://w3id.org/crgo/crgo-crg` | The CRG v1.0c model: the six parameters, CVSS input, reductions, KRI quantities, calculation activity, screening |
| crgo (umbrella) | `https://w3id.org/crgo/crgo` | Imports all four |

Import chain: `crg → measure → core → {gov, BFO-2020, CCO slice}`. Term IRIs are
opaque (`https://w3id.org/crgo/CRGO_nnnnnnn`) and stay stable across versions;
the number assigned to each key is kept in `src/ids.tsv`.

The w3id.org redirects are not registered yet; until they are, use the local
`ontology/catalog-v001.xml` (Protégé and ROBOT read it automatically).

## Layout

```
ontology/        generated OWL modules (Turtle) and the import catalog
src/             specification (spec_core.py, spec_props.py), generator (build.py), ids.tsv
imports/         BFO-2020 core, CCO 2.2 slice and seed list, CCO licence
tests/           make_fixtures.py and generated fixtures (one positive, three negative)
scripts/         check.sh, check_metadata.py, check_modules.py
docs/            decisions.md (design decisions, review fixes, deferred items)
```

The `.ttl` files in `ontology/` are generated. Edit the specification in `src/`
and rebuild rather than editing the Turtle by hand.

## Build and check

Requirements: Python 3 with `rdflib`, Java 11 or later, and
[ROBOT](https://robot.obolibrary.org/) 1.9 or later.

```
ROBOT_JAR=/path/to/robot.jar ./scripts/check.sh
```

The script regenerates the modules and fixtures, merges the imports, then checks:

1. consistency and unsatisfiable classes with HermiT and ELK;
2. the OWL 2 DL profile, with imports;
3. the positive fixture is consistent and each negative fixture is inconsistent;
4. every term has en/fr labels and definitions, a status, a confidence and a source, and labels are unique per language;
5. no module refers to a term from a module it does not import.

Large merges may need more memory: `JAVA_TOOL_OPTIONS=-Xmx8g`.

`python3 scripts/make_review_workbook.py` writes the term review workbook
(`build/CRGO-0.1.0-term-review.xlsx`, needs `openpyxl`) from `build/terms.json`.

## Profile

The core is OWL 2 DL and is kept inside OWL 2 EL where possible: no inverse
properties and no functional object properties (cardinality constraints will be
expressed in SHACL in Phase 4). The one known EL exception is the `xsd:boolean`
range of *is crown jewel*.

## Roadmap

| Phase | Content | State |
|---|---|---|
| 1 | Discovery: sources, scenarios, CRG model, competency questions | done |
| 2 | Core OWL 2 modules with governance annotations | draft for review |
| 3 | ABox from the consolidated scenario library; SKOS framework mappings; CRG JSON-LD bridge | not started |
| 4 | Validation: SHACL shapes, OOPS!, competency questions as SPARQL tests | not started |
| 5 | Documentation (WIDOCO), release, extension plan | not started |

## Citation

Léger, Marc-André (2026). *CyberRiskGuardian Ontology (CRGO)*, version 0.1.0 (draft).
