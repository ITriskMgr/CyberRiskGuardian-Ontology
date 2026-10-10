# Ontology pitfall scan (OOPS! catalogue, local implementation)

The OOPS! web service is not reachable from the build environment, so the pitfalls that can be checked mechanically were implemented locally. Pitfalls that need human judgement (P02 synonyms as classes, P03 'is' relationships, P05 wrong inverses, P06 cycles in hierarchies beyond self-loops, P09 missing domain information, P12, P30, P31) are not covered.

| Pitfall | Name | Result | Count | Note |
|---|---|---|---|---|
| P04 | Unconnected ontology elements | ok | 0 |  |
| P07 | Merging different concepts in the same class | ok | 0 | Review: a class named 'X and Y' may hide two concepts. |
| P08 | Missing annotations | ok | 0 |  |
| P10 | Missing disjointness between sibling classes | review | 13 | Most CRGO siblings inherit disjointness from BFO/CCO categories; same-category siblings (for example the CRG parameters) are left open on purpose. |
| P11 | Missing domain or range in properties | review | 30 | Open on purpose where the specification says so (for example weaknessOf, mapsToRequirement, hasOwner); SHACL constrains the values instead. |
| P13 | Inverse relationships not explicitly declared | ok | 0 | By design: CRGO declares no inverse properties to stay within OWL 2 EL where possible. |
| P19 | Multiple domains or ranges in properties | ok | 0 |  |
| P21 | Using a miscellaneous class | ok | 0 |  |
| P22 | Using different naming conventions | ok | 0 |  |
| P24 | Using recursive definitions | ok | 0 |  |
| P28 | Defining wrong symmetric relationships | ok | 0 |  |
| P29 | Defining wrong transitive relationships | ok | 0 |  |
| P32 | Several classes with the same label | ok | 0 |  |
| P34 | Untyped class | ok | 0 |  |
| P35 | Untyped property | ok | 0 |  |
| P36 | URI contains file extension | ok | 0 |  |
| P41 | No license declared | ok | 0 |  |
| P40 | Namespace hijacking | ok | 0 |  |

## P10 Missing disjointness between sibling classes (13)

- risk scenario
- Descriptive Information Content Entity
- computed risk quantity
- estimate
- http://www.w3.org/2004/02/skos/core#Concept
- asset
- Prescriptive Information Content Entity
- CRG parameter
- likelihood
- process
- impact estimate
- hardware asset
- risk level

## P11 Missing domain or range in properties (30)

- reporting frequency
- triggers obligation
- statement
- monitors
- background
- part of framework
- has control function
- target value
- data source
- has external reference
- warning threshold
- rationale
- applicability note
- purpose
- critical threshold
- … 15 more

