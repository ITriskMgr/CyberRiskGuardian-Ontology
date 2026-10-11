# ADR-003 Control objective, implementation and assessment

Status: proposed (0.9.0). Specification sections 5 (Controls), 6, 13.

## Decision
Three distinct things, three classes:
- `control` (since 0.1.0): a prescription of a risk-modifying measure, independent of any organisation (the objective or requirement level; framework requirements such as CSF or SP 800-53 entries are vocabulary concepts linked to it).
- `control measure` (since 0.1.0): the control as it stands in one organisation, with status (in place, planned, proposed), owner, scope and evidence: the implementation.
- `control assessment` (new, `crgo-grc`): a planned act in which an assessor tests a control measure at a date, over a scope and by a procedure, and records a result (effective, partly effective, ineffective, not tested) with evidence.
Effectiveness claims come from control assessments, not from the existence of a control measure or a framework mapping.

## Alternatives
A single "control" class with an implemented flag was rejected in Phase 1 (it mixes a rule with its application). Putting the test result on the control measure was rejected: results are dated and can contradict each other, so they need their own records.

## Counterexample and test
A control measure stated `owl:sameAs` a control violates SHACL (`tests/shacl/neg-measure-sameas-control`). A tested assessment with no evidence violates SHACL (`neg-control-test-no-evidence`). CQ-04 returns only in-place measures whose latest assessment is effective or partly effective; a later *ineffective* test removes the measure (`tests/spec_cq`). CQ-05 returns every assessment, so two contradictory results remain visible.
