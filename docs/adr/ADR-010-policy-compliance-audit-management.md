# ADR-010 Policy, compliance and audit management

Status: proposed for 0.10.0 (decisions D1-D14 approved by the project owner on 2026-10-12; the P1 terms approved the same day; the design record itself awaits the release go-ahead).

## Decision
- **Modules** (D1): `crgo-policy` (imports governance and mapping) and `crgo-compliance` (imports grc and policy); additions to `crgo-audit` (which now also imports compliance) and `crgo-mapping` (which now imports core, for the CCO parent of mapping assertions). Opaque IRIs in the single namespace (D2).
- **Directives have versions** (D4): `directive version` (policy, standard, procedure, guideline, charter, methodology, playbook) with a lifecycle state separate from CRGO's governance status; a policy statement belongs to one exact version and states its normative modality. Published versions need an effective date and an approval decision; drafts need neither (lifecycle-aware SHACL).
- **Qualified mappings** (I1, D6): `mapping assertion` with source, target, type (exact to conflicting), editions mapped, rationale, confidence, reviewer and review state. Exact and full-coverage mappings need full review metadata. The approved reference mappings stay direct triples.
- **Attestations are declarations** (I2): policy acknowledgements and compliance attestations are disjoint from compliance determinations and audit conclusions.
- **Compliance**: programme and objectives, requirement interpretations (with a legal-review state and a privilege flag), regulatory authorities, framework adoption (a decision record: I4), compliance assessment campaigns, provision versions only for amended wording (D5), deadlines (calendar or event-triggered, offset in hours), regulatory submissions with receipts, regulatory exemptions granted only by an authority. "Not applicable" stays an applicability state; a determination for a requirement found not applicable at that date is refused (D10).
- **Audit**: audit function and charter, methodology, plan entries with deferral reason and authoriser, engagement type (nature and focus) and state, workpapers (no sole self-review), observations disjoint from findings (D8), quality reviews; root-cause categories shared with nonconformities (I5).
- **Widenings of approved terms** (D9 and the P1 review): closure and reopening also apply to nonconformities; applicability also covers policy statements; *version label* has no domain; the legal instrument and compliance determination definitions cover contracts and adopted frameworks.

## Alternatives
Separate `crgop:`/`crgoc:` namespaces (rejected, D2); a full obligation-version layer (rejected, D5); reifying all 161 k reference mappings (rejected, D6); an AuditorCompetency class (excluded: personal data, D7).

## Counterexample and test
Eighteen SHACL negative fixtures `tests/shacl/neg-pca-*`, two OWL fixtures (guideline that is a policy statement, observation that is a finding); 30 specification competency questions (POL CQ01-10, CMP CQ1-10, AUD CQ-01-10) with positive and negative checks in `tests/pca_cq/run_pca_cq.py`; read contract `contracts/compliance/v1`.
