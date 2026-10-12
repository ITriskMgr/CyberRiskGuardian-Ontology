# CRGO 0.10.0 — P1 review: term list for policy, compliance and audit management

**Status: proposed — awaiting the project owner's review (checkpoint P1).** Prepared 2026-10-12.

The Phase 0 decisions D1–D14 were approved as recommended (`docs/decisions.md` §20). This step drafts every new term with English and French labels and definitions, sources and confidence notes. It builds the modules and checks that they are consistent. The SHACL shapes, fixtures, competency questions and contract follow in P2–P4.

## Summary

| | Count |
|---|---|
| New IRIs | CRGO_0000885 to CRGO_0001096 (208 numbers: 195 terms, 13 concept schemes; 4 numbers are left unused, see below) |
| New classes | 28 (policy 9, compliance 11, audit 7, mapping 1) |
| New value sets | 13, with 62 values; 6 values added to 3 existing value sets |
| New properties | 60 object properties, 26 data properties |
| Approved terms changed | 11: 5 under decision D9, and 6 needing your approval (below) |
| New modules | `crgo-policy` (imports governance and mapping), `crgo-compliance` (imports grc and policy) |
| Imports changed | `crgo-audit` now also imports `crgo-compliance`; `crgo-mapping` imports `crgo-core` (was `crgo-gov`) |
| Approved, after this build | 877 of 1,091 terms (the 208 new terms and 6 changed terms are proposed) |

All new terms are **proposed**. The 0.9.0 group approvals of `governance`, `assurance`, `audit`, `incident`, `evidence`, `grc` and `mapping` are now limited to the terms that existed when you gave them (up to CRGO_0000884), so that new terms in those modules do not inherit the approval.

## Approval groups (one row each in `src/approvals.tsv`)

| # | Group (approval key) | Content | Recommendation |
|---|---|---|---|
| 1 | `terms/policy` | 52 terms: directive version and policy version, policy clause, guideline, policy family, directive review, attestation and policy acknowledgement, training requirement; normative modality, directive lifecycle state, review trigger; 23 properties | Approve |
| 2 | `terms/compliance` | 65 terms: compliance programme and objective, requirement interpretation, regulatory authority, framework adoption, compliance assessment campaign, provision version, compliance deadline, regulatory submission, regulatory exemption, compliance attestation; legal review state, submission state, deadline trigger kind, root-cause category; 34 properties | Approve |
| 3 | Additions to `crgo-audit` (`terms/audit-0.10.0`) | 49 terms: audit function, audit charter, audit methodology, audit plan entry, audit workpaper, audit observation, audit quality review; engagement type, engagement state, plan entry state, quality review kind; 21 properties | Approve |
| 4 | Additions to `crgo-mapping` (`terms/mapping-0.10.0`) | 23 terms: mapping assertion, mapping type, review state; source, target, type, edition mapped, review state, reviewer, confidence, review date | Approve |
| 5 | Values added to existing value sets (`values/0.10.0`) | Instrument kind: contract, directive to be transposed. Condition kind: role, asset category. Sufficiency conclusion: sufficient with limitations, unavailable | Approve |
| 6 | Changes to approved terms not covered by D9 (`changes/0.10.0`) | See the next section | Approve |
| 7 | Source record (`sources/records-pca`) | ISO 37301:2021/Amd 1:2024, which you supplied (D12): identifier, official title, affected clauses 4.1 and 4.2, checksum | Approve |

## Changes to approved terms

These five are covered by **D9** and stay approved, each with a `skos:changeNote`:

- *closes finding*: range widened from audit finding to audit finding or nonconformity. SHACL will check it in P2.
- *applicability condition*, *applicability assessment*, *condition of* and *applicability of*: definitions widened to policy statements.

These six go **beyond what D9 approved**. They are proposed again until you approve group 6, and each has a change note:

| Term | Change | Why |
|---|---|---|
| *reopens finding* (CRGO_0000813) | Range widened like *closes finding* | A nonconformity that can be closed must also be reopenable. |
| *version label* (CRGO_0000844) | Domain removed (was instrument version); definition widened | The independent review found that using it on a directive version would infer an instrument version and make the data inconsistent. It now also serves as the audit report revision (AUD section 7). |
| *audit finding* (CRGO_0000541) | Alternative label "audit observation" removed | That is now the label of the separate class *audit observation* (D8), which is disjoint from *audit finding*. |
| *policy statement* (CRGO_0000498) | Alternative labels "policy requirement" / « exigence de politique » added | Promised in Phase 0 §2.1 (POL PolicyRequirement). |
| *legal instrument* (CRGO_0000343) | Definition widened to contracts and directives to be transposed | Required by the two new instrument kinds. |
| *compliance determination* (CRGO_0000346) | Definition widened to contractual obligations and adopted framework requirements | Required by framework adoption (I4) and compliance assessment campaigns. |

## Points decided by Claude while drafting, for review

- **The specifications' names, aligned to CRGO.** Some names were changed to fit CRGO's conventions:
  - PolicyReview became *directive review*, because it covers every directive.
  - PolicyGuideline became *guideline*.
  - AuditActionReference and AuditEvidenceReference reuse *corrective action* and *evidence item*, as the matrix said.
  - `meetsDeadline` became *answers deadline*: the original label claimed timeliness, which is to be computed from the dates, not stated.
- **Hours, not days, for event-triggered deadlines** (`dueOffsetHours`; Phase 0 said days). This is needed for 72-hour breach notices.
- **Framework adoption is a subclass of decision record.** It therefore reuses *decided on*, *decision made by* and *decision outcome*.
- **Requirement interpretation reuses *depends on assumption*** instead of a new free-text property.
- **Engagement type is not functional.** An engagement has one nature (assurance or advisory) and may also have one focus (compliance or follow-up); SHACL will check that combination in P2.
- **Several properties are deliberately not functional:**
  - *attested by*, so that joint signatories are possible;
  - *interpretation of*, so that one interpretation can cover several provisions;
  - *prepared by*;
  - *reviewed on* and *review due on*, so that a second review or a moved due date does not make data inconsistent.
- **"Not yet reviewed" was not added to the sufficiency conclusions** (Phase 0 §2.2 listed it). A sufficiency assessment that has not been made is better represented by its absence. As a result, IDs 1005, 1039, 1072 and 1080 were assigned to keys dropped or renamed while drafting, and they stay unused; IDs are never reused.
- **Additions Phase 0 did not list:**
  - the value set *review state*, for mapping assertions and other organisation records (I1 had referred to "governance status", which is reserved for CRGO terms);
  - *engagement state*;
  - *estimated effort (hours)* and *mandatory engagement* on plan entries (AUD section 7);
  - *sampling seed* (AUD section 7);
  - the condition kinds *role* and *asset category*, needed by the D9 widening.
- **Imports.** `crgo-mapping` now imports `crgo-core`, so that mapping assertions have their CCO parent. The 161 k reference mappings, which import `crgo-mapping`, therefore also load core, BFO and CCO.
- **Licensed text.** No licensed text was reproduced. The new citations are clause numbers only: GIAS 6.2, 8.3, 8.4, 9.3, 9.4, 12.1, 12.3, 14.6 and Domain III; ITAF 1204; ISO 37301 4.3, 4.4, 6.2 and 10.2; CSF GV.PO; SP 800-53 PL-1; ISO/IEC 27002 5.1. Each was checked against the vocabularies.

## Independent review

A separate agent reviewed the draft against Phase 0, the existing ontology and the specifications. It raised 2 high, 10 medium and 8 low findings; the 21st and 22nd items were positive confirmations. All findings are addressed in this version, except two that are deferred to P2:

- the SHACL rules (the nonconformity closure, the independence check extended to nonconformities, the attestation knowledge status, and the engagement-type combination);
- reporting the items listed above for your approval, which this document does.

Main fixes:

- **High:** the *version label* inconsistency, fixed by removing its domain; the "audit observation" label clash, fixed by removing the alternative label.
- **Medium:**
  - *meets deadline* renamed to *answers deadline*;
  - `crgo-mapping` imports `crgo-core` instead of `crgo-governance`;
  - definitions of *legal instrument* and *compliance determination* widened;
  - condition kinds *role* and *asset category* added;
  - functional review dates relaxed;
  - the guideline / policy statement boundary clarified, and *applies to scope* opened to guidelines;
  - engagement type documented as nature plus focus;
  - "policy requirement" alternative label added, and report revision covered by *version label*;
  - *granted by* made a sub-property of *issued by authority*;
  - framework adoption made a decision record;
  - the duplicate assumptions property dropped.
- **Low:**
  - the sufficiency values moved to the assurance module;
  - the "compliance management system" alternative label dropped;
  - policy clause made prescriptive;
  - GIAS 12.1 added;
  - unused source key removed;
  - French wording fixed ("revue sur le plan juridique", "le fait de").
- **Not changed:** the reviewer asked to verify "corrected version 2024-09" for the amendment. It is printed on the document you supplied (« Version corrigée 2024-09 »), so it stays.

## Checks run

`scripts/check.sh` was run in full (`WITH_LIBRARY=1`) on this build. Results:

- **Reasoning:** HermiT and ELK find the ontology consistent, with no unsatisfiable classes, and it is in OWL 2 DL with its imports. `crgo-full` (modules, scenario library and vocabularies) is consistent and in OWL 2 DL.
- **Negative OWL fixtures:** all 9 are inconsistent, as expected.
- **Metadata and modules:** governance metadata is complete and labels are unique (1,091 terms); module references are clean (each module uses only what it imports); the SKOS vocabularies pass.
- **Regression tests:**
  - MediBec regression: 84,491 / 41,104, round trip, consistent.
  - SHACL conforms, with the 1 deliberate warning; 41 negative SHACL fixtures are rejected as expected.
  - No critical pitfalls; identification tests pass.
  - Nordelle and Nordelle-GRCA plus the second tenant are consistent and in OWL 2 DL; 27/27 specification CQs pass.
  - 0 unresolved w3id IRIs; tenants are separated; 29/29 contract checks pass.
- **Two expected results at a checkpoint:**
  - **CQ17 ("which terms are not yet approved?") fails with 214 rows**: the 208 new IRIs and the 6 changed terms awaiting group 6. It will pass once you approve. This is the release gate working as intended.
  - **GRCA CQ-17 failed on the first run** because the test hard-coded release "0.9.0". It now reads the release from `crgo.ttl`, and 57/57 pass.

Not yet done (P2–P4): SHACL shapes and fixtures for the new terms, the 30 specification competency questions, the synthetic Nordelle policy, compliance and audit data, the `contracts/compliance/v1` contract, the MCP tool and the documentation pages.

## New terms

Generated from `build/terms.json` by `python3 scripts/review_table.py`. Concept schemes are not listed.

### crgo-policy (52)

| IRI | Kind | Label (en / fr) | Parent, domain/range or value set | Definition (en) |
|---|---|---|---|---|
| CRGO_0000885 | class | policy family / famille de politiques | cco:ont00000853 | A named grouping of related directives, such as all the documents on access control, used to find the policies, standards and procedures that cover the same subject. |
| CRGO_0000886 | class | directive version / version de directive | cco:ont00000965 | A fixed release of a policy, technical standard, procedure, guideline, audit charter or methodology, identified by a version label, with its approval, effective and retirement dates. Once effective its content does not change; a change makes a new version. |
| CRGO_0000887 | class | policy version / version de politique | directive version | A directive version of a policy. |
| CRGO_0000888 | class | policy clause / article de politique | cco:ont00000965 | A numbered or titled part of a directive version that contains one or more policy statements, used to cite where a statement appears. |
| CRGO_0000889 | class | guideline / ligne directrice interne | cco:ont00000965 | A directive, issued as guidance separate from any policy, that recommends a practice without making it mandatory. Departing from a guideline needs no exception. A 'should' or 'may' statement written inside a policy is a policy statement, not a guideline. |
| CRGO_0000890 | class | directive review / revue de directive | cco:ont00000228 | A planned act in which a directive or some of its statements are reviewed, on schedule or after a trigger such as a regulatory change, an incident or an audit finding, ending in a decision to keep, revise or retire them. |
| CRGO_0000891 | class | attestation / attestation | cco:ont00000853 | A dated declaration by an identified agent about a stated subject and scope, such as having read a policy version or that a requirement is met. It records what the agent declares, not what was verified. |
| CRGO_0000892 | class | policy acknowledgement / accusé de lecture de politique | attestation | An attestation by a person that they have received and read an exact policy version that applies to them. Acknowledging a policy is not understanding or complying with it. |
| CRGO_0000893 | class | training requirement / exigence de formation | cco:ont00000965 | A directive that persons in a stated role or scope complete stated training, usually because a policy statement applies to them. Completing training is not the same as acknowledging or complying. |
| CRGO_0000913 | value set (class) | normative modality / modalité normative | skos:Concept | How binding a policy statement is. |
| CRGO_0000919 | value set (class) | directive lifecycle state / état du cycle de vie d'une directive | skos:Concept | The state of a directive version in the organisation's document lifecycle. Not the governance status of a CRGO term. |
| CRGO_0000927 | value set (class) | review trigger / déclencheur de revue | skos:Concept | What caused a directive review. |
| CRGO_0000915 | value | must / doit | normative modality | The statement is mandatory (must, shall). |
| CRGO_0000916 | value | must not / ne doit pas | normative modality | The statement prohibits something. |
| CRGO_0000917 | value | should / devrait | normative modality | The statement is recommended; departing from it needs a recorded reason. |
| CRGO_0000918 | value | may / peut | normative modality | The statement permits something without requiring it. |
| CRGO_0000921 | value | draft (directive) / ébauche (directive) | directive lifecycle state | Being written; not binding. |
| CRGO_0000922 | value | under review (directive) / en revue (directive) | directive lifecycle state | Submitted for review or approval; not binding. |
| CRGO_0000923 | value | approved (directive) / approuvée (directive) | directive lifecycle state | Approved by the competent authority; not yet in effect. |
| CRGO_0000924 | value | published (directive) / publiée (directive) | directive lifecycle state | Communicated and in effect. |
| CRGO_0000925 | value | retired (directive) / retirée (directive) | directive lifecycle state | No longer in effect and not replaced. |
| CRGO_0000926 | value | superseded (directive) / remplacée (directive) | directive lifecycle state | No longer in effect; replaced by a later version. |
| CRGO_0000929 | value | scheduled review / revue planifiée | review trigger | The review interval has elapsed. |
| CRGO_0000930 | value | regulatory change (trigger) / changement réglementaire (déclencheur) | review trigger | A legal or regulatory change affects the directive. |
| CRGO_0000931 | value | incident (trigger) / incident (déclencheur) | review trigger | An incident revealed that the directive is inadequate. |
| CRGO_0000932 | value | audit or assessment finding (trigger) / constatation d'audit ou d'évaluation (déclencheur) | review trigger | A finding or nonconformity concerns the directive. |
| CRGO_0000933 | value | risk change (trigger) / changement du risque (déclencheur) | review trigger | A change in assessed risk or risk appetite. |
| CRGO_0000934 | value | organisational change (trigger) / changement organisationnel (déclencheur) | review trigger | A change in structure, mandate, activities or roles. |
| CRGO_0000935 | value | technology change (trigger) / changement technologique (déclencheur) | review trigger | A change in systems, services or technology. |
| CRGO_0001006 | object property | version of directive / version de la directive | domain: directive version; range: — | Relates a directive version to the policy, technical standard, procedure, guideline, charter or methodology it is a version of. |
| CRGO_0001007 | object property | statement in version / énoncé de la version | domain: policy statement; range: directive version | Relates a policy statement to the directive version it is part of. |
| CRGO_0001008 | object property | clause of / article de | domain: policy clause; range: directive version | Relates a policy clause to the directive version it is part of. |
| CRGO_0001009 | object property | in clause / dans l'article | domain: policy statement; range: policy clause | Relates a policy statement to the clause where it appears. |
| CRGO_0001010 | object property | in policy family / dans la famille de politiques | domain: —; range: policy family | Relates a directive to a policy family it belongs to. |
| CRGO_0001011 | object property | has normative modality / a pour modalité normative | domain: policy statement; range: normative modality | Gives how binding a policy statement is. |
| CRGO_0001012 | object property | has lifecycle state / a pour état de cycle de vie | domain: directive version; range: directive lifecycle state | Gives the lifecycle state of a directive version, as last recorded. |
| CRGO_0001013 | object property | statement implemented by / énoncé appliqué par | domain: policy statement; range: control measure | Relates a policy statement to a control measure the organisation relies on to meet it. Implementation is not evidence that the measure is effective. |
| CRGO_0001014 | object property | intended to mitigate / vise à atténuer | domain: policy statement; range: risk scenario | Relates a policy statement to a risk scenario it is meant to reduce. States intent only; it does not say that the risk is reduced. |
| CRGO_0001015 | object property | applies to scope / s'applique au périmètre | domain: —; range: — | Relates a policy statement, guideline or directive to an asset, process, role, organisational unit or jurisdiction it explicitly applies to. |
| CRGO_0001016 | object property | requires training / exige la formation | domain: policy statement; range: training requirement | Relates a policy statement to a training requirement for those it applies to. |
| CRGO_0001017 | object property | authorised by risk acceptance / autorisée par l'acceptation du risque | domain: policy exception; range: risk acceptance | Relates a policy exception to the risk acceptance decision that accepts the risk it leaves. A policy exception does not imply a risk acceptance; the link is stated when one was made. |
| CRGO_0001018 | object property | review of / revue de | domain: directive review; range: — | Relates a directive review to the directive, directive version or policy statement reviewed. |
| CRGO_0001019 | object property | has review trigger / a pour déclencheur de revue | domain: directive review; range: review trigger | Gives what caused a directive review. |
| CRGO_0001020 | object property | review triggered by / revue déclenchée par | domain: directive review; range: — | Relates a directive review to the regulatory change, incident, finding or other record that caused it. |
| CRGO_0001021 | object property | attested by / attestée par | domain: attestation; range: — | Relates an attestation to the agent who made it. |
| CRGO_0001022 | object property | attestation about / attestation portant sur | domain: attestation; range: — | Relates an attestation to what it declares about, such as an exact policy version or a set of obligations. |
| CRGO_0001066 | data property | statement text / texte de l'énoncé | domain: policy statement; range: literal | Gives the wording of an organisation's own policy statement. Never used for the text of a licensed standard. |
| CRGO_0001067 | data property | retired on / retirée le | domain: directive version; range: xsd:dateTime | Gives when a directive version ceased to be in effect. |
| CRGO_0001068 | data property | review due on / revue due le | domain: —; range: xsd:dateTime | Gives the date by which a directive or directive version must next be reviewed, as last recorded. |
| CRGO_0001069 | data property | review interval (months) / intervalle de revue (mois) | domain: —; range: xsd:nonNegativeInteger | Gives the number of months between scheduled reviews of a directive. |
| CRGO_0001070 | data property | attested on / attestée le | domain: attestation; range: xsd:dateTime | Gives when an attestation was made. |
| CRGO_0001071 | data property | attestation scope / périmètre de l'attestation | domain: attestation; range: literal | States the scope and period an attestation covers and what it is based on. |

### crgo-compliance (65)

| IRI | Kind | Label (en / fr) | Parent, domain/range or value set | Definition (en) |
|---|---|---|---|---|
| CRGO_0000894 | class | compliance programme / programme de conformité | cco:ont00000974 | The plan by which an organisation operates its compliance management system: its scope, the obligations and commitments it covers, its objectives, the roles involved and its review cycle. |
| CRGO_0000895 | class | compliance objective / objectif de conformité | business objective | A measurable objective that a compliance programme sets itself, such as reviewing every obligation of the register once a year. |
| CRGO_0000896 | class | requirement interpretation / interprétation d'exigence | cco:ont00000853 | A statement, subject to legal review, of how an organisation reads an obligation, provision or framework requirement for its own situation, with the assumptions made and its legal review state. It is the organisation's reading, not the text and not legal advice. |
| CRGO_0000897 | class | regulatory authority / autorité de réglementation | cco:ont00001180 | An organisation with legal power to issue, supervise or enforce legal instruments in a jurisdiction, such as a data protection authority. |
| CRGO_0000898 | class | framework adoption / adoption de référentiel | decision record | A decision record by which an organisation has committed to meet a framework, or a stated part of it, for a stated scope, which makes its requirements commitments of that organisation. It records the commitment, not conformity. |
| CRGO_0000899 | class | compliance assessment campaign / campagne d'évaluation de la conformité | cco:ont00000228 | A planned act in which an organisation assesses compliance with a stated set of obligations or requirements, for a stated scope, period and method, producing compliance determinations. |
| CRGO_0000900 | class | provision version / version de disposition | cco:ont00000853 | A record of the wording of a provision as in force over a stated period, kept when an amendment changes that wording, so that earlier assessments can be reproduced against the text that applied then. |
| CRGO_0000901 | class | compliance deadline / échéance de conformité | cco:ont00000853 | A record of when an obligation must be met, either on a calendar date or within a period counted from a triggering event, such as 72 hours after becoming aware of a breach, with how the date is computed. |
| CRGO_0000902 | class | regulatory submission / transmission réglementaire | cco:ont00000853 | A record of a notice, filing or report sent to an authority under an obligation, with when it was submitted, its state and the receipt or acknowledgement obtained. |
| CRGO_0000903 | class | regulatory exemption / dispense réglementaire | cco:ont00000965 | A directive issued by an authority that relieves an organisation, for a stated scope and period, from an obligation or part of it, on a stated legal basis. Only an authority with power over the obligation can grant it; an internal approval cannot. |
| CRGO_0000904 | class | compliance attestation / attestation de conformité | attestation | An attestation by an identified signatory that an organisation meets stated obligations or requirements for a stated scope and period, citing what it is based on. It is a management declaration, not an audit conclusion. |
| CRGO_0000936 | value set (class) | legal review state / état de la revue juridique | skos:Concept | How far a requirement interpretation has been reviewed by legal counsel. |
| CRGO_0000941 | value set (class) | submission state / état de la transmission | skos:Concept | The state of a regulatory submission. |
| CRGO_0000947 | value set (class) | deadline trigger kind / type de déclenchement d'échéance | skos:Concept | How a compliance deadline is set. |
| CRGO_0000951 | value set (class) | root-cause category / catégorie de cause fondamentale | skos:Concept | A broad category of the cause of a finding or nonconformity, used to group recurring causes. CRGO's own scale. |
| CRGO_0000938 | value | not legally reviewed / non revue sur le plan juridique | legal review state | No legal review yet; the interpretation is provisional. |
| CRGO_0000939 | value | legal review in progress / revue juridique en cours | legal review state | Submitted to counsel. |
| CRGO_0000940 | value | legally reviewed / validée par le conseiller juridique | legal review state | Reviewed and accepted by counsel for the stated situation. |
| CRGO_0000943 | value | submission in preparation / transmission en préparation | submission state | Being prepared; not sent. |
| CRGO_0000944 | value | submitted / transmise | submission state | Sent to the authority; no acknowledgement yet. |
| CRGO_0000945 | value | acknowledged by the authority / reçue par l'autorité | submission state | The authority has acknowledged receipt. |
| CRGO_0000946 | value | rejected by the authority / refusée par l'autorité | submission state | The authority has refused or returned it. |
| CRGO_0000949 | value | calendar deadline / échéance calendaire | deadline trigger kind | A fixed date or a recurring date, such as an annual filing. |
| CRGO_0000950 | value | event-triggered deadline / échéance déclenchée par un événement | deadline trigger kind | A period counted from an event, such as becoming aware of a breach. |
| CRGO_0000953 | value | people (cause) / personnes (cause) | root-cause category | Awareness, skills, workload or behaviour. |
| CRGO_0000954 | value | process (cause) / processus (cause) | root-cause category | A missing, unclear or unfollowed process. |
| CRGO_0000955 | value | technology (cause) / technologie (cause) | root-cause category | A tool, system or configuration that does not support the control. |
| CRGO_0000956 | value | governance (cause) / gouvernance (cause) | root-cause category | Unclear accountability, oversight or direction. |
| CRGO_0000957 | value | third party (cause) / tiers (cause) | root-cause category | A supplier or other external party did not perform as required. |
| CRGO_0000958 | value | control design (cause) / conception de la mesure (cause) | root-cause category | The control would not meet its objective even if operated as designed. |
| CRGO_0000959 | value | resourcing (cause) / ressources (cause) | root-cause category | Insufficient budget, staff or time. |
| CRGO_0001023 | object property | programme covers / programme visant | domain: compliance programme; range: — | Relates a compliance programme to an obligation, legal instrument, framework adoption or commitment within its scope. |
| CRGO_0001024 | object property | objective of programme / objectif du programme | domain: compliance objective; range: compliance programme | Relates a compliance objective to the compliance programme that sets it. |
| CRGO_0001025 | object property | interpretation of / interprétation de | domain: requirement interpretation; range: — | Relates a requirement interpretation to the obligation, provision or requirement it interprets. |
| CRGO_0001026 | object property | has legal review state / a pour état de revue juridique | domain: requirement interpretation; range: legal review state | Gives how far a requirement interpretation has been reviewed by counsel. |
| CRGO_0001027 | object property | issued by authority / émis par l'autorité | domain: —; range: regulatory authority | Relates a legal instrument, guidance or exemption to the regulatory authority that issued it. |
| CRGO_0001028 | object property | enforced by / dont l'application relève de | domain: —; range: regulatory authority | Relates a legal instrument or provision to a regulatory authority that supervises or enforces it. |
| CRGO_0001029 | object property | adopts framework / adopte le référentiel | domain: framework adoption; range: — | Relates a framework adoption to the framework, or the part of a framework, adopted. |
| CRGO_0001030 | object property | determination in / constat effectué dans | domain: compliance determination; range: compliance assessment campaign | Relates a compliance determination to the compliance assessment campaign that produced it. |
| CRGO_0001031 | object property | provision version of / version de la disposition | domain: provision version; range: — | Relates a provision version to the provision whose wording it records. |
| CRGO_0001032 | object property | in instrument version / dans la version de l'instrument | domain: provision version; range: instrument version | Relates a provision version to the instrument version that carries that wording. |
| CRGO_0001033 | object property | evaluates provision version / évalue la version de la disposition | domain: —; range: provision version | Relates a compliance or applicability determination to the exact provision version it evaluated, when the wording has changed over time. |
| CRGO_0001034 | object property | deadline for / échéance de | domain: compliance deadline; range: — | Relates a compliance deadline to the obligation or provision that sets it. |
| CRGO_0001035 | object property | has deadline trigger kind / a pour type de déclenchement | domain: compliance deadline; range: deadline trigger kind | Gives whether a compliance deadline is a calendar date or counted from an event. |
| CRGO_0001036 | object property | deadline triggered by / échéance déclenchée par | domain: compliance deadline; range: — | Relates an event-triggered compliance deadline to the record of the triggering event, such as an incident confirmation. |
| CRGO_0001037 | object property | submission to / transmise à | domain: regulatory submission; range: regulatory authority | Relates a regulatory submission to the authority it was sent to. |
| CRGO_0001038 | object property | submission under / transmise en vertu de | domain: regulatory submission; range: — | Relates a regulatory submission to the obligation or provision it is made under. |
| CRGO_0001040 | object property | has submission state / a pour état de transmission | domain: regulatory submission; range: submission state | Gives the state of a regulatory submission, as last recorded. |
| CRGO_0001041 | object property | receipt evidence / preuve de réception | domain: regulatory submission; range: evidence register entry | Relates a regulatory submission to the evidence item recording its submission or the authority's acknowledgement. |
| CRGO_0001042 | object property | exemption from / dispense de | domain: regulatory exemption; range: — | Relates a regulatory exemption to the obligation or provision it relieves the organisation from. |
| CRGO_0001043 | object property | granted by / accordée par | domain: regulatory exemption; range: regulatory authority | Relates a regulatory exemption to the authority that granted it. |
| CRGO_0001044 | object property | obligation at stake in / obligation en jeu dans | domain: —; range: risk scenario | Relates an obligation or provision to a risk scenario in which failing to meet it is part of the consequence. |
| CRGO_0001045 | object property | has root-cause category / a pour catégorie de cause | domain: —; range: root-cause category | Gives a broad category of the cause of a finding or nonconformity. |
| CRGO_0001095 | object property | answers deadline / répond à l'échéance | domain: regulatory submission; range: compliance deadline | Relates a regulatory submission to the compliance deadline it answers. Whether it was on time is computed from the dates, not stated. |
| CRGO_0001073 | data property | legally privileged / protégé par le secret professionnel | domain: —; range: xsd:boolean | States that a record contains or summarises legally privileged advice and must not be passed to general reasoning, reporting or AI services. |
| CRGO_0001074 | data property | legal basis / fondement juridique | domain: regulatory exemption; range: literal | States the legal basis on which a regulatory exemption is granted. |
| CRGO_0001075 | data property | adoption scope / périmètre de l'adoption | domain: framework adoption; range: literal | States which parts of a framework are adopted and for which entities, systems or services. |
| CRGO_0001076 | data property | provision wording / libellé de la disposition | domain: provision version; range: literal | Gives the wording of a provision version, only for texts CRGO may reproduce, such as legislation; otherwise only its citation. |
| CRGO_0001077 | data property | due offset (hours) / délai (heures) | domain: compliance deadline; range: xsd:nonNegativeInteger | Gives the number of hours, counted from the triggering event, within which an event-triggered deadline falls. |
| CRGO_0001078 | data property | deadline computation / calcul de l'échéance | domain: compliance deadline; range: literal | States how a compliance deadline is computed, such as calendar or business days, time zone and the provision cited. |
| CRGO_0001079 | data property | submitted on / transmise le | domain: regulatory submission; range: xsd:dateTime | Gives when a regulatory submission was sent. |
| CRGO_0001081 | data property | rule version / version de la règle | domain: —; range: xsd:string | Gives the version of the applicability rules used by an applicability assessment, so that it can be reproduced. |
| CRGO_0001082 | data property | fact relied on / fait retenu | domain: applicability assessment; range: literal | States a fact about the organisation that an applicability assessment relied on. |
| CRGO_0001083 | data property | missing fact / fait manquant | domain: applicability assessment; range: literal | States a fact that an applicability assessment needed but did not have. |
| CRGO_0001096 | data property | receipt acknowledged on / réception confirmée le | domain: regulatory submission; range: xsd:dateTime | Gives when the authority acknowledged a regulatory submission. |

### crgo-audit (49)

| IRI | Kind | Label (en / fr) | Parent, domain/range or value set | Definition (en) |
|---|---|---|---|---|
| CRGO_0000905 | class | audit function / fonction d'audit | cco:ont00000300 | The group of agents in an organisation that performs internal audit under a charter, led by the chief audit executive. |
| CRGO_0000906 | class | audit charter / charte d'audit | cco:ont00000965 | A directive approved by the governing body that sets the internal audit function's purpose, authority, responsibilities and reporting lines. |
| CRGO_0000907 | class | audit methodology / méthodologie d'audit | cco:ont00000965 | A directive that sets how an audit function plans, performs and reports engagements, including its sampling and rating rules, identified by version. |
| CRGO_0000908 | class | audit plan entry / entrée du plan d'audit | cco:ont00000853 | An entry of an audit plan for one candidate or planned engagement, with its priority rationale, its state (proposed, approved, deferred, cancelled or completed) and, when deferred or cancelled, the reason and who authorised it. |
| CRGO_0000909 | class | audit workpaper / feuille de travail d'audit | cco:ont00000853 | A record prepared by an auditor that documents work performed, evidence examined and conclusions reached in an engagement, with who prepared it and who reviewed it. CRGO holds its metadata, not its content. |
| CRGO_0000910 | class | audit observation / observation d'audit | cco:ont00000853 | A preliminary record of a condition noted during an engagement that has not yet been validated against criteria and evidence. It is not a finding and carries no audit conclusion. |
| CRGO_0000911 | class | audit quality review / revue de qualité de l'audit | cco:ont00000228 | A planned act in which the work of an engagement or of the audit function is evaluated against its methodology and the standards it follows, by a supervisor, an internal quality assessor or an external assessor. |
| CRGO_0000960 | value set (class) | engagement type / type de mission | skos:Concept | The kind of an audit engagement: its nature (assurance or advisory) and, where relevant, its focus (compliance or follow-up). An engagement may have one nature and one focus. |
| CRGO_0000966 | value set (class) | engagement state / état de la mission | skos:Concept | The recorded stage of an audit engagement. |
| CRGO_0000973 | value set (class) | plan entry state / état de l'entrée du plan | skos:Concept | The state of an audit plan entry. |
| CRGO_0000980 | value set (class) | quality review kind / type de revue de qualité | skos:Concept | The kind of an audit quality review. |
| CRGO_0000962 | value | assurance engagement / mission d'assurance | engagement type | Gives an opinion or conclusion on governance, risk management or control. |
| CRGO_0000963 | value | advisory engagement / mission de conseil | engagement type | Gives advice at management's request; gives no assurance. |
| CRGO_0000964 | value | compliance audit / audit de conformité | engagement type | Checks conformity with stated obligations or requirements. |
| CRGO_0000965 | value | follow-up engagement / mission de suivi | engagement type | Checks the status and effectiveness of earlier corrective actions. |
| CRGO_0000968 | value | engagement planning / planification de la mission | engagement state | Scope, objectives and programme are being set. |
| CRGO_0000969 | value | fieldwork / travaux sur le terrain | engagement state | Procedures are being performed. |
| CRGO_0000970 | value | engagement reporting / communication des résultats | engagement state | Findings and conclusions are being communicated. |
| CRGO_0000971 | value | engagement closed / mission close | engagement state | The report is issued and the file is closed. |
| CRGO_0000972 | value | engagement cancelled / mission annulée | engagement state | Stopped before completion. |
| CRGO_0000975 | value | proposed (plan entry) / proposée (entrée du plan) | plan entry state | Candidate engagement, not yet approved. |
| CRGO_0000976 | value | approved (plan entry) / approuvée (entrée du plan) | plan entry state | Approved as part of the plan. |
| CRGO_0000977 | value | deferred (plan entry) / reportée (entrée du plan) | plan entry state | Moved to a later period, with a recorded reason and authoriser. |
| CRGO_0000978 | value | cancelled (plan entry) / annulée (entrée du plan) | plan entry state | Removed from the plan, with a recorded reason and authoriser. |
| CRGO_0000979 | value | completed (plan entry) / réalisée (entrée du plan) | plan entry state | The engagement was carried out. |
| CRGO_0000982 | value | supervisory review / revue de supervision | quality review kind | Review of engagement work by its supervisor. |
| CRGO_0000983 | value | internal quality assessment / évaluation interne de la qualité | quality review kind | Periodic self-assessment of the audit function. |
| CRGO_0000984 | value | external quality assessment / évaluation externe de la qualité | quality review kind | Assessment of the audit function by a qualified independent assessor. |
| CRGO_0001046 | object property | charter of / charte de | domain: audit charter; range: audit function | Relates an audit charter to the audit function it governs. |
| CRGO_0001047 | object property | entry in plan / entrée du plan | domain: audit plan entry; range: audit plan | Relates an audit plan entry to the audit plan it belongs to. |
| CRGO_0001048 | object property | entry for engagement / entrée pour la mission | domain: audit plan entry; range: audit engagement | Relates an audit plan entry to the engagement it plans. |
| CRGO_0001049 | object property | entry for auditable entity / entrée pour l'entité auditable | domain: audit plan entry; range: auditable entity | Relates an audit plan entry to an auditable entity it covers. |
| CRGO_0001050 | object property | has plan entry state / a pour état d'entrée | domain: audit plan entry; range: plan entry state | Gives the state of an audit plan entry. |
| CRGO_0001051 | object property | entry informed by / entrée éclairée par | domain: audit plan entry; range: — | Relates an audit plan entry to a risk assessment or risk scenario that informed its priority. |
| CRGO_0001052 | object property | has engagement type / a pour type de mission | domain: audit engagement; range: engagement type | Gives the nature, and where relevant the focus, of an audit engagement. |
| CRGO_0001053 | object property | has engagement state / a pour état de mission | domain: audit engagement; range: engagement state | Gives the recorded stage of an audit engagement. |
| CRGO_0001054 | object property | follows methodology / suit la méthodologie | domain: —; range: — | Relates an audit engagement or plan to the audit methodology version it follows. |
| CRGO_0001055 | object property | workpaper for / feuille de travail de | domain: audit workpaper; range: — | Relates an audit workpaper to the engagement, procedure or control assessment it documents. |
| CRGO_0001056 | object property | prepared by / préparée par | domain: —; range: — | Relates an audit workpaper or report to an agent who prepared it. |
| CRGO_0001057 | object property | validated as / validée en tant que | domain: audit observation; range: audit finding | Relates an audit observation to the audit finding it became after validation. |
| CRGO_0001058 | object property | quality review of / revue de qualité de | domain: audit quality review; range: — | Relates an audit quality review to the engagement, workpaper or audit function reviewed. |
| CRGO_0001059 | object property | has quality review kind / a pour type de revue de qualité | domain: audit quality review; range: quality review kind | Gives the kind of an audit quality review. |
| CRGO_0001084 | data property | priority rationale / justification de la priorité | domain: audit plan entry; range: literal | States why an audit plan entry has its priority, such as the risks and mandatory requirements it addresses. |
| CRGO_0001085 | data property | deferral reason / motif du report | domain: audit plan entry; range: literal | States why an audit plan entry was deferred or cancelled. |
| CRGO_0001086 | data property | estimated effort (hours) / effort estimé (heures) | domain: audit plan entry; range: xsd:nonNegativeInteger | Gives the estimated effort of a planned engagement, in hours. |
| CRGO_0001087 | data property | mandatory engagement / mission obligatoire | domain: audit plan entry; range: xsd:boolean | States that an audit plan entry is required by law, regulation or the governing body, whatever its risk ranking. |
| CRGO_0001088 | data property | sampling seed / germe d'échantillonnage | domain: sampling plan; range: xsd:string | Gives the seed or starting point used to select a random or systematic sample, so that the selection can be reproduced. |
| CRGO_0001089 | data property | report audience / destinataires du rapport | domain: audit report; range: literal | States who an audit report is addressed to. |
| CRGO_0001090 | data property | prepared on / préparée le | domain: audit workpaper; range: xsd:dateTime | Gives when an audit workpaper was completed by its preparer. |

### crgo-assurance (2)

| IRI | Kind | Label (en / fr) | Parent, domain/range or value set | Definition (en) |
|---|---|---|---|---|
| CRGO_0001003 | value | sufficient with limitations / suffisantes avec limites | sufficiency conclusion | The evidence supports a conclusion only with stated limitations. |
| CRGO_0001004 | value | unavailable / non disponibles | sufficiency conclusion | The evidence needed could not be obtained. |

### crgo-grc (4)

| IRI | Kind | Label (en / fr) | Parent, domain/range or value set | Definition (en) |
|---|---|---|---|---|
| CRGO_0001001 | value | contract / contrat | instrument kind | An agreement that binds the organisation to obligations towards another party, such as a customer or a supplier. |
| CRGO_0001002 | value | directive (to be transposed) / directive (à transposer) | instrument kind | An instrument that binds states to a result and is given effect through national law, such as a European Union directive. |
| CRGO_0001093 | value | role condition / condition de rôle | condition kind | Whether a person or unit holds a stated role, for a policy statement that applies to that role. |
| CRGO_0001094 | value | asset-category condition / condition de catégorie d'actifs | condition kind | Whether an asset belongs to a stated category or tier, for a policy statement that applies to it. |

### crgo-mapping (23)

| IRI | Kind | Label (en / fr) | Parent, domain/range or value set | Definition (en) |
|---|---|---|---|---|
| CRGO_0000912 | class | mapping assertion / assertion de correspondance | cco:ont00000853 | A directional statement, subject to review, that a source requirement corresponds to a target requirement in a stated way (exact, full or partial coverage, broader, narrower, related or conflicting), with the editions mapped, the rationale, the confidence, the reviewer and its review state. A mapping is not evidence of compliance. |
| CRGO_0000985 | value set (class) | mapping type / type de correspondance | skos:Concept | How the source of a mapping assertion corresponds to its target. |
| CRGO_0000994 | value set (class) | review state / état de la revue | skos:Concept | The review state of an organisation record such as a mapping assertion or a requirement interpretation. Not the governance status of a CRGO term. |
| CRGO_0000987 | value | exact mapping / correspondance exacte | mapping type | Source and target say the same thing. |
| CRGO_0000988 | value | full coverage / couverture totale | mapping type | Meeting the source meets all of the target. |
| CRGO_0000989 | value | partial coverage / couverture partielle | mapping type | Meeting the source meets only part of the target. |
| CRGO_0000990 | value | broader mapping / correspondance plus large | mapping type | The source is broader than the target. |
| CRGO_0000991 | value | narrower mapping / correspondance plus étroite | mapping type | The source is narrower than the target. |
| CRGO_0000992 | value | related mapping / correspondance liée | mapping type | Source and target concern the same subject without coverage. |
| CRGO_0000993 | value | conflicting mapping / correspondance contradictoire | mapping type | Meeting the source makes the target harder or impossible to meet. |
| CRGO_0000996 | value | draft (record) / ébauche (enregistrement) | review state | Written; not yet submitted for review. |
| CRGO_0000997 | value | under review (record) / en revue (enregistrement) | review state | Submitted for review. |
| CRGO_0000998 | value | approved (record) / approuvé (enregistrement) | review state | Approved by the reviewer. |
| CRGO_0000999 | value | rejected (record) / rejeté (enregistrement) | review state | Rejected by the reviewer. |
| CRGO_0001000 | value | withdrawn (record) / retiré (enregistrement) | review state | Withdrawn by its author or no longer valid. |
| CRGO_0001060 | object property | mapping source / source de la correspondance | domain: mapping assertion; range: — | Relates a mapping assertion to its source requirement, such as a policy statement or a control. |
| CRGO_0001061 | object property | mapping target / cible de la correspondance | domain: mapping assertion; range: — | Relates a mapping assertion to its target requirement, such as an obligation or a framework requirement. |
| CRGO_0001062 | object property | has mapping type / a pour type de correspondance | domain: mapping assertion; range: mapping type | Gives how the source of a mapping assertion corresponds to its target. |
| CRGO_0001063 | object property | mapped edition / édition mise en correspondance | domain: mapping assertion; range: — | Relates a mapping assertion to the source record or version of each side that was mapped, so that a later edition does not silently change it. |
| CRGO_0001064 | object property | has review state / a pour état de revue | domain: —; range: review state | Gives the review state of an organisation record such as a mapping assertion. A requirement interpretation also has a legal review state, which says whether counsel has reviewed it. |
| CRGO_0001065 | object property | reviewed by / revu par | domain: —; range: — | Relates a record, such as a mapping assertion, a requirement interpretation, an audit workpaper or a report, to an agent who reviewed it. |
| CRGO_0001091 | data property | mapping confidence / confiance dans la correspondance | domain: mapping assertion; range: xsd:decimal | Gives the reviewer's confidence in a mapping assertion, from 0 to 1. |
| CRGO_0001092 | data property | reviewed on / revu le | domain: —; range: xsd:dateTime | Gives when a record was reviewed. |
