# -*- coding: utf-8 -*-
"""CRGO 0.10.0: policy, compliance and audit management (Phase 0 decisions D1-D14, 2026-10-12;
docs/baseline/policy_compliance_audit_phase0.md). Same tuple layouts as spec_grca.py.

New modules (decision D1)
  policy      directive versions and lifecycle, clauses, guidelines, policy families, directive reviews, attestations
              and policy acknowledgements, training requirements                  (imports governance, mapping)
  compliance  compliance programme and objectives, requirement interpretations, regulatory authorities, framework
              adoption, compliance assessment campaigns, provision versions, deadlines, regulatory submissions and
              exemptions, compliance attestations, root-cause categories          (imports grc, policy)
Additions to existing modules
  audit       audit function and charter, audit methodology, plan entries, workpapers, observations, quality reviews,
              engagement type and state                                           (now also imports compliance)
  mapping     qualified mapping assertions, mapping type, review state, reviewer (now imports governance)
Widenings of approved terms (decision D9): EXTENSIONS and MODIFY below.

Every new term is proposed until the project owner approves it. Licensed standards are cited by identifier only (R-d).
"""
SOURCES_PCA = {
    "POL": "Information Security Policy Governance, Compliance Traceability and Assurance, specification O-ISPMS-001 v1.0 (project owner, 2026-10-12)",
    "CMP": "Compliance management ontology extension: implementation specification v1.0 (project owner, 2026-10-12)",
    "AUD": "Audit management ontology extension: implementation specification v1.0 (project owner, 2026-10-12)",
    "PH0": "CRGO 0.10.0 Phase 0 analysis and decisions D1-D14 (docs/baseline/policy_compliance_audit_phase0.md, approved 2026-10-12)",
    "CSFPO": "NIST CSF 2.0 (CSWP 29), category GV.PO (Policy), subcategories GV.PO-01 and GV.PO-02",
    "PL1": "NIST SP 800-53 Rev. 5, control PL-1 (Policy and Procedures) and the -1 controls of each family",
    "I27002P": "ISO/IEC 27002:2022, control 5.1 (Policies for information security); identifier cited",
}

DESC = "cco:ont00000853"
DIRECTIVE = "cco:ont00000965"
PLAN = "cco:ont00000974"
PLANNED_ACT = "cco:ont00000228"
GROUP = "cco:ont00000300"
ORG = "cco:ont00001180"

def C(key, module, parents, en, fr, den, dfr, src, rat="", alts=(), conf="H"):
    return (key, module, parents, en, fr, den, dfr, src, conf, rat, list(alts))

def OP(key, module, en, fr, den, dfr, dom, rng, src, rat="", chars=(), sup=None, conf="H"):
    return (key, module, en, fr, den, dfr, dom, rng, src, conf, rat, list(chars), sup)

def DP(key, module, en, fr, den, dfr, dom, rng, src, rat="", functional=False, conf="H"):
    return (key, module, en, fr, den, dfr, dom, rng, src, conf, rat, functional)

# ======================================================================================== classes
CLASSES_PCA = [
# ---------------------------------------------------------------- policy
C("PolicyFamily", "policy", [DESC], "policy family", "famille de politiques",
  "A named grouping of related directives, such as all the documents on access control, used to find the policies, standards and procedures that cover the same subject.",
  "Regroupement nommé de directives apparentées, comme l'ensemble des documents sur le contrôle d'accès, servant à repérer les politiques, normes et procédures qui portent sur un même sujet.",
  ["POL"], "POL section 4 (PolicyFamily); needed by POL CQ03 and CQ08."),
C("DirectiveVersion", "policy", [DIRECTIVE], "directive version", "version de directive",
  "A fixed release of a policy, technical standard, procedure, guideline, audit charter or methodology, identified by a version label, with its approval, effective and retirement dates. Once effective its content does not change; a change makes a new version.",
  "Diffusion figée d'une politique, d'une norme technique, d'une procédure, d'une ligne directrice, d'une charte ou d'une méthodologie d'audit, désignée par un libellé de version, avec ses dates d'approbation, d'entrée en vigueur et de retrait. Une fois en vigueur, son contenu ne change plus; toute modification crée une nouvelle version.",
  ["POL", "PH0"], "Decision D4: one version class for all directives (POL PolicyVersion generalised). Distinct from instrument version, which is a version of a legal instrument."),
C("PolicyVersion", "policy", ["DirectiveVersion"], "policy version", "version de politique",
  "A directive version of a policy.", "Version de directive d'une politique.",
  ["POL", "PH0"], "POL section 4 (PolicyVersion); decision D4."),
C("PolicyClause", "policy", [DIRECTIVE], "policy clause", "article de politique",
  "A numbered or titled part of a directive version that contains one or more policy statements, used to cite where a statement appears.",
  "Partie numérotée ou titrée d'une version de directive qui contient un ou plusieurs énoncés de politique, servant à citer l'emplacement d'un énoncé.",
  ["POL"], "POL section 4 (PolicyClause). Optional in data: a statement may be cited by its own identifier."),
C("Guideline", "policy", [DIRECTIVE], "guideline", "ligne directrice interne",
  "A directive, issued as guidance separate from any policy, that recommends a practice without making it mandatory. Departing from a guideline needs no exception. A 'should' or 'may' statement written inside a policy is a policy statement, not a guideline.",
  "Directive, publiée à titre d'orientation distincte de toute politique, qui recommande une pratique sans la rendre obligatoire. S'en écarter n'exige aucune dérogation. Un énoncé « devrait » ou « peut » rédigé dans une politique est un énoncé de politique, et non une ligne directrice.",
  ["POL"], "POL section 4 (PolicyGuideline). Disjoint from policy statement, so that a guidance document is never read as a binding requirement; modality distinguishes binding from non-binding statements within a policy.", [("policy guideline", "en")]),
C("DirectiveReview", "policy", [PLANNED_ACT], "directive review", "revue de directive",
  "A planned act in which a directive or some of its statements are reviewed, on schedule or after a trigger such as a regulatory change, an incident or an audit finding, ending in a decision to keep, revise or retire them.",
  "Acte planifié par lequel une directive ou certains de ses énoncés sont revus, selon le calendrier ou à la suite d'un déclencheur comme un changement réglementaire, un incident ou une constatation d'audit, et qui aboutit à la décision de les maintenir, de les réviser ou de les retirer.",
  ["POL", "CSFPO", "PL1", "I27002P"], "POL section 4 (PolicyReview, PolicyChangeEvent); CSF 2.0 GV.PO-02; SP 800-53 PL-1 (review and update frequency); ISO/IEC 27002:2022 control 5.1 (cited by number).", [("policy review", "en")]),
C("Attestation", "policy", [DESC], "attestation", "attestation",
  "A dated declaration by an identified agent about a stated subject and scope, such as having read a policy version or that a requirement is met. It records what the agent declares, not what was verified.",
  "Déclaration datée d'un agent identifié portant sur un objet et un périmètre précisés, comme le fait d'avoir lu une version de politique ou le fait qu'une exigence soit respectée. Elle consigne ce que l'agent déclare, et non ce qui a été vérifié.",
  ["POL", "CMP", "PH0"], "Improvement I2: common parent of policy acknowledgement and compliance attestation; disjoint from compliance determination and audit conclusion."),
C("PolicyAcknowledgement", "policy", ["Attestation"], "policy acknowledgement", "accusé de lecture de politique",
  "An attestation by a person that they have received and read an exact policy version that applies to them. Acknowledging a policy is not understanding or complying with it.",
  "Attestation par laquelle une personne déclare avoir reçu et lu une version précise d'une politique qui s'applique à elle. Prendre connaissance d'une politique n'équivaut ni à la comprendre ni à la respecter.",
  ["POL"], "POL sections 4 and 7 (acknowledged is not understood or compliant). Instances belong in organisation graphs or the application (POL section 1: no employee PII in CRGO)."),
C("TrainingRequirement", "policy", [DIRECTIVE], "training requirement", "exigence de formation",
  "A directive that persons in a stated role or scope complete stated training, usually because a policy statement applies to them. Completing training is not the same as acknowledging or complying.",
  "Directive exigeant que les personnes d'un rôle ou d'un périmètre précisés suivent une formation donnée, généralement parce qu'un énoncé de politique s'applique à elles. Suivre la formation ne revient ni à prendre connaissance de la politique ni à la respecter.",
  ["POL"], "POL sections 4-5 (TrainingRequirement, requiresTraining); decision D7."),
# ---------------------------------------------------------------- compliance
C("ComplianceProgramme", "compliance", [PLAN], "compliance programme", "programme de conformité",
  "The plan by which an organisation operates its compliance management system: its scope, the obligations and commitments it covers, its objectives, the roles involved and its review cycle.",
  "Plan par lequel une organisation exploite son système de management de la conformité : son périmètre, les obligations et engagements qu'il couvre, ses objectifs, les rôles en cause et son cycle de revue.",
  ["CMP", "I37301"], "CMP section 4 (ComplianceProgram); ISO 37301:2021 clauses 4.3-4.4 and 6.2 (cited by number).", ),
C("ComplianceObjective", "compliance", ["BusinessObjective"], "compliance objective", "objectif de conformité",
  "A measurable objective that a compliance programme sets itself, such as reviewing every obligation of the register once a year.",
  "Objectif mesurable que se fixe un programme de conformité, comme revoir chaque obligation du registre une fois par année.",
  ["CMP", "I37301"], "CMP section 4; ISO 37301:2021 clause 6.2."),
C("RequirementInterpretation", "compliance", [DESC], "requirement interpretation", "interprétation d'exigence",
  "A statement, subject to legal review, of how an organisation reads an obligation, provision or framework requirement for its own situation, with the assumptions made and its legal review state. It is the organisation's reading, not the text and not legal advice.",
  "Énoncé, soumis à une revue juridique, de la façon dont une organisation lit une obligation, une disposition ou une exigence de référentiel au regard de sa propre situation, avec les hypothèses retenues et l'état de sa revue juridique. C'est la lecture de l'organisation, et non le texte ni un avis juridique.",
  ["CMP"], "CMP sections 4 and 9 (privilege flag)."),
C("RegulatoryAuthority", "compliance", [ORG], "regulatory authority", "autorité de réglementation",
  "An organisation with legal power to issue, supervise or enforce legal instruments in a jurisdiction, such as a data protection authority.",
  "Organisation ayant le pouvoir légal d'édicter, de surveiller ou de faire appliquer des instruments juridiques dans une juridiction, comme une autorité de protection des données.",
  ["CMP"], "CMP section 4 (RegulatoryAuthority). Until now CRGO recorded issuers only as text on source records.", [("regulator", "en"), ("organisme de réglementation", "fr")]),
C("FrameworkAdoption", "compliance", ["DecisionRecord"], "framework adoption", "adoption de référentiel",
  "A decision record by which an organisation has committed to meet a framework, or a stated part of it, for a stated scope, which makes its requirements commitments of that organisation. It records the commitment, not conformity.",
  "Relevé de décision par lequel une organisation s'engage à respecter un référentiel, ou une partie précisée de celui-ci, pour un périmètre donné, ce qui fait de ses exigences des engagements de cette organisation. Il consigne l'engagement, et non la conformité.",
  ["CMP", "PH0"], "Improvement I4; CMP section 7 (source kind 'voluntary standard', 'internal commitment'). A decision record, so it reuses decided on, decision made by and decision outcome."),
C("ComplianceAssessmentCampaign", "compliance", [PLANNED_ACT], "compliance assessment campaign", "campagne d'évaluation de la conformité",
  "A planned act in which an organisation assesses compliance with a stated set of obligations or requirements, for a stated scope, period and method, producing compliance determinations.",
  "Acte planifié par lequel une organisation évalue sa conformité à un ensemble précisé d'obligations ou d'exigences, pour un périmètre, une période et une méthode donnés, et qui produit des constats de conformité.",
  ["CMP", "PH0"], "CMP section 4 (ComplianceAssessment as a campaign); conflict C3: the per-requirement result stays the compliance determination."),
C("ProvisionVersion", "compliance", [DESC], "provision version", "version de disposition",
  "A record of the wording of a provision as in force over a stated period, kept when an amendment changes that wording, so that earlier assessments can be reproduced against the text that applied then.",
  "Enregistrement du libellé d'une disposition tel qu'il était en vigueur pendant une période donnée, conservé lorsqu'une modification change ce libellé, afin que les évaluations antérieures puissent être reproduites au regard du texte alors applicable.",
  ["CMP", "PH0"], "Decision D5 (a): versions stay at instrument level; a provision version is recorded only when an amendment changes the wording."),
C("ComplianceDeadline", "compliance", [DESC], "compliance deadline", "échéance de conformité",
  "A record of when an obligation must be met, either on a calendar date or within a period counted from a triggering event, such as 72 hours after becoming aware of a breach, with how the date is computed.",
  "Enregistrement du moment où une obligation doit être respectée, soit à une date fixe, soit dans un délai compté à partir d'un événement déclencheur, comme 72 heures après la prise de connaissance d'une atteinte, avec le mode de calcul de la date.",
  ["CMP"], "CMP sections 4 and 8; generalises the incident-specific 'notification due by'."),
C("RegulatorySubmission", "compliance", [DESC], "regulatory submission", "transmission réglementaire",
  "A record of a notice, filing or report sent to an authority under an obligation, with when it was submitted, its state and the receipt or acknowledgement obtained.",
  "Enregistrement d'un avis, d'un dépôt ou d'un rapport transmis à une autorité en vertu d'une obligation, avec sa date de transmission, son état et l'accusé de réception obtenu.",
  ["CMP"], "CMP section 4 (RegulatorySubmission); links to breach reportability assessments for incident notices.", [("regulatory filing", "en"), ("déclaration à l'autorité", "fr")]),
C("RegulatoryExemption", "compliance", [DIRECTIVE], "regulatory exemption", "dispense réglementaire",
  "A directive issued by an authority that relieves an organisation, for a stated scope and period, from an obligation or part of it, on a stated legal basis. Only an authority with power over the obligation can grant it; an internal approval cannot.",
  "Directive émise par une autorité qui dispense une organisation, pour un périmètre et une période donnés, de tout ou partie d'une obligation, sur un fondement juridique précisé. Seule une autorité compétente à l'égard de l'obligation peut l'accorder; une approbation interne ne le peut pas.",
  ["CMP"], "CMP sections 4 and 9 (ComplianceException: internal approval does not remove a binding duty). Distinct from policy exception, which cannot waive law."),
C("ComplianceAttestation", "compliance", ["Attestation"], "compliance attestation", "attestation de conformité",
  "An attestation by an identified signatory that an organisation meets stated obligations or requirements for a stated scope and period, citing what it is based on. It is a management declaration, not an audit conclusion.",
  "Attestation par laquelle un signataire identifié déclare qu'une organisation respecte des obligations ou des exigences précisées pour un périmètre et une période donnés, en citant ce sur quoi elle se fonde. C'est une déclaration de la direction, et non une conclusion d'audit.",
  ["CMP", "AUD"], "CMP section 4; AUD section 7 (management attestation is not an independent audit conclusion)."),
# ---------------------------------------------------------------- audit
C("AuditFunction", "audit", [GROUP], "audit function", "fonction d'audit",
  "The group of agents in an organisation that performs internal audit under a charter, led by the chief audit executive.",
  "Groupe d'agents d'une organisation qui exerce l'audit interne en vertu d'une charte, sous la direction du responsable de l'audit interne.",
  ["AUD", "GIAS"], "AUD section 5; GIAS Domain III (cited by number). The function is the unit; the chief audit executive role is held within it.", [("internal audit function", "en"), ("fonction d'audit interne", "fr")]),
C("AuditCharter", "audit", [DIRECTIVE], "audit charter", "charte d'audit",
  "A directive approved by the governing body that sets the internal audit function's purpose, authority, responsibilities and reporting lines.",
  "Directive approuvée par l'organe de gouvernance qui fixe la mission, les pouvoirs, les responsabilités et les liens hiérarchiques de la fonction d'audit interne.",
  ["AUD", "GIAS"], "AUD section 5; GIAS Standard 6.2 (cited by number). Versioned through directive versions.", [("internal audit charter", "en"), ("charte d'audit interne", "fr")]),
C("AuditMethodology", "audit", [DIRECTIVE], "audit methodology", "méthodologie d'audit",
  "A directive that sets how an audit function plans, performs and reports engagements, including its sampling and rating rules, identified by version.",
  "Directive qui fixe la façon dont une fonction d'audit planifie, réalise et communique ses missions, y compris ses règles d'échantillonnage et de cotation, désignée par sa version.",
  ["AUD", "GIAS"], "AUD section 5 (AuditMethodology); GIAS Standard 9.3 (cited by number)."),
C("AuditPlanEntry", "audit", [DESC], "audit plan entry", "entrée du plan d'audit",
  "An entry of an audit plan for one candidate or planned engagement, with its priority rationale, its state (proposed, approved, deferred, cancelled or completed) and, when deferred or cancelled, the reason and who authorised it.",
  "Entrée d'un plan d'audit pour une mission envisagée ou prévue, avec la justification de sa priorité, son état (proposée, approuvée, reportée, annulée ou réalisée) et, en cas de report ou d'annulation, le motif et l'auteur de l'autorisation.",
  ["AUD", "GIAS"], "AUD sections 5 and 7; needed by AUD CQ-09 (changes between plan versions and who authorised deferrals)."),
C("AuditWorkpaper", "audit", [DESC], "audit workpaper", "feuille de travail d'audit",
  "A record prepared by an auditor that documents work performed, evidence examined and conclusions reached in an engagement, with who prepared it and who reviewed it. CRGO holds its metadata, not its content.",
  "Document établi par un auditeur qui consigne les travaux effectués, les preuves examinées et les conclusions tirées dans une mission, avec son auteur et son réviseur. CRGO en conserve les métadonnées, et non le contenu.",
  ["AUD", "GIAS", "ITAF"], "AUD sections 5 and 9 (self-review check); GIAS Standard 14.6 (Engagement Documentation); ITAF 1204 (Performance and Supervision); cited by number.", [("working paper", "en"), ("dossier de travail", "fr")]),
C("AuditObservation", "audit", [DESC], "audit observation", "observation d'audit",
  "A preliminary record of a condition noted during an engagement that has not yet been validated against criteria and evidence. It is not a finding and carries no audit conclusion.",
  "Enregistrement préliminaire d'une situation relevée pendant une mission, qui n'a pas encore été validée au regard des critères et des preuves. Ce n'est pas une constatation et elle ne porte aucune conclusion d'audit.",
  ["AUD", "PH0"], "Decision D8: disjoint from audit finding; a validated observation is linked to the finding it became."),
C("AuditQualityReview", "audit", [PLANNED_ACT], "audit quality review", "revue de qualité de l'audit",
  "A planned act in which the work of an engagement or of the audit function is evaluated against its methodology and the standards it follows, by a supervisor, an internal quality assessor or an external assessor.",
  "Acte planifié par lequel les travaux d'une mission ou de la fonction d'audit sont évalués au regard de sa méthodologie et des normes qu'elle suit, par un superviseur, un évaluateur interne de la qualité ou un évaluateur externe.",
  ["AUD", "GIAS"], "AUD section 5; GIAS Standards 8.3-8.4, 12.1 and 12.3 (cited by number)."),
# ---------------------------------------------------------------- mapping
C("MappingAssertion", "mapping", [DESC], "mapping assertion", "assertion de correspondance",
  "A directional statement, subject to review, that a source requirement corresponds to a target requirement in a stated way (exact, full or partial coverage, broader, narrower, related or conflicting), with the editions mapped, the rationale, the confidence, the reviewer and its review state. A mapping is not evidence of compliance.",
  "Énoncé orienté, soumis à une revue, selon lequel une exigence source correspond à une exigence cible d'une façon précisée (exacte, couverture totale ou partielle, plus large, plus étroite, liée ou contradictoire), avec les éditions mises en correspondance, la justification, le degré de confiance, le réviseur et l'état de la revue. Une correspondance ne prouve pas la conformité.",
  ["POL", "CMP", "PH0"], "Improvement I1; decision D6 (organisation crosswalks and newly reviewed mappings; approved direct mappings are not reified)."),
]

# ======================================================================================== value sets
VALUE_SETS_PCA = [
("NormativeModality", "policy", "normative modality", "modalité normative",
 "How binding a policy statement is.", "Degré de contrainte d'un énoncé de politique.", ["POL"], [
  ("ModalityMust", "must", "doit", "The statement is mandatory (must, shall).", "L'énoncé est obligatoire (doit)."),
  ("ModalityMustNot", "must not", "ne doit pas", "The statement prohibits something.", "L'énoncé interdit quelque chose."),
  ("ModalityShould", "should", "devrait", "The statement is recommended; departing from it needs a recorded reason.", "L'énoncé est recommandé; s'en écarter exige un motif consigné."),
  ("ModalityMay", "may", "peut", "The statement permits something without requiring it.", "L'énoncé permet quelque chose sans l'exiger.")]),
("DirectiveLifecycleState", "policy", "directive lifecycle state", "état du cycle de vie d'une directive",
 "The state of a directive version in the organisation's document lifecycle. Not the governance status of a CRGO term.",
 "État d'une version de directive dans le cycle de vie documentaire de l'organisation. Ce n'est pas le statut de gouvernance d'un terme de CRGO.", ["POL", "PH0"], [
  ("LifeDraft", "draft (directive)", "ébauche (directive)", "Being written; not binding.", "En cours de rédaction; non contraignante."),
  ("LifeUnderReview", "under review (directive)", "en revue (directive)", "Submitted for review or approval; not binding.", "Soumise à la revue ou à l'approbation; non contraignante."),
  ("LifeApproved", "approved (directive)", "approuvée (directive)", "Approved by the competent authority; not yet in effect.", "Approuvée par l'autorité compétente; pas encore en vigueur."),
  ("LifePublished", "published (directive)", "publiée (directive)", "Communicated and in effect.", "Communiquée et en vigueur."),
  ("LifeRetired", "retired (directive)", "retirée (directive)", "No longer in effect and not replaced.", "N'est plus en vigueur et n'est pas remplacée."),
  ("LifeSuperseded", "superseded (directive)", "remplacée (directive)", "No longer in effect; replaced by a later version.", "N'est plus en vigueur; remplacée par une version ultérieure.")]),
("ReviewTrigger", "policy", "review trigger", "déclencheur de revue",
 "What caused a directive review.", "Ce qui a provoqué une revue de directive.", ["POL", "CSFPO"], [
  ("RevTrigScheduled", "scheduled review", "revue planifiée", "The review interval has elapsed.", "L'intervalle de revue est écoulé."),
  ("RevTrigRegulatory", "regulatory change (trigger)", "changement réglementaire (déclencheur)", "A legal or regulatory change affects the directive.", "Un changement juridique ou réglementaire touche la directive."),
  ("RevTrigIncident", "incident (trigger)", "incident (déclencheur)", "An incident revealed that the directive is inadequate.", "Un incident a révélé que la directive est inadéquate."),
  ("RevTrigFinding", "audit or assessment finding (trigger)", "constatation d'audit ou d'évaluation (déclencheur)", "A finding or nonconformity concerns the directive.", "Une constatation ou une non-conformité porte sur la directive."),
  ("RevTrigRisk", "risk change (trigger)", "changement du risque (déclencheur)", "A change in assessed risk or risk appetite.", "Un changement du risque évalué ou de l'appétence au risque."),
  ("RevTrigOrganisation", "organisational change (trigger)", "changement organisationnel (déclencheur)", "A change in structure, mandate, activities or roles.", "Un changement de structure, de mandat, d'activités ou de rôles."),
  ("RevTrigTechnology", "technology change (trigger)", "changement technologique (déclencheur)", "A change in systems, services or technology.", "Un changement de systèmes, de services ou de technologie.")]),
("LegalReviewState", "compliance", "legal review state", "état de la revue juridique",
 "How far a requirement interpretation has been reviewed by legal counsel.", "Degré de revue d'une interprétation d'exigence par un conseiller juridique.", ["CMP"], [
  ("LegalNotReviewed", "not legally reviewed", "non revue sur le plan juridique", "No legal review yet; the interpretation is provisional.", "Aucune revue juridique; l'interprétation est provisoire."),
  ("LegalUnderReview", "legal review in progress", "revue juridique en cours", "Submitted to counsel.", "Soumise au conseiller juridique."),
  ("LegalReviewed", "legally reviewed", "validée par le conseiller juridique", "Reviewed and accepted by counsel for the stated situation.", "Revue et acceptée par le conseiller juridique pour la situation précisée.")]),
("SubmissionState", "compliance", "submission state", "état de la transmission",
 "The state of a regulatory submission.", "État d'une transmission réglementaire.", ["CMP"], [
  ("SubDraft", "submission in preparation", "transmission en préparation", "Being prepared; not sent.", "En préparation; non transmise."),
  ("SubSubmitted", "submitted", "transmise", "Sent to the authority; no acknowledgement yet.", "Transmise à l'autorité; pas encore d'accusé de réception."),
  ("SubAcknowledged", "acknowledged by the authority", "reçue par l'autorité", "The authority has acknowledged receipt.", "L'autorité en a accusé réception."),
  ("SubRejected", "rejected by the authority", "refusée par l'autorité", "The authority has refused or returned it.", "L'autorité l'a refusée ou renvoyée.")]),
("DeadlineTriggerKind", "compliance", "deadline trigger kind", "type de déclenchement d'échéance",
 "How a compliance deadline is set.", "Façon dont une échéance de conformité est fixée.", ["CMP"], [
  ("DeadlineCalendar", "calendar deadline", "échéance calendaire", "A fixed date or a recurring date, such as an annual filing.", "Une date fixe ou récurrente, comme un dépôt annuel."),
  ("DeadlineEvent", "event-triggered deadline", "échéance déclenchée par un événement", "A period counted from an event, such as becoming aware of a breach.", "Un délai compté à partir d'un événement, comme la prise de connaissance d'une atteinte.")]),
("RootCauseCategory", "compliance", "root-cause category", "catégorie de cause fondamentale",
 "A broad category of the cause of a finding or nonconformity, used to group recurring causes. CRGO's own scale.",
 "Grande catégorie de la cause d'une constatation ou d'une non-conformité, servant à regrouper les causes récurrentes. Échelle propre à CRGO.", ["AUD", "CMP", "PH0"], [
  ("RootPeople", "people (cause)", "personnes (cause)", "Awareness, skills, workload or behaviour.", "Sensibilisation, compétences, charge de travail ou comportement."),
  ("RootProcess", "process (cause)", "processus (cause)", "A missing, unclear or unfollowed process.", "Un processus absent, imprécis ou non suivi."),
  ("RootTechnology", "technology (cause)", "technologie (cause)", "A tool, system or configuration that does not support the control.", "Un outil, un système ou une configuration qui ne soutient pas la mesure."),
  ("RootGovernance", "governance (cause)", "gouvernance (cause)", "Unclear accountability, oversight or direction.", "Responsabilité, surveillance ou orientation imprécises."),
  ("RootThirdParty", "third party (cause)", "tiers (cause)", "A supplier or other external party did not perform as required.", "Un fournisseur ou une autre partie externe n'a pas agi comme exigé."),
  ("RootDesign", "control design (cause)", "conception de la mesure (cause)", "The control would not meet its objective even if operated as designed.", "La mesure n'atteindrait pas son objectif même si elle fonctionnait comme prévu."),
  ("RootResourcing", "resourcing (cause)", "ressources (cause)", "Insufficient budget, staff or time.", "Budget, personnel ou temps insuffisants.")]),
("EngagementType", "audit", "engagement type", "type de mission",
 "The kind of an audit engagement: its nature (assurance or advisory) and, where relevant, its focus (compliance or follow-up). An engagement may have one nature and one focus.", "Type d'une mission d'audit : sa nature (assurance ou conseil) et, le cas échéant, son objet (conformité ou suivi). Une mission peut avoir une nature et un objet.", ["AUD", "GIAS"], [
  ("EngAssurance", "assurance engagement", "mission d'assurance", "Gives an opinion or conclusion on governance, risk management or control.", "Donne une opinion ou une conclusion sur la gouvernance, la gestion des risques ou le contrôle."),
  ("EngAdvisory", "advisory engagement", "mission de conseil", "Gives advice at management's request; gives no assurance.", "Donne des conseils à la demande de la direction; ne donne aucune assurance."),
  ("EngCompliance", "compliance audit", "audit de conformité", "Checks conformity with stated obligations or requirements.", "Vérifie la conformité à des obligations ou exigences précisées."),
  ("EngFollowUp", "follow-up engagement", "mission de suivi", "Checks the status and effectiveness of earlier corrective actions.", "Vérifie l'état et l'efficacité d'actions correctives antérieures.")]),
("EngagementState", "audit", "engagement state", "état de la mission",
 "The recorded stage of an audit engagement.", "Étape consignée d'une mission d'audit.", ["AUD"], [
  ("EngStatePlanning", "engagement planning", "planification de la mission", "Scope, objectives and programme are being set.", "Le périmètre, les objectifs et le programme sont en cours d'établissement."),
  ("EngStateFieldwork", "fieldwork", "travaux sur le terrain", "Procedures are being performed.", "Les procédures sont en cours d'exécution."),
  ("EngStateReporting", "engagement reporting", "communication des résultats", "Findings and conclusions are being communicated.", "Les constatations et conclusions sont en cours de communication."),
  ("EngStateClosed", "engagement closed", "mission close", "The report is issued and the file is closed.", "Le rapport est émis et le dossier est clos."),
  ("EngStateCancelled", "engagement cancelled", "mission annulée", "Stopped before completion.", "Arrêtée avant d'être menée à terme.")]),
("PlanEntryState", "audit", "plan entry state", "état de l'entrée du plan",
 "The state of an audit plan entry.", "État d'une entrée du plan d'audit.", ["AUD"], [
  ("EntryProposed", "proposed (plan entry)", "proposée (entrée du plan)", "Candidate engagement, not yet approved.", "Mission envisagée, pas encore approuvée."),
  ("EntryApproved", "approved (plan entry)", "approuvée (entrée du plan)", "Approved as part of the plan.", "Approuvée dans le cadre du plan."),
  ("EntryDeferred", "deferred (plan entry)", "reportée (entrée du plan)", "Moved to a later period, with a recorded reason and authoriser.", "Reportée à une période ultérieure, avec un motif et un auteur consignés."),
  ("EntryCancelled", "cancelled (plan entry)", "annulée (entrée du plan)", "Removed from the plan, with a recorded reason and authoriser.", "Retirée du plan, avec un motif et un auteur consignés."),
  ("EntryCompleted", "completed (plan entry)", "réalisée (entrée du plan)", "The engagement was carried out.", "La mission a été réalisée.")]),
("QualityReviewKind", "audit", "quality review kind", "type de revue de qualité",
 "The kind of an audit quality review.", "Type d'une revue de qualité de l'audit.", ["AUD", "GIAS"], [
  ("QRSupervisory", "supervisory review", "revue de supervision", "Review of engagement work by its supervisor.", "Revue des travaux d'une mission par son superviseur."),
  ("QRInternal", "internal quality assessment", "évaluation interne de la qualité", "Periodic self-assessment of the audit function.", "Autoévaluation périodique de la fonction d'audit."),
  ("QRExternal", "external quality assessment", "évaluation externe de la qualité", "Assessment of the audit function by a qualified independent assessor.", "Évaluation de la fonction d'audit par un évaluateur indépendant qualifié.")]),
("MappingType", "mapping", "mapping type", "type de correspondance",
 "How the source of a mapping assertion corresponds to its target.", "Façon dont la source d'une assertion de correspondance correspond à sa cible.", ["CMP", "POL"], [
  ("MapExact", "exact mapping", "correspondance exacte", "Source and target say the same thing.", "La source et la cible disent la même chose."),
  ("MapFullCoverage", "full coverage", "couverture totale", "Meeting the source meets all of the target.", "Respecter la source permet de respecter toute la cible."),
  ("MapPartialCoverage", "partial coverage", "couverture partielle", "Meeting the source meets only part of the target.", "Respecter la source ne permet de respecter qu'une partie de la cible."),
  ("MapBroader", "broader mapping", "correspondance plus large", "The source is broader than the target.", "La source est plus large que la cible."),
  ("MapNarrower", "narrower mapping", "correspondance plus étroite", "The source is narrower than the target.", "La source est plus étroite que la cible."),
  ("MapRelated", "related mapping", "correspondance liée", "Source and target concern the same subject without coverage.", "La source et la cible portent sur le même sujet sans couverture."),
  ("MapConflicting", "conflicting mapping", "correspondance contradictoire", "Meeting the source makes the target harder or impossible to meet.", "Respecter la source rend la cible plus difficile ou impossible à respecter.")]),
("ReviewState", "mapping", "review state", "état de la revue",
 "The review state of an organisation record such as a mapping assertion or a requirement interpretation. Not the governance status of a CRGO term.",
 "État de la revue d'un enregistrement d'une organisation, comme une assertion de correspondance ou une interprétation d'exigence. Ce n'est pas le statut de gouvernance d'un terme de CRGO.", ["CMP"], [
  ("RevDraft", "draft (record)", "ébauche (enregistrement)", "Written; not yet submitted for review.", "Rédigé; pas encore soumis à la revue."),
  ("RevUnderReview", "under review (record)", "en revue (enregistrement)", "Submitted for review.", "Soumis à la revue."),
  ("RevApproved", "approved (record)", "approuvé (enregistrement)", "Approved by the reviewer.", "Approuvé par le réviseur."),
  ("RevRejected", "rejected (record)", "rejeté (enregistrement)", "Rejected by the reviewer.", "Rejeté par le réviseur."),
  ("RevWithdrawn", "withdrawn (record)", "retiré (enregistrement)", "Withdrawn by its author or no longer valid.", "Retiré par son auteur ou n'étant plus valide.")]),
]

# Members added to value sets approved earlier: (value set key, module of the new members, sources, members).
EXTENSIONS_PCA = [
("InstrumentKind", "grc", ["CMP"], [
  ("KindContract", "contract", "contrat", "An agreement that binds the organisation to obligations towards another party, such as a customer or a supplier.", "Entente qui lie l'organisation à des obligations envers une autre partie, comme un client ou un fournisseur."),
  ("KindDirective", "directive (to be transposed)", "directive (à transposer)", "An instrument that binds states to a result and is given effect through national law, such as a European Union directive.", "Instrument qui oblige des États quant au résultat et qui produit ses effets par le droit national, comme une directive de l'Union européenne.")]),
("SufficiencyConclusion", "assurance", ["CMP"], [
  ("SuffLimited", "sufficient with limitations", "suffisantes avec limites", "The evidence supports a conclusion only with stated limitations.", "Les preuves permettent de conclure seulement sous réserve de limites précisées."),
  ("SuffUnavailable", "unavailable", "non disponibles", "The evidence needed could not be obtained.", "Les preuves nécessaires n'ont pu être obtenues.")]),
("ConditionKind", "grc", ["POL", "PH0"], [
  ("CondRole", "role condition", "condition de rôle", "Whether a person or unit holds a stated role, for a policy statement that applies to that role.", "Si une personne ou une unité exerce un rôle donné, pour un énoncé de politique qui s'applique à ce rôle."),
  ("CondAssetCategory", "asset-category condition", "condition de catégorie d'actifs", "Whether an asset belongs to a stated category or tier, for a policy statement that applies to it.", "Si un actif appartient à une catégorie ou à un niveau donné, pour un énoncé de politique qui s'y applique.")]),
]

INDIVIDUALS_PCA = []

# ======================================================================================== object properties
OBJECT_PROPERTIES_PCA = [
# policy
OP("versionOfDirective", "policy", "version of directive", "version de la directive", "Relates a directive version to the policy, technical standard, procedure, guideline, charter or methodology it is a version of.", "Relie une version de directive à la politique, la norme technique, la procédure, la ligne directrice, la charte ou la méthodologie dont elle est une version.", "DirectiveVersion", None, ["POL"], "POL hasVersion, inverted so that the version points to its directive.", ["functional"]),
OP("statementInVersion", "policy", "statement in version", "énoncé de la version", "Relates a policy statement to the directive version it is part of.", "Relie un énoncé de politique à la version de directive dont il fait partie.", "PolicyStatement", "DirectiveVersion", ["POL"], "POL derivedFromVersion: a statement belongs to one exact version.", ["functional"]),
OP("clauseOf", "policy", "clause of", "article de", "Relates a policy clause to the directive version it is part of.", "Relie un article de politique à la version de directive dont il fait partie.", "PolicyClause", "DirectiveVersion", ["POL"], "", ["functional"]),
OP("inClause", "policy", "in clause", "dans l'article", "Relates a policy statement to the clause where it appears.", "Relie un énoncé de politique à l'article où il figure.", "PolicyStatement", "PolicyClause", ["POL"], "", ["functional"]),
OP("inPolicyFamily", "policy", "in policy family", "dans la famille de politiques", "Relates a directive to a policy family it belongs to.", "Relie une directive à une famille de politiques dont elle fait partie.", None, "PolicyFamily", ["POL"]),
OP("hasNormativeModality", "policy", "has normative modality", "a pour modalité normative", "Gives how binding a policy statement is.", "Indique le degré de contrainte d'un énoncé de politique.", "PolicyStatement", "NormativeModality", ["POL"], "", ["functional"]),
OP("hasLifecycleState", "policy", "has lifecycle state", "a pour état de cycle de vie", "Gives the lifecycle state of a directive version, as last recorded.", "Indique l'état du cycle de vie d'une version de directive, selon le dernier enregistrement.", "DirectiveVersion", "DirectiveLifecycleState", ["POL"], "", ["functional"]),
OP("statementImplementedBy", "policy", "statement implemented by", "énoncé appliqué par", "Relates a policy statement to a control measure the organisation relies on to meet it. Implementation is not evidence that the measure is effective.", "Relie un énoncé de politique à une mesure appliquée sur laquelle l'organisation s'appuie pour le respecter. L'application ne prouve pas que la mesure est efficace.", "PolicyStatement", "ControlMeasure", ["POL"], "Conflict C7: separate from 'implemented by procedure'."),
OP("intendedToMitigate", "policy", "intended to mitigate", "vise à atténuer", "Relates a policy statement to a risk scenario it is meant to reduce. States intent only; it does not say that the risk is reduced.", "Relie un énoncé de politique à un scénario de risque qu'il vise à réduire. N'indique que l'intention; il n'affirme pas que le risque est réduit.", "PolicyStatement", "RiskScenario", ["POL"], "Conflict C6: deliberately not a sub-property of 'mitigated by'."),
OP("appliesToScope", "policy", "applies to scope", "s'applique au périmètre", "Relates a policy statement, guideline or directive to an asset, process, role, organisational unit or jurisdiction it explicitly applies to.", "Relie un énoncé de politique, une ligne directrice ou une directive à un actif, un processus, un rôle, une unité organisationnelle ou une juridiction auquel il s'applique explicitement.", None, None, ["POL"], "POL scopedToAsset generalised. Conditional applicability goes through applicability conditions."),
OP("requiresTraining", "policy", "requires training", "exige la formation", "Relates a policy statement to a training requirement for those it applies to.", "Relie un énoncé de politique à une exigence de formation pour les personnes visées.", "PolicyStatement", "TrainingRequirement", ["POL"]),
OP("authorisedByRiskAcceptance", "policy", "authorised by risk acceptance", "autorisée par l'acceptation du risque", "Relates a policy exception to the risk acceptance decision that accepts the risk it leaves. A policy exception does not imply a risk acceptance; the link is stated when one was made.", "Relie une dérogation à la décision d'acceptation du risque qui accepte le risque qu'elle laisse subsister. Une dérogation n'implique pas une acceptation du risque; le lien est indiqué lorsqu'il y en a une.", "PolicyException", "RiskAcceptance", ["POL"], "POL section 7 (no implied risk acceptance)."),
OP("reviewOf", "policy", "review of", "revue de", "Relates a directive review to the directive, directive version or policy statement reviewed.", "Relie une revue de directive à la directive, la version de directive ou l'énoncé de politique revu.", "DirectiveReview", None, ["POL"]),
OP("hasReviewTrigger", "policy", "has review trigger", "a pour déclencheur de revue", "Gives what caused a directive review.", "Indique ce qui a provoqué une revue de directive.", "DirectiveReview", "ReviewTrigger", ["POL"]),
OP("reviewTriggeredBy", "policy", "review triggered by", "revue déclenchée par", "Relates a directive review to the regulatory change, incident, finding or other record that caused it.", "Relie une revue de directive au changement réglementaire, à l'incident, à la constatation ou à tout autre enregistrement qui l'a provoquée.", "DirectiveReview", None, ["POL"], "POL raisedBy (PolicyChangeEvent)."),
OP("attestedBy", "policy", "attested by", "attestée par", "Relates an attestation to the agent who made it.", "Relie une attestation à l'agent qui l'a faite.", "Attestation", None, ["POL", "CMP"], "Not functional: an attestation may have joint signatories."),
OP("attestationAbout", "policy", "attestation about", "attestation portant sur", "Relates an attestation to what it declares about, such as an exact policy version or a set of obligations.", "Relie une attestation à ce sur quoi porte la déclaration, comme une version précise de politique ou un ensemble d'obligations.", "Attestation", None, ["POL", "CMP"]),
# compliance
OP("programmeCovers", "compliance", "programme covers", "programme visant", "Relates a compliance programme to an obligation, legal instrument, framework adoption or commitment within its scope.", "Relie un programme de conformité à une obligation, un instrument juridique, une adoption de référentiel ou un engagement compris dans son périmètre.", "ComplianceProgramme", None, ["CMP", "I37301"]),
OP("objectiveOfProgramme", "compliance", "objective of programme", "objectif du programme", "Relates a compliance objective to the compliance programme that sets it.", "Relie un objectif de conformité au programme de conformité qui le fixe.", "ComplianceObjective", "ComplianceProgramme", ["CMP"], "", ["functional"]),
OP("interpretationOf", "compliance", "interpretation of", "interprétation de", "Relates a requirement interpretation to the obligation, provision or requirement it interprets.", "Relie une interprétation d'exigence à l'obligation, la disposition ou l'exigence qu'elle interprète.", "RequirementInterpretation", None, ["CMP"], "Not functional: one interpretation may cover several provisions read together."),
OP("hasLegalReviewState", "compliance", "has legal review state", "a pour état de revue juridique", "Gives how far a requirement interpretation has been reviewed by counsel.", "Indique le degré de revue d'une interprétation d'exigence par un conseiller juridique.", "RequirementInterpretation", "LegalReviewState", ["CMP"], "", ["functional"]),
OP("issuedByAuthority", "compliance", "issued by authority", "émis par l'autorité", "Relates a legal instrument, guidance or exemption to the regulatory authority that issued it.", "Relie un instrument juridique, une orientation ou une dispense à l'autorité de réglementation qui l'a émis.", None, "RegulatoryAuthority", ["CMP"]),
OP("enforcedBy", "compliance", "enforced by", "dont l'application relève de", "Relates a legal instrument or provision to a regulatory authority that supervises or enforces it.", "Relie un instrument juridique ou une disposition à une autorité de réglementation qui en surveille ou en assure l'application.", None, "RegulatoryAuthority", ["CMP"]),
OP("adoptsFramework", "compliance", "adopts framework", "adopte le référentiel", "Relates a framework adoption to the framework, or the part of a framework, adopted.", "Relie une adoption de référentiel au référentiel, ou à la partie de référentiel, adopté.", "FrameworkAdoption", None, ["CMP"]),
OP("determinationIn", "compliance", "determination in", "constat effectué dans", "Relates a compliance determination to the compliance assessment campaign that produced it.", "Relie un constat de conformité à la campagne d'évaluation de la conformité qui l'a produit.", "ComplianceDetermination", "ComplianceAssessmentCampaign", ["CMP"], "", ["functional"]),
OP("provisionVersionOf", "compliance", "provision version of", "version de la disposition", "Relates a provision version to the provision whose wording it records.", "Relie une version de disposition à la disposition dont elle consigne le libellé.", "ProvisionVersion", None, ["CMP"], "", ["functional"]),
OP("inInstrumentVersion", "compliance", "in instrument version", "dans la version de l'instrument", "Relates a provision version to the instrument version that carries that wording.", "Relie une version de disposition à la version de l'instrument qui porte ce libellé.", "ProvisionVersion", "InstrumentVersion", ["CMP"]),
OP("evaluatesProvisionVersion", "compliance", "evaluates provision version", "évalue la version de la disposition", "Relates a compliance or applicability determination to the exact provision version it evaluated, when the wording has changed over time.", "Relie un constat de conformité ou d'applicabilité à la version précise de la disposition évaluée, lorsque le libellé a changé au fil du temps.", None, "ProvisionVersion", ["CMP"], "CMP evaluatesObligation (historical snapshot)."),
OP("deadlineFor", "compliance", "deadline for", "échéance de", "Relates a compliance deadline to the obligation or provision that sets it.", "Relie une échéance de conformité à l'obligation ou à la disposition qui la fixe.", "ComplianceDeadline", None, ["CMP"]),
OP("hasDeadlineTriggerKind", "compliance", "has deadline trigger kind", "a pour type de déclenchement", "Gives whether a compliance deadline is a calendar date or counted from an event.", "Indique si une échéance de conformité est une date calendaire ou un délai compté à partir d'un événement.", "ComplianceDeadline", "DeadlineTriggerKind", ["CMP"], "", ["functional"]),
OP("deadlineTriggeredBy", "compliance", "deadline triggered by", "échéance déclenchée par", "Relates an event-triggered compliance deadline to the record of the triggering event, such as an incident confirmation.", "Relie une échéance déclenchée par un événement à l'enregistrement de cet événement, comme une confirmation d'incident.", "ComplianceDeadline", None, ["CMP"]),
OP("submissionTo", "compliance", "submission to", "transmise à", "Relates a regulatory submission to the authority it was sent to.", "Relie une transmission réglementaire à l'autorité à laquelle elle a été envoyée.", "RegulatorySubmission", "RegulatoryAuthority", ["CMP"], "", ["functional"]),
OP("submissionUnder", "compliance", "submission under", "transmise en vertu de", "Relates a regulatory submission to the obligation or provision it is made under.", "Relie une transmission réglementaire à l'obligation ou à la disposition en vertu de laquelle elle est faite.", "RegulatorySubmission", None, ["CMP"]),
OP("answersDeadline", "compliance", "answers deadline", "répond à l'échéance", "Relates a regulatory submission to the compliance deadline it answers. Whether it was on time is computed from the dates, not stated.", "Relie une transmission réglementaire à l'échéance de conformité à laquelle elle répond. Le respect du délai se calcule à partir des dates; il n'est pas affirmé.", "RegulatorySubmission", "ComplianceDeadline", ["CMP"]),
OP("hasSubmissionState", "compliance", "has submission state", "a pour état de transmission", "Gives the state of a regulatory submission, as last recorded.", "Indique l'état d'une transmission réglementaire, selon le dernier enregistrement.", "RegulatorySubmission", "SubmissionState", ["CMP"], "", ["functional"]),
OP("receiptEvidence", "compliance", "receipt evidence", "preuve de réception", "Relates a regulatory submission to the evidence item recording its submission or the authority's acknowledgement.", "Relie une transmission réglementaire à l'élément de preuve qui en consigne l'envoi ou l'accusé de réception de l'autorité.", "RegulatorySubmission", "EvidenceItem", ["CMP"]),
OP("exemptionFrom", "compliance", "exemption from", "dispense de", "Relates a regulatory exemption to the obligation or provision it relieves the organisation from.", "Relie une dispense réglementaire à l'obligation ou à la disposition dont elle dispense l'organisation.", "RegulatoryExemption", None, ["CMP"]),
OP("grantedBy", "compliance", "granted by", "accordée par", "Relates a regulatory exemption to the authority that granted it.", "Relie une dispense réglementaire à l'autorité qui l'a accordée.", "RegulatoryExemption", "RegulatoryAuthority", ["CMP"], "Sub-property of 'issued by authority'.", ["functional"], "issuedByAuthority"),
OP("obligationAtStakeIn", "compliance", "obligation at stake in", "obligation en jeu dans", "Relates an obligation or provision to a risk scenario in which failing to meet it is part of the consequence.", "Relie une obligation ou une disposition à un scénario de risque dont le non-respect fait partie des conséquences.", None, "RiskScenario", ["CMP"], "CMP ComplianceRiskLink as a property; no link class needed."),
OP("hasRootCauseCategory", "compliance", "has root-cause category", "a pour catégorie de cause", "Gives a broad category of the cause of a finding or nonconformity.", "Indique une grande catégorie de la cause d'une constatation ou d'une non-conformité.", None, "RootCauseCategory", ["AUD", "CMP"], "Improvement I5; AUD CQ-10 and CMP CQ-9."),
# audit
OP("charterOf", "audit", "charter of", "charte de", "Relates an audit charter to the audit function it governs.", "Relie une charte d'audit à la fonction d'audit qu'elle régit.", "AuditCharter", "AuditFunction", ["AUD"], "", ["functional"]),
OP("entryInPlan", "audit", "entry in plan", "entrée du plan", "Relates an audit plan entry to the audit plan it belongs to.", "Relie une entrée du plan d'audit au plan d'audit dont elle fait partie.", "AuditPlanEntry", "AuditPlan", ["AUD"], "", ["functional"]),
OP("entryForEngagement", "audit", "entry for engagement", "entrée pour la mission", "Relates an audit plan entry to the engagement it plans.", "Relie une entrée du plan d'audit à la mission qu'elle prévoit.", "AuditPlanEntry", "AuditEngagement", ["AUD"], "", ["functional"]),
OP("entryForAuditableEntity", "audit", "entry for auditable entity", "entrée pour l'entité auditable", "Relates an audit plan entry to an auditable entity it covers.", "Relie une entrée du plan d'audit à une entité auditable qu'elle vise.", "AuditPlanEntry", "AuditableEntity", ["AUD"]),
OP("hasPlanEntryState", "audit", "has plan entry state", "a pour état d'entrée", "Gives the state of an audit plan entry.", "Indique l'état d'une entrée du plan d'audit.", "AuditPlanEntry", "PlanEntryState", ["AUD"], "", ["functional"]),
OP("entryInformedBy", "audit", "entry informed by", "entrée éclairée par", "Relates an audit plan entry to a risk assessment or risk scenario that informed its priority.", "Relie une entrée du plan d'audit à une appréciation du risque ou à un scénario de risque qui en a éclairé la priorité.", "AuditPlanEntry", None, ["AUD", "GIAS"], "AUD informedByRiskAssessment; GIAS Standard 9.4 (risk-based plan)."),
OP("hasEngagementType", "audit", "has engagement type", "a pour type de mission", "Gives the nature, and where relevant the focus, of an audit engagement.", "Indique la nature et, le cas échéant, l'objet d'une mission d'audit.", "AuditEngagement", "EngagementType", ["AUD"], "Not functional: one nature (assurance or advisory) and at most one focus (compliance or follow-up); checked by SHACL."),
OP("hasEngagementState", "audit", "has engagement state", "a pour état de mission", "Gives the recorded stage of an audit engagement.", "Indique l'étape consignée d'une mission d'audit.", "AuditEngagement", "EngagementState", ["AUD"], "", ["functional"]),
OP("followsMethodology", "audit", "follows methodology", "suit la méthodologie", "Relates an audit engagement or plan to the audit methodology version it follows.", "Relie une mission ou un plan d'audit à la version de méthodologie d'audit qu'il suit.", None, None, ["AUD"]),
OP("workpaperFor", "audit", "workpaper for", "feuille de travail de", "Relates an audit workpaper to the engagement, procedure or control assessment it documents.", "Relie une feuille de travail d'audit à la mission, la procédure ou l'évaluation de mesure qu'elle documente.", "AuditWorkpaper", None, ["AUD"]),
OP("preparedBy", "audit", "prepared by", "préparée par", "Relates an audit workpaper or report to an agent who prepared it.", "Relie une feuille de travail ou un rapport d'audit à un agent qui l'a préparé.", None, None, ["AUD"]),
OP("validatedAs", "audit", "validated as", "validée en tant que", "Relates an audit observation to the audit finding it became after validation.", "Relie une observation d'audit à la constatation d'audit qu'elle est devenue après validation.", "AuditObservation", "AuditFinding", ["AUD"], "", ["functional"]),
OP("qualityReviewOf", "audit", "quality review of", "revue de qualité de", "Relates an audit quality review to the engagement, workpaper or audit function reviewed.", "Relie une revue de qualité de l'audit à la mission, à la feuille de travail ou à la fonction d'audit revue.", "AuditQualityReview", None, ["AUD"]),
OP("hasQualityReviewKind", "audit", "has quality review kind", "a pour type de revue de qualité", "Gives the kind of an audit quality review.", "Indique le type d'une revue de qualité de l'audit.", "AuditQualityReview", "QualityReviewKind", ["AUD"], "", ["functional"]),
# mapping
OP("mappingSource", "mapping", "mapping source", "source de la correspondance", "Relates a mapping assertion to its source requirement, such as a policy statement or a control.", "Relie une assertion de correspondance à son exigence source, comme un énoncé de politique ou une mesure.", "MappingAssertion", None, ["POL", "CMP"], "", ["functional"]),
OP("mappingTarget", "mapping", "mapping target", "cible de la correspondance", "Relates a mapping assertion to its target requirement, such as an obligation or a framework requirement.", "Relie une assertion de correspondance à son exigence cible, comme une obligation ou une exigence de référentiel.", "MappingAssertion", None, ["POL", "CMP"], "", ["functional"]),
OP("hasMappingType", "mapping", "has mapping type", "a pour type de correspondance", "Gives how the source of a mapping assertion corresponds to its target.", "Indique comment la source d'une assertion de correspondance correspond à sa cible.", "MappingAssertion", "MappingType", ["POL", "CMP"], "", ["functional"]),
OP("mappedEdition", "mapping", "mapped edition", "édition mise en correspondance", "Relates a mapping assertion to the source record or version of each side that was mapped, so that a later edition does not silently change it.", "Relie une assertion de correspondance à la notice de source ou à la version de chaque côté mise en correspondance, pour qu'une édition ultérieure ne la modifie pas à l'insu de tous.", "MappingAssertion", None, ["POL", "CMP"], "POL section 10 (edition changes must not silently mutate historical claims)."),
OP("hasReviewState", "mapping", "has review state", "a pour état de revue", "Gives the review state of an organisation record such as a mapping assertion. A requirement interpretation also has a legal review state, which says whether counsel has reviewed it.", "Indique l'état de la revue d'un enregistrement d'une organisation, comme une assertion de correspondance. Une interprétation d'exigence a aussi un état de revue juridique, qui indique si un conseiller juridique l'a revue.", None, "ReviewState", ["CMP"], "", ["functional"]),
OP("reviewedBy", "mapping", "reviewed by", "revu par", "Relates a record, such as a mapping assertion, a requirement interpretation, an audit workpaper or a report, to an agent who reviewed it.", "Relie un enregistrement, comme une assertion de correspondance, une interprétation d'exigence, une feuille de travail ou un rapport d'audit, à un agent qui l'a revu.", None, None, ["POL", "CMP", "AUD"]),
]

# ======================================================================================== data properties
DATA_PROPERTIES_PCA = [
# policy
DP("statementText", "policy", "statement text", "texte de l'énoncé", "Gives the wording of an organisation's own policy statement. Never used for the text of a licensed standard.", "Indique le libellé d'un énoncé de politique de l'organisation. N'est jamais utilisé pour le texte d'une norme sous licence.", "PolicyStatement", None, ["POL"], "Conflict C5; rule R-d."),
DP("retiredOn", "policy", "retired on", "retirée le", "Gives when a directive version ceased to be in effect.", "Indique quand une version de directive a cessé d'être en vigueur.", "DirectiveVersion", "xsd:dateTime", ["POL"], "", True),
DP("reviewDueOn", "policy", "review due on", "revue due le", "Gives the date by which a directive or directive version must next be reviewed, as last recorded.", "Indique la date à laquelle une directive ou une version de directive doit faire l'objet de sa prochaine revue, selon le dernier enregistrement.", None, "xsd:dateTime", ["POL", "PL1"], "xsd:dateTime rather than xsd:date (conflict C4, ADR-006). Not functional in OWL, so that a moved date does not make data inconsistent; the latest value is selected by queries."),
DP("reviewIntervalMonths", "policy", "review interval (months)", "intervalle de revue (mois)", "Gives the number of months between scheduled reviews of a directive.", "Indique le nombre de mois entre les revues planifiées d'une directive.", None, "xsd:nonNegativeInteger", ["POL", "PL1"], "", True),
DP("attestedOn", "policy", "attested on", "attestée le", "Gives when an attestation was made.", "Indique quand une attestation a été faite.", "Attestation", "xsd:dateTime", ["POL", "CMP"], "", True),
DP("attestationScope", "policy", "attestation scope", "périmètre de l'attestation", "States the scope and period an attestation covers and what it is based on.", "Indique le périmètre et la période que couvre une attestation et ce sur quoi elle se fonde.", "Attestation", None, ["CMP"]),
# compliance
DP("isPrivileged", "compliance", "legally privileged", "protégé par le secret professionnel", "States that a record contains or summarises legally privileged advice and must not be passed to general reasoning, reporting or AI services.", "Indique qu'un enregistrement contient ou résume un avis protégé par le secret professionnel et ne doit pas être transmis à des services généraux de raisonnement, de rapport ou d'IA.", None, "xsd:boolean", ["CMP"], "CMP section 9.", True),
DP("legalBasis", "compliance", "legal basis", "fondement juridique", "States the legal basis on which a regulatory exemption is granted.", "Indique le fondement juridique sur lequel une dispense réglementaire est accordée.", "RegulatoryExemption", None, ["CMP"]),
DP("adoptionScope", "compliance", "adoption scope", "périmètre de l'adoption", "States which parts of a framework are adopted and for which entities, systems or services.", "Indique quelles parties d'un référentiel sont adoptées et pour quelles entités, quels systèmes ou quels services.", "FrameworkAdoption", None, ["CMP"]),
DP("provisionWording", "compliance", "provision wording", "libellé de la disposition", "Gives the wording of a provision version, only for texts CRGO may reproduce, such as legislation; otherwise only its citation.", "Indique le libellé d'une version de disposition, seulement pour les textes que CRGO peut reproduire, comme une loi; sinon seulement sa citation.", "ProvisionVersion", None, ["CMP"], "Rule R-d."),
DP("dueOffsetHours", "compliance", "due offset (hours)", "délai (heures)", "Gives the number of hours, counted from the triggering event, within which an event-triggered deadline falls.", "Indique le nombre d'heures, comptées à partir de l'événement déclencheur, dans lequel tombe une échéance déclenchée par un événement.", "ComplianceDeadline", "xsd:nonNegativeInteger", ["CMP"], "Integer hours rather than xsd:duration, which is outside the OWL 2 datatype map (conflict C4); hours cover the 72-hour notices.", True),
DP("deadlineComputation", "compliance", "deadline computation", "calcul de l'échéance", "States how a compliance deadline is computed, such as calendar or business days, time zone and the provision cited.", "Indique comment une échéance de conformité est calculée, comme en jours civils ou ouvrables, le fuseau horaire et la disposition citée.", "ComplianceDeadline", None, ["CMP"]),
DP("submittedOn", "compliance", "submitted on", "transmise le", "Gives when a regulatory submission was sent.", "Indique quand une transmission réglementaire a été envoyée.", "RegulatorySubmission", "xsd:dateTime", ["CMP"], "", True),
DP("receiptAcknowledgedOn", "compliance", "receipt acknowledged on", "réception confirmée le", "Gives when the authority acknowledged a regulatory submission.", "Indique quand l'autorité a accusé réception d'une transmission réglementaire.", "RegulatorySubmission", "xsd:dateTime", ["CMP"], "", True),
DP("ruleVersion", "compliance", "rule version", "version de la règle", "Gives the version of the applicability rules used by an applicability assessment, so that it can be reproduced.", "Indique la version des règles d'applicabilité utilisée par une évaluation de l'applicabilité, pour qu'elle puisse être reproduite.", None, "xsd:string", ["CMP"], "CMP section 8.", True),
DP("factRelied", "compliance", "fact relied on", "fait retenu", "States a fact about the organisation that an applicability assessment relied on.", "Indique un fait relatif à l'organisation sur lequel s'est appuyée une évaluation de l'applicabilité.", "ApplicabilityAssessment", None, ["CMP"], "CMP section 8."),
DP("missingFact", "compliance", "missing fact", "fait manquant", "States a fact that an applicability assessment needed but did not have.", "Indique un fait dont une évaluation de l'applicabilité avait besoin et dont elle ne disposait pas.", "ApplicabilityAssessment", None, ["CMP"], "CMP section 8."),
# audit
DP("priorityRationale", "audit", "priority rationale", "justification de la priorité", "States why an audit plan entry has its priority, such as the risks and mandatory requirements it addresses.", "Indique pourquoi une entrée du plan d'audit a sa priorité, comme les risques et les exigences obligatoires qu'elle vise.", "AuditPlanEntry", None, ["AUD"]),
DP("deferralReason", "audit", "deferral reason", "motif du report", "States why an audit plan entry was deferred or cancelled.", "Indique pourquoi une entrée du plan d'audit a été reportée ou annulée.", "AuditPlanEntry", None, ["AUD"]),
DP("estimatedEffortHours", "audit", "estimated effort (hours)", "effort estimé (heures)", "Gives the estimated effort of a planned engagement, in hours.", "Indique l'effort estimé d'une mission prévue, en heures.", "AuditPlanEntry", "xsd:nonNegativeInteger", ["AUD"], "", True),
DP("isMandatory", "audit", "mandatory engagement", "mission obligatoire", "States that an audit plan entry is required by law, regulation or the governing body, whatever its risk ranking.", "Indique qu'une entrée du plan d'audit est exigée par la loi, la réglementation ou l'organe de gouvernance, quel que soit son classement selon le risque.", "AuditPlanEntry", "xsd:boolean", ["AUD"], "", True),
DP("samplingSeed", "audit", "sampling seed", "germe d'échantillonnage", "Gives the seed or starting point used to select a random or systematic sample, so that the selection can be reproduced.", "Indique le germe ou le point de départ utilisé pour tirer un échantillon aléatoire ou systématique, pour que la sélection puisse être reproduite.", "SamplingPlan", "xsd:string", ["AUD"], "AUD section 7 (reproducibility).", True),
DP("reportAudience", "audit", "report audience", "destinataires du rapport", "States who an audit report is addressed to.", "Indique à qui s'adresse un rapport d'audit.", "AuditReport", None, ["AUD"]),
DP("preparedOn", "audit", "prepared on", "préparée le", "Gives when an audit workpaper was completed by its preparer.", "Indique quand une feuille de travail d'audit a été terminée par son auteur.", "AuditWorkpaper", "xsd:dateTime", ["AUD"], "", True),
# mapping
DP("mappingConfidence", "mapping", "mapping confidence", "confiance dans la correspondance", "Gives the reviewer's confidence in a mapping assertion, from 0 to 1.", "Indique la confiance du réviseur dans une assertion de correspondance, de 0 à 1.", "MappingAssertion", "xsd:decimal", ["POL", "CMP"], "", True),
DP("reviewedOn", "mapping", "reviewed on", "revu le", "Gives when a record was reviewed.", "Indique quand un enregistrement a été revu.", None, "xsd:dateTime", ["POL", "CMP", "AUD"], "Not functional: a record may be reviewed more than once."),
]

DISJOINT_PCA = [("Guideline", "PolicyStatement"), ("Attestation", "ComplianceDetermination"), ("Attestation", "AuditConclusion"),
                ("AuditObservation", "AuditFinding"), ("RegulatoryExemption", "PolicyException"), ("DirectiveVersion", "InstrumentVersion"),
                ("MappingAssertion", "ComplianceDetermination")]

# Decision D9: widenings of approved terms. Each entry replaces fields of an existing tuple (by key) and adds a change note.
MODIFY_PCA = {
    "versionLabel": dict(dom=None,
        den="Gives the version label of an instrument version, directive version or report as its issuer states it, such as a consolidation date, an edition or a revision number.",
        dfr="Indique le libellé de version d'une version d'instrument, d'une version de directive ou d'un rapport tel que l'énonce son émetteur, comme une date de mise à jour, une édition ou un numéro de révision.",
        note="0.10.0 (2026-10-12): domain removed (was instrument version) so that directive versions and audit report revisions can reuse it; asserting it on a directive version would otherwise have inferred an instrument version."),
    "AuditFinding": dict(alts=[],
        note="0.10.0 (decision D8, 2026-10-12): alternative label 'audit observation' removed; audit observation is now a separate class, disjoint from audit finding."),
    "PolicyStatement": dict(alts=[("policy requirement", "en"), ("exigence de politique", "fr")],
        note="0.10.0 (2026-10-12): alternative labels 'policy requirement' / 'exigence de politique' added (POL PolicyRequirement)."),
    "LegalInstrument": dict(
        den="A statute, regulation, regulatory guideline, directive to be transposed or binding contract taken as a whole, identified by its official citation or reference, with its jurisdiction and the dates of its publication, coming into force, application and consolidation. Its provisions are the concepts of the corresponding CRGO vocabulary or, for an organisation's contracts, its own clauses.",
        dfr="Loi, règlement, ligne directrice réglementaire, directive à transposer ou contrat contraignant pris dans son ensemble, identifié par sa citation officielle ou sa référence, avec sa juridiction et les dates de sa publication, de son entrée en vigueur, de sa prise d'effet et de sa mise à jour. Ses dispositions sont les concepts du vocabulaire CRGO correspondant ou, pour les contrats d'une organisation, leurs propres clauses.",
        note="0.10.0 (2026-10-12): definition widened to contracts and directives to be transposed, with the new instrument kinds."),
    "ComplianceDetermination": dict(
        den="A dated record, made by an identified assessor, of the extent to which a given organisation satisfies a legal provision or obligation, a contractual obligation or a requirement of a framework it has adopted, with the evidence relied on or an explicit statement of the missing evidence. A mapped control or framework requirement is not by itself evidence of compliance.",
        dfr="Enregistrement daté, établi par un évaluateur identifié, du degré auquel une organisation donnée satisfait à une disposition ou à une obligation légale, à une obligation contractuelle ou à une exigence d'un référentiel qu'elle a adopté, avec les preuves retenues ou un énoncé explicite des preuves manquantes. Un contrôle ou une exigence de référentiel mis en correspondance ne constitue pas à lui seul une preuve de conformité.",
        note="0.10.0 (2026-10-12): definition widened to contractual obligations and adopted framework requirements (improvement I4)."),
    "closesFinding": dict(rng=None,
        den="Relates a finding closure to the audit finding or nonconformity it closes.",
        dfr="Relie une clôture de constatation à la constatation d'audit ou à la non-conformité qu'elle clôt.",
        note="0.10.0 (decision D9, 2026-10-12): range widened from audit finding to audit finding or nonconformity; checked by SHACL."),
    "reopensFinding": dict(rng=None,
        den="Relates a finding reopening to the audit finding or nonconformity it reopens.",
        dfr="Relie une réouverture de constatation à la constatation d'audit ou à la non-conformité qu'elle rouvre.",
        note="0.10.0 (decision D9, 2026-10-12): range widened from audit finding to audit finding or nonconformity; checked by SHACL."),
    "ApplicabilityCondition": dict(
        den="A description of a condition under which a legal instrument, one of its provisions or a policy statement applies to an organisation or part of it, such as its territory, organisation type, sector, role in processing personal information, a threshold or, for a policy statement, a role or asset category, written as a CRGO paraphrase or the organisation's own wording, with its citation and a machine-readable test.",
        dfr="Description d'une condition à laquelle un instrument juridique, l'une de ses dispositions ou un énoncé de politique s'applique à une organisation ou à une partie de celle-ci, comme son territoire, son type d'organisation, son secteur, son rôle dans le traitement de renseignements personnels, un seuil ou, pour un énoncé de politique, un rôle ou une catégorie d'actifs, rédigée comme une paraphrase de CRGO ou dans les termes de l'organisation, avec sa citation et un test lisible par machine.",
        note="0.10.0 (decision D9, 2026-10-12): definition widened to policy statements."),
    "ApplicabilityAssessment": dict(
        den="A dated record (not the act of assessing) of whether a legal instrument, provision or policy statement applies to a given organisation or part of it, giving the state reached (applicable, not applicable, potentially applicable or unknown) and the conditions found met, not met or undetermined.",
        dfr="Enregistrement daté indiquant si un instrument juridique, une disposition ou un énoncé de politique s'applique à une organisation donnée ou à une partie de celle-ci, avec l'état retenu (applicable, non applicable, potentiellement applicable ou inconnu) et les conditions jugées remplies, non remplies ou indéterminées.",
        note="0.10.0 (decision D9, 2026-10-12): definition widened to policy statements."),
    "conditionOf": dict(
        den="Relates an applicability condition to the instrument, provision or policy statement whose application it governs.",
        dfr="Relie une condition d'applicabilité à l'instrument, à la disposition ou à l'énoncé de politique dont elle régit l'application.",
        note="0.10.0 (decision D9, 2026-10-12): definition widened to policy statements."),
    "applicabilityOf": dict(
        den="Relates an applicability assessment to the instrument, provision or policy statement assessed.",
        dfr="Relie une évaluation de l'applicabilité à l'instrument, à la disposition ou à l'énoncé de politique évalué.",
        note="0.10.0 (decision D9, 2026-10-12): definition widened to policy statements."),
}

# Changes to approved terms covered by decision D9 (approved 2026-10-12). The other entries of MODIFY_PCA stay proposed
# until the project owner approves them (approval key "changes/0.10.0").
D9_APPROVED = {"closesFinding", "ApplicabilityCondition", "ApplicabilityAssessment", "conditionOf", "applicabilityOf"}
