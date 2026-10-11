# -*- coding: utf-8 -*-
"""CRGO 0.9.0 additions (Sprint 1 of the v0.8 -> v1.0 specification). Five new modules; the four 0.8.0 modules are
unchanged (decision D2, 2026-10-11). Same tuple layouts as spec_core.py and spec_props.py.

  evidence  source records, observations, assumptions; aligned to PROV-O and OWL-Time (imports measure, PROV, Time)
  org       organisation profile for applicability: type, jurisdictions, processing activities, supplier role (imports core)
  vuln      published-vulnerability observations: EPSS observations, KEV data (imports evidence)
  grc       legal instruments, applicability, compliance determinations, control assessments (imports evidence, org)
  mapping   typed correspondence relations between vocabulary concepts, sub-properties of SKOS mapping relations (imports gov)

Design records: docs/adr/ADR-001 to ADR-006. Every term is proposed until the project owner approves it.
"""
SOURCES_09 = {
    "SPEC": "CRGO v0.8 to v1.0 Claude Implementation Specification (project owner, 2026-10-11), sections 3-13",
    "PROV": "W3C PROV-O: The PROV Ontology, W3C Recommendation 30 April 2013 (slice: imports/prov-slice.ttl)",
    "TIME": "W3C Time Ontology in OWL (OWL-Time), edition of 2025-08-27 (slice: imports/time-slice.ttl)",
    "GDPR": "Regulation (EU) 2016/679, Arts. 3, 4, 24, 28, 30 (OJ L 119, 4.5.2016)",
    "QCPRIV": "CQLR c. P-39.1 ss. 1, 3.1-3.8, 17, 18.3; CQLR c. A-2.1 s. 3; CQLR c. R-22.1 s. 4 (LégisQuébec, updated to 2026-08-12)",
    "PIPEDA": "PIPEDA ss. 4, 26(2)(b), Sch. 1 (S.C. 2000, c. 5, current to 2026-09-21)",
    "B13": "OSFI Guideline B-13, scope (federally regulated financial institutions), 2022-07-31",
    "EPSS": "FIRST, Exploit Prediction Scoring System: model documentation and data (first.org/epss)",
    "KEV": "CISA Known Exploited Vulnerabilities catalogue, schema fields dateAdded and knownRansomwareCampaignUse",
    "CTID": "MITRE CTID Mappings Explorer, mapping types (mitigates; exploitation technique, primary and secondary impact)",
    "OLIR": "NIST OLIR relationship types (subset of, intersects with, equal, superset of, not related to)",
    "STAGE0": "CRGO Stage 0 gap analysis (docs/baseline/gap_analysis.md, 2026-10-11)",
}

DESC = "cco:ont00000853"   # descriptive information content entity
DIRECTIVE = "cco:ont00000965"
PLANNED_ACT = "cco:ont00000228"
MEASUREMENT = "cco:ont00001163"
ORG = "cco:ont00001180"
AGENT = "cco:ont00001017"

# (key, module, parent(s), en, fr, def_en, def_fr, source keys, conf, rationale, altLabels)
CLASSES_09 = [
# ---- evidence
("SourceRecord", "evidence", [DESC, "prov:Entity"], "source record", "notice de source",
 "A description of a dataset, publication or legal text from which CRGO content was imported or derived, recording its issuer, official identifier, version, retrieval date, licence, what CRGO redistributes and the checksum of the file used.",
 "Description d'un jeu de données, d'une publication ou d'un texte juridique dont un contenu de CRGO est importé ou dérivé, indiquant son émetteur, son identifiant officiel, sa version, sa date d'obtention, sa licence, ce que CRGO en rediffuse et l'empreinte du fichier utilisé.",
 ["SPEC", "PROV", "STAGE0"], "H", "Specification section 7 (SourceRecord fields); one per row of docs/baseline/source_registry.csv.", []),
("Observation", "evidence", [MEASUREMENT, "prov:Entity"], "observation", "observation",
 "A dated record that a stated source reported a value or category for an entity at a stated time, such as the EPSS score of a vulnerability on a given day. An observation reports what a source said; it is not an estimate made for an assessment.",
 "Enregistrement daté indiquant qu'une source donnée a rapporté une valeur ou une catégorie pour une entité à un moment donné, comme le score EPSS d'une vulnérabilité un jour donné. Une observation rapporte ce qu'une source a dit; ce n'est pas une estimation faite pour une appréciation.",
 ["SPEC", "PROV"], "H", "Disjoint from estimate (specification rule 3: separate source facts from model estimates); negative fixture tests it.", []),
("Assumption", "evidence", [DESC], "assumption", "hypothèse",
 "A statement taken as true without verification for an estimate, an assessment or a decision, recorded so that the result can be reviewed when the statement turns out to be false or changes.",
 "Énoncé tenu pour vrai sans vérification aux fins d'une estimation, d'une appréciation ou d'une décision, consigné afin que le résultat puisse être revu si l'énoncé se révèle faux ou change.",
 ["SPEC"], "H", "Specification sections 6, 7 and 11 (assessments depend on assumptions). Alt label 'hypothesis' removed 2026-10-11 (project owner), to keep it apart from analytical hypothesis.", []),
# ---- vuln
("EPSSObservation", "vuln", ["Observation"], "EPSS observation", "observation EPSS",
 "An observation of the Exploit Prediction Scoring System score of a published vulnerability on a given day: FIRST's estimated probability that the vulnerability is exploited in the wild in the following 30 days, with its percentile among all scored vulnerabilities. It concerns the vulnerability in general, not its presence in any organisation, and it is not the likelihood of a risk scenario.",
 "Observation du score de l'Exploit Prediction Scoring System d'une vulnérabilité publiée un jour donné : la probabilité, estimée par FIRST, que la vulnérabilité soit exploitée dans les 30 jours suivants, avec son centile parmi toutes les vulnérabilités évaluées. Elle porte sur la vulnérabilité en général, non sur sa présence dans une organisation, et ce n'est pas la vraisemblance d'un scénario de risque.",
 ["EPSS", "SPEC"], "H", "Replaces the 0.8.0 EPSS likelihood estimates (decision D4); specification section 5 (do not conflate probability of exploitation with scenario likelihood).", []),
# ---- org
("ProcessingActivity", "org", ["BusinessProcess"], "processing activity", "activité de traitement",
 "A business process, or part of one, in which an organisation collects, uses, discloses, keeps or destroys personal information for stated purposes.",
 "Processus d'affaires, ou partie de processus, dans lequel une organisation recueille, utilise, communique, conserve ou détruit des renseignements personnels à des fins déterminées.",
 ["GDPR", "QCPRIV"], "H", "GDPR Art. 30 record entries; Loi 25 purposes of collection. Needed to evaluate applicability (specification section 9).", [("traitement de données", "fr")]),
("SupplierRole", "org", ["bfo:BFO_0000023"], "supplier role", "rôle de fournisseur",
 "A role of an organisation that supplies goods, services or the operation of assets to another organisation, which comes to depend on it.",
 "Rôle d'une organisation qui fournit des biens, des services ou l'exploitation d'actifs à une autre organisation, laquelle en vient à en dépendre.",
 ["SPEC"], "H", "Anti-rigid (OntoClean): an organisation is a supplier only relative to a customer, so modelled as a BFO role borne by the organisation.", [("third party", "en"), ("tiers", "fr")]),
# ---- grc
("LegalInstrument", "grc", [DIRECTIVE], "legal instrument", "instrument juridique",
 "A statute, regulation or regulatory guideline taken as a whole, identified by its official citation, with its jurisdiction and the dates of its publication, coming into force, application and consolidation. Its provisions are the concepts of the corresponding CRGO vocabulary.",
 "Loi, règlement ou ligne directrice réglementaire pris dans son ensemble, identifié par sa citation officielle, avec sa juridiction et les dates de sa publication, de son entrée en vigueur, de sa prise d'effet et de sa mise à jour. Ses dispositions sont les concepts du vocabulaire CRGO correspondant.",
 ["SPEC", "QCPRIV", "GDPR"], "H", "Specification section 5 (separate instrument, provision, obligation, applicability, determination).", []),
("ApplicabilityCondition", "grc", [DESC], "applicability condition", "condition d'applicabilité",
 "A description of a condition under which a legal instrument or one of its provisions applies to an organisation, such as its territory, organisation type, sector, role in processing personal information or a threshold, written as a CRGO paraphrase with its citation and a machine-readable test.",
 "Description d'une condition à laquelle un instrument juridique ou l'une de ses dispositions s'applique à une organisation, comme son territoire, son type d'organisation, son secteur, son rôle dans le traitement de renseignements personnels ou un seuil, rédigée comme une paraphrase de CRGO avec sa citation et un test lisible par machine.",
 ["SPEC", "QCPRIV", "GDPR", "PIPEDA", "B13"], "H", "Conditions are evaluated over an organisation profile, never asserted as class membership (specification section 9).", []),
("ApplicabilityAssessment", "grc", [DESC], "applicability assessment", "évaluation de l'applicabilité",
 "A dated record (not the act of assessing) of whether a legal instrument or provision applies to a given organisation, giving the state reached (applicable, not applicable, potentially applicable or unknown) and the conditions found met, not met or undetermined.",
 "Enregistrement daté indiquant si un instrument juridique ou une disposition s'applique à une organisation donnée, avec l'état retenu (applicable, non applicable, potentiellement applicable ou inconnu) et les conditions jugées remplies, non remplies ou indéterminées.",
 ["SPEC"], "H", "Specification section 9 states; 'unknown' when a needed fact is absent, so missing data never yields 'not applicable'.", []),
("ComplianceDetermination", "grc", [DESC], "compliance determination", "constat de conformité",
 "A dated record, made by an identified assessor, of the extent to which a given organisation satisfies a legal provision or obligation, with the evidence relied on or an explicit statement of the missing evidence. A mapped control or framework requirement is not by itself evidence of compliance.",
 "Enregistrement daté, établi par un évaluateur identifié, du degré auquel une organisation donnée satisfait à une disposition ou à une obligation légale, avec les preuves retenues ou un énoncé explicite des preuves manquantes. Un contrôle ou une exigence de référentiel mis en correspondance ne constitue pas à lui seul une preuve de conformité.",
 ["SPEC"], "H", "Specification sections 9 and 13 (state, assessor, date, evidence or evidence gap).", [("compliance assessment", "en")]),
("ControlAssessment", "grc", [PLANNED_ACT], "control assessment", "évaluation d'une mesure de sécurité",
 "A planned act in which an assessor tests or reviews a control measure of an organisation at a stated date, over a stated scope and by a stated procedure, and records its result and the evidence gathered.",
 "Acte planifié par lequel un évaluateur teste ou examine une mesure de sécurité d'une organisation à une date, sur un périmètre et selon une procédure donnés, et en consigne le résultat et les preuves recueillies.",
 ["SPEC", "80030"], "H", "Specification section 5 (separate objective, implementation and assessment result): control = objective, control measure = implementation, control assessment = test.", [("control test", "en")]),
]

# (class key, module, en, fr, def_en, def_fr, source, members[(key, en, fr, def_en, def_fr)])
VALUE_SETS_09 = [
("Jurisdiction", "org", "jurisdiction", "juridiction",
 "A territory whose law or regulator CRGO's legal vocabularies come from, used to state where an organisation is established, offers services or has data subjects.",
 "Territoire dont proviennent le droit ou l'autorité de réglementation des vocabulaires juridiques de CRGO, servant à indiquer où une organisation est établie, offre des services ou compte des personnes concernées.",
 ["SPEC"], [
  ("JurQuebec", "Québec", "Québec", "The province of Québec.", "La province de Québec."),
  ("JurCanada", "Canada (federal legal order)", "Canada (ordre juridique fédéral)", "Canada as the legal order of federal statutes and regulators. It is the jurisdiction of an instrument, not a place: an organisation's establishment, markets and data subjects are given by a province or territory.", "Le Canada en tant qu'ordre juridique des lois et autorités fédérales. C'est la juridiction d'un instrument, non un lieu : l'établissement, les marchés et les personnes concernées d'une organisation sont indiqués par une province ou un territoire."),
  ("JurCanadaOtherProvince", "Canadian province or territory without substantially similar privacy law", "province ou territoire canadien sans loi essentiellement similaire", "A Canadian province or territory other than Québec, British Columbia and Alberta, whose private sector is not covered by a provincial law declared substantially similar to PIPEDA.", "Province ou territoire canadien autre que le Québec, la Colombie-Britannique et l'Alberta, dont le secteur privé n'est pas régi par une loi provinciale déclarée essentiellement similaire à la LPRPDE."),
  ("JurCanadaSimilarProvince", "British Columbia or Alberta", "Colombie-Britannique ou Alberta", "British Columbia or Alberta, whose private-sector privacy Acts are declared substantially similar to PIPEDA.", "La Colombie-Britannique ou l'Alberta, dont les lois sur la protection des renseignements personnels dans le secteur privé sont déclarées essentiellement similaires à la LPRPDE."),
  ("JurEU", "European Union", "Union européenne", "The European Union and its Member States.", "L'Union européenne et ses États membres."),
  ("JurOtherCountry", "other country", "autre pays", "A country outside Canada and the European Union.", "Pays situé hors du Canada et de l'Union européenne.")]),
("OrganisationType", "org", "organisation type", "type d'organisation",
 "The legal category of an organisation that decides which privacy and security regime binds it.",
 "Catégorie juridique d'une organisation qui détermine le régime de protection et de sécurité qui la lie.",
 ["QCPRIV", "PIPEDA", "B13"], [
  ("OrgEnterprise", "enterprise (private sector)", "entreprise (secteur privé)", "A person or organisation carrying on an enterprise within the meaning of the Civil Code of Québec, or a private-sector organisation in commercial activity.", "Personne ou organisation qui exploite une entreprise au sens du Code civil du Québec, ou organisation du secteur privé exerçant une activité commerciale."),
  ("OrgPublicBody", "public body (Québec)", "organisme public (Québec)", "A body subject to CQLR c. A-2.1, such as a ministry, municipality or school service centre.", "Organisme assujetti à la Loi sur l'accès (c. A-2.1), comme un ministère, une municipalité ou un centre de services scolaire."),
  ("OrgHealthBody", "health and social services body (Québec)", "organisme du secteur de la santé et des services sociaux (Québec)", "A body listed in s. 4 or the Schedules of CQLR c. R-22.1.", "Organisme visé à l'article 4 ou aux annexes de la loi c. R-22.1."),
  ("OrgFRFI", "federally regulated financial institution", "institution financière fédérale", "A bank, insurer or trust and loan company regulated by OSFI.", "Banque, société d'assurance ou société de fiducie et de prêt réglementée par le BSIF."),
  ("OrgFederalWork", "federal work, undertaking or business", "entreprise fédérale", "An organisation that operates a federal work, undertaking or business, such as a bank, airline or telecommunications carrier.", "Organisation qui exploite une entreprise fédérale, comme une banque, un transporteur aérien ou une entreprise de télécommunications.")]),
("ProcessingRole", "org", "processing role", "rôle dans le traitement",
 "The role an organisation plays in a processing activity.", "Rôle d'une organisation dans une activité de traitement.",
 ["GDPR", "QCPRIV"], [
  ("RoleController", "controller", "responsable du traitement", "Decides the purposes and means of the processing; under Loi 25, the person carrying on an enterprise who holds the information.", "Détermine les finalités et les moyens du traitement; sous la Loi 25, la personne qui exploite une entreprise et détient les renseignements."),
  ("RoleProcessor", "processor or service provider", "sous-traitant ou prestataire de services", "Processes personal information on behalf of a controller under a mandate or contract.", "Traite des renseignements personnels pour le compte d'un responsable en vertu d'un mandat ou d'un contrat.")]),
("PersonalDataCategory", "org", "personal data category", "catégorie de renseignements personnels",
 "A category of personal information that a processing activity handles, used for applicability conditions and sensitivity.",
 "Catégorie de renseignements personnels traitée par une activité de traitement, utilisée pour les conditions d'applicabilité et la sensibilité.",
 ["GDPR", "QCPRIV"], [
  ("DataIdentityContact", "identity and contact data", "données d'identité et de contact", "Names, addresses, e-mail addresses, telephone numbers.", "Noms, adresses, courriels, numéros de téléphone."),
  ("DataFinancial", "financial and payment data", "données financières et de paiement", "Payment card, bank account or transaction data.", "Données de carte de paiement, de compte bancaire ou de transaction."),
  ("DataHealth", "health data", "données de santé", "Information about a person's physical or mental health or health services.", "Renseignements sur la santé physique ou mentale d'une personne ou sur les services de santé reçus."),
  ("DataBiometric", "biometric data", "données biométriques", "Characteristics used to identify a person, such as fingerprints or facial geometry.", "Caractéristiques servant à identifier une personne, comme les empreintes digitales ou la géométrie faciale."),
  ("DataLocation", "location data", "données de localisation", "Information revealing where a person is or has been.", "Renseignements révélant où une personne se trouve ou s'est trouvée."),
  ("DataMinors", "data about minors", "données concernant des mineurs", "Personal information about persons under 14 (Loi 25) or under 16 (GDPR information society services).", "Renseignements personnels sur des personnes de moins de 14 ans (Loi 25) ou de moins de 16 ans (services de la société de l'information, RGPD)."),
  ("DataGovernmentId", "government identifiers", "identifiants gouvernementaux", "Social insurance, health insurance, passport or driver's licence numbers.", "Numéros d'assurance sociale, d'assurance maladie, de passeport ou de permis de conduire."),
  ("DataOnlineId", "online identifiers", "identifiants en ligne", "Account names, device identifiers, IP addresses, cookies.", "Noms de compte, identifiants d'appareil, adresses IP, témoins.")]),
("InstrumentKind", "grc", "instrument kind", "type d'instrument",
 "The kind of a legal instrument.", "Type d'un instrument juridique.", ["SPEC"], [
  ("KindStatute", "statute", "loi", "An act adopted by a legislature, or an EU regulation.", "Loi adoptée par un parlement, ou règlement de l'Union européenne."),
  ("KindRegulation", "regulation", "règlement", "Delegated legislation made under a statute.", "Texte réglementaire pris en vertu d'une loi."),
  ("KindGuideline", "regulatory guideline", "ligne directrice", "A regulator's guideline setting expectations for regulated organisations.", "Ligne directrice d'une autorité de réglementation énonçant ses attentes envers les organisations réglementées.")]),
("ApplicabilityState", "grc", "applicability state", "état d'applicabilité",
 "The result of evaluating whether an instrument or provision applies to an organisation.", "Résultat de l'évaluation de l'applicabilité d'un instrument ou d'une disposition à une organisation.", ["SPEC"], [
  ("AppApplicable", "applicable", "applicable", "Every required condition is met and no exception applies.", "Toutes les conditions requises sont remplies et aucune exception ne s'applique."),
  ("AppNotApplicable", "not applicable", "non applicable", "A required condition is not met.", "Une condition requise n'est pas remplie."),
  ("AppPotentiallyApplicable", "potentially applicable", "potentiellement applicable", "The conditions met point to application, but the result depends on an interpretation or a fact that needs review by a qualified person.", "Les conditions remplies indiquent l'application, mais le résultat dépend d'une interprétation ou d'un fait qui doit être examiné par une personne qualifiée."),
  ("AppUnknown", "unknown", "inconnu", "A fact needed to evaluate a condition is missing; nothing is concluded.", "Un fait nécessaire à l'évaluation d'une condition est absent; rien n'est conclu.")]),
("ComplianceState", "grc", "compliance state", "état de conformité",
 "The result of a compliance determination.", "Résultat d'un constat de conformité.", ["SPEC"], [
  ("CompSatisfied", "satisfied", "satisfaite", "The evidence shows the provision is met.", "Les preuves montrent que la disposition est respectée."),
  ("CompPartial", "partially satisfied", "partiellement satisfaite", "The evidence shows the provision is met in part.", "Les preuves montrent que la disposition est respectée en partie."),
  ("CompUnsatisfied", "unsatisfied", "non satisfaite", "The evidence shows the provision is not met.", "Les preuves montrent que la disposition n'est pas respectée."),
  ("CompNotAssessed", "not assessed", "non évaluée", "No assessment has been made.", "Aucune évaluation n'a été faite."),
  ("CompUndetermined", "undetermined", "indéterminée", "An assessment was attempted but the evidence does not allow a conclusion.", "Une évaluation a été tentée mais les preuves ne permettent pas de conclure.")]),
("ConditionKind", "grc", "condition kind", "type de condition",
 "The kind of fact an applicability condition tests.", "Type de fait que vérifie une condition d'applicabilité.", ["SPEC"], [
  ("CondTerritorial", "territorial", "territoriale", "Where the organisation is established, offers services or monitors behaviour.", "Lieu d'établissement de l'organisation, ou lieu où elle offre des services ou suit des comportements."),
  ("CondOrgType", "organisation-type condition", "condition de type d'organisation", "The legal category of the organisation.", "Catégorie juridique de l'organisation."),
  ("CondProcessing", "processing", "traitement", "Whether and how the organisation processes personal information.", "Si et comment l'organisation traite des renseignements personnels."),
  ("CondDataCategory", "data category", "catégorie de données", "Which categories of personal information are processed.", "Catégories de renseignements personnels traitées."),
  ("CondException", "exception", "exception", "A condition that, when met, excludes application.", "Condition qui, lorsqu'elle est remplie, exclut l'application.")]),
("ControlTestResult", "grc", "control test result", "résultat d'évaluation d'une mesure",
 "The result recorded by a control assessment.", "Résultat consigné par une évaluation de mesure de sécurité.", ["SPEC"], [
  ("TestEffective", "effective", "efficace", "Operates as designed over the scope tested.", "Fonctionne comme prévu sur le périmètre testé."),
  ("TestPartlyEffective", "partly effective", "partiellement efficace", "Operates as designed for part of the scope or with exceptions.", "Fonctionne comme prévu pour une partie du périmètre ou avec des exceptions."),
  ("TestIneffective", "ineffective", "inefficace", "Does not operate as designed.", "Ne fonctionne pas comme prévu."),
  ("TestNotTested", "not tested", "non testée", "In scope but not yet tested.", "Dans le périmètre mais pas encore testée.")]),
]

INDIVIDUALS_09 = []

# disjointness between new classes and existing ones (pairs)
DISJOINT_09 = [("Observation", "Estimate"), ("ApplicabilityAssessment", "ComplianceDetermination"),
               ("ControlAssessment", "RiskAssessment"), ("SourceRecord", "EvidenceItem")]

# (key, module, en, fr, def_en, def_fr, domain, range, source keys, conf, rationale, characteristics, superproperty)
OBJECT_PROPERTIES_09 = [
# evidence
("hasSourceRecord", "evidence", "has source record", "a pour notice de source", "Relates a vocabulary, dataset, observation or other record to the source record of the content it was imported or derived from.", "Relie un vocabulaire, un jeu de données, une observation ou un autre enregistrement à la notice de source du contenu dont il est importé ou dérivé.", None, "SourceRecord", ["PROV", "SPEC"], "H", "Sub-property of prov:hadPrimarySource.", [], "prov:hadPrimarySource"),
("observationOf", "evidence", "observation of", "observation de", "Relates an observation to the entity it reports on, such as a published vulnerability.", "Relie une observation à l'entité sur laquelle elle porte, comme une vulnérabilité publiée.", "Observation", None, ["SPEC"], "H", "Sub-property of CCO 'is about'.", ["functional"], "cco:ont00001808"),
("dependsOnAssumption", "evidence", "depends on assumption", "repose sur l'hypothèse", "Relates an estimate, assessment, determination or decision to an assumption it takes as true.", "Relie une estimation, une appréciation, un constat ou une décision à une hypothèse qu'il tient pour vraie.", None, "Assumption", ["SPEC"], "H", "", [], None),
# org
("hasOrganisationType", "org", "has organisation type", "a pour type d'organisation", "Gives the legal category of an organisation.", "Indique la catégorie juridique d'une organisation.", ORG, "OrganisationType", ["QCPRIV", "PIPEDA", "B13"], "H", "", [], None),
("establishedIn", "org", "established in", "établie dans", "Relates an organisation to a jurisdiction where it has an establishment.", "Relie une organisation à une juridiction où elle a un établissement.", ORG, "Jurisdiction", ["GDPR", "QCPRIV"], "H", "GDPR Art. 3(1); Loi 25 s. 1.", [], None),
("offersServicesIn", "org", "offers goods or services to persons in", "offre des biens ou services aux personnes situées dans", "Relates an organisation to a jurisdiction whose residents it targets with goods or services, paid or not.", "Relie une organisation à une juridiction dont elle cible les résidents par des biens ou services, payants ou non.", ORG, "Jurisdiction", ["GDPR"], "H", "GDPR Art. 3(2)(a).", [], None),
("monitorsBehaviourIn", "org", "monitors behaviour of persons in", "suit le comportement des personnes situées dans", "Relates an organisation to a jurisdiction in which it monitors the behaviour of persons, such as by online tracking or profiling.", "Relie une organisation à une juridiction dans laquelle elle suit le comportement des personnes, par exemple par traçage en ligne ou profilage.", ORG, "Jurisdiction", ["GDPR"], "H", "GDPR Art. 3(2)(b).", [], None),
("carriedOutBy", "org", "carried out by", "exercée par", "Relates a processing activity to the organisation that carries it out.", "Relie une activité de traitement à l'organisation qui l'exerce.", "ProcessingActivity", ORG, ["GDPR"], "H", "", [], None),
("processesDataCategory", "org", "processes data category", "traite la catégorie de données", "Relates a processing activity to a category of personal information it handles.", "Relie une activité de traitement à une catégorie de renseignements personnels qu'elle traite.", "ProcessingActivity", "PersonalDataCategory", ["GDPR", "QCPRIV"], "H", "", [], None),
("hasProcessingRole", "org", "has processing role", "a pour rôle dans le traitement", "Gives the role the organisation carrying out a processing activity plays in it.", "Indique le rôle que joue dans une activité de traitement l'organisation qui l'exerce.", "ProcessingActivity", "ProcessingRole", ["GDPR"], "H", "", [], None),
("dataSubjectsIn", "org", "data subjects in", "personnes concernées situées dans", "Relates a processing activity to a jurisdiction where persons whose information it handles are located.", "Relie une activité de traitement à une juridiction où se trouvent des personnes dont elle traite les renseignements.", "ProcessingActivity", "Jurisdiction", ["GDPR", "QCPRIV"], "H", "", [], None),
("transfersDataTo", "org", "transfers personal information to", "communique des renseignements personnels vers", "Relates a processing activity to a jurisdiction where personal information is disclosed to, or stored by, a recipient.", "Relie une activité de traitement à une juridiction où des renseignements personnels sont communiqués à un destinataire ou conservés par lui.", "ProcessingActivity", "Jurisdiction", ["QCPRIV", "GDPR", "PIPEDA"], "H", "Loi 25 s. 17; GDPR Chapter V; PIPEDA interprovincial and international disclosures.", [], None),
("supplierTo", "org", "supplier to", "fournisseur de", "Relates a supplier role to the organisation that depends on what its bearer supplies.", "Relie un rôle de fournisseur à l'organisation qui dépend de ce que fournit le porteur du rôle.", "SupplierRole", ORG, ["SPEC"], "H", "The bearer is given by BFO 'bearer of'; assets the supplier provides keep 'provided by'.", [], None),
# grc
("hasJurisdiction", "grc", "has jurisdiction", "a pour juridiction", "Relates a legal instrument, applicability assessment or compliance determination to its jurisdiction.", "Relie un instrument juridique, une évaluation de l'applicabilité ou un constat de conformité à sa juridiction.", None, "Jurisdiction", ["SPEC"], "H", "", [], None),
("hasInstrumentKind", "grc", "has instrument kind", "a pour type d'instrument", "Gives the kind of a legal instrument.", "Indique le type d'un instrument juridique.", "LegalInstrument", "InstrumentKind", ["SPEC"], "H", "", ["functional"], None),
("provisionOf", "grc", "provision of", "disposition de", "Relates a provision, such as a concept of a CRGO legal vocabulary, to the legal instrument it belongs to.", "Relie une disposition, comme un concept d'un vocabulaire juridique de CRGO, à l'instrument juridique dont elle fait partie.", None, "LegalInstrument", ["SPEC"], "H", "", [], None),
("hasInForcePeriod", "grc", "has in-force period", "a pour période de vigueur", "Relates a legal instrument to the OWL-Time interval during which it is in force; the interval has no end while the instrument is not repealed.", "Relie un instrument juridique à l'intervalle OWL-Time pendant lequel il est en vigueur; l'intervalle n'a pas de fin tant que l'instrument n'est pas abrogé.", "LegalInstrument", "time:ProperInterval", ["TIME", "SPEC"], "H", "OWL-Time used where a period is the object of a claim (ADR-006).", ["functional"], None),
("conditionOf", "grc", "condition of", "condition de", "Relates an applicability condition to the instrument or provision whose application it governs.", "Relie une condition d'applicabilité à l'instrument ou à la disposition dont elle régit l'application.", "ApplicabilityCondition", None, ["SPEC"], "H", "", [], None),
("hasConditionKind", "grc", "has condition kind", "a pour type de condition", "Gives the kind of fact an applicability condition tests.", "Indique le type de fait que vérifie une condition d'applicabilité.", "ApplicabilityCondition", "ConditionKind", ["SPEC"], "H", "", ["functional"], None),
("applicabilityOf", "grc", "applicability of", "applicabilité de", "Relates an applicability assessment to the instrument or provision assessed.", "Relie une évaluation de l'applicabilité à l'instrument ou à la disposition évalués.", "ApplicabilityAssessment", None, ["SPEC"], "H", "", ["functional"], None),
("concernsOrganisation", "grc", "concerns organisation", "concerne l'organisation", "Relates an applicability assessment, compliance determination or control assessment to the organisation it is about.", "Relie une évaluation de l'applicabilité, un constat de conformité ou une évaluation de mesure à l'organisation qu'il concerne.", None, ORG, ["SPEC"], "H", "", [], None),
("hasApplicabilityState", "grc", "has applicability state", "a pour état d'applicabilité", "Gives the state reached by an applicability assessment.", "Indique l'état retenu par une évaluation de l'applicabilité.", "ApplicabilityAssessment", "ApplicabilityState", ["SPEC"], "H", "", ["functional"], None),
("conditionMet", "grc", "condition met", "condition remplie", "Relates an applicability assessment to a condition found met.", "Relie une évaluation de l'applicabilité à une condition jugée remplie.", "ApplicabilityAssessment", "ApplicabilityCondition", ["SPEC"], "H", "", [], None),
("conditionNotMet", "grc", "condition not met", "condition non remplie", "Relates an applicability assessment to a condition found not met.", "Relie une évaluation de l'applicabilité à une condition jugée non remplie.", "ApplicabilityAssessment", "ApplicabilityCondition", ["SPEC"], "H", "", [], None),
("conditionUndetermined", "grc", "condition undetermined", "condition indéterminée", "Relates an applicability assessment to a condition that could not be evaluated because a needed fact is missing.", "Relie une évaluation de l'applicabilité à une condition qui n'a pu être évaluée faute d'un fait nécessaire.", "ApplicabilityAssessment", "ApplicabilityCondition", ["SPEC"], "H", "", [], None),
("complianceWith", "grc", "compliance with", "conformité à", "Relates a compliance determination to the provision or obligation determined.", "Relie un constat de conformité à la disposition ou à l'obligation visée.", "ComplianceDetermination", None, ["SPEC"], "H", "", ["functional"], None),
("hasComplianceState", "grc", "has compliance state", "a pour état de conformité", "Gives the state recorded by a compliance determination.", "Indique l'état consigné par un constat de conformité.", "ComplianceDetermination", "ComplianceState", ["SPEC"], "H", "", ["functional"], None),
("basedOnControlAssessment", "grc", "based on control assessment", "fondé sur l'évaluation de mesure", "Relates a compliance determination to a control assessment it relies on.", "Relie un constat de conformité à une évaluation de mesure de sécurité sur laquelle il s'appuie.", "ComplianceDetermination", "ControlAssessment", ["SPEC"], "H", "", [], None),
("assessedBy", "grc", "assessed by", "évalué par", "Relates an applicability assessment, compliance determination or control assessment to the agent responsible for it.", "Relie une évaluation de l'applicabilité, un constat de conformité ou une évaluation de mesure à l'agent qui en est responsable.", None, AGENT, ["SPEC"], "H", "", [], None),
("evaluatesControlMeasure", "grc", "evaluates control measure", "évalue la mesure", "Relates a control assessment to the control measure it tests.", "Relie une évaluation de mesure de sécurité à la mesure appliquée qu'elle teste.", "ControlAssessment", "ControlMeasure", ["SPEC"], "H", "", ["functional"], None),
("hasTestResult", "grc", "has test result", "a pour résultat d'évaluation", "Gives the result recorded by a control assessment.", "Indique le résultat consigné par une évaluation de mesure de sécurité.", "ControlAssessment", "ControlTestResult", ["SPEC"], "H", "", ["functional"], None),
# mapping (typed correspondences, decision D3): direction subject -> object as in the label
("mitigatedByControl", "mapping", "technique mitigated by control", "technique atténuée par le contrôle", "Relates an ATT&CK technique to an SP 800-53 control that can mitigate it, as mapped by MITRE CTID.", "Relie une technique ATT&CK à un contrôle SP 800-53 qui peut l'atténuer, selon la correspondance de MITRE CTID.", None, None, ["CTID"], "H", "", [], "skos:relatedMatch"),
("counteredByDefensiveTechnique", "mapping", "technique countered by defensive technique", "technique contrée par la technique défensive", "Relates an ATT&CK technique to a D3FEND defensive technique that can counter it.", "Relie une technique ATT&CK à une technique défensive D3FEND qui peut la contrer.", None, None, ["SPEC"], "H", "Judged correspondences (0.7.0).", [], "skos:relatedMatch"),
("attackPatternExploitsWeakness", "mapping", "attack pattern exploits weakness", "patron d'attaque exploitant la faiblesse", "Relates a CAPEC attack pattern to a CWE weakness it exploits, as referenced by CAPEC.", "Relie un patron d'attaque CAPEC à une faiblesse CWE qu'il exploite, selon les références de CAPEC.", None, None, ["SPEC"], "H", "", [], "skos:relatedMatch"),
("attackPatternRelatedToTechnique", "mapping", "attack pattern related to technique", "patron d'attaque lié à la technique", "Relates a CAPEC attack pattern to an ATT&CK technique it references.", "Relie un patron d'attaque CAPEC à une technique ATT&CK qu'il cite.", None, None, ["SPEC"], "H", "", [], "skos:relatedMatch"),
("vulnerabilityInstanceOfWeakness", "mapping", "vulnerability is an instance of weakness", "vulnérabilité relevant de la faiblesse", "Relates a CVE in the KEV catalogue to a CWE weakness it is an instance of, as given by CISA.", "Relie une CVE du catalogue KEV à une faiblesse CWE dont elle relève, selon la CISA.", None, None, ["KEV"], "H", "", [], "skos:relatedMatch"),
("vulnerabilityAssociatedWithTechnique", "mapping", "vulnerability associated with technique", "vulnérabilité associée à la technique", "Relates a CVE in the KEV catalogue to an ATT&CK technique used to exploit it or describing its impact, as mapped by MITRE CTID; the mapping type is in the annotation.", "Relie une CVE du catalogue KEV à une technique ATT&CK servant à l'exploiter ou décrivant son impact, selon MITRE CTID; le type de correspondance est dans l'annotation.", None, None, ["CTID"], "H", "", [], "skos:relatedMatch"),
("subcategorySupportedByControl", "mapping", "subcategory supported by control", "sous-catégorie appuyée par le contrôle", "Relates a NIST CSF 2.0 element to an SP 800-53 control that supports it.", "Relie un élément du NIST CSF 2.0 à un contrôle SP 800-53 qui l'appuie.", None, None, ["SPEC"], "H", "Derived from NIST's CSF 1.1 mapping (0.8.0).", [], "skos:relatedMatch"),
("controlCorrespondsToControl", "mapping", "control corresponds to control", "contrôle correspondant au contrôle", "Relates an SP 800-53 control to an ISO/IEC 27002 control that NIST OLIR relates to it.", "Relie un contrôle SP 800-53 à un contrôle ISO/IEC 27002 que NIST OLIR y rattache.", None, None, ["OLIR"], "H", "", [], "skos:relatedMatch"),
("principleAddressedByCategory", "mapping", "principle addressed by category", "principe couvert par la catégorie", "Relates an OSFI B-13 principle to a NIST CSF 2.0 category that addresses it.", "Relie un principe de la ligne directrice B-13 du BSIF à une catégorie du NIST CSF 2.0 qui le couvre.", None, None, ["B13"], "H", "", [], "skos:relatedMatch"),
("comparableObligation", "mapping", "comparable obligation", "obligation comparable", "Relates an obligation in one legal regime to a comparable obligation in another regime; comparable is not equivalent, and the annotation states the differences.", "Relie une obligation d'un régime juridique à une obligation comparable d'un autre régime; comparable ne veut pas dire équivalente, et l'annotation précise les différences.", None, None, ["SPEC"], "H", "Specification section 3: framework mapping is not legal equivalence.", [], "skos:relatedMatch"),
("sameObligationOtherRegime", "mapping", "same obligation in another regime", "même obligation dans un autre régime", "Relates an obligation of the Québec private-sector Act to the obligation worded the same way for public bodies.", "Relie une obligation de la loi sur le secteur privé à l'obligation formulée de la même façon pour les organismes publics.", None, None, ["QCPRIV"], "H", "", [], "skos:closeMatch"),
]

# (key, module, en, fr, def_en, def_fr, domain, range, source keys, conf, rationale, functional)
DATA_PROPERTIES_09 = [
("retrievedOn", "evidence", "retrieved on", "obtenu le", "Gives when the file a source record describes was obtained.", "Indique quand le fichier décrit par une notice de source a été obtenu.", "SourceRecord", "xsd:dateTime", ["SPEC"], "H", "", True),
("sourceVersion", "evidence", "source version", "version de la source", "Gives the version, release or consolidation date of a source as its issuer states it.", "Indique la version, l'édition ou la date de mise à jour d'une source telle que l'énonce son émetteur.", "SourceRecord", "xsd:string", ["SPEC"], "H", "", True),
("officialIdentifier", "evidence", "official identifier", "identifiant officiel", "Gives the official citation, identifier or web address of a source.", "Indique la citation officielle, l'identifiant ou l'adresse web d'une source.", "SourceRecord", "xsd:string", ["SPEC"], "H", "", False),
("issuerName", "evidence", "issuer", "émetteur", "Gives the organisation that issues or publishes a source.", "Indique l'organisation qui émet ou publie une source.", "SourceRecord", "xsd:string", ["SPEC"], "H", "", False),
("licenceTerms", "evidence", "licence or terms", "licence ou conditions", "Gives the licence or terms of use of a source.", "Indique la licence ou les conditions d'utilisation d'une source.", "SourceRecord", "xsd:string", ["SPEC"], "H", "", False),
("redistributionTerms", "evidence", "redistribution in CRGO", "rediffusion dans CRGO", "States what CRGO reproduces or derives from a source, such as identifiers and titles only, or counts only.", "Indique ce que CRGO reproduit ou dérive d'une source, comme les identifiants et titres seulement, ou des décomptes seulement.", "SourceRecord", "xsd:string", ["SPEC"], "H", "", False),
("checksumSha256", "evidence", "SHA-256 checksum", "empreinte SHA-256", "Gives the SHA-256 checksum of a file a source record describes, so that a rebuild can verify it used the same file.", "Indique l'empreinte SHA-256 d'un fichier décrit par une notice de source, afin qu'une reconstruction puisse vérifier qu'elle utilise le même fichier.", "SourceRecord", "xsd:string", ["SPEC"], "H", "", False),
("verificationNote", "evidence", "verification note", "note de vérification", "States how and against what a source's content was verified.", "Indique comment et par rapport à quoi le contenu d'une source a été vérifié.", "SourceRecord", "xsd:string", ["SPEC"], "H", "", False),
("publishedOn", "evidence", "published on", "publié le", "Gives the publication date of a source or legal instrument.", "Indique la date de publication d'une source ou d'un instrument juridique.", None, "xsd:dateTime", ["SPEC"], "H", "", False),
("observedOn", "evidence", "observed on", "observé le", "Gives the date and time an observation refers to, such as the date of an EPSS score.", "Indique la date et l'heure auxquelles se rapporte une observation, comme la date d'un score EPSS.", "Observation", "xsd:dateTime", ["SPEC"], "H", "", True),
("observationHorizon", "evidence", "observation horizon", "horizon de l'observation", "Gives the period a reported probability or frequency refers to, such as 'next 30 days'.", "Indique la période à laquelle se rapporte une probabilité ou une fréquence rapportée, comme « 30 prochains jours ».", "Observation", "xsd:string", ["SPEC"], "H", "", True),
("sourceModelVersion", "evidence", "model version", "version du modèle", "Gives the version of the model that produced an observed score.", "Indique la version du modèle qui a produit un score observé.", "Observation", "xsd:string", ["SPEC"], "H", "", True),
("epssPercentile", "vuln", "EPSS percentile", "centile EPSS", "Gives the share of scored vulnerabilities whose EPSS score is at or below that of the observed vulnerability on that day, from 0 to 1.", "Indique la proportion des vulnérabilités évaluées dont le score EPSS est inférieur ou égal à celui de la vulnérabilité observée ce jour-là, de 0 à 1.", "EPSSObservation", "xsd:decimal", ["EPSS"], "H", "", True),
("kevDateAdded", "vuln", "added to KEV on", "ajoutée au KEV le", "Gives the date CISA added a vulnerability to its Known Exploited Vulnerabilities catalogue.", "Indique la date à laquelle la CISA a ajouté une vulnérabilité à son catalogue des vulnérabilités exploitées connues.", None, "xsd:dateTime", ["KEV"], "H", "", True),
("knownRansomwareUse", "vuln", "known ransomware campaign use", "utilisation connue par rançongiciel", "Gives whether CISA knows of a ransomware campaign using the vulnerability ('Known' or 'Unknown').", "Indique si la CISA connaît une campagne de rançongiciel exploitant la vulnérabilité (« Known » ou « Unknown »).", None, "xsd:string", ["KEV"], "H", "", True),
("profileCompleteFor", "org", "profile complete for", "profil complet pour", "Names a property (by its CRGO key, such as offersServicesIn or transfersDataTo) for which the organisation profile lists every value, so that a value it does not list can be taken as absent. Without it, an unlisted value is unknown.", "Nomme une propriété (par sa clé CRGO, comme offersServicesIn ou transfersDataTo) pour laquelle le profil de l'organisation énumère toutes les valeurs, de sorte qu'une valeur non énumérée peut être tenue pour absente. Sans cela, une valeur non énumérée est inconnue.", ORG, "xsd:string", ["SPEC"], "H", "Independent review 2026-10-11: closed-world reading only where the profile declares it (ADR-004).", False),
("assessedOn", "grc", "assessed on", "évalué le", "Gives when an applicability assessment, compliance determination or control assessment was made.", "Indique quand une évaluation de l'applicabilité, un constat de conformité ou une évaluation de mesure a été fait.", None, "xsd:dateTime", ["SPEC"], "H", "", True),
("officialCitation", "grc", "official citation", "citation officielle", "Gives the official citation of a legal instrument, such as CQLR c. P-39.1.", "Indique la citation officielle d'un instrument juridique, comme RLRQ c. P-39.1.", "LegalInstrument", "xsd:string", ["SPEC"], "H", "", True),
("appliesFrom", "grc", "applies from", "s'applique à compter du", "Gives the date from which an instrument or provision applies, when it differs from its coming into force.", "Indique la date à partir de laquelle un instrument ou une disposition s'applique, lorsqu'elle diffère de son entrée en vigueur.", None, "xsd:dateTime", ["SPEC"], "H", "GDPR in force 2016-05-24, applies from 2018-05-25.", False),
("lastAmendedOn", "grc", "last amended on", "dernière modification le", "Gives the date of the latest amendment of a legal instrument known to the consolidation used.", "Indique la date de la dernière modification d'un instrument juridique connue de la mise à jour utilisée.", "LegalInstrument", "xsd:dateTime", ["SPEC"], "H", "", False),
("consolidatedTo", "grc", "consolidated to", "à jour au", "Gives the date to which the consolidated text used by CRGO is up to date.", "Indique la date à laquelle le texte consolidé utilisé par CRGO est à jour.", "LegalInstrument", "xsd:dateTime", ["SPEC"], "H", "", False),
("conditionTest", "grc", "condition test", "test de la condition", "Gives the machine-readable test of an applicability condition, evaluated over an organisation profile by pipeline/grc/applicability.py.", "Indique le test lisible par machine d'une condition d'applicabilité, évalué sur le profil d'une organisation par pipeline/grc/applicability.py.", "ApplicabilityCondition", "xsd:string", ["SPEC"], "H", "", True),
("evidenceGap", "grc", "evidence gap", "preuve manquante", "States what evidence a compliance determination lacks; required when no evidence is linked.", "Indique les preuves qui manquent à un constat de conformité; obligatoire lorsqu'aucune preuve n'est liée.", "ComplianceDetermination", "xsd:string", ["SPEC"], "H", "", False),
("testProcedure", "grc", "test procedure", "procédure d'évaluation", "Describes how a control assessment tested the control measure, such as inspection, sampling or a restore test.", "Décrit comment une évaluation de mesure a testé la mesure appliquée, par inspection, échantillonnage ou essai de restauration.", "ControlAssessment", "xsd:string", ["SPEC"], "H", "", False),
("assessmentScope", "grc", "assessment scope", "périmètre de l'évaluation", "States what a control assessment or compliance determination covered.", "Indique ce que couvre une évaluation de mesure ou un constat de conformité.", None, "xsd:string", ["SPEC"], "H", "", False),
]
