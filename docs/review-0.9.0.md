# CRGO 0.9.0 review: what needs the project owner's decision

Prepared 2026-10-11. Approving a group writes one row in `src/approvals.tsv` (for terms: `terms/<module>`); nothing is approved until then. An independent review of this work was made before this list; its findings were fixed (`docs/decisions.md` section 17).

| # | Group | Content | Recommendation |
|---|---|---|---|
| 1 | Terms `crgo-evidence` (18) | source record, observation, assumption and their properties | Approve (`terms/evidence`) |
| 2 | Terms `crgo-org` (42, including 4 value-set schemes) | organisation type, jurisdictions, processing activity, roles, data categories, supplier role, profile complete for | Approve (`terms/org`) |
| 3 | Terms `crgo-vuln` (4) | EPSS observation, percentile, KEV date added, ransomware use | Approve (`terms/vuln`) |
| 4 | Terms `crgo-grc` (63, including 5 value-set schemes) | legal instrument, applicability condition and assessment, compliance determination, control assessment, their states and properties | Approve (`terms/grc`) |
| 5 | Terms `crgo-mapping` (11) | 11 typed correspondence relations | Approve (`terms/mapping`) |
| 6 | `sources/records` | 29 source records (`ontology/vocab/sources.ttl`) from the Stage 0 registry, with checksums | Approve |
| 7 | `legal/instruments` | 11 legal instruments with citations, jurisdictions and the dates printed in the PDFs you saved (`ontology/vocab/legal.ttl`) | Approve |
| 8 | `legal/conditions` | 19 applicability conditions: CRGO paraphrases, 5 marked interpretive (they yield only *potentially applicable*): Loi 25 activity in Québec without an establishment, C-1.1 biometrics, PIPEDA cross-border collection or disclosure, GDPR Art. 3(2)(a) and (b). Not legal advice | Approve, or keep proposed until a qualified review of the 5 interpretive ones |
| 9 | Design records | ADR-001 to ADR-006 (`docs/adr/`) | Approve |
| 10 | Test assets | synthetic Nordelle Market inc., applicability evaluator, CQ-03/04/05/07/08/11 (27 checks), 11 SHACL and 1 OWL negative fixtures | Approve |
| 11 | w3id.org rules | generalised rules for the new modules, import slices and the proposal file; branch `crgo-0.9.0-modules` ready in the local w3id.org clone (w3id checker: no problems); needs a push to your fork and a pull request to perma-id/w3id.org | Approve opening the pull request |

Already decided (no new decision needed): the GDPR (approved earlier today), EPSS as observations (D4), typed relations (D3), proposal files (gap G5, following the specification).

## New terms

138 new IRIs (CRGO_0000337 to CRGO_0000474): the 129 below plus 9 concept-scheme individuals, one per value set.

| IRI | Module | Kind | Label (en) | Label (fr) | Parent / domain-range | Definition (en) |
|---|---|---|---|---|---|---|
| CRGO_0000337 | evidence | class | source record | notice de source | cco:ont00000853, prov:Entity | A description of a dataset, publication or legal text from which CRGO content was imported or derived, recording its issuer, official identifier, version, retrieval date, licence, what CRGO redistributes and the checksum of the file used. |
| CRGO_0000338 | evidence | class | observation | observation | cco:ont00001163, prov:Entity | A dated record that a stated source reported a value or category for an entity at a stated time, such as the EPSS score of a vulnerability on a given day. An observation reports what a source said; it is not an estimate made for an assessment. |
| CRGO_0000339 | evidence | class | assumption | hypothèse | cco:ont00000853 | A statement taken as true without verification for an estimate, an assessment or a decision, recorded so that the result can be reviewed when the statement turns out to be false or changes. |
| CRGO_0000340 | vuln | class | EPSS observation | observation EPSS | observation | An observation of the Exploit Prediction Scoring System score of a published vulnerability on a given day: FIRST's estimated probability that the vulnerability is exploited in the wild in the following 30 days, with its percentile among all scored vulnerabilities. It concerns the vulnerability in general, not its presence in any organisation, and it is not the likelihood of a risk scenario. |
| CRGO_0000341 | org | class | processing activity | activité de traitement | business process | A business process, or part of one, in which an organisation collects, uses, discloses, keeps or destroys personal information for stated purposes. |
| CRGO_0000342 | org | class | supplier role | rôle de fournisseur | bfo:BFO_0000023 | A role of an organisation that supplies goods, services or the operation of assets to another organisation, which comes to depend on it. |
| CRGO_0000343 | grc | class | legal instrument | instrument juridique | cco:ont00000965 | A statute, regulation or regulatory guideline taken as a whole, identified by its official citation, with its jurisdiction and the dates of its publication, coming into force, application and consolidation. Its provisions are the concepts of the corresponding CRGO vocabulary. |
| CRGO_0000344 | grc | class | applicability condition | condition d'applicabilité | cco:ont00000853 | A description of a condition under which a legal instrument or one of its provisions applies to an organisation, such as its territory, organisation type, sector, role in processing personal information or a threshold, written as a CRGO paraphrase with its citation and a machine-readable test. |
| CRGO_0000345 | grc | class | applicability assessment | évaluation de l'applicabilité | cco:ont00000853 | A dated record (not the act of assessing) of whether a legal instrument or provision applies to a given organisation, giving the state reached (applicable, not applicable, potentially applicable or unknown) and the conditions found met, not met or undetermined. |
| CRGO_0000346 | grc | class | compliance determination | constat de conformité | cco:ont00000853 | A dated record, made by an identified assessor, of the extent to which a given organisation satisfies a legal provision or obligation, with the evidence relied on or an explicit statement of the missing evidence. A mapped control or framework requirement is not by itself evidence of compliance. |
| CRGO_0000347 | grc | class | control assessment | évaluation d'une mesure de sécurité | cco:ont00000228 | A planned act in which an assessor tests or reviews a control measure of an organisation at a stated date, over a stated scope and by a stated procedure, and records its result and the evidence gathered. |
| CRGO_0000348 | org | value set (class) | jurisdiction | juridiction | skos:Concept | A territory whose law or regulator CRGO's legal vocabularies come from, used to state where an organisation is established, offers services or has data subjects. |
| CRGO_0000350 | org | value | Québec | Québec | jurisdiction | The province of Québec. |
| CRGO_0000351 | org | value | Canada (federal legal order) | Canada (ordre juridique fédéral) | jurisdiction | Canada as the legal order of federal statutes and regulators. It is the jurisdiction of an instrument, not a place: an organisation's establishment, markets and data subjects are given by a province or territory. |
| CRGO_0000352 | org | value | Canadian province or territory without substantially similar privacy law | province ou territoire canadien sans loi essentiellement similaire | jurisdiction | A Canadian province or territory other than Québec, British Columbia and Alberta, whose private sector is not covered by a provincial law declared substantially similar to PIPEDA. |
| CRGO_0000473 | org | value | British Columbia or Alberta | Colombie-Britannique ou Alberta | jurisdiction | British Columbia or Alberta, whose private-sector privacy Acts are declared substantially similar to PIPEDA. |
| CRGO_0000353 | org | value | European Union | Union européenne | jurisdiction | The European Union and its Member States. |
| CRGO_0000354 | org | value | other country | autre pays | jurisdiction | A country outside Canada and the European Union. |
| CRGO_0000355 | org | value set (class) | organisation type | type d'organisation | skos:Concept | The legal category of an organisation that decides which privacy and security regime binds it. |
| CRGO_0000357 | org | value | enterprise (private sector) | entreprise (secteur privé) | organisation type | A person or organisation carrying on an enterprise within the meaning of the Civil Code of Québec, or a private-sector organisation in commercial activity. |
| CRGO_0000358 | org | value | public body (Québec) | organisme public (Québec) | organisation type | A body subject to CQLR c. A-2.1, such as a ministry, municipality or school service centre. |
| CRGO_0000359 | org | value | health and social services body (Québec) | organisme du secteur de la santé et des services sociaux (Québec) | organisation type | A body listed in s. 4 or the Schedules of CQLR c. R-22.1. |
| CRGO_0000360 | org | value | federally regulated financial institution | institution financière fédérale | organisation type | A bank, insurer or trust and loan company regulated by OSFI. |
| CRGO_0000361 | org | value | federal work, undertaking or business | entreprise fédérale | organisation type | An organisation that operates a federal work, undertaking or business, such as a bank, airline or telecommunications carrier. |
| CRGO_0000362 | org | value set (class) | processing role | rôle dans le traitement | skos:Concept | The role an organisation plays in a processing activity. |
| CRGO_0000364 | org | value | controller | responsable du traitement | processing role | Decides the purposes and means of the processing; under Loi 25, the person carrying on an enterprise who holds the information. |
| CRGO_0000365 | org | value | processor or service provider | sous-traitant ou prestataire de services | processing role | Processes personal information on behalf of a controller under a mandate or contract. |
| CRGO_0000366 | org | value set (class) | personal data category | catégorie de renseignements personnels | skos:Concept | A category of personal information that a processing activity handles, used for applicability conditions and sensitivity. |
| CRGO_0000368 | org | value | identity and contact data | données d'identité et de contact | personal data category | Names, addresses, e-mail addresses, telephone numbers. |
| CRGO_0000369 | org | value | financial and payment data | données financières et de paiement | personal data category | Payment card, bank account or transaction data. |
| CRGO_0000370 | org | value | health data | données de santé | personal data category | Information about a person's physical or mental health or health services. |
| CRGO_0000371 | org | value | biometric data | données biométriques | personal data category | Characteristics used to identify a person, such as fingerprints or facial geometry. |
| CRGO_0000372 | org | value | location data | données de localisation | personal data category | Information revealing where a person is or has been. |
| CRGO_0000373 | org | value | data about minors | données concernant des mineurs | personal data category | Personal information about persons under 14 (Loi 25) or under 16 (GDPR information society services). |
| CRGO_0000374 | org | value | government identifiers | identifiants gouvernementaux | personal data category | Social insurance, health insurance, passport or driver's licence numbers. |
| CRGO_0000375 | org | value | online identifiers | identifiants en ligne | personal data category | Account names, device identifiers, IP addresses, cookies. |
| CRGO_0000376 | grc | value set (class) | instrument kind | type d'instrument | skos:Concept | The kind of a legal instrument. |
| CRGO_0000378 | grc | value | statute | loi | instrument kind | An act adopted by a legislature, or an EU regulation. |
| CRGO_0000379 | grc | value | regulation | règlement | instrument kind | Delegated legislation made under a statute. |
| CRGO_0000380 | grc | value | regulatory guideline | ligne directrice | instrument kind | A regulator's guideline setting expectations for regulated organisations. |
| CRGO_0000381 | grc | value set (class) | applicability state | état d'applicabilité | skos:Concept | The result of evaluating whether an instrument or provision applies to an organisation. |
| CRGO_0000383 | grc | value | applicable | applicable | applicability state | Every required condition is met and no exception applies. |
| CRGO_0000384 | grc | value | not applicable | non applicable | applicability state | A required condition is not met. |
| CRGO_0000385 | grc | value | potentially applicable | potentiellement applicable | applicability state | The conditions met point to application, but the result depends on an interpretation or a fact that needs review by a qualified person. |
| CRGO_0000386 | grc | value | unknown | inconnu | applicability state | A fact needed to evaluate a condition is missing; nothing is concluded. |
| CRGO_0000387 | grc | value set (class) | compliance state | état de conformité | skos:Concept | The result of a compliance determination. |
| CRGO_0000389 | grc | value | satisfied | satisfaite | compliance state | The evidence shows the provision is met. |
| CRGO_0000390 | grc | value | partially satisfied | partiellement satisfaite | compliance state | The evidence shows the provision is met in part. |
| CRGO_0000391 | grc | value | unsatisfied | non satisfaite | compliance state | The evidence shows the provision is not met. |
| CRGO_0000392 | grc | value | not assessed | non évaluée | compliance state | No assessment has been made. |
| CRGO_0000393 | grc | value | undetermined | indéterminée | compliance state | An assessment was attempted but the evidence does not allow a conclusion. |
| CRGO_0000394 | grc | value set (class) | condition kind | type de condition | skos:Concept | The kind of fact an applicability condition tests. |
| CRGO_0000396 | grc | value | territorial | territoriale | condition kind | Where the organisation is established, offers services or monitors behaviour. |
| CRGO_0000397 | grc | value | organisation-type condition | condition de type d'organisation | condition kind | The legal category of the organisation. |
| CRGO_0000398 | grc | value | processing | traitement | condition kind | Whether and how the organisation processes personal information. |
| CRGO_0000399 | grc | value | data category | catégorie de données | condition kind | Which categories of personal information are processed. |
| CRGO_0000400 | grc | value | exception | exception | condition kind | A condition that, when met, excludes application. |
| CRGO_0000401 | grc | value set (class) | control test result | résultat d'évaluation d'une mesure | skos:Concept | The result recorded by a control assessment. |
| CRGO_0000403 | grc | value | effective | efficace | control test result | Operates as designed over the scope tested. |
| CRGO_0000404 | grc | value | partly effective | partiellement efficace | control test result | Operates as designed for part of the scope or with exceptions. |
| CRGO_0000405 | grc | value | ineffective | inefficace | control test result | Does not operate as designed. |
| CRGO_0000406 | grc | value | not tested | non testée | control test result | In scope but not yet tested. |
| CRGO_0000407 | evidence | object property | has source record | a pour notice de source | domain: —; range: source record | Relates a vocabulary, dataset, observation or other record to the source record of the content it was imported or derived from. |
| CRGO_0000408 | evidence | object property | observation of | observation de | domain: observation; range: — | Relates an observation to the entity it reports on, such as a published vulnerability. |
| CRGO_0000409 | evidence | object property | depends on assumption | repose sur l'hypothèse | domain: —; range: assumption | Relates an estimate, assessment, determination or decision to an assumption it takes as true. |
| CRGO_0000410 | org | object property | has organisation type | a pour type d'organisation | domain: cco:ont00001180; range: organisation type | Gives the legal category of an organisation. |
| CRGO_0000411 | org | object property | established in | établie dans | domain: cco:ont00001180; range: jurisdiction | Relates an organisation to a jurisdiction where it has an establishment. |
| CRGO_0000412 | org | object property | offers goods or services to persons in | offre des biens ou services aux personnes situées dans | domain: cco:ont00001180; range: jurisdiction | Relates an organisation to a jurisdiction whose residents it targets with goods or services, paid or not. |
| CRGO_0000413 | org | object property | monitors behaviour of persons in | suit le comportement des personnes situées dans | domain: cco:ont00001180; range: jurisdiction | Relates an organisation to a jurisdiction in which it monitors the behaviour of persons, such as by online tracking or profiling. |
| CRGO_0000414 | org | object property | carried out by | exercée par | domain: processing activity; range: cco:ont00001180 | Relates a processing activity to the organisation that carries it out. |
| CRGO_0000415 | org | object property | processes data category | traite la catégorie de données | domain: processing activity; range: personal data category | Relates a processing activity to a category of personal information it handles. |
| CRGO_0000416 | org | object property | has processing role | a pour rôle dans le traitement | domain: processing activity; range: processing role | Gives the role the organisation carrying out a processing activity plays in it. |
| CRGO_0000417 | org | object property | data subjects in | personnes concernées situées dans | domain: processing activity; range: jurisdiction | Relates a processing activity to a jurisdiction where persons whose information it handles are located. |
| CRGO_0000418 | org | object property | transfers personal information to | communique des renseignements personnels vers | domain: processing activity; range: jurisdiction | Relates a processing activity to a jurisdiction where personal information is disclosed to, or stored by, a recipient. |
| CRGO_0000419 | org | object property | supplier to | fournisseur de | domain: supplier role; range: cco:ont00001180 | Relates a supplier role to the organisation that depends on what its bearer supplies. |
| CRGO_0000420 | grc | object property | has jurisdiction | a pour juridiction | domain: —; range: jurisdiction | Relates a legal instrument, applicability assessment or compliance determination to its jurisdiction. |
| CRGO_0000421 | grc | object property | has instrument kind | a pour type d'instrument | domain: legal instrument; range: instrument kind | Gives the kind of a legal instrument. |
| CRGO_0000422 | grc | object property | provision of | disposition de | domain: —; range: legal instrument | Relates a provision, such as a concept of a CRGO legal vocabulary, to the legal instrument it belongs to. |
| CRGO_0000423 | grc | object property | has in-force period | a pour période de vigueur | domain: legal instrument; range: time:ProperInterval | Relates a legal instrument to the OWL-Time interval during which it is in force; the interval has no end while the instrument is not repealed. |
| CRGO_0000424 | grc | object property | condition of | condition de | domain: applicability condition; range: — | Relates an applicability condition to the instrument or provision whose application it governs. |
| CRGO_0000425 | grc | object property | has condition kind | a pour type de condition | domain: applicability condition; range: condition kind | Gives the kind of fact an applicability condition tests. |
| CRGO_0000426 | grc | object property | applicability of | applicabilité de | domain: applicability assessment; range: — | Relates an applicability assessment to the instrument or provision assessed. |
| CRGO_0000427 | grc | object property | concerns organisation | concerne l'organisation | domain: —; range: cco:ont00001180 | Relates an applicability assessment, compliance determination or control assessment to the organisation it is about. |
| CRGO_0000428 | grc | object property | has applicability state | a pour état d'applicabilité | domain: applicability assessment; range: applicability state | Gives the state reached by an applicability assessment. |
| CRGO_0000429 | grc | object property | condition met | condition remplie | domain: applicability assessment; range: applicability condition | Relates an applicability assessment to a condition found met. |
| CRGO_0000430 | grc | object property | condition not met | condition non remplie | domain: applicability assessment; range: applicability condition | Relates an applicability assessment to a condition found not met. |
| CRGO_0000431 | grc | object property | condition undetermined | condition indéterminée | domain: applicability assessment; range: applicability condition | Relates an applicability assessment to a condition that could not be evaluated because a needed fact is missing. |
| CRGO_0000432 | grc | object property | compliance with | conformité à | domain: compliance determination; range: — | Relates a compliance determination to the provision or obligation determined. |
| CRGO_0000433 | grc | object property | has compliance state | a pour état de conformité | domain: compliance determination; range: compliance state | Gives the state recorded by a compliance determination. |
| CRGO_0000434 | grc | object property | based on control assessment | fondé sur l'évaluation de mesure | domain: compliance determination; range: control assessment | Relates a compliance determination to a control assessment it relies on. |
| CRGO_0000435 | grc | object property | assessed by | évalué par | domain: —; range: cco:ont00001017 | Relates an applicability assessment, compliance determination or control assessment to the agent responsible for it. |
| CRGO_0000436 | grc | object property | evaluates control measure | évalue la mesure | domain: control assessment; range: control measure | Relates a control assessment to the control measure it tests. |
| CRGO_0000437 | grc | object property | has test result | a pour résultat d'évaluation | domain: control assessment; range: control test result | Gives the result recorded by a control assessment. |
| CRGO_0000438 | mapping | object property | technique mitigated by control | technique atténuée par le contrôle | domain: —; range: — | Relates an ATT&CK technique to an SP 800-53 control that can mitigate it, as mapped by MITRE CTID. |
| CRGO_0000439 | mapping | object property | technique countered by defensive technique | technique contrée par la technique défensive | domain: —; range: — | Relates an ATT&CK technique to a D3FEND defensive technique that can counter it. |
| CRGO_0000440 | mapping | object property | attack pattern exploits weakness | patron d'attaque exploitant la faiblesse | domain: —; range: — | Relates a CAPEC attack pattern to a CWE weakness it exploits, as referenced by CAPEC. |
| CRGO_0000441 | mapping | object property | attack pattern related to technique | patron d'attaque lié à la technique | domain: —; range: — | Relates a CAPEC attack pattern to an ATT&CK technique it references. |
| CRGO_0000442 | mapping | object property | vulnerability is an instance of weakness | vulnérabilité relevant de la faiblesse | domain: —; range: — | Relates a CVE in the KEV catalogue to a CWE weakness it is an instance of, as given by CISA. |
| CRGO_0000443 | mapping | object property | vulnerability associated with technique | vulnérabilité associée à la technique | domain: —; range: — | Relates a CVE in the KEV catalogue to an ATT&CK technique used to exploit it or describing its impact, as mapped by MITRE CTID; the mapping type is in the annotation. |
| CRGO_0000444 | mapping | object property | subcategory supported by control | sous-catégorie appuyée par le contrôle | domain: —; range: — | Relates a NIST CSF 2.0 element to an SP 800-53 control that supports it. |
| CRGO_0000445 | mapping | object property | control corresponds to control | contrôle correspondant au contrôle | domain: —; range: — | Relates an SP 800-53 control to an ISO/IEC 27002 control that NIST OLIR relates to it. |
| CRGO_0000446 | mapping | object property | principle addressed by category | principe couvert par la catégorie | domain: —; range: — | Relates an OSFI B-13 principle to a NIST CSF 2.0 category that addresses it. |
| CRGO_0000447 | mapping | object property | comparable obligation | obligation comparable | domain: —; range: — | Relates an obligation in one legal regime to a comparable obligation in another regime; comparable is not equivalent, and the annotation states the differences. |
| CRGO_0000448 | mapping | object property | same obligation in another regime | même obligation dans un autre régime | domain: —; range: — | Relates an obligation of the Québec private-sector Act to the obligation worded the same way for public bodies. |
| CRGO_0000449 | evidence | data property | retrieved on | obtenu le | domain: source record; range: xsd:dateTime | Gives when the file a source record describes was obtained. |
| CRGO_0000450 | evidence | data property | source version | version de la source | domain: source record; range: xsd:string | Gives the version, release or consolidation date of a source as its issuer states it. |
| CRGO_0000451 | evidence | data property | official identifier | identifiant officiel | domain: source record; range: xsd:string | Gives the official citation, identifier or web address of a source. |
| CRGO_0000452 | evidence | data property | issuer | émetteur | domain: source record; range: xsd:string | Gives the organisation that issues or publishes a source. |
| CRGO_0000453 | evidence | data property | licence or terms | licence ou conditions | domain: source record; range: xsd:string | Gives the licence or terms of use of a source. |
| CRGO_0000454 | evidence | data property | redistribution in CRGO | rediffusion dans CRGO | domain: source record; range: xsd:string | States what CRGO reproduces or derives from a source, such as identifiers and titles only, or counts only. |
| CRGO_0000455 | evidence | data property | SHA-256 checksum | empreinte SHA-256 | domain: source record; range: xsd:string | Gives the SHA-256 checksum of a file a source record describes, so that a rebuild can verify it used the same file. |
| CRGO_0000456 | evidence | data property | verification note | note de vérification | domain: source record; range: xsd:string | States how and against what a source's content was verified. |
| CRGO_0000457 | evidence | data property | published on | publié le | domain: —; range: xsd:dateTime | Gives the publication date of a source or legal instrument. |
| CRGO_0000458 | evidence | data property | observed on | observé le | domain: observation; range: xsd:dateTime | Gives the date and time an observation refers to, such as the date of an EPSS score. |
| CRGO_0000459 | evidence | data property | observation horizon | horizon de l'observation | domain: observation; range: xsd:string | Gives the period a reported probability or frequency refers to, such as 'next 30 days'. |
| CRGO_0000460 | evidence | data property | model version | version du modèle | domain: observation; range: xsd:string | Gives the version of the model that produced an observed score. |
| CRGO_0000461 | vuln | data property | EPSS percentile | centile EPSS | domain: EPSS observation; range: xsd:decimal | Gives the share of scored vulnerabilities whose EPSS score is at or below that of the observed vulnerability on that day, from 0 to 1. |
| CRGO_0000462 | vuln | data property | added to KEV on | ajoutée au KEV le | domain: —; range: xsd:dateTime | Gives the date CISA added a vulnerability to its Known Exploited Vulnerabilities catalogue. |
| CRGO_0000463 | vuln | data property | known ransomware campaign use | utilisation connue par rançongiciel | domain: —; range: xsd:string | Gives whether CISA knows of a ransomware campaign using the vulnerability ('Known' or 'Unknown'). |
| CRGO_0000474 | org | data property | profile complete for | profil complet pour | domain: cco:ont00001180; range: xsd:string | Names a property (by its CRGO key, such as offersServicesIn or transfersDataTo) for which the organisation profile lists every value, so that a value it does not list can be taken as absent. Without it, an unlisted value is unknown. |
| CRGO_0000464 | grc | data property | assessed on | évalué le | domain: —; range: xsd:dateTime | Gives when an applicability assessment, compliance determination or control assessment was made. |
| CRGO_0000465 | grc | data property | official citation | citation officielle | domain: legal instrument; range: xsd:string | Gives the official citation of a legal instrument, such as CQLR c. P-39.1. |
| CRGO_0000466 | grc | data property | applies from | s'applique à compter du | domain: —; range: xsd:dateTime | Gives the date from which an instrument or provision applies, when it differs from its coming into force. |
| CRGO_0000467 | grc | data property | last amended on | dernière modification le | domain: legal instrument; range: xsd:dateTime | Gives the date of the latest amendment of a legal instrument known to the consolidation used. |
| CRGO_0000468 | grc | data property | consolidated to | à jour au | domain: legal instrument; range: xsd:dateTime | Gives the date to which the consolidated text used by CRGO is up to date. |
| CRGO_0000469 | grc | data property | condition test | test de la condition | domain: applicability condition; range: xsd:string | Gives the machine-readable test of an applicability condition, evaluated over an organisation profile by pipeline/grc/applicability.py. |
| CRGO_0000470 | grc | data property | evidence gap | preuve manquante | domain: compliance determination; range: xsd:string | States what evidence a compliance determination lacks; required when no evidence is linked. |
| CRGO_0000471 | grc | data property | test procedure | procédure d'évaluation | domain: control assessment; range: xsd:string | Describes how a control assessment tested the control measure, such as inspection, sampling or a restore test. |
| CRGO_0000472 | grc | data property | assessment scope | périmètre de l'évaluation | domain: —; range: xsd:string | States what a control assessment or compliance determination covered. |
