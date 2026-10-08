# -*- coding: utf-8 -*-
"""Build test fixtures (instance data) from the CRG template scenario S1, using the stable ids.
These are tests of the TBox, not Phase 3 data."""
import os
from rdflib import Graph, Namespace, Literal, URIRef
from rdflib.namespace import RDF, OWL, XSD
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ids = dict(l.rstrip("\n").split("\t") for l in open(os.path.join(ROOT, "src", "ids.tsv"), encoding="utf-8"))
C = lambda k: URIRef("https://w3id.org/crgo/CRGO_%07d" % int(ids[k]))
CCO = Namespace("https://www.commoncoreontologies.org/")
BFO = Namespace("http://purl.obolibrary.org/obo/")
EX = Namespace("https://w3id.org/crgo/data/crg-template/")

def base():
    g = Graph(); g.bind("ex", EX); g.bind("crgo", "https://w3id.org/crgo/")
    o = URIRef("https://w3id.org/crgo/tests/fixture")
    g.add((o, RDF.type, OWL.Ontology)); g.add((o, OWL.imports, URIRef("https://w3id.org/crgo/crgo")))
    return g

g = base()
A = lambda *t: [g.add(x) for x in t]
# organisation, assessment, appetite
A((EX.Org, RDF.type, CCO.ont00001180), (EX.Assess, RDF.type, C("RiskAssessment")), (EX.Assess, C("assessesOrganization"), EX.Org),
  (EX.Assess, C("assessmentFactor"), Literal("1000", datatype=XSD.decimal)), (EX.Assess, C("assessmentHorizon"), Literal("next 12 months")),
  (EX.Assess, C("usesCalculationMethod"), C("MethodCRG_v1_0c")),
  (EX.Appetite, RDF.type, C("RiskAppetiteStatement")), (EX.Appetite, C("numericValue"), Literal("0.30", datatype=XSD.decimal)),
  (EX.Assess, C("hasRiskAppetite"), EX.Appetite))
# evidence
A((EX.E2, RDF.type, C("EvidenceItem")), (EX.E2, C("localIdentifier"), Literal("E2")), (EX.E2, C("hasEvidenceBasis"), C("EvDocumented")),
  (EX.E2, C("evidenceLocator"), Literal("Incident exercise or incident records")))
# assets and valuation
A((EX.IdP, RDF.type, C("SoftwareAsset")), (EX.CoreRecords, RDF.type, C("InformationAsset")), (EX.CoreRecords, C("dependsOn"), EX.IdP),
  (EX.Val1, RDF.type, C("AssetValuation")), (EX.Val1, C("valuationOf"), EX.IdP), (EX.Val1, C("valuedBy"), EX.Org),
  (EX.Val1, C("isCrownJewel"), Literal(True)), (EX.Val1, C("hasConfidentialityRequirement"), C("ReqVeryHigh")))
# threat source, vulnerability, scenario
A((EX.Actor, RDF.type, CCO.ont00001017), (EX.ActorRole, RDF.type, C("ThreatSourceRole")), (EX.ActorRole, BFO.BFO_0000197, EX.Actor),
  (EX.ActorRole, C("hasThreatSourceType"), C("SrcAdversarial")),
  (EX.PushMFA, RDF.type, C("Vulnerability")), (EX.PushMFA, C("weaknessOf"), EX.IdP),
  (EX.Phish, RDF.type, C("ThreatEventDescription")),
  (EX.S1, RDF.type, C("AssessmentScenario")), (EX.S1, C("localIdentifier"), Literal("S1")),
  (EX.S1, C("statement"), Literal("A financially motivated external actor phishes administrators...", lang="en")),
  (EX.S1, C("initiatedBy"), EX.Actor), (EX.S1, C("hasThreatEvent"), EX.Phish), (EX.S1, C("exploits"), EX.PushMFA),
  (EX.S1, C("affectsAsset"), EX.IdP), (EX.S1, C("affectsAsset"), EX.CoreRecords), (EX.S1, C("hasDisposition"), C("DispSelect")),
  (EX.Assess, C("includesScenario"), EX.S1),
  (EX.Cons1, RDF.type, C("ConsequenceDescription")), (EX.Cons1, C("hasImpactDimension"), C("DimConfidentiality")), (EX.S1, C("hasConsequence"), EX.Cons1),
  (EX.Step1, RDF.type, C("ScenarioStep")), (EX.Step1, C("stepOrder"), Literal(1)), (EX.Step2, RDF.type, C("ScenarioStep")),
  (EX.Step2, C("stepOrder"), Literal(2)), (EX.Step1, C("nextStep"), EX.Step2), (EX.S1, C("hasStep"), EX.Step1), (EX.S1, C("hasStep"), EX.Step2))
# control measure in place
A((EX.MFA, RDF.type, C("ControlMeasure")), (EX.MFA, C("hasControlStatus"), C("CtlInPlace")), (EX.MFA, C("hasEvidence"), EX.E2),
  (EX.MFA, C("protectsAsset"), EX.IdP), (EX.S1, C("mitigatedBy"), EX.MFA))
# parameters
for k, v in [("ThreatPresence", "0.85"), ("ExploitationProbability", "0.55"), ("ExpectedDamage", "0.55"), ("MaximumDamage", "0.85"),
             ("Resilience", "0.40"), ("Criticality", "0.85"), ("ProbabilityReduction", "0.80"), ("ImpactReduction", "0.75")]:
    e = EX["S1-" + k]
    A((e, RDF.type, C(k)), (e, C("estimateOf"), EX.S1), (e, C("assessedIn"), EX.Assess), (e, C("numericValue"), Literal(v, datatype=XSD.decimal)),
      (e, C("onScale"), C("ScaleUnitInterval")), (e, C("hasConfidence"), C("ConfMedium")), (e, C("hasEvidence"), EX.E2),
      (e, C("hasRiskStage"), C("StageInherent")))
A((EX["S1-CVSS"], RDF.type, C("CVSSInput")), (EX["S1-CVSS"], C("estimateOf"), EX.S1), (EX["S1-CVSS"], C("cvssVersion"), Literal("4.0")),
  (EX["S1-CVSS"], C("cvssVector"), Literal("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:H/VI:H/VA:N/SC:H/SI:L/SA:L")))
# computed quantities with provenance (values deliberately omitted: computed by crg_calc.py in Phase 3)
A((EX.Calc1, RDF.type, C("CalculationActivity")), (EX.Calc1, C("usesMethod"), C("MethodCRG_v1_0c")))
for k in ["EstimatedRisk", "ToleratedRisk", "ResidualRisk", "RiskToToleranceRatio"]:
    e = EX["S1-" + k]
    A((e, RDF.type, C(k)), (e, C("estimateOf"), EX.S1), (e, C("generatedBy"), EX.Calc1), (e, C("usedInput"), EX["S1-ThreatPresence"]))
A((EX["S1-RiskToToleranceRatio"], C("hasToleranceClassification"), C("TolAbove")))
# initiative, allocation, KRI, treatment decision, acceptance
A((EX.I01, RDF.type, C("TreatmentInitiative")), (EX.I01, C("addresses"), EX.S1), (EX.I01, C("initialCost"), Literal("180000", datatype=XSD.decimal)),
  (EX.I01, C("recurringCost"), Literal("60000", datatype=XSD.decimal)), (EX.I01, C("hasPriority"), C("PrioImmediate")), (EX.I01, C("hasControlFunction"), C("FnPrevention")),
  (EX.Alloc1, RDF.type, C("CostAllocation")), (EX.Alloc1, C("allocationOf"), EX.I01), (EX.Alloc1, C("allocatedTo"), EX.S1),
  (EX.KRI01, RDF.type, C("KeyRiskIndicator")), (EX.KRI01, C("monitors"), EX.S1), (EX.KRI01, C("targetValue"), Literal("100%")),
  (EX.Dec1, RDF.type, C("RiskAcceptance")), (EX.S1, C("hasTreatmentDecision"), EX.Dec1), (EX.Dec1, C("hasTreatmentOption"), C("TreatRetain")),
  (EX.Dec1, C("expiryDate"), Literal("2027-10-08T00:00:00", datatype=XSD.dateTime)))
# library scenario pattern (no organisation): descriptions and categories only
A((EX.L1, RDF.type, C("LibraryScenario")), (EX.L1, C("localIdentifier"), Literal("LIB-0001")),
  (EX.TSD1, RDF.type, C("ThreatSourceDescription")), (EX.TSD1, C("hasThreatSourceType"), C("SrcAccidental")),
  (EX.VD1, RDF.type, C("VulnerabilityDescription")), (EX.Gap1, RDF.type, C("ControlGap")), (EX.Ctl1, RDF.type, C("Control")),
  (EX.Gap1, C("missingControl"), EX.Ctl1), (EX.L1, C("hasThreatSourceDescription"), EX.TSD1), (EX.L1, C("hasVulnerabilityDescription"), EX.VD1),
  (EX.L1, C("hasControlGap"), EX.Gap1), (EX.L1, C("affectsAssetCategory"), C("CatFacility")), (EX.S1, C("refines"), EX.L1),
  (EX.VD1, C("weaknessOf"), EX.IdP), (EX.Svc, RDF.type, C("ServiceAsset")), (EX.IdP, C("dependsOn"), EX.Svc), (EX.Svc, C("providedBy"), EX.Org),
  (EX.CE1, RDF.type, C("ControlEffectiveness")), (EX.CE1, C("estimateOf"), EX.MFA), (EX.CE1, C("numericValue"), Literal("0.6", datatype=XSD.decimal)))
g.serialize(os.path.join(ROOT, "tests", "fixtures", "crg-template-s1.ttl"), format="turtle")

# negative fixtures: each must make the ontology inconsistent
neg = {
  "neg-information-is-hardware.ttl": [(EX.X, RDF.type, C("InformationAsset")), (EX.X, RDF.type, C("HardwareAsset"))],
  "neg-scenario-is-process.ttl": [(EX.Y, RDF.type, C("RiskScenario")), (EX.Y, RDF.type, C("BusinessProcess"))],
  "neg-role-is-asset-object.ttl": [(EX.Z, RDF.type, C("ThreatSourceRole")), (EX.Z, RDF.type, C("HardwareAsset"))],
}
for name, triples in neg.items():
    h = base()
    for t in triples: h.add(t)
    h.serialize(os.path.join(ROOT, "tests", "fixtures", name), format="turtle")
print("fixtures written")
