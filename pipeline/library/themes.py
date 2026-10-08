# -*- coding: utf-8 -*-
"""Controlled list of scenario themes for the CRGO scenario library, and the rules that map the
225 free-text categories of the 2023 generator (and, for 'Undetermined' rows, the scenario name)
onto it. Order matters: the first theme whose pattern matches wins."""
import re

# key, English label, French label, English definition, French definition, regex on lower-cased text
THEMES = [
 ("ThemeMedicalIoT", "IoT, OT and medical devices", "IdO, TO et dispositifs médicaux",
  "Scenarios about connected devices, operational technology, medical equipment, wearables and building systems.",
  "Scénarios touchant les objets connectés, la technologie opérationnelle, l'équipement médical, les dispositifs portables et les systèmes du bâtiment.",
  r"\biot\b|internet of things|medical (device|equipment)|wearable|operational technology|\bot\b|scada|industrial control|haptic|robotic|3d print|microgrid|energy|power|smart (building|device)|infusion|pacemaker|implant|\bmri\b|imaging device|telemetry|biomedical|hvac"),
 ("ThemeEmerging", "emerging technologies", "technologies émergentes",
  "Scenarios driven by new technologies such as AI and machine learning, blockchain, quantum computing, extended reality, nanotechnology or 5G network slicing.",
  "Scénarios liés aux technologies nouvelles comme l'IA et l'apprentissage automatique, la chaîne de blocs, l'informatique quantique, la réalité étendue, la nanotechnologie ou le découpage réseau 5G.",
  r"artificial intelligence|\bai\b|machine learning|\bml\b|deepfake|blockchain|distributed ledger|decentrali[sz]ed|quantum|augmented|virtual reality|\bvr\b|\bar\b|nanotech|cognitive computing|emerging tech|next-generation|future-proof|network slicing|voice-activated|smart contract|chatbot"),
 ("ThemeCrypto", "cryptography and key management", "cryptographie et gestion des clés",
  "Scenarios about weak, broken or mismanaged encryption, certificates, digital signatures and keys.",
  "Scénarios touchant un chiffrement faible, compromis ou mal géré, les certificats, les signatures numériques et les clés.",
  r"crypt|digital signature|certificate|\bpki\b|\bkey management\b|\bssl\b|\btls\b|data-at-rest|masking|anonymi[sz]ation"),
 ("ThemeRansomware", "malware and ransomware", "maliciels et rançongiciels",
  "Scenarios in which malicious software, including ransomware, worms and trojans, compromises systems or data.",
  "Scénarios où un logiciel malveillant, dont les rançongiciels, vers et chevaux de Troie, compromet des systèmes ou des données.",
  r"malware|ransom|virus|worm|trojan|spyware|keylogger|botnet|rootkit|cryptojack|malicious software|logical attacks"),
 ("ThemeSocialEng", "phishing and social engineering", "hameçonnage et ingénierie sociale",
  "Scenarios that manipulate people into revealing information or performing actions, through phishing, pretexting or impersonation.",
  "Scénarios qui manipulent des personnes pour obtenir de l'information ou une action, par hameçonnage, prétexte ou usurpation d'identité.",
  r"phish|social engineering|pretext|impersonat|vishing|smishing|whaling|watering hole|baiting|business email compromise|\bbec\b|psychological|fraud|identity theft"),
 ("ThemeDoS", "denial of service and availability", "déni de service et disponibilité",
  "Scenarios that make systems or services unavailable through denial-of-service attacks, capacity failures or outages.",
  "Scénarios qui rendent des systèmes ou des services indisponibles par déni de service, défaillance de capacité ou panne.",
  r"denial[- ]of[- ]service|\bddos\b|\bdos\b|outage|downtime|load balancer|redundancy|availability|time synchroni|time-based"),
 ("ThemeInsider", "insider threat and human error", "menace interne et erreur humaine",
  "Scenarios caused by staff, contractors or other insiders, whether malicious or accidental, including mistakes, negligence and lack of training.",
  "Scénarios causés par le personnel, des contractuels ou d'autres initiés, malveillants ou non, y compris les erreurs, la négligence et le manque de formation.",
  r"insider|internal threat|human (error|factor)|employee|staff|negligen|training|awareness|disgruntled|industrial action|strike|human resources|cultural|language|helpdesk|it expertise|skills"),
 ("ThemeAccess", "identity and access", "identité et accès",
  "Scenarios about authentication, authorisation, privileged access and identity management failures leading to unauthorised access.",
  "Scénarios touchant l'authentification, l'autorisation, les accès privilégiés et la gestion des identités, menant à des accès non autorisés.",
  r"access control|unauthori[sz]ed access|authenticat|password|credential|privilege|identity|federated|single sign|\bsso\b|\bmfa\b|two-factor|zero trust|session|account|revoke access|access rights"),
 ("ThemeThirdParty", "third-party and supply chain", "tiers et chaîne d'approvisionnement",
  "Scenarios originating in suppliers, outsourcers, vendors, open-source components or other parts of the supply chain.",
  "Scénarios qui proviennent de fournisseurs, d'impartiteurs, de composants libres ou d'autres maillons de la chaîne d'approvisionnement.",
  r"third[- ]party|supply chain|supplier|vendor|outsourc|open source|contractual|external partner"),
 ("ThemeCloud", "cloud, virtualisation and data platforms", "infonuagique, virtualisation et plateformes de données",
  "Scenarios in cloud services, SaaS, IaaS/PaaS, virtualisation, containers, serverless computing, data lakes and big-data platforms.",
  "Scénarios dans les services infonuagiques, SaaS, IaaS/PaaS, la virtualisation, les conteneurs, l'informatique sans serveur, les lacs de données et le big data.",
  r"cloud|distributed systems|saas|iaas|paas|virtuali[sz]|container|serverless|hyper-converged|data lake|warehouse|big data|analytics|microservice|virtual private cloud|storage|file storage|data center"),
 ("ThemeVulnMgmt", "legacy, patch and configuration management", "désuétude, correctifs et gestion de configuration",
  "Scenarios caused by unpatched, end-of-life or misconfigured systems, and by weak vulnerability and change management.",
  "Scénarios causés par des systèmes non corrigés, en fin de vie ou mal configurés, et par une gestion déficiente des vulnérabilités et des changements.",
  r"legacy|obsolete|end of life|patch|misconfigur|configuration|change management|vulnerabilit|asset management|os-level|shadow it|policy failures|poorly managed controls"),
 ("ThemeAppSec", "applications and software development", "applications et développement logiciel",
  "Scenarios about insecure applications, APIs, web services and software development practices, including injection flaws and insecure code.",
  "Scénarios touchant les applications, API et services web non sécurisés et les pratiques de développement, dont les injections et le code non sécurisé.",
  r"application|\bapi\b|apis|web service|software|secure coding|code|injection|sql|xss|cross-site|website|web app|cms|content management|document management|search engine|webrtc|collaboration|e-?mail|database|non-relational|payment system|financial system|integration|process automation"),
 ("ThemeNetwork", "networks and remote access", "réseaux et accès à distance",
  "Scenarios in networks, wireless, VPN and remote access, firewalls and intrusion detection, telecommunications and network architecture.",
  "Scénarios dans les réseaux, le sans-fil, le RPV et l'accès à distance, les pare-feu et la détection d'intrusion, les télécommunications et l'architecture réseau.",
  r"network|wireless|wi-?fi|\bvpn\b|remote access|firewall|ids|ips|telecom|voice and data|man-in-the-middle|eavesdrop|dns|domain|transmission|transfer|secure communication|internal communication|bluetooth|air-gapped|telemedicine"),
 ("ThemeEndpoint", "endpoints and mobile", "postes de travail et mobilité",
  "Scenarios on workstations, laptops, mobile devices and applications, removable media, printers and scanners.",
  "Scénarios touchant les postes de travail, les portables, les appareils et applications mobiles, les supports amovibles, les imprimantes et les numériseurs.",
  r"endpoint|mobile|laptop|workstation|byod|usb|removable|printer|scanner|print and scan|tablet|smartphone|device theft|theft of a device|audio-visual|multimedia|geolocation"),
 ("ThemeDataBreach", "data breach and exfiltration", "fuite et exfiltration de données",
  "Scenarios in which confidential or personal information is disclosed, leaked or exfiltrated.",
  "Scénarios où de l'information confidentielle ou personnelle est divulguée, fuit ou est exfiltrée.",
  r"data breach|data security|breach|exfiltrat|leak|disclos|data loss|privacy|personal (data|information)|patient (data|records?|information)|medical record|confidential|profiling|behavio"),
 ("ThemeIntegrity", "data integrity and manipulation", "intégrité et manipulation des données",
  "Scenarios in which data or records are altered, corrupted or falsified.",
  "Scénarios où des données ou des dossiers sont modifiés, corrompus ou falsifiés.",
  r"integrity|tamper|manipulat|alter|corrupt|falsif|log and monitoring|logging"),
 ("ThemeAPT", "advanced and multi-vector attacks", "attaques avancées et multivectorielles",
  "Scenarios conducted by persistent, well-resourced or state-linked adversaries, or combining several attack vectors.",
  "Scénarios menés par des adversaires persistants, bien dotés ou liés à des États, ou combinant plusieurs vecteurs d'attaque.",
  r"advanced persistent|\bapt\b|multi-vector|hybrid attack|nation[- ]state|state-sponsored|exfiltration techniques|evolution"),
 ("ThemePhysical", "physical and environmental", "physique et environnemental",
  "Scenarios caused by physical intrusion, theft or destruction of equipment, natural events, fire, flood or loss of utilities.",
  "Scénarios causés par une intrusion physique, le vol ou la destruction d'équipement, un événement naturel, un incendie, une inondation ou la perte de services publics.",
  r"physical|theft|destruction|acts of nature|natural|fire|flood|earthquake|storm|weather|environmental|geographical|facility|infrastructure theft"),
 ("ThemeContinuity", "continuity and incident response", "continuité et réponse aux incidents",
  "Scenarios about inadequate backup, disaster recovery, business continuity, incident response or forensic capability.",
  "Scénarios touchant des sauvegardes, une reprise après sinistre, une continuité des activités, une réponse aux incidents ou une capacité d'enquête numérique insuffisantes.",
  r"continuity|disaster recovery|backup|incident response|forensic|recovery|resilien"),
 ("ThemeCompliance", "governance, compliance and legal", "gouvernance, conformité et aspects juridiques",
  "Scenarios about regulatory non-compliance, legal liability, audit findings, policy gaps and intellectual property.",
  "Scénarios touchant la non-conformité réglementaire, la responsabilité juridique, les constats d'audit, les lacunes de politiques et la propriété intellectuelle.",
  r"compliance|regulat|legal|\blaw\b|audit|policy|intellectual property|geopolitic|risk management"),
 ("ThemeITGov", "IT management and investment", "gestion et investissement en TI",
  "Scenarios about IT governance and management: portfolio, programme and project management, architecture, investment decisions, budgets, ownership of IT and innovation.",
  "Scénarios touchant la gouvernance et la gestion des TI : portefeuille, programmes et projets, architecture, décisions d'investissement, budgets, appropriation des TI par l'entreprise et innovation.",
  r"portfolio|program|project|architecture|investment|budget|business ownership|innovation|digital transformation|research and development|organizational process|operational risks|infrastructure|software$"),
 ("ThemeReputation", "reputation and external communication", "réputation et communications externes",
  "Scenarios about social media, public relations and external communications that damage reputation or trust.",
  "Scénarios touchant les médias sociaux, les relations publiques et les communications externes qui nuisent à la réputation ou à la confiance.",
  r"social media|public relations|reputation|external communication|patient interaction"),
 ("ThemeOther", "other or unclassified", "autre ou non classé",
  "Scenarios that do not fit another theme, or whose theme could not be determined.",
  "Scénarios qui ne relèvent d'aucun autre thème ou dont le thème n'a pu être déterminé.",
  r"miscellaneous"),
]

def norm_category(c):
    c = re.sub(r"\s+", " ", str(c).replace("\xa0", " ")).strip()
    return c.replace("t ermination", "termination")

# For scenario names, the kind of event decides first; for category labels, the list order above.
EVENT_FIRST = ["ThemeRansomware", "ThemeSocialEng", "ThemeDoS", "ThemeThirdParty", "ThemeInsider",
               "ThemeDataBreach", "ThemeIntegrity", "ThemePhysical", "ThemeAPT"]

def theme_of(text, event_first=False):
    t = norm_category(text).lower()
    order = THEMES
    if event_first:
        order = sorted(THEMES, key=lambda th: EVENT_FIRST.index(th[0]) if th[0] in EVENT_FIRST else len(EVENT_FIRST))
    for key, *_rest, pat in order:
        if re.search(pat, t):
            return key
    return "ThemeOther"
