# LLM-Assisted Threat Modeling - STRIDE Methodology

> **Objectif** : Modélisation de menaces assistée par LLM utilisant la méthodologie STRIDE. Produit un threat model structuré avec identification des trust boundaries, menaces par composant, scoring likelihood/impact, et mitigations priorisées. Applicable aux applications web, APIs, microservices, applications mobiles, systèmes IoT, et infrastructures cloud.

---

## System Prompt

```
Tu es un architecte sécurité senior spécialisé en threat modeling, avec 15+ années d'expérience dans la modélisation de menaces pour des systèmes critiques (finance, santé, infrastructure, défense). Tu maîtrises les méthodologies STRIDE, PASTA, LINDDUN, et Attack Trees. Tu as formé des équipes de développement au threat modeling et conduit des centaines de sessions de modélisation.

Tu appliques la méthodologie STRIDE de manière systématique et rigoureuse :
- **S**poofing : usurpation d'identité (violation d'authentification)
- **T**ampering : altération de données (violation d'intégrité)
- **R**epudiation : déni d'action (violation de non-répudiation)
- **I**nformation Disclosure : fuite d'information (violation de confidentialité)
- **D**enial of Service : déni de service (violation de disponibilité)
- **E**levation of Privilege : escalade de privilèges (violation d'autorisation)

Tu es pragmatique : tu produis des threat models ACTIONNABLES, pas des documents académiques. Chaque menace identifiée est accompagnée de mitigations concrètes et priorisées. Tu te concentres sur les menaces les plus réalistes et les plus impactantes, pas sur des scénarios exotiques à faible probabilité.

Tu ne devines PAS l'architecture quand l'information est insuffisante. Tu demandes des clarifications plutôt que d'inventer des composants.
```

---

## User Prompt

```xml
<context>
Mission : Threat modeling d'une application/système.
Nom du système : {{SYSTEM_NAME}}
Type de système : {{SYSTEM_TYPE}}  <!-- web_app | api | microservices | mobile_app | iot | desktop | infrastructure | saas_platform -->
Phase du projet : {{PROJECT_PHASE}}  <!-- design | development | pre_launch | production | incident_response -->
Criticité business : {{BUSINESS_CRITICALITY}}  <!-- critical | high | medium | low -->
Données traitées : {{DATA_TYPES}}  <!-- pii | phi | financial | credentials | public | internal | classified -->
Utilisateurs : {{USER_BASE}}  <!-- internal_only | b2b | b2c | public | mixed -->
Conformité : {{COMPLIANCE}}  <!-- pci_dss | hipaa | soc2 | gdpr | iso27001 | none -->
</context>

<target>
=== Architecture Description ===
{{ARCHITECTURE_DESCRIPTION}}
<!-- Description textuelle de l'architecture : composants, interactions, protocoles, flux de données.
     Inclure autant de détails que possible :
     - Composants (frontend, backend, BDD, cache, message queue, services tiers)
     - Protocoles (HTTPS, gRPC, WebSocket, AMQP, etc.)
     - Mécanismes d'authentification (JWT, OAuth2, SAML, API keys, mTLS)
     - Points d'entrée (web UI, API publique, API interne, webhooks, CLI)
     - Stockage de données (types de BDD, stockage fichiers, cache)
     - Infrastructure (cloud provider, CDN, load balancer, WAF)
-->

=== Technology Stack ===
{{TECH_STACK}}
<!-- Liste détaillée : langages, frameworks, bases de données, services cloud, outils de CI/CD -->

=== Data Flow Description ===
{{DATA_FLOW}}
<!-- Description des flux de données principaux :
     - Flux d'authentification (login, token refresh, SSO)
     - Flux de données utilisateur (CRUD, upload, export)
     - Flux de paiement (si applicable)
     - Flux inter-services (communication interne)
     - Flux de données vers des tiers (API externes, analytics, logs)
-->

=== Existing Security Controls ===
{{EXISTING_CONTROLS}}
<!-- Contrôles de sécurité déjà en place :
     - WAF, rate limiting, CAPTCHA
     - Chiffrement (at rest, in transit)
     - Logging/monitoring (SIEM, alerting)
     - Access control (RBAC, ABAC)
     - Secrets management
     - Vulnerability scanning
-->

=== Known Concerns ===
{{KNOWN_CONCERNS}}
<!-- Préoccupations spécifiques à investiguer, incidents passés, zones de risque identifiées -->
</target>

<instructions>
Produis un threat model complet en suivant STRICTEMENT les 6 étapes ci-dessous. Tu DOIS raisonner dans un block <thinking> pour chaque étape avant de produire le résultat final.

## ÉTAPE 1 : Décomposition du Système

Identifie et cartographie :

1. **Composants** : Chaque composant logique du système
   - Nom, type (frontend, backend, database, cache, queue, external service, CDN, load balancer)
   - Technologie utilisée
   - Niveau de confiance (trusted | semi-trusted | untrusted)
   - Données traitées (types et sensibilité)

2. **Points d'entrée (Entry Points)** : Chaque interface où des données entrent dans le système
   - Type (web UI, REST API, GraphQL, WebSocket, webhook, CLI, file upload, email)
   - Authentification requise (none | api_key | jwt | oauth2 | mtls | basic_auth)
   - Exposition (internet | internal_network | localhost)

3. **Assets** : Données et ressources de valeur
   - Données utilisateur (PII, credentials, sessions)
   - Données business (transactions, propriété intellectuelle)
   - Infrastructure (compute, storage, secrets)
   - Réputation (disponibilité du service, confiance des utilisateurs)

4. **Trust Boundaries** : Frontières de confiance entre les composants
   - Internet ↔ DMZ (load balancer, WAF, CDN)
   - DMZ ↔ Application tier (frontend, API gateway)
   - Application tier ↔ Data tier (databases, cache, file storage)
   - Application ↔ Third-party services (APIs externes, SaaS)
   - User device ↔ Server
   - Service-to-service boundaries (microservices)

## ÉTAPE 2 : Analyse STRIDE par Composant

Pour CHAQUE composant identifié à l'étape 1, évalue systématiquement les 6 catégories STRIDE :

### Spoofing (Usurpation d'identité)
Questions à poser :
- Un attaquant peut-il se faire passer pour un utilisateur légitime ?
- Un attaquant peut-il se faire passer pour un service interne ?
- Les tokens/sessions sont-ils forgables ou rejouables ?
- Le mécanisme d'authentification peut-il être contourné ?
- DNS spoofing / ARP spoofing peuvent-ils affecter les communications inter-services ?

### Tampering (Altération de données)
Questions à poser :
- Un attaquant peut-il modifier les données en transit ?
- Un attaquant peut-il modifier les données au repos (DB, fichiers) ?
- Les paramètres de requête peuvent-ils être altérés (parameter tampering) ?
- Les messages inter-services peuvent-ils être modifiés (MITM) ?
- L'intégrité des fichiers uploadés est-elle vérifiée ?
- Les logs peuvent-ils être falsifiés ?

### Repudiation (Déni d'action)
Questions à poser :
- Les actions critiques sont-elles journalisées de manière fiable ?
- Les logs sont-ils protégés contre la falsification ?
- Un utilisateur peut-il nier avoir effectué une transaction ?
- Les horodatages sont-ils fiables (NTP, sources de temps trustées) ?
- Y a-t-il des audit trails pour les opérations administratives ?

### Information Disclosure (Fuite d'information)
Questions à poser :
- Des données sensibles sont-elles exposées dans les messages d'erreur ?
- Les communications sont-elles chiffrées en transit et au repos ?
- Les logs contiennent-ils des données sensibles (tokens, passwords, PII) ?
- Les API renvoient-elles plus de données que nécessaire (over-fetching) ?
- Les métadonnées (headers, versions) révèlent-elles des informations utiles à un attaquant ?
- Les backups et caches sont-ils protégés ?
- Les side channels (timing, error messages) leak-ils des informations ?

### Denial of Service (Déni de service)
Questions à poser :
- Les endpoints ont-ils du rate limiting ?
- Les requêtes coûteuses (recherche, export, upload) sont-elles limitées ?
- Le système est-il résilient aux pics de charge (auto-scaling) ?
- Les dépendances externes sont-elles des single points of failure ?
- Les ressources (CPU, mémoire, disque) peuvent-elles être épuisées par un attaquant ?
- Les regex sont-elles vulnérables au ReDoS ?
- Les parseurs XML sont-ils vulnérables aux billion laughs / XXE ?

### Elevation of Privilege (Escalade de privilèges)
Questions à poser :
- Un utilisateur standard peut-il accéder aux fonctionnalités admin ?
- Les autorisations sont-elles vérifiées côté serveur (pas seulement côté client) ?
- Les IDOR (Insecure Direct Object References) sont-ils possibles ?
- Un service peut-il être utilisé pour pivoter vers d'autres services ?
- Les rôles et permissions sont-ils correctement implémentés (RBAC/ABAC) ?
- L'injection (SQLi, CMDi, SSTI) peut-elle mener à une exécution privilégiée ?

## ÉTAPE 3 : Scoring des Menaces

Pour chaque menace identifiée, évalue :

1. **Likelihood** (probabilité qu'un attaquant tente ET réussisse l'exploitation) :
   - `Critical` : Exploitation triviale, attaquants automatisés, pas de contrôle en place
   - `High` : Exploitation connue, skill modéré requis, contrôles partiels
   - `Medium` : Exploitation nécessite du skill et/ou des conditions spécifiques
   - `Low` : Exploitation très complexe, conditions très spécifiques, contrôles forts

2. **Impact** (conséquences en cas d'exploitation réussie) :
   - `Critical` : Compromission complète, perte de données massive, arrêt total du service
   - `High` : Accès non autorisé large, perte de données significative, service dégradé
   - `Medium` : Accès limité, perte de données partielle, impact localisé
   - `Low` : Impact minimal, données non sensibles, récupération facile

3. **Risk Level** = combinaison Likelihood x Impact :

   |                    | Impact Critical | Impact High | Impact Medium | Impact Low |
   |--------------------|-----------------|-------------|---------------|------------|
   | Likelihood Critical | Critical        | Critical    | High          | Medium     |
   | Likelihood High     | Critical        | High        | High          | Medium     |
   | Likelihood Medium   | High            | High        | Medium        | Low        |
   | Likelihood Low      | Medium          | Medium      | Low           | Low        |

## ÉTAPE 4 : Identification des Mitigations

Pour chaque menace, identifie :

1. **Mitigations déjà en place** (d'après les contrôles existants fournis)
2. **Mitigations recommandées** avec :
   - Priorité (P0 = immédiat, P1 = court terme, P2 = moyen terme, P3 = long terme)
   - Effort (low, medium, high)
   - Efficacité estimée (haute réduction de risque, moyenne, faible)
3. **Risque résiduel** après application des mitigations recommandées

## ÉTAPE 5 : Identification des Attack Paths

Identifie les chemins d'attaque les plus critiques qui chaînent plusieurs menaces :
- Chemin complet : entry point → vulnérabilité 1 → pivot → vulnérabilité 2 → impact final
- Probabilité du chemin complet
- Impact du scénario bout-en-bout

## ÉTAPE 6 : Priorisation et Recommandations

Produis une liste priorisée d'actions :
1. Actions immédiates (P0) — menaces Critical avec mitigations manquantes
2. Actions court terme (P1) — menaces High avec mitigations partielles
3. Actions moyen terme (P2) — menaces Medium, hardening
4. Actions long terme (P3) — améliorations architecturales

Produis le résultat UNIQUEMENT au format JSON spécifié ci-dessous.
</instructions>

<output_format>
{
  "threat_model": {
    "metadata": {
      "system_name": "<nom du système>",
      "system_type": "<type>",
      "methodology": "STRIDE",
      "business_criticality": "Critical | High | Medium | Low",
      "data_classification": "<types de données>",
      "compliance_requirements": ["<frameworks>"],
      "model_version": "1.0",
      "timestamp": "<ISO 8601>",
      "analyst_notes": "Notes et hypothèses faites pendant l'analyse"
    },
    "system_decomposition": {
      "components": [
        {
          "id": "COMP-001",
          "name": "Nom du composant",
          "type": "frontend | backend | database | cache | queue | external_service | cdn | load_balancer | api_gateway | identity_provider | file_storage | monitoring",
          "technology": "Technologie utilisée",
          "trust_level": "trusted | semi-trusted | untrusted",
          "data_handled": [
            {
              "type": "Type de données",
              "sensitivity": "public | internal | confidential | restricted",
              "operations": ["read", "write", "process", "store", "transmit"]
            }
          ],
          "exposure": "internet | internal_network | localhost",
          "authentication_mechanism": "none | api_key | jwt | oauth2 | mtls | basic_auth | session_cookie"
        }
      ],
      "entry_points": [
        {
          "id": "EP-001",
          "name": "Nom du point d'entrée",
          "type": "web_ui | rest_api | graphql | websocket | webhook | cli | file_upload | email | grpc",
          "url_pattern": "/api/v1/endpoint ou N/A",
          "authentication_required": true | false,
          "authentication_type": "type d'auth",
          "authorization_level": "public | authenticated | admin | service",
          "protocol": "HTTPS | HTTP | gRPC | WSS | AMQP",
          "data_input": "Types de données acceptées en entrée"
        }
      ],
      "assets": [
        {
          "id": "ASSET-001",
          "name": "Nom de l'asset",
          "type": "data | infrastructure | reputation | financial",
          "sensitivity": "public | internal | confidential | restricted",
          "description": "Description et valeur de l'asset",
          "stored_in": ["COMP-XXX"],
          "processed_by": ["COMP-XXX"],
          "transmitted_between": ["COMP-XXX → COMP-YYY"]
        }
      ],
      "trust_boundaries": [
        {
          "id": "TB-001",
          "name": "Nom de la frontière de confiance",
          "description": "Description de la frontière",
          "between": ["COMP-XXX (trust_level)", "COMP-YYY (trust_level)"],
          "crossing_protocols": ["HTTPS", "gRPC"],
          "authentication_at_boundary": "Type d'auth à cette frontière",
          "encryption_at_boundary": "TLS 1.3, mTLS, etc."
        }
      ],
      "data_flows": [
        {
          "id": "DF-001",
          "name": "Nom du flux de données",
          "description": "Description du flux",
          "from": "COMP-XXX",
          "to": "COMP-YYY",
          "data_types": ["types de données dans ce flux"],
          "protocol": "HTTPS | gRPC | TCP | AMQP",
          "encrypted": true | false,
          "authenticated": true | false,
          "crosses_trust_boundary": "TB-XXX ou null"
        }
      ]
    },
    "stride_analysis": [
      {
        "id": "THREAT-001",
        "stride_category": "Spoofing | Tampering | Repudiation | Information Disclosure | Denial of Service | Elevation of Privilege",
        "affected_component": "COMP-XXX",
        "affected_entry_point": "EP-XXX ou null",
        "affected_data_flow": "DF-XXX ou null",
        "affected_asset": "ASSET-XXX",
        "trust_boundary_crossed": "TB-XXX ou null",
        "threat_title": "Titre concis de la menace",
        "threat_description": "Description détaillée du scénario de menace",
        "attack_vector": "Comment l'attaquant exploiterait cette menace concrètement",
        "threat_actor": "external_attacker | authenticated_user | malicious_insider | compromised_service | automated_bot",
        "likelihood": "Critical | High | Medium | Low",
        "likelihood_justification": "Pourquoi ce niveau de likelihood",
        "impact": "Critical | High | Medium | Low",
        "impact_justification": "Pourquoi ce niveau d'impact",
        "risk_level": "Critical | High | Medium | Low",
        "existing_mitigations": [
          {
            "control": "Description du contrôle existant",
            "effectiveness": "High | Medium | Low | None",
            "gaps": "Lacunes identifiées dans ce contrôle"
          }
        ],
        "recommended_mitigations": [
          {
            "mitigation": "Description de la mitigation recommandée",
            "priority": "P0 | P1 | P2 | P3",
            "effort": "Low | Medium | High",
            "effectiveness": "High | Medium | Low",
            "implementation_guidance": "Guidance concrète d'implémentation"
          }
        ],
        "residual_risk_after_mitigations": "Critical | High | Medium | Low | Minimal",
        "related_threats": ["THREAT-XXX — pour les chaînages"],
        "references": ["CWE-XXX", "OWASP reference", "etc."]
      }
    ],
    "attack_paths": [
      {
        "id": "APATH-001",
        "name": "Nom du chemin d'attaque",
        "description": "Description du scénario bout-en-bout",
        "threat_actor": "Type d'attaquant",
        "steps": [
          {
            "step": 1,
            "action": "Action de l'attaquant",
            "exploits_threat": "THREAT-XXX",
            "prerequisite": "Condition préalable",
            "outcome": "Résultat de cette étape"
          }
        ],
        "final_impact": "Impact final du chemin complet",
        "overall_likelihood": "Critical | High | Medium | Low",
        "overall_risk": "Critical | High | Medium | Low",
        "key_mitigation_point": "La mitigation la plus efficace pour couper ce chemin"
      }
    ],
    "prioritized_actions": {
      "p0_immediate": [
        {
          "action": "Action à prendre immédiatement",
          "addresses_threats": ["THREAT-XXX"],
          "effort": "Low | Medium | High",
          "risk_reduction": "Description de la réduction de risque"
        }
      ],
      "p1_short_term": [
        {
          "action": "Action court terme (< 1 mois)",
          "addresses_threats": ["THREAT-XXX"],
          "effort": "Low | Medium | High",
          "risk_reduction": "Description de la réduction de risque"
        }
      ],
      "p2_medium_term": [
        {
          "action": "Action moyen terme (1-3 mois)",
          "addresses_threats": ["THREAT-XXX"],
          "effort": "Low | Medium | High",
          "risk_reduction": "Description de la réduction de risque"
        }
      ],
      "p3_long_term": [
        {
          "action": "Action long terme (3-6 mois) / amélioration architecturale",
          "addresses_threats": ["THREAT-XXX"],
          "effort": "Low | Medium | High",
          "risk_reduction": "Description de la réduction de risque"
        }
      ]
    },
    "summary": {
      "total_threats_identified": 0,
      "by_stride_category": {
        "spoofing": 0,
        "tampering": 0,
        "repudiation": 0,
        "information_disclosure": 0,
        "denial_of_service": 0,
        "elevation_of_privilege": 0
      },
      "by_risk_level": {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0
      },
      "total_attack_paths": 0,
      "most_critical_attack_path": "APATH-XXX — description",
      "total_components": 0,
      "total_trust_boundaries": 0,
      "total_entry_points": 0,
      "overall_security_posture": "Critical | Weak | Moderate | Good | Strong",
      "top_3_risks": [
        "Risque prioritaire 1",
        "Risque prioritaire 2",
        "Risque prioritaire 3"
      ],
      "key_architectural_concern": "La préoccupation architecturale principale qui nécessite le plus d'attention"
    }
  }
}
</output_format>

<constraints>
- N'INVENTE PAS de composants qui ne sont pas décrits dans l'architecture fournie. Si un composant est sous-entendu mais pas confirmé (ex: "il y a probablement un load balancer"), indique-le comme hypothèse dans analyst_notes.
- Si l'architecture fournie est trop vague pour produire un threat model utile, dis-le explicitement et demande des clarifications spécifiques plutôt que de deviner.
- Les menaces doivent être SPÉCIFIQUES au système décrit, pas des menaces génériques applicables à tout système web. "XSS est possible" n'est pas un bon threat — "XSS via le champ de commentaire utilisateur dans COMP-003 qui est rendu sans escaping dans COMP-001" en est un.
- Pour chaque menace, la likelihood doit refléter le contexte réel. Une SQLi sur un endpoint authentifié avec WAF n'a pas la même likelihood qu'une SQLi sur un endpoint public sans protection.
- Ne confonds PAS les mitigations existantes (déjà en place) avec les recommandations (à implémenter). Vérifie dans les existing_controls ce qui est déjà fait.
- Priorise les menaces qui traversent des trust boundaries — elles sont presque toujours plus critiques que les menaces intra-zone.
- Les attack paths doivent être RÉALISTES et utiliser des menaces déjà identifiées dans stride_analysis. Ne crée pas de menaces nouvelles uniquement pour les attack paths.
- Le threat model n'est pas un pentest report. Il identifie les menaces POTENTIELLES et les mitigations, pas des vulnérabilités confirmées avec PoC. Le langage doit refléter cette distinction.
- Si des contrôles de sécurité existants adressent correctement une catégorie STRIDE pour un composant, indique-le clairement (existing_mitigations avec effectiveness: High) plutôt que d'ignorer le contrôle pour gonfler le nombre de findings.
</constraints>

<examples>
Exemple de menace STRIDE (Spoofing — Authentication Bypass) :

{
  "id": "THREAT-001",
  "stride_category": "Spoofing",
  "affected_component": "COMP-002",
  "affected_entry_point": "EP-001",
  "affected_data_flow": "DF-001",
  "affected_asset": "ASSET-001",
  "trust_boundary_crossed": "TB-001",
  "threat_title": "JWT algorithm confusion allows authentication bypass on REST API",
  "threat_description": "Le backend API (COMP-002) utilise la bibliothèque jsonwebtoken pour vérifier les JWT. Si l'implémentation ne fixe pas explicitement l'algorithme attendu lors de la vérification (jwt.verify(token, key) sans option {algorithms: ['RS256']}), un attaquant peut forger un token valide en utilisant l'algorithme HS256 avec la clé publique RSA comme secret HMAC. Cela permet d'usurper l'identité de n'importe quel utilisateur, y compris les administrateurs.",
  "attack_vector": "1) L'attaquant récupère la clé publique RSA (souvent exposée via /.well-known/jwks.json ou dans le code source). 2) Il crée un JWT avec header {\"alg\":\"HS256\"} et un payload arbitraire (ex: {\"sub\":\"admin\",\"role\":\"admin\"}). 3) Il signe le token avec HMAC-SHA256 en utilisant la clé publique RSA comme secret. 4) Le serveur vérifie le token avec la clé publique, qui fonctionne à la fois comme clé publique RSA et comme secret HMAC. 5) Le token est accepté comme valide.",
  "threat_actor": "external_attacker",
  "likelihood": "High",
  "likelihood_justification": "L'attaque algorithm confusion est bien documentée, des outils automatisés existent (jwt_tool), et la clé publique est souvent accessible. Ne nécessite aucune authentification préalable.",
  "impact": "Critical",
  "impact_justification": "Usurpation totale d'identité. L'attaquant peut se faire passer pour n'importe quel utilisateur, y compris les administrateurs, ce qui donne accès à toutes les données et fonctionnalités du système.",
  "risk_level": "Critical",
  "existing_mitigations": [
    {
      "control": "JWT vérifié côté serveur (pas seulement côté client)",
      "effectiveness": "Low",
      "gaps": "La vérification ne fixe pas l'algorithme attendu, rendant l'attaque algorithm confusion possible"
    }
  ],
  "recommended_mitigations": [
    {
      "mitigation": "Fixer explicitement l'algorithme attendu lors de la vérification JWT : jwt.verify(token, publicKey, {algorithms: ['RS256']})",
      "priority": "P0",
      "effort": "Low",
      "effectiveness": "High",
      "implementation_guidance": "Modifier le middleware d'authentification pour ajouter l'option algorithms. Tester avec un token HS256 forgé pour vérifier que la protection est en place."
    },
    {
      "mitigation": "Migrer vers une bibliothèque JWT avec des defaults sécurisés (ex: jose) qui refuse les algorithmes non explicitement autorisés",
      "priority": "P1",
      "effort": "Medium",
      "effectiveness": "High",
      "implementation_guidance": "Remplacer jsonwebtoken par jose. Tester la compatibilité avec les tokens existants."
    }
  ],
  "residual_risk_after_mitigations": "Low",
  "related_threats": ["THREAT-005 — Elevation of Privilege si l'attaquant forge un token admin"],
  "references": ["CWE-287", "CWE-327", "https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/"]
}

Exemple d'Attack Path :

{
  "id": "APATH-001",
  "name": "SSRF to Cloud Credential Theft to Full Data Exfiltration",
  "description": "Un attaquant exploite un SSRF dans le service de génération de PDF pour accéder au metadata endpoint AWS, récupérer les credentials IAM du service, puis utiliser ces credentials pour accéder au bucket S3 contenant les données clients.",
  "threat_actor": "external_attacker",
  "steps": [
    {
      "step": 1,
      "action": "Exploiter le SSRF dans le endpoint /api/reports/generate en soumettant une URL interne comme template",
      "exploits_threat": "THREAT-003",
      "prerequisite": "Compte utilisateur authentifié avec accès à la génération de rapports",
      "outcome": "Accès au réseau interne depuis le serveur de l'application"
    },
    {
      "step": 2,
      "action": "Requêter le metadata endpoint AWS (169.254.169.254) pour récupérer les credentials IAM temporaires du rôle EC2/ECS",
      "exploits_threat": "THREAT-007",
      "prerequisite": "IMDSv1 activé ou IMDSv2 sans token hop limit",
      "outcome": "Obtention de AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN"
    },
    {
      "step": 3,
      "action": "Utiliser les credentials IAM pour lister et télécharger les objets du bucket S3 contenant les données clients",
      "exploits_threat": "THREAT-012",
      "prerequisite": "Le rôle IAM a des permissions s3:GetObject sur le bucket de données",
      "outcome": "Exfiltration complète des données clients (PII, données financières)"
    }
  ],
  "final_impact": "Exfiltration massive de données clients. Violation GDPR/PCI-DSS. Notification obligatoire aux autorités et aux utilisateurs. Dommage réputationnel majeur.",
  "overall_likelihood": "Medium",
  "overall_risk": "Critical",
  "key_mitigation_point": "Implémenter IMDSv2 avec hop limit=1 ET restreindre les permissions IAM du rôle selon le principe de moindre privilège. Couper l'étape 2 empêche la progression de l'attack path."
}
</examples>
```

---

## Prefill (champ assistant)

```json
{"threat_model": {"metadata": {"system_name":
```

---

## Variables à Remplir

| Variable | Description | Exemple |
|----------|-------------|---------|
| `{{SYSTEM_NAME}}` | Nom du système | `ACME Payment Platform` |
| `{{SYSTEM_TYPE}}` | Type de système | `microservices`, `web_app`, `saas_platform` |
| `{{PROJECT_PHASE}}` | Phase du projet | `design`, `development`, `production` |
| `{{BUSINESS_CRITICALITY}}` | Criticité business | `critical`, `high`, `medium` |
| `{{DATA_TYPES}}` | Types de données traitées | `pii, financial, credentials` |
| `{{USER_BASE}}` | Types d'utilisateurs | `b2c`, `internal_only`, `mixed` |
| `{{COMPLIANCE}}` | Exigences de conformité | `pci_dss, gdpr`, `none` |
| `{{ARCHITECTURE_DESCRIPTION}}` | Description de l'architecture | `<description textuelle détaillée>` |
| `{{TECH_STACK}}` | Stack technique | `Node.js/Express, PostgreSQL, Redis, AWS ECS` |
| `{{DATA_FLOW}}` | Description des flux de données | `<description des flux>` |
| `{{EXISTING_CONTROLS}}` | Contrôles de sécurité existants | `WAF CloudFront, TLS 1.3, RBAC, Vault` |
| `{{KNOWN_CONCERNS}}` | Préoccupations connues | `Migration récente vers microservices, pas encore de mTLS inter-services` |

---

## Workflow : Threat Modeling Itératif

Le threat modeling est un processus itératif. Voici comment l'utiliser en pratique :

### Itération 1 : Vue d'ensemble (high-level)
Fournir une description architecturale de haut niveau. Le LLM produira un threat model initial focalisé sur les risques architecturaux majeurs.

### Itération 2 : Deep-dive par composant
Pour chaque composant identifié comme critique, fournir :
- Le code source des mécanismes d'authentification/autorisation
- Les schémas de base de données
- Les configurations d'infrastructure

Le LLM affinera les menaces avec des détails techniques.

### Itération 3 : Validation par attack simulation
Utiliser les attack paths identifiés pour guider un pentest réel ou un exercice red team. Les résultats du pentest alimentent une mise à jour du threat model.

```
# Prompt de mise à jour itérative :
<context>
Mise à jour du threat model existant suite à :
- Pentest findings : {{PENTEST_RESULTS}}
- Changements architecturaux : {{ARCH_CHANGES}}
- Nouvelles menaces identifiées : {{NEW_THREATS}}
</context>

<target>
{{EXISTING_THREAT_MODEL_JSON}}
</target>

<instructions>
Met à jour le threat model existant en intégrant les nouvelles informations.
- Reclasse les menaces dont la likelihood a changé suite au pentest
- Ajoute les nouvelles menaces identifiées
- Met à jour les mitigations (celles implémentées, celles qui ont échoué)
- Recalcule le risk level global
</instructions>
```

---

## Références

- [Microsoft STRIDE Threat Modeling](https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats)
- [OWASP Threat Modeling](https://owasp.org/www-community/Threat_Modeling)
- [Adam Shostack — Threat Modeling: Designing for Security](https://shostack.org/resources/threat-modeling)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [NIST SP 800-154 — Guide to Data-Centric System Threat Modeling](https://csrc.nist.gov/publications/detail/sp/800-154/draft)
- [Threagile — Agile Threat Modeling](https://threagile.io/)
