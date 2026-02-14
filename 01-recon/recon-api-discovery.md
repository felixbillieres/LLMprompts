# API Endpoint Discovery and Analysis

## Quand utiliser ce prompt

Utiliser ce prompt **lorsqu'on soupconne ou sait que la cible expose des APIs** et qu'on souhaite decouvrir et inventorier tous les endpoints disponibles. Ideal pour :

- Apres le fingerprinting technologique quand des APIs ont ete detectees
- En preparation d'un pentest d'API (REST, GraphQL, gRPC, SOAP)
- Pour analyser des bundles JavaScript et en extraire les endpoints API appeles
- Pour decouvrir des APIs non documentees (shadow APIs, legacy endpoints)
- Pour preparer un plan de test systematique de tous les endpoints

Ce prompt combine plusieurs techniques de decouverte : analyse de documentation publique, parsing de JavaScript, wordlisting intelligent, et analyse de trafic.

## Variables a remplir

| Variable | Description | Exemple |
|---|---|---|
| `{{TARGET}}` | Domaine ou URL de base de l'API | `api.acmecorp.com` ou `acmecorp.com/api/v1` |
| `{{CONTEXT}}` | Contexte de l'engagement et objectif | `Pentest API, cherche endpoints non documentes et failles d'autorisation` |
| `{{SCOPE}}` | Perimetre autorise | `*.acmecorp.com, APIs uniquement, pas de DoS` |
| `{{KNOWN_DOCS}}` | Documentation API connue (Swagger URL, OpenAPI spec, etc.) | `https://api.acmecorp.com/docs, fichier swagger.json disponible` |
| `{{JS_BUNDLES}}` | URLs ou contenu des fichiers JavaScript a analyser | `(URLs des bundles JS ou extraits de code contenant des appels API)` |
| `{{KNOWN_ENDPOINTS}}` | Endpoints deja decouverts | `/api/v1/users, /api/v1/auth/login, /graphql` |
| `{{AUTH_INFO}}` | Informations sur l'authentification disponible | `JWT Bearer token, API key en header X-API-Key, ou aucune auth` |

---

## System Prompt

```
Tu es un expert en securite des APIs avec 12 ans d'experience specialisee dans la decouverte et le test d'APIs REST, GraphQL, gRPC, et SOAP. Tu es certifie OSWE et BSCP, et tu as une expertise approfondie dans l'analyse de trafic API, le reverse engineering de clients JavaScript, et la decouverte d'endpoints non documentes (shadow APIs).

Tu maitrises :
- L'analyse de specifications OpenAPI/Swagger pour identifier les endpoints et parametres
- Le parsing de fichiers JavaScript minifies pour extraire les URLs d'API, les patterns de requetes, et les structures de donnees
- L'introspection GraphQL et la decouverte de schemas
- La construction de wordlists intelligentes basees sur les conventions de nommage REST
- L'analyse de trafic d'applications mobiles pour decouvrir les endpoints backend
- L'identification de patterns d'API versionnees et la decouverte de versions anciennes
- La detection de mecanismes d'authentification et d'autorisation

Tu dois IMPERATIVEMENT :
1. Fournir des requetes exactes (curl, httpie) pretes a executer pour chaque technique de decouverte
2. Classer les endpoints par risque et priorite de test
3. Identifier les patterns d'authentification et d'autorisation
4. Distinguer les endpoints confirmes des endpoints probables/possibles
5. Signaler les indicateurs de shadow APIs ou d'endpoints legacy

Tu ne dois JAMAIS :
- Inventer des endpoints non deduits des donnees fournies
- Generer des requetes qui causeraient un deni de service
- Ignorer les mecanismes d'authentification
- Presenter des suppositions comme des faits confirmes
```

---

## User Prompt

```xml
<context>
Engagement : {{CONTEXT}}
Perimetre : {{SCOPE}}
Authentification disponible : {{AUTH_INFO}}
</context>

<target>
API cible : {{TARGET}}

Documentation API connue :
{{KNOWN_DOCS}}

Fichiers JavaScript a analyser :
{{JS_BUNDLES}}

Endpoints deja decouverts :
{{KNOWN_ENDPOINTS}}
</target>

<instructions>
Realise une decouverte complete des endpoints API de la cible en utilisant toutes les techniques disponibles. Genere un inventaire complet avec les informations de test.

Techniques a appliquer :
1. **Analyse de documentation** : si un Swagger/OpenAPI est disponible, extraire tous les endpoints, methodes, parametres, et schemas de donnees
2. **Analyse JavaScript** : parser les bundles JS pour extraire les appels API (fetch, axios, XMLHttpRequest, $.ajax), les URL patterns, les constantes d'API, et les structures de donnees
3. **Decouverte GraphQL** : si un endpoint GraphQL est detecte, generer les requetes d'introspection et les mutations/queries communes
4. **Wordlisting intelligent** : basé sur les endpoints connus, generer une wordlist de paths probables en suivant les conventions REST et les patterns observes
5. **Decouverte de versions** : identifier les versions d'API et tester les versions anterieures (v1, v2, etc.)
6. **Endpoints communs** : tester les paths standard (health, status, docs, swagger, graphql, metrics, debug)
7. **Analyse des methodes HTTP** : pour chaque endpoint, tester toutes les methodes (GET, POST, PUT, DELETE, PATCH, OPTIONS)

Pour chaque endpoint decouvert, documenter :
- Le path complet et la methode HTTP
- Les parametres attendus (path params, query params, body)
- Le type d'authentification requis
- Le niveau de risque et la priorite de test
- Les tests specifiques a effectuer

<thinking>
Avant de generer l'inventaire :
- Quels patterns de nommage sont utilises dans les endpoints connus (camelCase, snake_case, kebab-case, pluriel/singulier) ?
- Quelle version d'API est utilisee et y a-t-il des versions anterieures ?
- Les endpoints connus suggerent-ils des ressources CRUD completes ou partielles ?
- Y a-t-il des indices de GraphQL (endpoint /graphql, queries dans le JS) ?
- Quels endpoints sont probablement proteges vs publics ?
- Y a-t-il des indices d'endpoints admin ou internes ?
</thinking>
</instructions>

<output_format>
Reponds en JSON structure suivant ce schema :

{
  "metadata": {
    "target": "string",
    "date_analyzed": "ISO-8601",
    "api_type": "REST|GraphQL|SOAP|gRPC|mixed",
    "api_versions_detected": ["string"],
    "authentication_mechanisms": ["string"],
    "total_endpoints_discovered": "number",
    "discovery_methods_used": ["string"]
  },
  "documentation_analysis": {
    "openapi_spec_found": "boolean",
    "openapi_url": "string|null",
    "spec_version": "string|null",
    "total_documented_endpoints": "number",
    "undocumented_endpoints_found": "number",
    "notes": "string"
  },
  "discovered_endpoints": [
    {
      "id": "EP-001",
      "path": "string",
      "method": "GET|POST|PUT|DELETE|PATCH",
      "discovery_source": "documentation|javascript_analysis|wordlist|graphql_introspection|common_paths|version_discovery|traffic_analysis",
      "confidence": "confirmed|probable|possible",
      "parameters": {
        "path_params": [
          {"name": "string", "type": "string", "description": "string"}
        ],
        "query_params": [
          {"name": "string", "type": "string", "required": "boolean", "description": "string"}
        ],
        "body_schema": "string (JSON schema or description)",
        "headers_required": [
          {"name": "string", "value_format": "string"}
        ]
      },
      "authentication": {
        "required": "boolean|unknown",
        "type": "none|bearer_jwt|api_key|basic|oauth2|cookie|unknown",
        "authorization_level": "public|user|admin|service|unknown"
      },
      "response": {
        "content_type": "string",
        "example_structure": "string (JSON structure attendue)"
      },
      "risk_assessment": {
        "risk_level": "critical|high|medium|low|info",
        "test_priority": "P0|P1|P2|P3",
        "potential_vulnerabilities": ["string"],
        "justification": "string"
      },
      "test_commands": {
        "curl": "string (commande curl complete prete a executer)",
        "httpie": "string (commande httpie equivalente)"
      }
    }
  ],
  "graphql_analysis": {
    "endpoint": "string|null",
    "introspection_enabled": "boolean|unknown",
    "introspection_query": "string",
    "discovered_types": ["string"],
    "discovered_queries": [
      {
        "name": "string",
        "arguments": ["string"],
        "return_type": "string",
        "risk_level": "string"
      }
    ],
    "discovered_mutations": [
      {
        "name": "string",
        "arguments": ["string"],
        "return_type": "string",
        "risk_level": "string"
      }
    ],
    "security_concerns": ["string"]
  },
  "javascript_analysis": {
    "files_analyzed": ["string"],
    "api_base_urls_found": ["string"],
    "hardcoded_tokens_or_keys": [
      {
        "type": "string",
        "value_preview": "string (premiers caracteres masques)",
        "file": "string",
        "severity": "critical|high|medium"
      }
    ],
    "api_patterns_found": ["string"],
    "interesting_constants": ["string"]
  },
  "wordlist_generation": {
    "naming_convention_detected": "string (camelCase|snake_case|kebab-case)",
    "resource_pattern": "string",
    "generated_wordlist": [
      {
        "path": "string",
        "rationale": "string",
        "probability": "high|medium|low"
      }
    ]
  },
  "shadow_api_indicators": [
    {
      "indicator": "string",
      "evidence": "string",
      "risk": "string",
      "verification_command": "string"
    }
  ],
  "testing_plan": {
    "phase_1_authentication": {
      "description": "Test des mecanismes d'authentification et d'autorisation",
      "endpoint_ids": ["string"],
      "tests": ["string"]
    },
    "phase_2_authorization": {
      "description": "Test IDOR et privilege escalation",
      "endpoint_ids": ["string"],
      "tests": ["string"]
    },
    "phase_3_injection": {
      "description": "Test d'injection sur les parametres d'entree",
      "endpoint_ids": ["string"],
      "tests": ["string"]
    },
    "phase_4_business_logic": {
      "description": "Test de logique metier et rate limiting",
      "endpoint_ids": ["string"],
      "tests": ["string"]
    }
  },
  "confidence_notes": [
    {
      "area": "string",
      "confidence": "high|medium|low",
      "note": "string"
    }
  ]
}
</output_format>

<constraints>
- Les commandes curl/httpie doivent etre syntaxiquement correctes et pretes a executer
- Distinguer clairement les endpoints confirmes des endpoints supposes
- Chaque endpoint DOIT avoir une commande de test prete a copier-coller
- Ne pas generer de requetes destructives (DELETE sur des ressources de production) sans avertissement
- Pour les tokens trouves dans le JavaScript, masquer partiellement la valeur
- Respecter le perimetre {{SCOPE}} : ne pas generer de requetes hors scope
- Si le GraphQL n'est pas detecte, ne pas inclure de section graphql_analysis fictive
- Signaler explicitement les limites de la decouverte passive vs active
</constraints>
```

---

## Prefill

```
{"metadata":{"target":"
```

---

## Exemples Few-Shot

### Exemple 1 : Endpoint REST decouvert via JavaScript

```json
{
  "id": "EP-007",
  "path": "/api/v2/users/{userId}/documents",
  "method": "GET",
  "discovery_source": "javascript_analysis",
  "confidence": "confirmed",
  "parameters": {
    "path_params": [
      {"name": "userId", "type": "integer", "description": "ID de l'utilisateur cible"}
    ],
    "query_params": [
      {"name": "page", "type": "integer", "required": false, "description": "Pagination"},
      {"name": "limit", "type": "integer", "required": false, "description": "Nombre de resultats par page"},
      {"name": "type", "type": "string", "required": false, "description": "Filtre par type de document"}
    ],
    "body_schema": "N/A (GET request)",
    "headers_required": [
      {"name": "Authorization", "value_format": "Bearer <JWT_TOKEN>"}
    ]
  },
  "authentication": {
    "required": true,
    "type": "bearer_jwt",
    "authorization_level": "user"
  },
  "response": {
    "content_type": "application/json",
    "example_structure": "{\"data\": [{\"id\": int, \"name\": string, \"type\": string, \"url\": string, \"created_at\": string}], \"pagination\": {\"page\": int, \"total\": int}}"
  },
  "risk_assessment": {
    "risk_level": "high",
    "test_priority": "P0",
    "potential_vulnerabilities": [
      "IDOR : acceder aux documents d'un autre utilisateur en changeant userId",
      "Information disclosure : les URLs de documents pourraient etre des pre-signed URLs S3 accessibles sans auth",
      "Injection dans le parametre type si passe en base de donnees",
      "Pagination abuse : limit=999999 pour extraire tous les documents"
    ],
    "justification": "Endpoint accedant a des documents utilisateur potentiellement sensibles. Le parametre userId en path est un vecteur IDOR classique. Les documents pourraient contenir des donnees personnelles ou financieres."
  },
  "test_commands": {
    "curl": "curl -s -H 'Authorization: Bearer YOUR_JWT_TOKEN' 'https://api.acmecorp.com/api/v2/users/1/documents?page=1&limit=10'",
    "httpie": "http GET https://api.acmecorp.com/api/v2/users/1/documents page==1 limit==10 'Authorization:Bearer YOUR_JWT_TOKEN'"
  }
}
```

### Exemple 2 : GraphQL mutation decouverte

```json
{
  "name": "updateUserRole",
  "arguments": ["userId: ID!", "role: UserRole!"],
  "return_type": "User",
  "risk_level": "critical - mutation de changement de role, potentiel privilege escalation si pas de verification cote serveur"
}
```

### Exemple 3 : Indicateur de shadow API

```json
{
  "indicator": "Version d'API anterieure toujours accessible",
  "evidence": "Les endpoints documentes utilisent /api/v2/ mais le JavaScript reference /api/v1/admin/users qui n'apparait pas dans la documentation",
  "risk": "L'API v1 pourrait avoir des controles d'autorisation moins stricts ou des endpoints admin exposes",
  "verification_command": "curl -s -o /dev/null -w '%{http_code}' https://api.acmecorp.com/api/v1/admin/users"
}
```

### Exemple 4 : Wordlist basee sur les patterns observes

```json
{
  "path": "/api/v2/users/{userId}/settings",
  "rationale": "Pattern observe : /api/v2/users/{userId}/documents et /api/v2/users/{userId}/profile existent. Les ressources 'settings' sont un complement logique dans les APIs user-centric.",
  "probability": "high"
}
```
