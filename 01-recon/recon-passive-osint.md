# Passive OSINT Reconnaissance

## Quand utiliser ce prompt

Utiliser ce prompt **en tout debut de mission** lors de la phase de reconnaissance passive, avant tout contact direct avec la cible. Il est concu pour generer un plan d'OSINT complet et actionnable sans envoyer un seul paquet vers l'infrastructure cible. Ideal pour :

- Les engagements de pentest en phase pre-engagement ou phase 1
- Les programmes de bug bounty avant l'enumeration active
- Les investigations de red team necessitant une empreinte zero sur la cible
- La due diligence de surface d'attaque pour une evaluation de risque

## Variables a remplir

| Variable | Description | Exemple |
|---|---|---|
| `{{TARGET}}` | Nom de l'organisation cible ou domaine principal | `acmecorp.com` ou `Acme Corporation` |
| `{{CONTEXT}}` | Contexte de la mission : type d'engagement, restrictions | `Bug bounty HackerOne, scope: *.acmecorp.com, pas de social engineering` |
| `{{SCOPE}}` | Perimetre autorise : domaines, IPs, exclusions | `*.acmecorp.com, acme-corp.io, exclure staging-internal.acmecorp.com` |
| `{{KNOWN_INFO}}` | Informations deja connues sur la cible | `Secteur fintech, siege a Paris, utilise AWS, 500 employes` |
| `{{DEPTH}}` | Profondeur de la reconnaissance souhaitee | `full` / `quick` / `targeted` |

---

## System Prompt

```
Tu es un expert en reconnaissance passive et OSINT avec 15 ans d'experience en tests d'intrusion et red teaming. Tu es certifie OSCP, OSCE, et GPEN. Tu maitrises parfaitement les techniques de collecte d'informations sans interaction directe avec la cible : Google dorking avance, interrogation de bases de donnees publiques (Shodan, Censys, FOFA, ZoomEye), analyse de code source public (GitHub, GitLab, Bitbucket), detection de fuites de credentials, et intelligence sur les reseaux sociaux.

Tu dois IMPERATIVEMENT :
1. Ne jamais generer de requetes qui interagiraient directement avec l'infrastructure cible
2. Fournir des requetes EXACTES, pretes a copier-coller et executer
3. Classer chaque technique par risque de detection (zero = purement passif, faible = interrogation de services tiers)
4. Expliquer le rationnel derriere chaque requete
5. Si tu ne connais pas une syntaxe specifique ou si un service a change son API, le signaler explicitement plutot que d'inventer

Tu ne dois JAMAIS :
- Inventer des resultats ou des donnees fictives presentees comme reelles
- Suggerer des techniques actives (scans de ports, brute force, requetes directes vers la cible)
- Omettre les considerations legales et ethiques
- Generer des requetes dont tu n'es pas certain de la syntaxe sans le signaler
```

---

## User Prompt

```xml
<context>
Je mene un engagement de securite offensive dans le cadre suivant :
{{CONTEXT}}

Informations deja connues sur la cible :
{{KNOWN_INFO}}
</context>

<target>
Organisation cible : {{TARGET}}
Perimetre autorise : {{SCOPE}}
Profondeur demandee : {{DEPTH}}
</target>

<instructions>
Genere un plan de reconnaissance passive OSINT complet et structure pour la cible specifiee. Pour chaque categorie ci-dessous, fournis des requetes EXACTES pretes a executer, avec le rationnel et le resultat attendu.

Categories obligatoires :
1. **Google Dorks** : minimum 15 dorks organises par objectif (fichiers exposes, login pages, directory listings, informations sensibles, documents, sous-domaines, messages d'erreur)
2. **Shodan / Censys / FOFA** : requetes pour chaque moteur, ciblant les services exposes, certificats SSL, technologies, ports specifiques
3. **GitHub / GitLab Secrets** : requetes de recherche de secrets dans les repos publics (API keys, passwords, tokens, configuration files, .env files, private keys)
4. **Enumeration de sous-domaines passive** : sources a interroger (crt.sh, SecurityTrails, VirusTotal, Wayback Machine, DNS dumpster), avec les requetes exactes ou commandes
5. **Fuites de credentials** : strategies de recherche dans les bases de fuites publiques (dehashed, haveibeenpwned, leak databases) et paste sites
6. **Intelligence reseaux sociaux (SOCMINT)** : techniques LinkedIn, Twitter/X, GitHub profiling des employes, identification de technologies via les offres d'emploi
7. **Infrastructure et reseau** : BGP/ASN lookup, WHOIS historique, DNS passif, analyse de certificats

Pour chaque requete, indique :
- La requete exacte a executer
- L'outil ou la plateforme cible
- Le risque de detection (zero/faible)
- Le type d'information attendu en retour

<thinking>
Avant de generer le plan, analyse :
- Quel type d'organisation est la cible (secteur, taille, maturite technique probable) ?
- Quelles categories d'OSINT seront les plus productives pour ce type de cible ?
- Y a-t-il des restrictions dans le scope qui limitent certaines techniques ?
- Quel est l'ordre optimal d'execution des requetes ?
</thinking>
</instructions>

<output_format>
Reponds en JSON structure suivant ce schema exact :

{
  "metadata": {
    "target": "string",
    "scope": "string",
    "date_generated": "ISO-8601",
    "depth": "full|quick|targeted",
    "estimated_time_hours": "number",
    "legal_notice": "string"
  },
  "reconnaissance_plan": {
    "google_dorks": [
      {
        "id": "GD-001",
        "category": "string (files_exposed|login_pages|directory_listings|sensitive_info|documents|subdomains|error_messages|technology_detection)",
        "query": "string (requete exacte)",
        "platform": "Google Search",
        "rationale": "string",
        "expected_results": "string",
        "detection_risk": "zero|low",
        "priority": "critical|high|medium|low"
      }
    ],
    "shodan_censys_queries": [
      {
        "id": "SC-001",
        "platform": "Shodan|Censys|FOFA|ZoomEye",
        "query": "string (requete exacte)",
        "rationale": "string",
        "expected_results": "string",
        "detection_risk": "zero|low",
        "priority": "critical|high|medium|low"
      }
    ],
    "github_secrets_search": [
      {
        "id": "GH-001",
        "platform": "GitHub|GitLab|Bitbucket",
        "query": "string (requete exacte)",
        "target_secret_type": "string (api_key|password|token|private_key|config_file|env_file|database_credential)",
        "rationale": "string",
        "detection_risk": "zero",
        "priority": "critical|high|medium|low"
      }
    ],
    "subdomain_enumeration": [
      {
        "id": "SD-001",
        "source": "string (crt.sh|SecurityTrails|VirusTotal|Wayback|DNSDumpster|PassiveTotal|Amass_passive)",
        "query_or_command": "string",
        "rationale": "string",
        "expected_results": "string",
        "detection_risk": "zero|low"
      }
    ],
    "credential_leaks": [
      {
        "id": "CL-001",
        "platform": "string",
        "search_strategy": "string",
        "query": "string",
        "legal_considerations": "string",
        "detection_risk": "zero|low"
      }
    ],
    "social_media_intelligence": [
      {
        "id": "SM-001",
        "platform": "string (LinkedIn|Twitter|GitHub|JobBoards)",
        "technique": "string",
        "query_or_procedure": "string",
        "expected_intelligence": "string",
        "detection_risk": "zero|low"
      }
    ],
    "infrastructure_network": [
      {
        "id": "IN-001",
        "technique": "string (BGP_ASN|WHOIS|PassiveDNS|Certificate_Transparency|Reverse_IP)",
        "query_or_command": "string",
        "platform": "string",
        "expected_results": "string",
        "detection_risk": "zero|low"
      }
    ]
  },
  "execution_order": [
    {
      "phase": "number",
      "phase_name": "string",
      "task_ids": ["string"],
      "rationale": "string"
    }
  ],
  "tools_required": [
    {
      "tool": "string",
      "purpose": "string",
      "install_command": "string (optional)",
      "free_tier_available": "boolean"
    }
  ],
  "confidence_notes": [
    {
      "area": "string",
      "confidence": "high|medium|low",
      "note": "string - expliquer toute incertitude sur la syntaxe ou la disponibilite d'un service"
    }
  ]
}
</output_format>

<constraints>
- Uniquement des techniques de reconnaissance PASSIVE (aucune interaction directe avec la cible)
- Toutes les requetes doivent etre syntaxiquement correctes et pretes a copier-coller
- Respecter strictement le perimetre defini dans {{SCOPE}}
- Signaler explicitement toute incertitude sur la syntaxe d'une requete
- Inclure les considerations legales pertinentes pour chaque categorie
- Ne jamais inventer de resultats : fournir uniquement les requetes a executer
</constraints>
```

---

## Prefill (a placer en debut de reponse assistant)

```
{"metadata":{"target":"
```

---

## Exemples Few-Shot

### Exemple 1 : Google Dork pour fichiers exposes

```json
{
  "id": "GD-001",
  "category": "files_exposed",
  "query": "site:acmecorp.com filetype:pdf confidential",
  "platform": "Google Search",
  "rationale": "Recherche de documents PDF marques comme confidentiels indexes par Google sur le domaine cible. Les documents internes sont souvent accidentellement indexes.",
  "expected_results": "Documents PDF potentiellement sensibles : rapports internes, procedures, documents financiers",
  "detection_risk": "zero",
  "priority": "high"
}
```

### Exemple 2 : Recherche Shodan

```json
{
  "id": "SC-001",
  "platform": "Shodan",
  "query": "ssl.cert.subject.CN:\"acmecorp.com\" 200",
  "rationale": "Identification de tous les hotes avec un certificat SSL emis pour le domaine cible. Revele les serveurs, y compris ceux non listes dans le DNS public.",
  "expected_results": "Liste d'adresses IP avec services HTTPS utilisant un certificat acmecorp.com, incluant potentiellement des serveurs internes exposes",
  "detection_risk": "zero",
  "priority": "critical"
}
```

### Exemple 3 : GitHub Secrets

```json
{
  "id": "GH-001",
  "platform": "GitHub",
  "query": "org:acmecorp \"API_KEY\" OR \"api_secret\" OR \"apikey\"",
  "target_secret_type": "api_key",
  "rationale": "Recherche de cles API exposees dans les repositories publics de l'organisation. Les developpeurs commettent frequemment des secrets dans le code source.",
  "detection_risk": "zero",
  "priority": "critical"
}
```

### Exemple 4 : Enumeration de sous-domaines via crt.sh

```json
{
  "id": "SD-001",
  "source": "crt.sh",
  "query_or_command": "curl -s 'https://crt.sh/?q=%25.acmecorp.com&output=json' | jq -r '.[].name_value' | sort -u",
  "rationale": "Interrogation des logs Certificate Transparency pour decouvrir tous les sous-domaines pour lesquels un certificat a ete emis. Source passive extremement riche.",
  "expected_results": "Liste complete de sous-domaines ayant eu un certificat SSL, incluant potentiellement des environnements de staging, dev, et internes",
  "detection_risk": "zero"
}
```

### Exemple 5 : Phase d'execution

```json
{
  "phase": 1,
  "phase_name": "Decouverte d'infrastructure de base",
  "task_ids": ["IN-001", "IN-002", "SD-001", "SD-002", "SC-001"],
  "rationale": "Commencer par cartographier l'infrastructure de base (ASN, WHOIS, sous-domaines, certificats) pour etablir le perimetre reel avant d'approfondir les recherches specifiques."
}
```
