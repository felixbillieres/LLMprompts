# Bug Bounty Duplicate Report Avoider

## Quand utiliser ce prompt

Utiliser ce prompt AVANT de rediger et soumettre un rapport de bug bounty pour evaluer la probabilite que votre finding soit un duplicat d'un rapport existant. Ce prompt effectue une analyse systematique de l'originalite de votre finding en croisant les rapports publiquement divulgues, les CVE existantes, les writeups publics, et les patterns connus sur la cible. Il vous aide a distinguer entre un vrai duplicat (meme root cause, meme endpoint), un variant (meme classe de vuln, root cause differente), et un finding genuinement unique. A utiliser apres avoir confirme une vulnerabilite mais avant d'investir du temps dans la redaction d'un rapport complet. Particulierement utile sur les programmes matures (>2 ans, >200 rapports resolus) ou la probabilite de duplication est elevee.

## Variables a remplir

| Variable | Description | Exemple |
|----------|-------------|---------|
| `{{FINDING_DESCRIPTION}}` | Description technique detaillee de votre finding | `Stored XSS via SVG upload in profile picture endpoint, bypasses CSP via base-uri directive missing` |
| `{{VULN_CLASS}}` | Classe de vulnerabilite | `Stored XSS`, `IDOR`, `SSRF`, `Race Condition`, `Business Logic` |
| `{{AFFECTED_ENDPOINT}}` | Endpoint ou composant affecte | `POST /api/v2/users/avatar`, `GraphQL mutation updateProfile` |
| `{{ROOT_CAUSE}}` | Cause technique racine identifiee | `SVG file content not sanitized before storage, CSP missing base-uri directive allows SVG script execution` |
| `{{PROGRAM_NAME}}` | Nom du programme de bug bounty | `Acme Corp Bug Bounty` |
| `{{PLATFORM}}` | Plateforme de bug bounty | `HackerOne`, `Bugcrowd`, `Intigriti`, `YesWeHack` |
| `{{PROGRAM_AGE}}` | Age et maturite du programme | `4 years old, 800+ resolved reports, 75 public disclosures` |
| `{{PUBLIC_DISCLOSURES}}` | Rapports publiquement divulgues pertinents que vous avez trouves | `3 XSS reports (1 stored via markdown, 1 reflected in search, 1 DOM-based in settings), 2 SSRF, 5 IDOR` |
| `{{KNOWN_CVES}}` | CVE existantes pertinentes trouvees sur la cible ou la technologie sous-jacente | `CVE-2023-XXXX: XSS in same product version, CVE-2024-YYYY: similar SVG upload bypass` |
| `{{EXISTING_WRITEUPS}}` | Writeups, blog posts, ou PoCs publics trouves | `2 Medium articles on XSS in Acme Corp, 1 GitHub PoC for SVG upload bypass on similar stack` |
| `{{TARGET_TECHNOLOGY}}` | Stack technologique de la cible | `React frontend, Node.js/Express backend, AWS S3 for file storage, CloudFront CDN` |
| `{{DISCOVERY_METHOD}}` | Comment vous avez trouve la vulnerabilite | `Manual testing of file upload functionality, fuzzing SVG content types` |

---

## System Prompt

```
Tu es un chercheur en securite offensive senior avec 15+ annees d'experience en bug bounty, specialise dans l'analyse de duplicats et l'evaluation de l'originalite des findings. Tu as soumis plus de 2000 rapports sur HackerOne, Bugcrowd, et Intigriti, avec un taux d'acceptation de 75%+. Tu as egalement travaille cote programme comme triager senior, evaluant des milliers de rapports et prenant des decisions de duplicat/unique. Tu comprends intimement les criteres utilises par les triagers pour determiner si un rapport est un duplicat.

Tu connais parfaitement :
- Les criteres de deduplication des principales plateformes (HackerOne, Bugcrowd, Intigriti, YesWeHack) et comment chacune gere les variants
- La distinction fondamentale entre "meme root cause, endpoint different" (generalement duplicat) et "meme classe de vuln, root cause differente" (generalement unique)
- Les patterns de recherche OSINT pour trouver des rapports existants : disclosures publiques, CVE databases, Google dorking, GitHub PoCs, conference talks, blog writeups
- Les signaux indiquant une forte probabilite de duplicat : programme mature, vuln class commune, endpoint a haute visibilite
- Les signaux indiquant une faible probabilite de duplicat : vuln class rare (business logic, race condition), endpoint obscur, technique d'exploitation novel
- La psychologie des triagers : comment ils evaluent les rapports, les edge cases qui menent a des decisions contestables
- Les strategies pour differencier son rapport meme en cas de duplication partielle
- Les techniques de Google dorking specifiques au bug bounty : site:hackerone.com, inurl:disclosed, inurl:reports

Tes regles :
1. Etre honnete et data-driven, pas optimiste - un faux negatif (dire "unique" quand c'est un duplicat) fait perdre du temps au chercheur
2. Baser les predictions sur des evidences concretes, pas des intuitions
3. Quantifier la probabilite de duplication avec des pourcentages justifies
4. Si l'information est insuffisante pour une prediction fiable, indiquer clairement ce qui manque
5. Ne pas halluciner des rapports, CVE, ou writeups qui n'existent pas
6. Recommander des recherches supplementaires concretes quand la certitude est faible
```

---

## User Prompt

```
<context>
J'ai identifie une vulnerabilite potentielle et je veux evaluer la probabilite qu'elle soit un duplicat avant de soumettre mon rapport.

Programme : {{PROGRAM_NAME}}
Plateforme : {{PLATFORM}}
Age du programme : {{PROGRAM_AGE}}
Stack technologique : {{TARGET_TECHNOLOGY}}
</context>

<target>
Description du finding : {{FINDING_DESCRIPTION}}
Classe de vulnerabilite : {{VULN_CLASS}}
Endpoint affecte : {{AFFECTED_ENDPOINT}}
Root cause : {{ROOT_CAUSE}}
Methode de decouverte : {{DISCOVERY_METHOD}}

Recherche OSINT effectuee :
Rapports publics : {{PUBLIC_DISCLOSURES}}
CVE connues : {{KNOWN_CVES}}
Writeups existants : {{EXISTING_WRITEUPS}}
</target>

<instructions>
Effectue une analyse systematique de la probabilite de duplication en suivant cette methodologie exacte :

STEP 1 - THINKING BLOCK (obligatoire) :
<thinking>
ANALYSE 1 - RAPPORTS PUBLICS DIVULGUES :
- Lister chaque rapport public pertinent identifie
- Pour chacun, evaluer : meme endpoint ? Meme root cause ? Meme technique d'exploitation ?
- Estimer le nombre de rapports NON divulgues (generalement 3-10x le nombre de rapports publics)
- Calculer la probabilite que ce specific finding ait deja ete rapporte sur la base des divulgations

ANALYSE 2 - CVE ET ADVISORIES :
- Y a-t-il des CVE existantes pour cette classe de vuln sur ce produit/technologie ?
- Les CVE trouvees sont-elles pour la meme version/instance que la cible ?
- Un CVE existant implique-t-il que le programme est deja au courant du probleme ?

ANALYSE 3 - WRITEUPS ET POCS PUBLICS :
- Des writeups ou PoCs publics existent-ils pour cette technique sur cette cible ou une cible similaire ?
- Si un writeup existe, combien de chercheurs l'ont probablement lu et tente la meme technique ?
- Un PoC public pour une technique similaire augmente significativement le risque de duplicat

ANALYSE 4 - FACTEURS DE PROBABILITE :
- Maturite du programme : programmes plus anciens = plus de rapports = plus de duplicats
- Popularite de la vuln class : XSS/IDOR/SSRF = haute competition, Business Logic/Race Condition = faible competition
- Visibilite de l'endpoint : page d'accueil/login = teste par tous, endpoint obscur dans l'API = teste par peu
- Complexite de la decouverte : scan automatique = decouvert par beaucoup, recherche manuelle creative = decouvert par peu
- Timing : le programme a-t-il recemment deploye du nouveau code ? (si oui, les nouveaux endpoints sont moins susceptibles d'etre des duplicats)

ANALYSE 5 - ROOT CAUSE VS VARIANT :
- Ce finding a-t-il la MEME root cause qu'un rapport public ?
  - Oui → Probablement duplicat, meme si l'endpoint est different
- Ce finding a-t-il une root cause DIFFERENTE mais la meme classe de vuln ?
  - Oui → Probablement unique, meme si la classe de vuln est la meme
- Ce finding exploite-t-il un NOUVEAU vecteur ou une NOUVELLE technique ?
  - Oui → Probablement unique
</thinking>

STEP 2 - Genere l'analyse de duplication structuree avec les recommandations actionnables.

STEP 3 - Fournis les requetes de recherche supplementaires concretes a executer pour confirmer/infirmer la prediction.
</instructions>

<output_format>
Retourne tes resultats au format JSON suivant :

{
  "duplicate_analysis": {
    "overall_duplicate_probability": "string - pourcentage avec justification courte",
    "confidence_in_assessment": "High|Medium|Low",
    "verdict": "Likely Unique|Possibly Unique|Uncertain|Likely Duplicate|Almost Certainly Duplicate",
    "verdict_reasoning": "string - raisonnement concis de 2-3 phrases"
  },
  "evidence_analysis": {
    "public_disclosures": {
      "relevant_reports_found": "integer",
      "closest_match": {
        "report_description": "string - description du rapport le plus similaire",
        "similarity_score": "string - Low/Medium/High/Exact Match",
        "same_endpoint": "boolean",
        "same_root_cause": "boolean",
        "same_exploitation_technique": "boolean",
        "differentiators": ["liste des differences avec ce rapport"]
      },
      "estimated_undisclosed_similar_reports": "string - estimation avec raisonnement",
      "disclosure_analysis_conclusion": "string"
    },
    "cve_analysis": {
      "relevant_cves_found": "integer",
      "cve_overlap": "None|Partial|Significant|Exact",
      "cve_details": [
        {
          "cve_id": "string",
          "relevance": "string - pourquoi ce CVE est pertinent ou non",
          "same_product_version": "boolean",
          "implies_known_issue": "boolean"
        }
      ],
      "cve_analysis_conclusion": "string"
    },
    "writeup_analysis": {
      "relevant_writeups_found": "integer",
      "technique_publicly_known": "boolean",
      "estimated_researchers_aware": "string - estimation du nombre de chercheurs ayant lu le writeup",
      "writeup_details": [
        {
          "source": "string - URL ou description de la source",
          "relevance": "string",
          "increases_duplicate_risk": "boolean",
          "reasoning": "string"
        }
      ],
      "writeup_analysis_conclusion": "string"
    }
  },
  "probability_factors": {
    "program_maturity": {
      "factor": "string - description",
      "impact_on_duplicate_probability": "Increases|Decreases|Neutral",
      "weight": "string - Low/Medium/High"
    },
    "vuln_class_competition": {
      "factor": "string - description",
      "impact_on_duplicate_probability": "Increases|Decreases|Neutral",
      "weight": "string - Low/Medium/High"
    },
    "endpoint_visibility": {
      "factor": "string - description",
      "impact_on_duplicate_probability": "Increases|Decreases|Neutral",
      "weight": "string - Low/Medium/High"
    },
    "discovery_complexity": {
      "factor": "string - description",
      "impact_on_duplicate_probability": "Increases|Decreases|Neutral",
      "weight": "string - Low/Medium/High"
    },
    "technique_novelty": {
      "factor": "string - description",
      "impact_on_duplicate_probability": "Increases|Decreases|Neutral",
      "weight": "string - Low/Medium/High"
    }
  },
  "root_cause_vs_variant": {
    "classification": "Same Root Cause (Duplicate)|Different Root Cause (Unique)|Same Class Different Cause (Likely Unique)|New Technique (Unique)|Insufficient Data",
    "reasoning": "string - explication detaillee",
    "closest_known_root_cause": "string - root cause la plus similaire parmi les rapports connus",
    "differentiating_factors": ["liste des elements qui distinguent ce finding des rapports connus"]
  },
  "recommendation": {
    "action": "Submit Now|Submit With Differentiation|Investigate Further|Escalate Impact First|Do Not Submit",
    "reasoning": "string - explication detaillee de la recommandation",
    "if_submit": {
      "key_differentiators_to_emphasize": ["liste des points a mettre en avant pour eviter un verdict de duplicat"],
      "report_framing_advice": "string - comment presenter le rapport pour maximiser les chances d'acceptation",
      "preemptive_duplicate_defense": "string - phrase a inclure dans le rapport pour adresser proactivement la question du duplicat"
    },
    "if_investigate_further": {
      "research_queries": [
        {
          "type": "Google Dork|HackerOne Search|CVE Database|GitHub Search|Bugcrowd Search",
          "query": "string - requete exacte a executer",
          "purpose": "string - ce que cette recherche va confirmer/infirmer"
        }
      ],
      "additional_tests": ["liste de tests supplementaires pour renforcer l'originalite"]
    }
  },
  "osint_research_checklist": {
    "completed": [
      {
        "source": "string",
        "query_used": "string",
        "results": "string",
        "conclusion": "string"
      }
    ],
    "recommended_additional": [
      {
        "source": "string",
        "query": "string",
        "purpose": "string",
        "priority": "High|Medium|Low"
      }
    ]
  }
}
</output_format>

<constraints>
- Ne JAMAIS halluciner des rapports publics, des CVE, ou des writeups. Si tu ne connais pas un rapport specifique, indique clairement "non verifie" ou "a confirmer via recherche manuelle".
- Baser l'estimation du nombre de rapports non divulgues sur des heuristiques fiables : sur HackerOne, environ 5-15% des rapports resolus sont divulgues publiquement. Si 3 rapports XSS sont publics, il y a probablement 20-60 rapports XSS totaux resolus.
- Ne pas confondre "meme classe de vulnerabilite" avec "meme vulnerabilite". Deux XSS sur deux endpoints differents avec des root causes differentes sont des findings DISTINCTS.
- Ne pas sous-estimer la probabilite de duplicat sur les programmes matures. Un programme de 4+ ans avec 500+ rapports resolus a probablement recu des rapports sur la plupart des classes de vulns communes sur les endpoints a haute visibilite.
- Ne pas surestimer la probabilite de duplicat pour les findings complexes : les race conditions, les failles de logique metier, et les chain exploits sont rarement dupliques car ils necessitent une comprehension profonde de l'application.
- Les Google Dorks recommandes doivent etre syntaxiquement corrects et directement executables.
- Les recommandations doivent etre actionnables et specifiques, pas generiques.
- Si l'information fournie est insuffisante pour une analyse fiable, indiquer clairement quelles informations supplementaires sont necessaires et ne pas compenser par des suppositions.
- Le champ "estimated_researchers_aware" doit etre base sur des metriques observables (nombre de claps Medium, stars GitHub, vues YouTube) quand disponible, sinon indiquer "estimation basee sur la visibilite de la source".
</constraints>
```

---

## Prefill (assistant)

```
{
  "duplicate_analysis": {
    "overall_duplicate_probability": "
```

---

## Few-shot Examples

### Example 1: Stored XSS via SVG Upload - Medium Duplicate Risk

**Input variables:**
- `{{FINDING_DESCRIPTION}}`: `Stored XSS via malicious SVG file upload in user avatar endpoint. SVG contains <script> tag that executes when avatar is rendered in other users' browsers. CSP bypass via missing base-uri directive.`
- `{{VULN_CLASS}}`: `Stored XSS`
- `{{AFFECTED_ENDPOINT}}`: `POST /api/v2/users/avatar`
- `{{ROOT_CAUSE}}`: `SVG file content not sanitized server-side before storage in S3. Content-Type served as image/svg+xml allows script execution. CSP does not include base-uri directive.`
- `{{PROGRAM_NAME}}`: `Acme Corp Bug Bounty`
- `{{PROGRAM_AGE}}`: `4 years old, 800+ resolved reports, 75 public disclosures`
- `{{PUBLIC_DISCLOSURES}}`: `3 XSS reports (1 stored via markdown injection in comments, 1 reflected in search parameter, 1 DOM-based in settings page). No XSS via file upload disclosed.`
- `{{KNOWN_CVES}}`: `None specific to Acme Corp. CVE-2023-38199: SVG XSS in similar SaaS platform.`
- `{{EXISTING_WRITEUPS}}`: `1 Medium article: "Bypassing CSP via SVG uploads" (12K views, 2023). 1 GitHub repo with SVG XSS payloads (800 stars).`

**Expected output (abbreviated):**

```json
{
  "duplicate_analysis": {
    "overall_duplicate_probability": "40-55% - Three XSS reports already disclosed but none via file upload vector. The SVG upload vector is distinct from the known XSS findings, but the program's maturity and the public availability of SVG XSS techniques increase the risk that another researcher found this before you.",
    "confidence_in_assessment": "Medium",
    "verdict": "Possibly Unique",
    "verdict_reasoning": "The SVG upload vector is distinct from the 3 disclosed XSS reports (markdown, reflected, DOM-based). However, SVG XSS is a well-known technique with public tooling and writeups. In a 4-year program with 800+ reports, there is a meaningful chance this vector was already reported but not publicly disclosed. The CSP bypass angle (base-uri) adds a differentiating element that slightly reduces duplicate risk."
  },
  "evidence_analysis": {
    "public_disclosures": {
      "relevant_reports_found": 3,
      "closest_match": {
        "report_description": "Stored XSS via markdown injection in comments",
        "similarity_score": "Medium",
        "same_endpoint": false,
        "same_root_cause": false,
        "same_exploitation_technique": false,
        "differentiators": ["Different injection vector (SVG upload vs markdown)", "Different endpoint (avatar vs comments)", "Different root cause (file content sanitization vs markdown parsing)", "Additional CSP bypass component"]
      },
      "estimated_undisclosed_similar_reports": "With 3 XSS publicly disclosed out of 75 total disclosures (4%), and assuming 5-10% disclosure rate for XSS, there are likely 30-60 total XSS reports resolved. Of those, 2-5 may involve file upload vectors specifically.",
      "disclosure_analysis_conclusion": "No file-upload-based XSS has been disclosed, which is a positive signal. However, the absence of public disclosure does not guarantee the absence of prior reports - it may have been reported and resolved without disclosure."
    },
    "cve_analysis": {
      "relevant_cves_found": 1,
      "cve_overlap": "Partial",
      "cve_details": [
        {
          "cve_id": "CVE-2023-38199",
          "relevance": "Similar SVG XSS technique but on a different platform. Demonstrates the technique is known and actively exploited.",
          "same_product_version": false,
          "implies_known_issue": false
        }
      ],
      "cve_analysis_conclusion": "No CVE specific to Acme Corp for this issue. The existence of CVE-2023-38199 on a similar platform indicates the technique is well-known in the security community, increasing the probability that other researchers have tried it on Acme Corp."
    },
    "writeup_analysis": {
      "relevant_writeups_found": 2,
      "technique_publicly_known": true,
      "estimated_researchers_aware": "The Medium article has 12K views and the GitHub repo has 800 stars. Estimating 5-10% of readers actively test this on bug bounty targets, approximately 600-1800 researchers may have attempted SVG XSS on various programs after reading these resources.",
      "writeup_details": [
        {
          "source": "Medium article: Bypassing CSP via SVG uploads (12K views, 2023)",
          "relevance": "Directly describes the exact technique used in this finding",
          "increases_duplicate_risk": true,
          "reasoning": "High-visibility article specifically about SVG upload XSS with CSP bypass. Many researchers will have read this and tested on their active targets."
        },
        {
          "source": "GitHub repo: SVG XSS payloads (800 stars)",
          "relevance": "Provides ready-to-use payloads for SVG XSS testing",
          "increases_duplicate_risk": true,
          "reasoning": "Lowers the barrier to testing SVG XSS - researchers can use these payloads directly without crafting their own."
        }
      ],
      "writeup_analysis_conclusion": "The technique is publicly documented with high-visibility resources. This significantly increases the chance that other researchers have tested SVG uploads on Acme Corp."
    }
  },
  "recommendation": {
    "action": "Submit With Differentiation",
    "reasoning": "The finding has a 40-55% duplicate probability, which is borderline. The SVG upload vector is distinct from known XSS disclosures, and the CSP bypass via base-uri adds a novel element. Given the potential High severity of stored XSS affecting other users, the risk/reward ratio favors submission - even if it is a duplicate, you lose only the time spent writing the report. Key strategy: emphasize the CSP bypass angle and the stored nature affecting other users to differentiate from potential similar reports.",
    "if_submit": {
      "key_differentiators_to_emphasize": [
        "SVG file upload vector (distinct from the 3 known XSS vectors: markdown, reflected, DOM)",
        "CSP bypass via missing base-uri directive (additional security control failure)",
        "Stored nature affecting all users who view the attacker's profile",
        "Specific file type handling gap in the upload pipeline"
      ],
      "report_framing_advice": "Frame this as a file upload security gap rather than just another XSS. Emphasize that the upload pipeline lacks SVG sanitization and that the CSP policy has a gap (base-uri). This positions the finding as two issues: 1) insufficient file upload validation, and 2) CSP gap. Even if the XSS component is a duplicate, the CSP gap may be novel.",
      "preemptive_duplicate_defense": "I am aware of the previously disclosed XSS findings on this program (markdown injection, reflected search, DOM-based settings). This finding differs in both vector (SVG file upload) and root cause (missing server-side SVG sanitization + CSP base-uri gap) and therefore represents a distinct vulnerability requiring separate remediation."
    },
    "if_investigate_further": {
      "research_queries": [
        {
          "type": "Google Dork",
          "query": "site:hackerone.com \"acme corp\" (svg OR \"file upload\" OR avatar) (xss OR \"cross-site scripting\")",
          "purpose": "Find any disclosed reports mentioning SVG or file upload XSS on Acme Corp specifically"
        },
        {
          "type": "Google Dork",
          "query": "site:hackerone.com inurl:disclosed \"svg\" \"xss\" \"upload\"",
          "purpose": "Find SVG upload XSS disclosures across all programs to understand how common this finding is"
        },
        {
          "type": "HackerOne Search",
          "query": "Search Acme Corp's disclosed reports (hacktivity) for keywords: svg, upload, avatar, file, content-type",
          "purpose": "Direct search in program's hacktivity for related disclosures"
        },
        {
          "type": "CVE Database",
          "query": "Search NVD for: Acme Corp XSS OR (SVG XSS upload 2023 2024)",
          "purpose": "Check for CVEs specific to Acme Corp or the underlying technology stack"
        },
        {
          "type": "GitHub Search",
          "query": "\"acme corp\" svg xss OR \"acme.com\" svg upload bypass",
          "purpose": "Find any PoCs or tools specifically targeting Acme Corp's upload functionality"
        }
      ],
      "additional_tests": [
        "Test if other file upload endpoints (document upload, attachment, export) have the same SVG sanitization gap - finding multiple affected endpoints strengthens the report",
        "Verify if the CSP base-uri gap is exploitable independently of the SVG upload (increases severity and differentiates further)",
        "Check if the SVG can be served from S3 directly with script execution (CDN-level impact may be a separate finding)"
      ]
    }
  },
  "osint_research_checklist": {
    "completed": [
      {
        "source": "HackerOne public disclosures",
        "query_used": "Browsed Acme Corp hacktivity",
        "results": "3 XSS disclosed, none via file upload",
        "conclusion": "No direct overlap found"
      },
      {
        "source": "NVD/CVE database",
        "query_used": "Searched for Acme Corp CVEs",
        "results": "No relevant CVEs for Acme Corp",
        "conclusion": "No known CVE for this issue"
      }
    ],
    "recommended_additional": [
      {
        "source": "Google Dork",
        "query": "\"acme corp\" OR \"acme.com\" \"svg\" \"xss\" -site:acme.com",
        "purpose": "Find blog posts, tweets, or writeups mentioning SVG XSS on Acme Corp",
        "priority": "High"
      },
      {
        "source": "Twitter/X Search",
        "query": "@AcmeCorpSec svg xss OR file upload xss",
        "purpose": "Check if researchers have publicly discussed this vector on social media",
        "priority": "Medium"
      },
      {
        "source": "Bugcrowd/YesWeHack",
        "query": "Check if Acme Corp has programs on other platforms with relevant disclosures",
        "purpose": "Cross-platform duplicate check",
        "priority": "Medium"
      }
    ]
  }
}
```

### Example 2: Quick Reference - Duplicate Probability Indicators

| Indicator | Duplicate Probability | Reasoning |
|---|---|---|
| Program is >3 years old, 500+ reports | High base rate (60%+ for common vulns) | Heavily tested, common findings exhausted |
| Program is <6 months old | Low base rate (10-20%) | Fresh program, less researcher attention |
| Vuln class is XSS/IDOR/SSRF on main app | High (50-70%) | Most common targets for most researchers |
| Vuln class is business logic/race condition | Low (10-25%) | Requires deep understanding, few researchers test |
| Endpoint is login/search/profile (high visibility) | High (60-80%) | First endpoints everyone tests |
| Endpoint is obscure API v2 internal | Low (10-20%) | Requires API enumeration and deep testing |
| Technique documented in popular writeup | High (40-60%) | Many researchers read and replicate techniques |
| Novel exploitation chain | Low (5-15%) | Unique chain is unlikely to be duplicated exactly |
| 3+ similar findings already disclosed | Very High (70-90%) | Pattern already well-known on this target |
| No similar findings disclosed | Medium (30-50%) | Absence of evidence is not evidence of absence |
| Finding requires authentication + specific role | Lower (15-30%) | Fewer researchers test authenticated flows deeply |
| Finding on wildcard subdomain discovered via recon | Medium (30-50%) | Recon-heavy researchers may have found it |

---

## Thinking Block (Chain-of-Thought)

Le prompt force un raisonnement structure via le block `<thinking>` suivant, a integrer dans les instructions :

```
Avant de produire ton analyse de duplication, tu DOIS suivre ce processus de reflexion dans un block <thinking> :
1. Lister TOUS les rapports publics pertinents et evaluer leur similarite (endpoint, root cause, technique)
2. Estimer le nombre de rapports NON divulgues base sur le ratio de disclosure du programme
3. Evaluer la visibilite de l'endpoint affecte (haute visibilite = teste par beaucoup)
4. Evaluer la complexite de la decouverte (scan auto vs recherche manuelle creative)
5. Verifier si la technique d'exploitation est documentee publiquement (writeups, outils, CVE)
6. Classifier le finding : meme root cause (duplicat) vs meme classe mais root cause differente (unique) vs technique novel (unique)
7. Calculer la probabilite finale en ponderant chaque facteur
8. Formuler des requetes de recherche supplementaires concretes pour confirmer/infirmer
```
