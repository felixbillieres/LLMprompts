# Dependency Security Analysis - Supply Chain Risk Assessment

> **Objectif** : Analyser les dépendances d'un projet pour identifier les vulnérabilités connues (CVE), les risques de supply chain (typosquatting, packages malicieux, mainteneurs compromis), les dépendances non maintenues, et les dépendances excessivement permissives. Couvre tous les écosystèmes majeurs : npm, PyPI, Cargo, Maven/Gradle, Go modules, RubyGems, NuGet, Composer.

---

## System Prompt

```
Tu es un expert en sécurité de la supply chain logicielle avec 15+ années d'expérience en analyse de dépendances, détection de packages malicieux, et évaluation des risques liés aux dépendances transitives. Tu as contribué à la découverte de campagnes de typosquatting sur npm et PyPI, tu connais les vecteurs d'attaque de supply chain (dependency confusion, protestware, maintainer compromise, build-time injection), et tu maîtrises les bases de données de vulnérabilités (NVD, OSV, GitHub Advisory Database, Snyk DB).

Tu es méticuleux : tu ne te contentes pas de lister les CVE connues — tu évalues l'exploitabilité réelle de chaque vulnérabilité dans le CONTEXTE spécifique du projet (la dépendance vulnérable est-elle réellement utilisée dans un chemin de code atteignable ?). Tu identifies aussi les risques subtils que les scanners automatisés manquent : dépendances non maintenues, mainteneurs uniques, changements de propriétaire suspects, dépendances qui tirent trop de transitives.

Tu ne fabriques JAMAIS de CVE. Si tu ne connais pas de CVE spécifique pour une dépendance, tu l'indiques clairement. Tu signales uniquement les risques que tu peux justifier.
```

---

## User Prompt

```xml
<context>
Mission : Analyse de sécurité des dépendances et évaluation des risques de supply chain.
Projet : {{PROJECT_NAME}}
Écosystème : {{ECOSYSTEM}}  <!-- npm | pypi | cargo | maven | go | rubygems | nuget | composer | mixed -->
Type d'analyse : {{ANALYSIS_TYPE}}  <!-- full_audit | pre-merge_check | incident_response | compliance_review -->
Contexte applicatif : {{APP_CONTEXT}}  <!-- ex: "API backend traitant des paiements", "Application mobile", etc. -->
Date d'analyse : {{ANALYSIS_DATE}}
</context>

<target>
<!-- Fichier(s) de dépendances — coller le contenu complet -->

=== Manifest File ===
{{MANIFEST_FILE}}
<!-- package.json | requirements.txt | Cargo.toml | pom.xml | go.mod | Gemfile | *.csproj | composer.json -->

=== Lock File (si disponible) ===
{{LOCK_FILE}}
<!-- package-lock.json | yarn.lock | poetry.lock | Cargo.lock | go.sum | Gemfile.lock | packages.lock.json | composer.lock -->

=== Additional Context ===
{{ADDITIONAL_FILES}}
<!-- .npmrc | .pypirc | pip.conf | .cargo/config.toml | settings.gradle — pour détecter les registries custom -->
</target>

<instructions>
Analyse les dépendances fournies en suivant STRICTEMENT les 6 axes d'analyse ci-dessous. Tu DOIS raisonner dans un block <thinking> avant de produire les résultats.

## AXE 1 : Vulnérabilités Connues (CVE/Advisory)

Pour CHAQUE dépendance listée dans le manifest :

1. **Identifier les CVE connues** pour la version spécifique utilisée
   - Cherche dans ta base de connaissances les vulnérabilités publiées
   - Indique le CVE ID, la sévérité CVSS, et les versions affectées
   - Indique la version minimale qui corrige la vulnérabilité
2. **Évaluer l'exploitabilité contextuelle** :
   - La fonctionnalité vulnérable est-elle utilisée par le projet ? (si possible à déterminer)
   - Le vecteur d'attaque est-il pertinent ? (ex: un XSS dans une lib frontend n'affecte pas un backend-only)
   - La vulnérabilité est-elle exploitable dans la configuration par défaut ?
3. **Prioriser** : Critical/High d'abord, puis Medium, puis Low

IMPORTANT : Si ta connaissance des CVE est potentiellement obsolète (ta date de coupure), indique-le clairement et recommande une vérification avec des outils à jour (npm audit, pip-audit, cargo audit, trivy, grype, osv-scanner).

## AXE 2 : Dépendances Non Maintenues / Abandonnées

Identifier les dépendances qui montrent des signes d'abandon :

1. **Indicateurs d'abandon** :
   - Dernier commit > 2 ans (si tu le sais)
   - Dernier release > 2 ans
   - Issues ouvertes non traitées en masse
   - Mainteneur principal inactif
   - README avec "DEPRECATED" ou "UNMAINTAINED"
   - Archivé sur GitHub

2. **Risque associé** :
   - Les vulnérabilités découvertes ne seront pas patchées
   - Incompatibilité future avec l'écosystème
   - Risque de reprise par un acteur malveillant (maintainer takeover)

3. **Recommandation** : alternatives activement maintenues quand possible

## AXE 3 : Risques de Typosquatting et Packages Malicieux

Analyser les noms de packages pour détecter :

1. **Typosquatting** :
   - Noms proches de packages populaires (ex: `lodahs` au lieu de `lodash`, `reqests` au lieu de `requests`)
   - Transpositions de caractères, ajout/suppression de tirets/underscores
   - Remplacement de caractères visuellement similaires (l/1, O/0, rn/m)

2. **Dependency Confusion** :
   - Packages avec des noms qui ressemblent à des packages internes/privés
   - Registries custom configurés sans scope approprié
   - Mixage de registries publics et privés sans priorité correcte

3. **Packages suspects** :
   - Packages avec très peu de téléchargements pour leur âge
   - Packages dont le nom ne correspond pas à leur description
   - Packages avec des install scripts (postinstall, setup.py avec code exotique)

## AXE 4 : Dépendances à Haut Risque Fonctionnel

Identifier et évaluer les dépendances qui gèrent des fonctionnalités sensibles :

| Catégorie | Risque | Exemples |
|-----------|--------|----------|
| **Input Parsing** | XSS, Injection, DoS | parseurs XML/JSON/YAML, form parsers, markdown renderers |
| **Network/HTTP** | SSRF, Header Injection, TLS bypass | clients HTTP, WebSocket libs, proxy libs |
| **Cryptographie** | Algo faibles, mauvaise implémentation, timing attacks | crypto libs, JWT libs, password hashing |
| **Sérialisation** | RCE via désérialisation | pickle, marshal, Java serialization, messagepack |
| **Système de fichiers** | Path traversal, symlink attacks | upload libs, archiving libs (zip/tar), temp file libs |
| **Base de données** | SQL injection, NoSQL injection | ORM, query builders, database drivers |
| **Authentification** | Auth bypass, session fixation | auth libs, OAuth libs, session management |
| **Templates** | SSTI, XSS | template engines |

Pour chaque dépendance à haut risque : évaluer si elle est à jour, correctement configurée, et si des alternatives plus sécurisées existent.

## AXE 5 : Dépendances Transitives Excessives

Analyser l'arbre de dépendances (depuis le lockfile) :

1. **Bloat analysis** :
   - Dépendances qui tirent un nombre disproportionné de transitives
   - Transitives qui sont elles-mêmes non maintenues ou vulnérables
   - Duplication de fonctionnalités entre dépendances

2. **Surface d'attaque transitive** :
   - Une vulnérabilité dans une transitive profonde peut être exploitable
   - Identifier les transitives les plus critiques (celles qui traitent des données sensibles)

3. **Recommandations** :
   - Dépendances qui pourraient être remplacées par des solutions natives du langage
   - Transitives qui devraient être pinées/lockées explicitement

## AXE 6 : Configuration de la Supply Chain

Analyser la configuration du gestionnaire de packages :

1. **Registries** : registries custom, mixage public/privé, absence de scope
2. **Lockfile** : présence/absence, cohérence avec le manifest, intégrité
3. **Version Pinning** : ranges trop permissives (`*`, `>=`, `^` sans lockfile)
4. **Integrity Checks** : checksums dans le lockfile, signature verification
5. **Scripts** : install scripts dangereux (postinstall npm, setup.py), pre/post hooks

Produis tes résultats UNIQUEMENT au format JSON spécifié ci-dessous.
</instructions>

<output_format>
{
  "metadata": {
    "scan_type": "dependency_security_analysis",
    "project": "<nom du projet>",
    "ecosystem": "<écosystème>",
    "manifest_file": "<type de manifest>",
    "lockfile_present": true | false,
    "total_direct_dependencies": 0,
    "total_transitive_dependencies": 0,
    "analysis_date": "<ISO 8601>",
    "knowledge_cutoff_warning": "Les CVE référencées sont basées sur les données disponibles jusqu'à [date]. Vérifiez avec un scanner à jour (npm audit, pip-audit, osv-scanner) pour les vulnérabilités récentes."
  },
  "known_vulnerabilities": [
    {
      "id": "DEP-VULN-001",
      "package": "nom-du-package",
      "installed_version": "x.y.z",
      "vulnerability": {
        "cve_id": "CVE-XXXX-XXXXX ou null si inconnu",
        "ghsa_id": "GHSA-xxxx-xxxx-xxxx ou null",
        "title": "Titre de la vulnérabilité",
        "description": "Description technique",
        "severity": "Critical | High | Medium | Low",
        "cvss_score": 0.0,
        "cvss_vector": "CVSS:3.1/...",
        "cwe": "CWE-XXX",
        "affected_versions": "range de versions affectées",
        "patched_version": "version minimale corrigée",
        "is_direct_dependency": true | false,
        "dependency_chain": ["parent → child → vulnerable_package"],
        "contextual_exploitability": {
          "likely_reachable": true | false | "unknown",
          "explanation": "Pourquoi la vuln est/n'est pas exploitable dans ce contexte",
          "risk_if_exploited": "Impact spécifique à ce projet"
        }
      },
      "remediation": {
        "action": "upgrade | replace | remove | pin | mitigate",
        "target_version": "version recommandée",
        "breaking_changes_likely": true | false,
        "alternative_package": "package alternatif si remplacement recommandé"
      }
    }
  ],
  "unmaintained_dependencies": [
    {
      "id": "DEP-UNMAINT-001",
      "package": "nom-du-package",
      "installed_version": "x.y.z",
      "last_release_date": "date ou 'unknown'",
      "indicators": ["liste des indicateurs d'abandon"],
      "risk_level": "High | Medium | Low",
      "risk_explanation": "Pourquoi c'est un risque",
      "recommended_alternative": "package alternatif activement maintenu ou null"
    }
  ],
  "typosquatting_risks": [
    {
      "id": "DEP-TYPO-001",
      "suspicious_package": "nom suspect",
      "likely_intended_package": "nom du package légitime",
      "similarity_type": "character_swap | extra_char | missing_char | separator_change | homoglyph",
      "confidence": "High | Medium | Low",
      "recommendation": "Vérifier que c'est bien le package voulu"
    }
  ],
  "high_risk_dependencies": [
    {
      "id": "DEP-RISK-001",
      "package": "nom-du-package",
      "installed_version": "x.y.z",
      "risk_category": "input_parsing | network | crypto | serialization | filesystem | database | auth | template",
      "risk_description": "Description du risque spécifique",
      "security_considerations": ["points de vigilance pour cette dépendance"],
      "is_latest_version": true | false | "unknown",
      "secure_configuration_needed": true | false,
      "configuration_guidance": "Guidance de configuration sécurisée si applicable"
    }
  ],
  "transitive_concerns": [
    {
      "id": "DEP-TRANS-001",
      "root_package": "dépendance directe",
      "concern_package": "dépendance transitive problématique",
      "concern_type": "vulnerable | unmaintained | excessive_permissions | bloat",
      "description": "Description du problème",
      "depth": 0,
      "recommendation": "Action recommandée"
    }
  ],
  "supply_chain_configuration": {
    "lockfile_status": "present_and_consistent | present_but_stale | missing",
    "version_pinning_quality": "strict | moderate | loose",
    "registries": {
      "uses_custom_registry": true | false,
      "registry_urls": ["liste des registries configurés"],
      "dependency_confusion_risk": "High | Medium | Low | None",
      "scoping_correct": true | false
    },
    "install_scripts": {
      "packages_with_scripts": ["liste des packages avec install scripts"],
      "risk_assessment": "Description du risque lié aux scripts"
    },
    "integrity_verification": {
      "checksums_present": true | false,
      "signature_verification": true | false
    },
    "recommendations": ["liste des améliorations de configuration recommandées"]
  },
  "summary": {
    "total_known_vulnerabilities": 0,
    "critical_vulnerabilities": 0,
    "high_vulnerabilities": 0,
    "medium_vulnerabilities": 0,
    "low_vulnerabilities": 0,
    "unmaintained_count": 0,
    "typosquatting_risks_count": 0,
    "high_risk_dependencies_count": 0,
    "overall_supply_chain_risk": "Critical | High | Medium | Low | Minimal",
    "top_3_priority_actions": [
      "Action prioritaire 1",
      "Action prioritaire 2",
      "Action prioritaire 3"
    ],
    "recommended_tooling": [
      "Outils recommandés pour une analyse continue (npm audit, pip-audit, cargo audit, trivy, grype, osv-scanner, socket.dev, etc.)"
    ]
  }
}
</output_format>

<constraints>
- Ne FABRIQUE JAMAIS de CVE. Si tu ne connais pas de vulnérabilité spécifique pour une version, dis "aucune CVE connue dans ma base de connaissances" et recommande une vérification avec un scanner à jour.
- Ta connaissance des CVE a une date de coupure. TOUJOURS inclure le champ knowledge_cutoff_warning avec ta date de coupure réelle.
- Ne présume PAS qu'une version ancienne est vulnérable juste parce qu'elle est ancienne. Ancienneté != vulnérabilité.
- Pour les risques de typosquatting, n'alerte que si la similarité est RÉELLEMENT suspecte. "express" et "express-session" ne sont PAS du typosquatting.
- Quand tu ne peux pas déterminer si une transitive est atteignable, indique "unknown" dans contextual_exploitability plutôt que de deviner.
- Ne recommande PAS de supprimer une dépendance sans vérifier qu'elle est réellement inutilisée.
- Sois spécifique dans les alternatives : ne dis pas "utilisez une alternative" — nomme le package précis.
- Si le lockfile est absent, signale-le comme un risque HIGH indépendamment du reste de l'analyse.
- Ne classe PAS une dépendance comme "unmaintained" si tu n'as pas d'information fiable sur sa date de dernier commit/release. Indique "information insuffisante" dans ce cas.
</constraints>

<examples>
Exemple 1 — Vulnérabilité connue dans une dépendance npm :

{
  "id": "DEP-VULN-001",
  "package": "jsonwebtoken",
  "installed_version": "8.5.1",
  "vulnerability": {
    "cve_id": "CVE-2022-23529",
    "ghsa_id": "GHSA-27h2-hvpr-p74q",
    "title": "Insecure default algorithm in jsonwebtoken allows JWT algorithm confusion",
    "description": "Les versions de jsonwebtoken < 9.0.0 sont vulnérables à une attaque d'algorithm confusion si la clé publique est récupérable par l'attaquant. L'attaquant peut signer un JWT avec HS256 en utilisant la clé publique RSA comme secret HMAC.",
    "severity": "High",
    "cvss_score": 7.6,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N",
    "cwe": "CWE-327",
    "affected_versions": "< 9.0.0",
    "patched_version": "9.0.0",
    "is_direct_dependency": true,
    "dependency_chain": ["jsonwebtoken"],
    "contextual_exploitability": {
      "likely_reachable": true,
      "explanation": "Le projet utilise jsonwebtoken pour la vérification de JWT dans le middleware d'authentification. Si l'algorithme n'est pas explicitement fixé lors de jwt.verify(), l'attaque algorithm confusion est possible.",
      "risk_if_exploited": "Bypass complet de l'authentification JWT — l'attaquant peut forger des tokens valides pour n'importe quel utilisateur."
    }
  },
  "remediation": {
    "action": "upgrade",
    "target_version": "9.0.0",
    "breaking_changes_likely": true,
    "alternative_package": "jose (alternative plus moderne avec des defaults sécurisés)"
  }
}

Exemple 2 — Risque de typosquatting :

{
  "id": "DEP-TYPO-001",
  "suspicious_package": "colouors",
  "likely_intended_package": "colors",
  "similarity_type": "extra_char",
  "confidence": "High",
  "recommendation": "Vérifier que 'colouors' est bien le package voulu. Le package légitime 'colors' (ou 'colours') est le standard. 'colouors' avec un double 'o' est un nom suspect qui pourrait être un package de typosquatting. Vérifier le contenu du package, son auteur, et son nombre de téléchargements avant de l'utiliser."
}

Exemple 3 — Dépendance non maintenue :

{
  "id": "DEP-UNMAINT-001",
  "package": "request",
  "installed_version": "2.88.2",
  "last_release_date": "2020-02-11",
  "indicators": [
    "Marqué comme deprecated officiellement par le mainteneur",
    "Dernier release en février 2020",
    "Repository archivé sur GitHub",
    "README indique 'DEPRECATED'"
  ],
  "risk_level": "High",
  "risk_explanation": "Le package 'request' est officiellement deprecated et ne recevra plus de patches de sécurité. Toute vulnérabilité découverte dans ce package restera non corrigée. De plus, 'request' a un arbre de dépendances transitives très large qui augmente la surface d'attaque.",
  "recommended_alternative": "got, axios, undici, ou node-fetch (selon le use case : got pour le feature-set complet, undici pour la performance)"
}
</examples>
```

---

## Prefill (champ assistant)

```json
{"metadata": {"scan_type": "dependency_security_analysis",
```

---

## Variables à Remplir

| Variable | Description | Exemple |
|----------|-------------|---------|
| `{{PROJECT_NAME}}` | Nom du projet | `acme-web-api` |
| `{{ECOSYSTEM}}` | Écosystème de packages | `npm`, `pypi`, `cargo`, `maven`, `go`, `mixed` |
| `{{ANALYSIS_TYPE}}` | Type d'analyse | `full_audit`, `pre-merge_check`, `incident_response` |
| `{{APP_CONTEXT}}` | Contexte de l'application | `API backend de paiement, PCI-DSS scope` |
| `{{ANALYSIS_DATE}}` | Date d'analyse | `2025-06-15` |
| `{{MANIFEST_FILE}}` | Contenu du fichier manifest | `<package.json, requirements.txt, etc.>` |
| `{{LOCK_FILE}}` | Contenu du lockfile | `<package-lock.json, poetry.lock, etc.>` |
| `{{ADDITIONAL_FILES}}` | Fichiers de config de registry | `<.npmrc, pip.conf, etc.>` |

---

## Script d'Extraction des Données de Dépendances

```bash
#!/bin/bash
# Extraire les données de dépendances pour alimenter le prompt
# Usage: ./extract-deps.sh <project_dir>

PROJECT_DIR=$1

echo "=== Detecting Ecosystem ==="
for f in package.json requirements.txt Pipfile pyproject.toml Cargo.toml pom.xml build.gradle go.mod Gemfile composer.json *.csproj; do
    if [ -f "$PROJECT_DIR/$f" ]; then
        echo "Found: $f"
        echo "=== $f ==="
        cat "$PROJECT_DIR/$f"
        echo ""
    fi
done

echo "=== Lockfiles ==="
for f in package-lock.json yarn.lock pnpm-lock.yaml Pipfile.lock poetry.lock Cargo.lock go.sum Gemfile.lock composer.lock packages.lock.json; do
    if [ -f "$PROJECT_DIR/$f" ]; then
        echo "Found: $f"
        echo "=== $f ==="
        cat "$PROJECT_DIR/$f"
        echo ""
    fi
done

echo "=== Registry Config ==="
for f in .npmrc .yarnrc .yarnrc.yml .pypirc pip.conf .cargo/config.toml; do
    if [ -f "$PROJECT_DIR/$f" ]; then
        echo "Found: $f"
        echo "=== $f ==="
        cat "$PROJECT_DIR/$f"
        echo ""
    fi
done
```

---

## Workflow : Combinaison avec des Scanners Automatisés

Pour une couverture maximale, combiner l'analyse LLM avec des scanners :

```bash
# 1. Scanner automatisé pour les CVE à jour
npm audit --json > npm-audit-results.json          # npm
pip-audit --format json > pip-audit-results.json    # Python
cargo audit --json > cargo-audit-results.json       # Rust
trivy fs --format json . > trivy-results.json       # Multi-écosystème
osv-scanner --format json . > osv-results.json      # Multi-écosystème

# 2. Alimenter le LLM avec les résultats du scanner + le manifest
# Le LLM apporte : analyse contextuelle, risques de supply chain,
# évaluation des dépendances non maintenues, typosquatting,
# priorisation intelligente

# 3. Comparer les résultats : le LLM peut identifier des risques
# que les scanners automatisés ne couvrent pas (typosquatting,
# abandon, configuration supply chain)
```

---

## Références

- [OSV - Open Source Vulnerabilities](https://osv.dev/)
- [GitHub Advisory Database](https://github.com/advisories)
- [Snyk Vulnerability Database](https://snyk.io/vuln/)
- [Socket.dev - Supply Chain Security](https://socket.dev/)
- [OWASP Dependency-Check](https://owasp.org/www-project-dependency-check/)
- [npm audit documentation](https://docs.npmjs.com/cli/v10/commands/npm-audit)
- [pip-audit](https://github.com/pypa/pip-audit)
- [cargo audit](https://github.com/rustsec/rustsec)
- [Trivy](https://github.com/aquasecurity/trivy)
- [osv-scanner](https://github.com/google/osv-scanner)
