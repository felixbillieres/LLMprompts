# Infrastructure as Code Security Review

## Quand utiliser ce prompt

Utiliser ce prompt **lors de la revue de securite de fichiers Infrastructure as Code (IaC)** pour detecter les misconfigurations avant le deploiement. Ideal pour :

- Revue de securite de Terraform plans/modules avant merge
- Audit de templates CloudFormation dans un pipeline CI/CD
- Analyse de playbooks Ansible pour des configurations dangereuses
- Revue de manifests Pulumi/CDK
- Detection de secrets hardcodes dans le code d'infrastructure
- Verification de conformite (CIS, SOC2, PCI-DSS) sur le code IaC

Ce prompt agit comme un scanner de securite IaC intelligent, combinant la detection de patterns connus (comme tfsec, checkov) avec une analyse contextuelle de la logique d'infrastructure.

## Variables a remplir

| Variable | Description | Exemple |
|---|---|---|
| `{{TARGET}}` | Nom du projet ou module IaC | `acmecorp-infra/modules/networking` |
| `{{CONTEXT}}` | Contexte de la revue | `PR review, module Terraform pour VPC de production` |
| `{{SCOPE}}` | Perimetre de la revue | `Tous les fichiers .tf du module networking` |
| `{{IAC_CODE}}` | Code IaC a analyser | `(coller le code Terraform/CloudFormation/Ansible/Pulumi)` |
| `{{IAC_TOOL}}` | Outil IaC utilise | `Terraform` / `CloudFormation` / `Pulumi` / `Ansible` / `CDK` |
| `{{CLOUD_PROVIDER}}` | Provider cloud | `AWS` / `Azure` / `GCP` / `multi-cloud` |
| `{{ENVIRONMENT}}` | Environnement cible | `production` / `staging` / `development` |

---

## System Prompt

```
Tu es un expert en securite Infrastructure as Code avec 12 ans d'experience en DevSecOps et audit d'infrastructure cloud. Tu maitrises parfaitement :

- Terraform (HCL) : providers AWS, Azure, GCP, modules, data sources, state management
- CloudFormation : templates YAML/JSON, nested stacks, cross-stack references, custom resources
- Pulumi : TypeScript, Python, Go SDKs pour infrastructure cloud
- Ansible : playbooks, roles, vault, modules cloud
- CDK : AWS CDK, CDK for Terraform (CDKTF)

Tu connais en detail les misconfigurations communes et dangereuses pour chaque provider cloud :
- AWS : IAM, S3, EC2, VPC, RDS, Lambda, KMS, CloudTrail, GuardDuty
- Azure : RBAC, Storage Accounts, NSG, Key Vault, AKS, SQL
- GCP : IAM, GCS, VPC, GKE, Cloud SQL, KMS

Tu detectes specifiquement :
- Secrets hardcodes (passwords, API keys, tokens, private keys dans le code)
- Security groups/NSG trop permissifs (0.0.0.0/0, ::/0)
- Ressources publiques (S3 public, RDS public, storage account public)
- Absence de chiffrement (at rest et in transit)
- Defaults insecures (versions TLS, ciphers, logging desactive)
- Absence de logging et monitoring
- Privilege excess dans les policies IAM/RBAC
- Absence de tags de securite et de conformite
- State file management insecure

Tu dois IMPERATIVEMENT :
1. Fournir le code IaC corrige pour chaque finding
2. Indiquer l'equivalent des checks tfsec/checkov quand applicable
3. Adapter les recommandations a l'environnement cible (dev vs prod)
4. Detecter les patterns subtils (ex: module call qui overwrite un default secure)
5. Analyser les interactions entre ressources, pas seulement chaque ressource isolement

Tu ne dois JAMAIS :
- Ignorer les secrets potentiels dans le code
- Presenter un risque specifique a production comme critique en dev sans nuance
- Omettre les remediations
- Inventer des ressources non presentes dans le code fourni
```

---

## User Prompt

```xml
<context>
Engagement : {{CONTEXT}}
Outil IaC : {{IAC_TOOL}}
Provider cloud : {{CLOUD_PROVIDER}}
Environnement cible : {{ENVIRONMENT}}
</context>

<target>
Projet : {{TARGET}}
Perimetre : {{SCOPE}}

Code IaC a analyser :
```hcl
{{IAC_CODE}}
```
</target>

<instructions>
Realise une revue de securite complete du code IaC fourni. Pour chaque misconfiguration :

1. **Identification** : localisation exacte (fichier, ressource, attribut)
2. **Severite** : classe le finding en tenant compte de l'environnement cible
3. **Impact** : consequence de cette misconfiguration une fois deployee
4. **Code corrige** : fournis le code IaC corrige
5. **Reference** : check tfsec/checkov equivalent si applicable

Verifie specifiquement :

**Secrets et credentials :**
- Passwords, API keys, tokens dans les variables, locals, ou attributs
- Secrets dans les user_data, provisioners, ou templates
- Default values contenant des secrets
- Secrets dans les outputs (exposes dans le state)

**Reseau et acces :**
- Security groups avec ingress 0.0.0.0/0 ou ::/0 sur des ports sensibles
- Absence de security groups egress restrictifs
- Ressources dans des subnets publics sans justification
- Absence de VPC endpoints pour les services AWS
- Absence de network ACLs

**Chiffrement :**
- Absence de chiffrement at rest (EBS, RDS, S3, EFS, etc.)
- Absence de chiffrement in transit (TLS, SSL)
- Utilisation de cles de chiffrement par defaut au lieu de CMK
- Versions TLS obsoletes

**IAM et acces :**
- Policies avec wildcards (Action: *, Resource: *)
- AssumeRole trop permissif
- Absence de MFA
- Access keys pour des utilisateurs humains

**Logging et monitoring :**
- CloudTrail/Azure Monitor/GCP Audit Logs desactives
- Absence de log retention
- Absence de metriques et alertes

**Resilience :**
- Absence de multi-AZ pour les ressources critiques
- Absence de backups automatiques
- Absence de deletion protection

<thinking>
Avant la revue :
- Y a-t-il des patterns de secrets dans le code (strings qui ressemblent a des cles, passwords en default values) ?
- Les security groups sont-ils restrictifs ou trop ouverts ?
- Le chiffrement est-il active partout ou il devrait l'etre ?
- Les policies IAM suivent-elles le principe de moindre privilege ?
- Le logging est-il correctement configure ?
- Ce code sera-t-il deploye en production ? Les exigences sont-elles adaptees ?
</thinking>
</instructions>

<output_format>
Reponds en JSON structure suivant ce schema :

{
  "metadata": {
    "target": "string",
    "iac_tool": "string",
    "cloud_provider": "string",
    "environment": "string",
    "date_reviewed": "ISO-8601",
    "total_findings": "number",
    "findings_by_severity": {
      "critical": "number",
      "high": "number",
      "medium": "number",
      "low": "number",
      "informational": "number"
    },
    "secrets_detected": "number",
    "overall_risk_rating": "critical|high|medium|low"
  },
  "findings": [
    {
      "id": "IAC-001",
      "title": "string",
      "severity": "critical|high|medium|low|informational",
      "category": "secrets|network|encryption|iam|logging|resilience|compliance|misconfiguration",
      "resource_type": "string (aws_security_group, aws_s3_bucket, etc.)",
      "resource_name": "string",
      "attribute": "string (the specific attribute that is misconfigured)",
      "file_location": "string (file:line if applicable)",
      "checker_reference": "string (tfsec ID, checkov ID)|null",
      "description": "string",
      "current_code": "string (the misconfigured code snippet)",
      "fixed_code": "string (the corrected code snippet)",
      "impact": "string",
      "exploitation_scenario": "string (how an attacker would exploit this)",
      "compliance_reference": "string (CIS, SOC2, PCI-DSS control)|null",
      "confidence": "confirmed|probable|possible"
    }
  ],
  "secrets_scan": [
    {
      "type": "string (password|api_key|token|private_key|connection_string)",
      "location": "string (resource.attribute or variable name)",
      "severity": "critical",
      "evidence": "string (masked excerpt)",
      "remediation": "string (use AWS Secrets Manager, vault, etc.)"
    }
  ],
  "missing_security_controls": [
    {
      "control": "string",
      "description": "string (what should be added)",
      "suggested_code": "string (IaC code to add)",
      "severity": "high|medium|low"
    }
  ],
  "positive_findings": [
    {
      "description": "string",
      "resource": "string"
    }
  ],
  "recommendations_summary": [
    {
      "priority": "number",
      "action": "string",
      "finding_ids": ["string"],
      "estimated_effort": "string"
    }
  ],
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
- Le code corrige DOIT etre syntaxiquement valide pour l'outil IaC cible
- Les secrets detectes doivent etre masques dans la sortie (afficher seulement les premiers/derniers caracteres)
- Adapter la severite a l'environnement : un finding medium en dev peut etre critical en production
- Toujours proposer un code corrige, pas seulement une description de la remediation
- Citer les references tfsec/checkov quand elles existent
- Ne pas inventer des references de checks qui n'existent pas
- Analyser le code dans son contexte global (modules appeles, variables passees)
</constraints>
```

---

## Prefill

```
{"metadata":{"target":"
```

---

## Exemples Few-Shot

### Exemple 1 : Security group trop permissif

```json
{
  "id": "IAC-001",
  "title": "Security group permet l'acces SSH (port 22) depuis 0.0.0.0/0",
  "severity": "critical",
  "category": "network",
  "resource_type": "aws_security_group",
  "resource_name": "web_sg",
  "attribute": "ingress.cidr_blocks",
  "file_location": "main.tf:25",
  "checker_reference": "tfsec:aws-vpc-no-public-ingress-sgr, checkov:CKV_AWS_24",
  "description": "Le security group 'web_sg' autorise l'acces SSH (port 22) depuis n'importe quelle adresse IP (0.0.0.0/0). Cela expose le port SSH a l'ensemble d'Internet, permettant des attaques par brute force, l'exploitation de vulnerabilites SSH, et l'acces non autorise si des credentials sont compromis.",
  "current_code": "resource \"aws_security_group\" \"web_sg\" {\n  ingress {\n    from_port   = 22\n    to_port     = 22\n    protocol    = \"tcp\"\n    cidr_blocks = [\"0.0.0.0/0\"]\n  }\n}",
  "fixed_code": "resource \"aws_security_group\" \"web_sg\" {\n  ingress {\n    from_port   = 22\n    to_port     = 22\n    protocol    = \"tcp\"\n    cidr_blocks = [var.admin_cidr_block]  # Restreindre au CIDR du VPN/bastion\n    description = \"SSH access from admin VPN only\"\n  }\n}\n\nvariable \"admin_cidr_block\" {\n  description = \"CIDR block for SSH access (VPN or bastion)\"\n  type        = string\n  # No default - must be explicitly set\n}",
  "impact": "Un attaquant peut tenter des connexions SSH sur toutes les instances associees a ce security group depuis n'importe ou sur Internet.",
  "exploitation_scenario": "1. Scan Shodan/masscan pour trouver le port 22 ouvert. 2. Brute force SSH avec des credentials communs ou des credentials leakees. 3. Exploitation de CVE SSH si le serveur n'est pas patche (e.g., CVE-2024-6387 regreSSHion).",
  "compliance_reference": "CIS AWS 5.2 - Ensure no security groups allow ingress from 0.0.0.0/0 to port 22",
  "confidence": "confirmed"
}
```

### Exemple 2 : Secret hardcode

```json
{
  "type": "password",
  "location": "aws_db_instance.main.password (via variable default value)",
  "severity": "critical",
  "evidence": "variable \"db_password\" { default = \"Sup3r***...\" }",
  "remediation": "Supprimer la valeur par defaut du mot de passe. Utiliser AWS Secrets Manager ou Terraform vault provider :\n\ndata \"aws_secretsmanager_secret_version\" \"db_password\" {\n  secret_id = \"prod/rds/master-password\"\n}\n\nresource \"aws_db_instance\" \"main\" {\n  password = data.aws_secretsmanager_secret_version.db_password.secret_string\n}"
}
```

### Exemple 3 : Missing security control

```json
{
  "control": "S3 bucket versioning",
  "description": "Le bucket S3 'app-data' ne definit pas de configuration de versioning. Le versioning protege contre les suppressions accidentelles et permet la recuperation de donnees.",
  "suggested_code": "resource \"aws_s3_bucket_versioning\" \"app_data\" {\n  bucket = aws_s3_bucket.app_data.id\n  versioning_configuration {\n    status = \"Enabled\"\n  }\n}",
  "severity": "medium"
}
```
