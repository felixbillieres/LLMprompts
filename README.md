# Security Research LLM Arsenal

Collection de prompts ultra-techniques pour la recherche en securite offensive, le bug bounty, et la chasse aux CVE. Chaque prompt est concu selon les meilleures pratiques de prompt engineering pour maximiser la precision et l'exploitabilite des resultats.

## Principes Appliques

Chaque prompt applique systematiquement ces 8 principes (voir [METHODOLOGY.md](METHODOLOGY.md)) :

1. **Role-Based Priming** : Identite d'expert specifique avec 15+ ans d'experience
2. **XML Tags Structures** : `<context>`, `<target>`, `<instructions>`, `<output_format>`, `<constraints>`
3. **Chain-of-Thought Force** : Block `<thinking>` obligatoire avant les conclusions
4. **Structured JSON Output** : Format de sortie predefined pour chaque type de finding
5. **Prefill Technique** : Pre-remplissage de la reponse assistant pour forcer le format
6. **Few-Shot Examples** : 1-2 exemples concrets de findings reels par prompt
7. **Scoring CVSS 3.1** : Score de criticite integre dans chaque output
8. **Anti-Hallucination Guards** : Contraintes explicites contre les faux positifs

---

## Table des Matieres

### 00 - Master Prompt (START HERE)
| Prompt | Description |
|--------|-------------|
| [master-0day-hunter.md](00-master/master-0day-hunter.md) | **LE prompt principal** : recherche autonome de 0-day avec methodologie ouverte, introspection, et chaining. Drop-in CLAUDE.md |

### 01 - Reconnaissance
| Prompt | Description |
|--------|-------------|
| [recon-passive-osint.md](01-recon/recon-passive-osint.md) | OSINT passif, Google dorks, Shodan, leak databases, GitHub secrets |
| [recon-attack-surface-mapping.md](01-recon/recon-attack-surface-mapping.md) | Cartographie complete de la surface d'attaque |
| [recon-tech-stack-fingerprint.md](01-recon/recon-tech-stack-fingerprint.md) | Identification stack technique, WAF detection, CMS detection |
| [recon-api-discovery.md](01-recon/recon-api-discovery.md) | Decouverte d'endpoints API caches et non-documentes |

### 02 - Vulnerability Research
| Prompt | Description |
|--------|-------------|
| [vuln-source-code-audit.md](02-vuln-research/vuln-source-code-audit.md) | Audit de code complet avec taint analysis source-to-sink (style Vulnhuntr) |
| [vuln-diff-patch-analysis.md](02-vuln-research/vuln-diff-patch-analysis.md) | Analyse de diffs/patches pour detection de negative-days (style spaceraccoon) |
| [vuln-dependency-analysis.md](02-vuln-research/vuln-dependency-analysis.md) | Analyse de dependances et risques supply chain |
| [vuln-config-review.md](02-vuln-research/vuln-config-review.md) | Revue de configuration securite (nginx, Docker, K8s, CI/CD, cloud) |
| [vuln-threat-modeling.md](02-vuln-research/vuln-threat-modeling.md) | Modelisation de menaces STRIDE assistee par LLM |

### 03 - Web Application Testing
| Prompt | Description |
|--------|-------------|
| [web-sqli-detection.md](03-web-app/web-sqli-detection.md) | Injection SQL (classic, blind, second-order, NoSQL, OOB) |
| [web-xss-analysis.md](03-web-app/web-xss-analysis.md) | Cross-Site Scripting (reflected, stored, DOM-based) |
| [web-ssrf-detection.md](03-web-app/web-ssrf-detection.md) | Server-Side Request Forgery et cloud metadata exploitation |
| [web-idor-analysis.md](03-web-app/web-idor-analysis.md) | Insecure Direct Object References et broken access control |
| [web-auth-bypass.md](03-web-app/web-auth-bypass.md) | Contournement d'authentification (JWT, OAuth, session) |
| [web-ssti-detection.md](03-web-app/web-ssti-detection.md) | Server-Side Template Injection (Jinja2, Twig, Freemarker, etc.) |
| [web-deserialization.md](03-web-app/web-deserialization.md) | Insecure Deserialization (Java, PHP, Python, .NET, Ruby) |
| [web-business-logic.md](03-web-app/web-business-logic.md) | Failles de logique metier, race conditions, workflow bypass |

### 04 - Binary & Memory Corruption
| Prompt | Description |
|--------|-------------|
| [binary-overflow-analysis.md](04-binary-memory/binary-overflow-analysis.md) | Buffer overflow (stack, heap, integer) |
| [binary-format-string.md](04-binary-memory/binary-format-string.md) | Format string vulnerabilities |
| [binary-use-after-free.md](04-binary-memory/binary-use-after-free.md) | Use-after-free detection |
| [binary-race-condition.md](04-binary-memory/binary-race-condition.md) | Race conditions et TOCTOU |
| [binary-rop-chain.md](04-binary-memory/binary-rop-chain.md) | ROP chain construction assistance |

### 05 - Cloud & Infrastructure
| Prompt | Description |
|--------|-------------|
| [cloud-aws-audit.md](05-cloud-infra/cloud-aws-audit.md) | Audit AWS (IAM, S3, EC2, Lambda, misconfigs) |
| [cloud-k8s-audit.md](05-cloud-infra/cloud-k8s-audit.md) | Kubernetes security audit (RBAC, pod security, network policies) |
| [cloud-iac-review.md](05-cloud-infra/cloud-iac-review.md) | Infrastructure as Code review (Terraform, CloudFormation) |
| [cloud-container-escape.md](05-cloud-infra/cloud-container-escape.md) | Container escape analysis (Docker, K8s) |

### 06 - Exploit Development
| Prompt | Description |
|--------|-------------|
| [exploit-poc-generator.md](06-exploit-dev/exploit-poc-generator.md) | Generation de PoC fonctionnels a partir d'une vuln identifiee |
| [exploit-payload-craft.md](06-exploit-dev/exploit-payload-craft.md) | Craft de payloads (encoding, obfuscation, bypass) |
| [exploit-chain-builder.md](06-exploit-dev/exploit-chain-builder.md) | Chainage de vulnerabilites low/medium en chaine critical |
| [exploit-bypass-techniques.md](06-exploit-dev/exploit-bypass-techniques.md) | Bypass de protections (WAF, CSP, ASLR, DEP, sandboxes) |

### 07 - Negative-Day & N-Day Research
| Prompt | Description |
|--------|-------------|
| [nday-commit-monitor.md](07-negative-nday/nday-commit-monitor.md) | Monitoring de commits securite (workflow spaceraccoon) |
| [nday-patch-diffing.md](07-negative-nday/nday-patch-diffing.md) | Patch diffing pour reverse de vulnerabilites |
| [nday-cve-analysis.md](07-negative-nday/nday-cve-analysis.md) | Analyse approfondie de CVE (root cause, variant hunting) |
| [nday-variant-analysis.md](07-negative-nday/nday-variant-analysis.md) | Analyse de variantes (style Google Project Zero) |
| [nday-1day-to-0day.md](07-negative-nday/nday-1day-to-0day.md) | Transformer un 1-day en 0-day via patches incomplets |

### 08 - Bug Bounty Workflow
| Prompt | Description |
|--------|-------------|
| [bb-program-analysis.md](08-bug-bounty/bb-program-analysis.md) | Analyse de programme, strategie de priorisation, expected value |
| [bb-scope-maximizer.md](08-bug-bounty/bb-scope-maximizer.md) | Maximiser la couverture du scope autorise |
| [bb-report-writer.md](08-bug-bounty/bb-report-writer.md) | Redaction de rapports de bounty professionnels |
| [bb-triage-predictor.md](08-bug-bounty/bb-triage-predictor.md) | Predire la severite et le risque de duplicate/NA |
| [bb-duplicate-avoider.md](08-bug-bounty/bb-duplicate-avoider.md) | Verifier l'unicite d'un finding avant soumission |

### 09 - CVE & RCE Maximizers (MAX CRITICITE)
| Prompt | Description |
|--------|-------------|
| [cve-rce-hunter.md](09-cve-rce/cve-rce-hunter.md) | Chasse systematique aux RCE (7 langages, taint analysis) |
| [cve-auth-bypass-critical.md](09-cve-rce/cve-auth-bypass-critical.md) | Auth bypass → account takeover (JWT, OAuth, session, MFA) |
| [cve-ssrf-to-rce.md](09-cve-rce/cve-ssrf-to-rce.md) | Chaine SSRF → cloud metadata → credential theft → RCE |
| [cve-deser-to-rce.md](09-cve-rce/cve-deser-to-rce.md) | Deserialization → RCE (Java, PHP, Python, .NET, Ruby) |
| [cve-ssti-to-rce.md](09-cve-rce/cve-ssti-to-rce.md) | SSTI → sandbox escape → RCE (8 template engines) |
| [cve-sqli-to-rce.md](09-cve-rce/cve-sqli-to-rce.md) | SQLi → RCE (MySQL, PostgreSQL, MSSQL, Oracle, SQLite) |
| [cve-supply-chain-rce.md](09-cve-rce/cve-supply-chain-rce.md) | Supply chain → RCE (dependency confusion, typosquatting, build scripts) |

### 10 - Agentic Workflows
| Prompt | Description |
|--------|-------------|
| [agent-vuln-scanner.md](10-agentic-workflows/agent-vuln-scanner.md) | Agent autonome de scan de vulnerabilites (SAST LLM) |
| [agent-code-reviewer.md](10-agentic-workflows/agent-code-reviewer.md) | Agent de revue de code securite pour PRs/MRs |
| [agent-exploit-validator.md](10-agentic-workflows/agent-exploit-validator.md) | Agent de validation d'exploits en sandbox |
| [agent-negative-day-monitor.md](10-agentic-workflows/agent-negative-day-monitor.md) | Agent de monitoring negative-day (workflow spaceraccoon) |

### 11 - Report & Communication
| Prompt | Description |
|--------|-------------|
| [report-cve-request.md](11-report-communication/report-cve-request.md) | Redaction de demande CVE (format MITRE/CNA) |
| [report-advisory-writer.md](11-report-communication/report-advisory-writer.md) | Redaction d'advisory (GHSA, vendor advisory) |
| [report-technical-writeup.md](11-report-communication/report-technical-writeup.md) | Writeup technique publiable (blog, conference) |
| [report-responsible-disclosure.md](11-report-communication/report-responsible-disclosure.md) | Templates de disclosure responsable |

### 12 - CTF Challenges
| Prompt | Description |
|--------|-------------|
| [ctf-challenge-solver.md](12-ctf/ctf-challenge-solver.md) | Solver autonome multi-categorie (web, pwn, crypto, reverse, forensics, OSINT, misc) |

### Templates
| Fichier | Description |
|---------|-------------|
| [finding-template.json](templates/finding-template.json) | Schema JSON standardise pour les findings |
| [severity-scoring.md](templates/severity-scoring.md) | Guide CVSS 3.1 avec patterns courants |
| [output-formats.md](templates/output-formats.md) | 6 formats de sortie standardises |

---

## Quick Start

### 1. Choisir le prompt adapte

```
Scenario                →  Section recommandee
─────────────────────────────────────────────────────
PREMIER LANCEMENT       →  00-master/ (drop dans CLAUDE.md)
CTF / Challenges        →  12-ctf/
Reconnaissance          →  01-recon/
Recherche de vulns      →  02-vuln-research/ ou 03-web-app/
Exploit dev             →  06-exploit-dev/
N-day / 0-day           →  07-negative-nday/
Bug bounty workflow     →  08-bug-bounty/
Max criticite (RCE)     →  09-cve-rce/
Automatisation          →  10-agentic-workflows/
Reporting               →  11-report-communication/
```

### 2. Remplir les variables

Chaque prompt utilise des variables `{{VARIABLE}}` a remplacer :

| Variable | Description |
|----------|-------------|
| `{{TARGET}}` | Code, diff, ou asset a analyser |
| `{{CONTEXT}}` | Contexte de la mission |
| `{{SCOPE}}` | Perimetre autorise |
| `{{LANGUAGE}}` | Langage de programmation |
| `{{FRAMEWORK}}` | Framework utilise |

### 3. Utiliser avec l'API Anthropic (recommande)

```python
import anthropic

client = anthropic.Anthropic()

# Charger le prompt
with open("prompts/09-cve-rce/cve-rce-hunter.md") as f:
    prompt_content = f.read()

# Extraire system prompt et user prompt
system_prompt = prompt_content.split("## System Prompt")[1].split("```")[1]
user_prompt = prompt_content.split("## User Prompt")[1].split("```xml")[1].split("```")[0]

# Remplacer les variables
user_prompt = user_prompt.replace("{{TARGET}}", code_source)
user_prompt = user_prompt.replace("{{CONTEXT}}", "Bug bounty audit")

message = client.messages.create(
    model="claude-sonnet-4-20250514",
    max_tokens=8192,
    system=system_prompt,
    messages=[
        {"role": "user", "content": user_prompt},
        {"role": "assistant", "content": '{"findings": ['}  # Prefill
    ]
)
```

### 4. Utiliser avec Claude Code CLI

```bash
# Copier le system prompt dans CLAUDE.md du projet cible
cp prompts/02-vuln-research/vuln-source-code-audit.md /path/to/project/CLAUDE.md

# Utiliser Claude Code normalement
claude "Analyse ce codebase pour des vulnerabilites de securite"
```

### 5. Utiliser en copier-coller

1. Ouvrir le prompt souhaite
2. Copier le **System Prompt** dans le champ systeme de l'interface LLM
3. Copier le **User Prompt** avec vos donnees injectees
4. Optionnel : utiliser le **Prefill** dans le champ assistant

---

## Modeles Recommandes

| Modele | Usage | Justification |
|--------|-------|---------------|
| **Claude Opus 4** | Audit de code complexe, 0-day research, exploit chains | Meilleur raisonnement, chain-of-thought le plus robuste |
| **Claude Sonnet 4** | Usage quotidien, bug bounty, N-day analysis | Excellent rapport qualite/cout/vitesse |
| **GPT-4o** | Second avis, validation croisee | Perspective differente, utile en cross-validation |

---

## Inspirations & References

- [spaceraccoon - Discovering Negative Days with LLM Workflows](https://spaceraccoon.dev/discovering-negative-days-llm-workflows/)
- [Vulnhuntr - LLM-powered vulnerability discovery](https://github.com/protectai/vulnhuntr)
- [Google Project Zero - Big Sleep / Naptime](https://googleprojectzero.blogspot.com/2024/10/from-naptime-to-big-sleep.html)
- [Anthropic Prompt Engineering Guide](https://docs.anthropic.com/en/docs/build-with-claude/prompt-engineering)
- [DARPA AIxCC - AI Cyber Challenge](https://aicyberchallenge.com/)

---

## Structure du Repo

```
LLMprompts/
├── README.md
├── METHODOLOGY.md
├── 00-master/                   (1 prompt - LE point d'entree)
│   └── master-0day-hunter.md
├── 01-recon/                    (4 prompts)
├── 02-vuln-research/            (5 prompts)
├── 03-web-app/                  (8 prompts)
├── 04-binary-memory/            (5 prompts)
├── 05-cloud-infra/              (4 prompts)
├── 06-exploit-dev/              (4 prompts)
├── 07-negative-nday/            (5 prompts)
├── 08-bug-bounty/               (5 prompts)
├── 09-cve-rce/                  (7 prompts)
├── 10-agentic-workflows/        (4 prompts)
├── 11-report-communication/     (4 prompts)
├── 12-ctf/                      (1 prompt)
│   └── ctf-challenge-solver.md
└── templates/                   (3 fichiers)
    ├── finding-template.json
    ├── severity-scoring.md
    └── output-formats.md
```

**Total : 62 fichiers dont 57 prompts operationnels**
