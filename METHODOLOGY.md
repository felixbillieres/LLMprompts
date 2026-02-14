# Méthodologie de Prompting - Security Research LLM Arsenal

## Principes Fondamentaux

Ce repository applique systématiquement les meilleures pratiques de prompt engineering adaptées au contexte de la recherche en sécurité offensive. Chaque prompt est conçu pour maximiser la précision, l'exploitabilité des résultats, et minimiser les faux positifs.

---

## 1. Role-Based Priming (Identité d'Expert)

Chaque prompt commence par une identité d'expert précise. Cela active les connaissances spécialisées du modèle.

```
Tu es un chercheur en sécurité offensive senior avec 15+ années d'expérience en [spécialité].
Tu as publié des CVE, participé à des programmes de bug bounty majeurs (HackerOne, Bugcrowd),
et contribué à des outils de sécurité open-source. Tu es spécialisé en [domaine spécifique].
```

**Pourquoi** : Les LLMs produisent des analyses plus rigoureuses et techniques quand ils adoptent un rôle d'expert spécifique plutôt qu'un rôle généraliste.

---

## 2. XML Tags Structurés

Tous les prompts utilisent des balises XML pour séparer clairement les sections :

| Tag | Usage |
|-----|-------|
| `<context>` | Contexte de la mission (type de test, scope, contraintes) |
| `<target>` | Code source, diff, configuration, ou asset à analyser |
| `<instructions>` | Directives détaillées étape par étape |
| `<output_format>` | Structure JSON/Markdown exacte attendue |
| `<constraints>` | Garde-fous contre les faux positifs et hallucinations |
| `<examples>` | Few-shot examples de findings réels |
| `<thinking>` | Block de réflexion forcé (chain-of-thought) |

**Pourquoi** : Les XML tags permettent au modèle de parser sans ambiguïté les différentes parties du prompt et de ne pas mélanger instructions et données.

---

## 3. Chain-of-Thought Forcé

Chaque prompt exige un raisonnement structuré AVANT les conclusions :

```
Avant de produire tes findings, tu DOIS suivre ce processus de réflexion dans un block <thinking> :
1. Identifier tous les points d'entrée utilisateur (sources)
2. Tracer le flux de données vers les opérations sensibles (sinks)
3. Vérifier l'existence de sanitization/validation sur chaque chemin
4. Évaluer l'exploitabilité réelle (pas théorique)
5. Construire mentalement un PoC avant de conclure
```

**Pourquoi** : Le chain-of-thought réduit drastiquement les faux positifs en forçant une vérification étape par étape plutôt qu'une conclusion hâtive.

---

## 4. Structured JSON Output

Tous les findings suivent le même schéma JSON (voir `templates/finding-template.json`) :

```json
{
  "findings": [{
    "id": "FINDING-001",
    "title": "Command Injection via unsanitized user input in export function",
    "severity": "Critical",
    "cvss_score": 9.8,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "vulnerability_class": "CWE-78: OS Command Injection",
    "confidence": "High",
    "affected_component": "src/export.py:42",
    "description": "",
    "root_cause": "",
    "proof_of_concept": "",
    "impact": "",
    "remediation": "",
    "references": []
  }]
}
```

**Pourquoi** : Un format standardisé permet l'intégration automatisée dans des pipelines, le tri par sévérité, et la traçabilité.

---

## 5. Prefill Technique

Pour forcer le format JSON, on pré-remplit le début de la réponse assistant :

```
# Dans le champ "assistant" de l'API :
{"findings": [
```

Le modèle continue naturellement dans le format JSON sans déviation.

**Pourquoi** : Élimine les réponses en prose quand un format structuré est requis. Particulièrement utile avec l'API Anthropic qui supporte le prefill.

---

## 6. Few-Shot Examples

Chaque prompt inclut 1-2 exemples de findings réels (CVE publiques) pour calibrer le niveau de détail attendu :

```
<examples>
Exemple de finding attendu :
{
  "id": "EXAMPLE-001",
  "title": "SSRF via PDF generation endpoint allows internal network scanning",
  "severity": "High",
  "cvss_score": 8.6,
  "vulnerability_class": "CWE-918: Server-Side Request Forgery",
  "confidence": "High",
  "affected_component": "api/v2/reports/generate:87",
  "root_cause": "User-controlled URL parameter passed directly to HTTP client without allowlist validation",
  "proof_of_concept": "curl -X POST https://target.com/api/v2/reports/generate -d '{\"template_url\": \"http://169.254.169.254/latest/meta-data/iam/security-credentials/\"}'",
  "impact": "Accès aux credentials IAM du service, pivot vers d'autres services AWS",
  "remediation": "Implémenter une allowlist de domaines autorisés, bloquer les plages IP internes (RFC1918, link-local)"
}
</examples>
```

**Pourquoi** : Les few-shot examples calibrent la qualité, le niveau de détail, et le format des réponses bien mieux que des instructions verbales seules.

---

## 7. Scoring de Criticité

Chaque finding inclut obligatoirement :
- **Severity** : Critical / High / Medium / Low / Info
- **CVSS Score** : Score numérique 0.0-10.0
- **CVSS Vector** : Vecteur CVSS 3.1 complet
- **Confidence** : High / Medium / Low (niveau de certitude du finding)

**Pourquoi** : Permet de prioriser immédiatement les actions et d'aligner avec les attentes des programmes de bug bounty.

---

## 8. Anti-Hallucination Guards

Chaque prompt inclut des contraintes explicites :

```
<constraints>
- Ne rapporte JAMAIS une vulnérabilité dont tu n'es pas sûr - utilise le champ "confidence" pour indiquer ton niveau de certitude
- Si tu ne peux pas construire un PoC concret, indique "PoC non démontrable" et explique pourquoi
- Distingue explicitement les vulnérabilités CONFIRMÉES des SUSPICIONS
- Ne génère PAS de findings génériques type "il faudrait vérifier X" - soit c'est un finding concret, soit tu ne le rapportes pas
- Priorise TOUJOURS l'exploitabilité réelle sur la possibilité théorique
- Si le code est correctement protégé, dis-le explicitement plutôt que de chercher des faux positifs
</constraints>
```

**Pourquoi** : Les LLMs ont tendance à sur-reporter des vulnérabilités théoriques. Ces guards forcent la rigueur et l'honnêteté.

---

## Comment Utiliser ce Repo

### Workflow Standard

1. **Choisir le prompt** adapté à votre phase de test (recon → vuln research → exploit dev → report)
2. **Remplir les variables** `{{VARIABLE}}` avec vos données spécifiques
3. **Copier le System Prompt** dans le champ system de votre interface LLM
4. **Copier le User Prompt** avec vos données injectées
5. **Optionnel** : Utiliser le Prefill dans le champ assistant pour forcer le format
6. **Itérer** : Affiner les résultats en fournissant plus de contexte si nécessaire

### Avec l'API Anthropic (recommandé)

```python
import anthropic

client = anthropic.Anthropic()

message = client.messages.create(
    model="claude-sonnet-4-20250514",
    max_tokens=4096,
    system=open("prompts/09-cve-rce/cve-rce-hunter.md").read(),  # System prompt
    messages=[
        {"role": "user", "content": f"<target>{code_source}</target>"},
        {"role": "assistant", "content": '{"findings": ['}  # Prefill
    ]
)
```

### Avec Claude Code CLI

```bash
# Coller le system prompt dans CLAUDE.md du projet cible
# Puis utiliser Claude Code normalement sur le codebase
```

---

## Modèles Recommandés

| Modèle | Usage | Justification |
|--------|-------|---------------|
| **Claude Opus 4** | Audit de code complexe, 0-day research | Meilleur raisonnement, chain-of-thought le plus robuste |
| **Claude Sonnet 4** | Usage quotidien, bug bounty, N-day analysis | Excellent rapport qualité/coût/vitesse |
| **GPT-4o** | Second avis, validation croisée | Perspective différente, utile en cross-validation |

---

## Références

- [Anthropic Prompt Engineering Guide](https://docs.anthropic.com/en/docs/build-with-claude/prompt-engineering)
- [spaceraccoon - Discovering Negative Days](https://spaceraccoon.dev/discovering-negative-days-llm-workflows/)
- [Vulnhuntr - LLM-powered vulnerability discovery](https://github.com/protectai/vulnhuntr)
- [Google Project Zero - Big Sleep](https://googleprojectzero.blogspot.com/2024/10/from-naptime-to-big-sleep.html)
