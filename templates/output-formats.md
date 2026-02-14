# Formats de Sortie Standardisés

## Format 1 : Finding JSON (Standard)

Utilisé par la majorité des prompts. Voir `finding-template.json` pour le schéma complet.

```json
{
  "metadata": {
    "scan_type": "source_code_audit",
    "target": "https://github.com/org/repo",
    "timestamp": "2025-01-15T10:30:00Z",
    "model": "claude-sonnet-4-20250514"
  },
  "findings": [
    {
      "id": "FINDING-001",
      "title": "...",
      "severity": "Critical",
      "cvss_score": 9.8,
      "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
      "vulnerability_class": "CWE-78: OS Command Injection",
      "confidence": "High",
      "affected_component": "src/utils/export.py:42",
      "description": "...",
      "root_cause": "...",
      "proof_of_concept": "...",
      "impact": "...",
      "remediation": "..."
    }
  ],
  "summary": {
    "total_findings": 1,
    "critical": 1,
    "high": 0,
    "medium": 0,
    "low": 0,
    "info": 0,
    "overall_risk": "Critical"
  }
}
```

**Prefill assistant** : `{"metadata": {"scan_type": "`

---

## Format 2 : Patch Analysis (N-day / Negative-day)

Utilisé par les prompts de la section 07-negative-nday.

```json
{
  "commit_analysis": {
    "commit_hash": "abc123def",
    "repository": "org/repo",
    "is_security_patch": true,
    "confidence": "High",
    "vulnerability": {
      "type": "Command Injection",
      "cwe": "CWE-78",
      "severity": "Critical",
      "cvss_score": 9.8,
      "description": "...",
      "affected_code": {
        "file": "src/utils.js",
        "line_range": "42-58",
        "before": "execSync(`cmd ${userInput}`)",
        "after": "execa('cmd', [userInput])"
      },
      "exploitability": {
        "is_exploitable": true,
        "prerequisites": "No authentication required",
        "proof_of_concept": "...",
        "attack_vector": "Network"
      },
      "cve_status": {
        "cve_assigned": false,
        "cve_id": null,
        "disclosure_status": "Patch public, no advisory",
        "time_window": "Exploitable between patch and disclosure"
      }
    },
    "pr_context": {
      "pr_number": 1234,
      "pr_title": "...",
      "labels": ["security", "bug"],
      "mentions_security": true
    }
  }
}
```

**Prefill assistant** : `{"commit_analysis": {`

---

## Format 3 : Bug Bounty Report

Utilisé par les prompts de la section 08-bug-bounty.

```markdown
## Title
[Severity] Vulnerability Type in Component

## Summary
One-paragraph description of the vulnerability and its impact.

## Severity
**CVSS Score**: X.X (Critical/High/Medium/Low)
**CVSS Vector**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

## Steps to Reproduce
1. Navigate to `https://target.com/endpoint`
2. Send the following request:
   ```http
   POST /api/v1/vulnerable-endpoint HTTP/1.1
   Host: target.com
   Content-Type: application/json

   {"param": "malicious_value"}
   ```
3. Observe [specific result]

## Impact
Concrete description of what an attacker can achieve.

## Root Cause
Technical explanation of why this vulnerability exists.

## Remediation
Specific fix recommendation with code example if applicable.

## Supporting Material
- Screenshots
- HTTP request/response logs
- PoC script
```

---

## Format 4 : Exploit Chain

Utilisé par les prompts de la section 06-exploit-dev.

```json
{
  "exploit_chain": {
    "name": "SSRF to RCE via Cloud Metadata",
    "total_steps": 3,
    "final_impact": "Remote Code Execution",
    "final_severity": "Critical",
    "final_cvss": 9.8,
    "prerequisites": "Unauthenticated access to PDF generation endpoint",
    "steps": [
      {
        "step": 1,
        "vulnerability": "SSRF in PDF generation",
        "individual_severity": "High",
        "action": "Forge PDF template URL to point to cloud metadata endpoint",
        "payload": "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "result": "AWS IAM temporary credentials leaked in PDF content"
      },
      {
        "step": 2,
        "vulnerability": "Overly permissive IAM role",
        "individual_severity": "Medium",
        "action": "Use leaked credentials to access AWS services",
        "payload": "aws sts get-caller-identity --access-key AKIA... --secret-key ...",
        "result": "Full access to S3, Lambda, and EC2 services"
      },
      {
        "step": 3,
        "vulnerability": "Lambda function with command execution",
        "individual_severity": "High",
        "action": "Invoke Lambda function with custom payload",
        "payload": "aws lambda invoke --function-name admin-exec --payload '{\"cmd\": \"id\"}'",
        "result": "Arbitrary command execution on Lambda runtime"
      }
    ],
    "full_poc": "#!/bin/bash\n# Step 1: Extract credentials via SSRF\ncurl -s ...\n# Step 2: Configure AWS CLI\nexport AWS_ACCESS_KEY_ID=...\n# Step 3: Execute command\naws lambda invoke ..."
  }
}
```

**Prefill assistant** : `{"exploit_chain": {`

---

## Format 5 : Threat Model

Utilisé par les prompts de threat modeling.

```json
{
  "threat_model": {
    "target": "Application Name",
    "methodology": "STRIDE",
    "assets": [
      {
        "name": "User Authentication System",
        "data_sensitivity": "High",
        "threats": [
          {
            "category": "Spoofing",
            "threat": "...",
            "likelihood": "High",
            "impact": "Critical",
            "mitigations_in_place": ["..."],
            "residual_risk": "Medium",
            "recommendations": ["..."]
          }
        ]
      }
    ],
    "trust_boundaries": ["..."],
    "data_flows": ["..."],
    "attack_surface": {
      "external": ["..."],
      "internal": ["..."]
    }
  }
}
```

---

## Format 6 : CVE Request

Utilisé par les prompts de la section 11-report-communication.

```
[Suggested description]
A [vulnerability type] vulnerability in [product] versions [affected versions] allows
[attacker type] to [impact] via [attack vector].

[Vendor]
[Product name]

[Version]
[Affected versions]

[Problem Type]
CWE-XXX

[References]
https://github.com/org/repo/commit/abc123
https://github.com/org/repo/security/advisories/GHSA-xxxx

[CVSS Score]
X.X

[CVSS Vector]
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
```

---

## Variables de Substitution

Tous les prompts utilisent ces variables à remplacer avant utilisation :

| Variable | Description | Exemple |
|----------|-------------|---------|
| `{{TARGET}}` | Code, diff, ou asset à analyser | `<le code source ici>` |
| `{{CONTEXT}}` | Contexte de la mission | `Bug bounty sur programme X` |
| `{{SCOPE}}` | Périmètre autorisé | `*.target.com, API v2` |
| `{{LANGUAGE}}` | Langage de programmation | `Python`, `JavaScript`, `Java` |
| `{{FRAMEWORK}}` | Framework utilisé | `Django`, `Express`, `Spring` |
| `{{TECH_STACK}}` | Stack technique complète | `Python/Django/PostgreSQL/AWS` |
| `{{COMMIT_DIFF}}` | Diff du commit à analyser | `<output de git diff>` |
| `{{PR_METADATA}}` | Metadata de la PR associée | `titre, labels, description` |
| `{{CVE_ID}}` | Identifiant CVE | `CVE-2024-XXXXX` |
| `{{PROGRAM_POLICY}}` | Policy du programme bounty | `<texte de la policy>` |
