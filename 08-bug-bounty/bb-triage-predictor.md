# Bug Bounty Triage Predictor

## Quand utiliser ce prompt

Utiliser ce prompt AVANT de soumettre un rapport pour evaluer la probabilite qu'il soit accepte, rejete comme informatif, marque comme duplicat, ou classe comme non-applicable. Ce prompt vous aide a prendre une decision eclairee : soumettre le rapport tel quel, ameliorer les preuves d'impact, chercher une chaine d'exploitation plus impactante, ou passer a une autre cible. Il analyse votre finding contre les criteres typiques de triage des programmes de bug bounty, l'historique du programme, et les standards de l'industrie. A utiliser apres avoir identifie une vulnerabilite mais avant d'investir du temps dans la redaction d'un rapport complet.

## Variables a remplir

| Variable | Description | Exemple |
|----------|-------------|---------|
| `{{VULN_DESCRIPTION}}` | Description technique de la vulnerabilite trouvee | `Reflected XSS in search parameter on blog.example.com via <svg/onload=alert(1)>` |
| `{{VULN_TYPE}}` | Classe de vulnerabilite | `Reflected XSS` |
| `{{SEVERITY_ESTIMATE}}` | Votre estimation de severite | `Medium` |
| `{{AFFECTED_ASSET}}` | Asset affecte | `blog.example.com` |
| `{{IMPACT_DEMONSTRATION}}` | Comment vous avez demontre l'impact | `alert(document.domain) fires in the browser, no CSP on the page` |
| `{{PROGRAM_NAME}}` | Nom du programme | `Example Corp Bug Bounty` |
| `{{PROGRAM_TYPE}}` | Type de programme (public, prive, VDP) | `Public bug bounty on HackerOne` |
| `{{PROGRAM_AGE}}` | Age et maturite du programme | `3 years old, 500+ resolved reports, 50 public disclosures` |
| `{{PROGRAM_SCOPE}}` | Perimetre du programme | `*.example.com, api.example.com, mobile apps` |
| `{{PROGRAM_EXCLUSIONS}}` | Exclusions du programme | `Self-XSS, CSRF on logout, missing security headers without demonstrated impact, subdomain takeover on non-customer-facing assets` |
| `{{PUBLIC_DISCLOSURES}}` | Rapports publiquement divulgues pertinents | `10 XSS (4 on blog.example.com), 5 IDOR, 2 SSRF, 3 info disclosure` |
| `{{CONTEXT}}` | Contexte additionnel | `Blog is a WordPress site, separate from main application, low traffic` |
| `{{POC_QUALITY}}` | Qualite de votre PoC | `Working curl command, screenshot of alert box, no automation script` |

---

## System Prompt

```
You are a veteran bug bounty triager and program manager who has triaged over 10,000 vulnerability reports across HackerOne, Bugcrowd, and Intigriti. You have managed programs for Fortune 500 companies and understand the nuances of how programs evaluate, accept, and reject reports. You know the common patterns that lead to valid/informative/duplicate/NA outcomes.

Your triage evaluation framework:
1. VALIDITY: Does this meet the minimum bar for a security vulnerability? Is there real impact?
2. SCOPE: Is the asset in scope? Is the vuln class accepted?
3. IMPACT: Is the demonstrated impact sufficient for the claimed severity?
4. QUALITY: Is the report clear enough for reproduction? Is the PoC working?
5. DUPLICATE LIKELIHOOD: Has this vuln class been found on this asset before?
6. PROGRAM FIT: Does this type of finding align with what the program values?

Common triage outcomes:
- TRIAGED (Valid): Clear vulnerability, in scope, demonstrated impact, good report quality
- INFORMATIVE: Real finding but insufficient impact, theoretical only, or commonly accepted risk
- DUPLICATE: Same vulnerability class on the same endpoint/asset already reported
- NOT APPLICABLE: Out of scope, excluded vuln class, or not a real vulnerability
- NEEDS MORE INFO: Unclear reproduction, missing PoC, or insufficient detail

Your rules:
1. Be brutally honest - a false positive prediction wastes the researcher's time
2. Base predictions on evidence and patterns, not optimism
3. Consider the program's perspective, not just the researcher's
4. Factor in program maturity and historical acceptance patterns
5. If the prediction is negative, explain what would change it
6. Do not hallucinate program policies, triage patterns, or industry standards
7. Acknowledge uncertainty when information is insufficient
```

---

## User Prompt

```
<context>
I have found a potential vulnerability and need to assess whether it is worth submitting as a bug bounty report. I want to predict how the program will triage this finding and decide whether to submit, improve, or move on.

Program: {{PROGRAM_NAME}}
Program type: {{PROGRAM_TYPE}}
Program age: {{PROGRAM_AGE}}
</context>

<target>
Vulnerability description: {{VULN_DESCRIPTION}}
Vulnerability class: {{VULN_TYPE}}
My severity estimate: {{SEVERITY_ESTIMATE}}
Affected asset: {{AFFECTED_ASSET}}
Impact demonstration: {{IMPACT_DEMONSTRATION}}
PoC quality: {{POC_QUALITY}}

Program context:
Scope: {{PROGRAM_SCOPE}}
Exclusions: {{PROGRAM_EXCLUSIONS}}
Public disclosures: {{PUBLIC_DISCLOSURES}}
Additional context: {{CONTEXT}}
</target>

<instructions>
Predict the triage outcome following this exact methodology:

STEP 1 - THINKING BLOCK (mandatory):
<thinking>
FACTOR 1 - SCOPE CHECK:
- Is the affected asset explicitly in scope?
- Is the vuln class explicitly excluded?
- Are there any policy rules that might invalidate this finding?

FACTOR 2 - IMPACT ASSESSMENT:
- Is the demonstrated impact real and significant?
- Does the severity estimate match the actual impact?
- Would a triager agree with the severity, or would they downgrade?
- Is there a "so what?" factor - does this matter to the business?

FACTOR 3 - DUPLICATE ANALYSIS:
- Have similar findings been reported on this asset before (based on public disclosures)?
- How many similar findings exist? (more = higher duplicate risk)
- Is there anything unique about this finding compared to what has been disclosed?
- How old is the program? (older = more findings = higher duplicate risk)

FACTOR 4 - QUALITY CHECK:
- Is the PoC complete enough for a triager to reproduce in 10 minutes?
- Are there screenshots, curl commands, or scripts?
- Is the impact clearly articulated?

FACTOR 5 - PROGRAM FIT:
- Does this type of finding align with what the program values?
- Is this the type of asset where the program expects high-value findings?
- Would the program be embarrassed by this finding, or shrug it off?

FACTOR 6 - INDUSTRY PATTERNS:
- How do similar programs typically handle this vuln class on this asset type?
- Is there an industry trend toward accepting or rejecting this class of finding?
</thinking>

STEP 2 - Generate the triage prediction with confidence levels and actionable recommendations.
</instructions>

<output_format>
Return a JSON object with this exact structure:
{
  "triage_prediction": {
    "predicted_outcome": "string - Triaged (Valid) / Informative / Duplicate / Not Applicable / Needs More Info",
    "confidence": "string - High (>80%) / Medium (50-80%) / Low (<50%)",
    "probability_breakdown": {
      "triaged_valid": "string - percentage with reasoning",
      "informative": "string - percentage with reasoning",
      "duplicate": "string - percentage with reasoning",
      "not_applicable": "string - percentage with reasoning",
      "needs_more_info": "string - percentage with reasoning"
    }
  },
  "factor_analysis": {
    "scope_check": {
      "in_scope": "boolean",
      "vuln_class_accepted": "boolean",
      "policy_concerns": ["list of policy rules that might affect this report"],
      "score": "string - Green/Yellow/Red"
    },
    "impact_assessment": {
      "demonstrated_impact_sufficient": "boolean",
      "severity_estimate_accurate": "boolean",
      "triager_likely_severity": "string - what severity the triager would assign",
      "business_relevance": "string - Low/Medium/High",
      "score": "string - Green/Yellow/Red"
    },
    "duplicate_risk": {
      "similar_findings_disclosed": "integer - count of similar public disclosures",
      "estimated_unreported_duplicates": "string - estimate based on program age",
      "unique_differentiators": ["list of what makes this finding different, if anything"],
      "duplicate_probability": "string - percentage",
      "score": "string - Green/Yellow/Red"
    },
    "quality_assessment": {
      "poc_completeness": "string - Complete/Partial/Insufficient",
      "reproduction_clarity": "string - Clear/Needs Improvement/Unclear",
      "missing_elements": ["list of things that should be added to the report"],
      "score": "string - Green/Yellow/Red"
    },
    "program_fit": {
      "asset_priority_for_program": "string - Core/Supporting/Peripheral",
      "vuln_class_value_to_program": "string - High/Medium/Low",
      "alignment": "string - description of how well this finding aligns with program priorities",
      "score": "string - Green/Yellow/Red"
    }
  },
  "recommendation": {
    "action": "string - Submit Now / Improve Then Submit / Escalate Impact / Find Alternative / Do Not Submit",
    "reasoning": "string - detailed explanation of the recommendation",
    "if_submit": {
      "suggested_improvements": ["list of specific improvements before submitting"],
      "severity_to_claim": "string - recommended severity to submit",
      "key_points_to_emphasize": ["list of points to emphasize in the report"]
    },
    "if_not_submit": {
      "why_not": "string - specific reason not to submit",
      "alternative_actions": ["list of alternative actions to take"],
      "what_would_change_recommendation": "string - what new evidence would make this worth submitting"
    },
    "escalation_paths": [
      {
        "strategy": "string - description of how to increase impact",
        "effort": "string - Low/Medium/High",
        "potential_impact_increase": "string - description of improved impact",
        "new_predicted_outcome": "string - predicted triage outcome after escalation"
      }
    ]
  },
  "severity_calibration": {
    "your_estimate": "string",
    "predicted_triager_assessment": "string",
    "reasoning": "string - why there is or is not a discrepancy",
    "cvss_v3_1": {
      "score": "float",
      "vector": "string",
      "notes": "string - any CVSS considerations specific to this finding"
    }
  },
  "comparable_precedents": [
    {
      "finding_type": "string - similar finding",
      "outcome": "string - how it was typically triaged",
      "reasoning": "string - why this precedent is relevant",
      "source": "string - where this precedent comes from (public disclosure, industry knowledge)"
    }
  ],
  "confidence_level": "string - overall confidence in this prediction with caveats"
}
</output_format>

<constraints>
- Be honest and data-driven, not optimistic
- If the finding is likely to be rejected, say so clearly and explain why
- Do not sugar-coat negative predictions
- Base duplicate analysis on provided public disclosures and program age
- Severity calibration must follow CVSS v3.1 specification
- If information is insufficient for a confident prediction, state what is missing
- Do not hallucinate program policies, triage patterns, or precedents
- When referencing industry patterns, be specific about which types of programs/industries you are comparing to
- Recommendations must be actionable and specific
- Escalation paths must be realistic, not theoretical
</constraints>
```

---

## Prefill (assistant)

```
{
  "triage_prediction": {
    "predicted_outcome": "
```

---

## Few-shot Examples

### Example 1: Reflected XSS on Low-Value Asset - Likely Duplicate

**Input variables:**
- `{{VULN_DESCRIPTION}}`: `Reflected XSS in search parameter on blog.example.com via <svg/onload=alert(1)>`
- `{{VULN_TYPE}}`: `Reflected XSS`
- `{{SEVERITY_ESTIMATE}}`: `Medium`
- `{{AFFECTED_ASSET}}`: `blog.example.com`
- `{{IMPACT_DEMONSTRATION}}`: `alert(document.domain) fires in the browser, no CSP on the page`
- `{{PROGRAM_AGE}}`: `3 years old, 500+ resolved reports, 50 public disclosures`
- `{{PUBLIC_DISCLOSURES}}`: `10 XSS (4 on blog.example.com), 5 IDOR, 2 SSRF, 3 info disclosure`
- `{{CONTEXT}}`: `Blog is WordPress, separate from main app, low traffic`
- `{{POC_QUALITY}}`: `Working curl command, screenshot of alert box, no automation script`

**Expected output (abbreviated):**

```json
{
  "triage_prediction": {
    "predicted_outcome": "Duplicate",
    "confidence": "High (85%)",
    "probability_breakdown": {
      "triaged_valid": "10% - Only if this is a genuinely new endpoint/parameter not covered by the 4 existing blog XSS reports",
      "informative": "5% - Could be marked informative if program has decided blog XSS is accepted risk",
      "duplicate": "75% - 4 XSS already disclosed on blog.example.com. High probability this endpoint/parameter was already reported",
      "not_applicable": "5% - Blog is in scope (*.example.com) but program might have internally deprioritized it",
      "needs_more_info": "5% - Current PoC quality is adequate for XSS, unlikely to need more info"
    }
  },
  "factor_analysis": {
    "scope_check": {
      "in_scope": true,
      "vuln_class_accepted": true,
      "policy_concerns": ["Self-XSS is excluded - ensure this is not self-XSS (reflected XSS with victim URL is fine)"],
      "score": "Green"
    },
    "impact_assessment": {
      "demonstrated_impact_sufficient": true,
      "severity_estimate_accurate": false,
      "triager_likely_severity": "Low to Medium - blog.example.com is not the main application. No user sessions to steal (WordPress blog may not share auth cookies with the main app). Limited impact compared to XSS on app.example.com.",
      "business_relevance": "Low - blog is a WordPress site separate from the core application, low traffic, likely no sensitive user interactions",
      "score": "Yellow"
    },
    "duplicate_risk": {
      "similar_findings_disclosed": 4,
      "estimated_unreported_duplicates": "In a 3-year-old program with 500+ reports, there are likely 10-15 additional unreported XSS findings on blog.example.com that were triaged as duplicates. The 4 disclosed represent the tip of the iceberg.",
      "unique_differentiators": ["Possibly a different parameter or endpoint than the disclosed 4", "If the search parameter is new, it could be unique"],
      "duplicate_probability": "75%",
      "score": "Red"
    },
    "quality_assessment": {
      "poc_completeness": "Partial",
      "reproduction_clarity": "Clear",
      "missing_elements": ["No impact demonstration beyond alert(1)", "No session theft PoC", "No explanation of why this is different from the 4 known blog XSS"],
      "score": "Yellow"
    },
    "program_fit": {
      "asset_priority_for_program": "Peripheral - blog is a WordPress site separate from the core product",
      "vuln_class_value_to_program": "Low - 10 XSS already found suggests diminishing returns",
      "alignment": "Poor - the program has already addressed multiple XSS on this asset. Finding another one on a low-priority asset provides minimal additional value.",
      "score": "Red"
    }
  },
  "recommendation": {
    "action": "Escalate Impact",
    "reasoning": "Submitting this as-is has a ~75% chance of being a duplicate and even if unique, the reward will likely be at the low end ($100-$500) due to the peripheral nature of the asset. The time spent writing a report may not be justified. However, if you can escalate the impact or chain it with another vulnerability, the calculus changes.",
    "if_submit": {
      "suggested_improvements": [
        "Explicitly address why this is different from the 4 disclosed blog XSS (different parameter, different injection context)",
        "Demonstrate impact beyond alert() - e.g., can you steal WordPress admin cookies if an admin visits the URL?",
        "Check if blog.example.com shares any cookies or authentication with the main app.example.com",
        "Create a working exploit URL that demonstrates realistic attack scenario"
      ],
      "severity_to_claim": "Low - claiming Medium will likely be downgraded by the triager given the asset's low priority",
      "key_points_to_emphasize": [
        "This is a different endpoint/parameter than the 4 known blog XSS",
        "Demonstrate specific impact relevant to this instance",
        "Note the lack of CSP as an additional concern"
      ]
    },
    "if_not_submit": {
      "why_not": "75% duplicate risk on a low-priority asset with low expected reward. Time is better spent on higher-value targets.",
      "alternative_actions": [
        "Focus on the main application (app.example.com) for XSS with higher impact",
        "Look for XSS on api.example.com responses that might be rendered in a browser",
        "Try to chain this XSS with CSRF to escalate impact",
        "Move to a different vuln class (IDOR, SSRF, business logic) on higher-priority assets"
      ],
      "what_would_change_recommendation": "If you can demonstrate: 1) Cookie theft affecting the main application, 2) Stored XSS (not just reflected), 3) XSS leading to admin account takeover on WordPress, or 4) Chain with another vuln to escalate impact."
    },
    "escalation_paths": [
      {
        "strategy": "Chain XSS with WordPress admin actions (CSRF + XSS = admin account compromise)",
        "effort": "Medium",
        "potential_impact_increase": "Reflected XSS -> Admin account takeover on WordPress blog = High severity",
        "new_predicted_outcome": "Triaged (Valid) at High severity if the chain is convincing"
      },
      {
        "strategy": "Check if blog.example.com cookies are shared with app.example.com (session sharing)",
        "effort": "Low",
        "potential_impact_increase": "If cookies are shared, XSS on blog = session theft for the main app = Critical severity",
        "new_predicted_outcome": "Triaged (Valid) at Critical severity if cookie sharing is confirmed"
      },
      {
        "strategy": "Find a stored XSS variant (e.g., in blog comments, user profile)",
        "effort": "Medium",
        "potential_impact_increase": "Stored XSS is higher impact than reflected, especially if it affects admin views",
        "new_predicted_outcome": "Triaged (Valid) at Medium severity with lower duplicate risk"
      }
    ]
  },
  "severity_calibration": {
    "your_estimate": "Medium",
    "predicted_triager_assessment": "Low",
    "reasoning": "The triager will likely downgrade to Low because: 1) blog.example.com is a peripheral asset, 2) Reflected XSS has lower impact than stored, 3) No demonstration of real-world impact beyond alert(), 4) Blog likely does not handle sensitive user data or sessions for the main app. Medium XSS on the main app.example.com would be appropriate, but on a WordPress blog, Low is more likely.",
    "cvss_v3_1": {
      "score": 4.7,
      "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:N/A:N",
      "notes": "UI:R because reflected XSS requires victim to click a crafted URL. S:C because the browser (vulnerable component) trusts the blog origin. C:L because impact is limited to the blog context without cookie sharing evidence. If cookie sharing with main app is confirmed, C would increase to H."
    }
  },
  "comparable_precedents": [
    {
      "finding_type": "Reflected XSS on secondary/blog subdomain",
      "outcome": "Typically triaged at Low severity ($100-$500) or Informative if program considers it accepted risk",
      "reasoning": "Many programs deprioritize XSS on blogs, documentation sites, and marketing subdomains because the impact is limited compared to the core application.",
      "source": "Industry pattern observed across mature HackerOne/Bugcrowd programs"
    },
    {
      "finding_type": "Multiple XSS on same asset (5th+ finding)",
      "outcome": "High duplicate risk. Programs often close later XSS findings as duplicates of earlier broad reports, or mark them as informative with 'we are aware of XSS issues on this asset'",
      "reasoning": "4 XSS already disclosed on blog.example.com. The program is aware of XSS issues on this asset. Additional instances may be closed as 'part of the known issue.'",
      "source": "Common pattern on mature programs with many resolved XSS reports"
    }
  ],
  "confidence_level": "Medium-High. Duplicate prediction is based on strong evidence (4 existing blog XSS disclosures in a 3-year program). Severity calibration is based on common triager behavior for peripheral assets. The main uncertainty is whether this specific parameter/endpoint has been reported before, which cannot be determined from public disclosures alone."
}
```

### Example 2: Quick Reference - Triage Outcome Indicators

| Indicator | Points Toward | Reasoning |
|---|---|---|
| Vuln class excluded in policy | Not Applicable | Policy clearly states this class is not accepted |
| Asset is wildcard subdomain, peripheral | Lower severity | Triagers downgrade for non-core assets |
| 3+ similar findings already disclosed | Duplicate (70%+) | High saturation of this vuln class on this asset |
| Program is <6 months old | Lower duplicate risk | Less researcher attention, fresher attack surface |
| Program is >3 years old, 500+ reports | Higher duplicate risk | Heavily tested, common findings are likely taken |
| PoC is alert(1) only for XSS | May request more info | Triagers increasingly want demonstrated impact |
| Business logic vuln on payment flow | High chance of valid, high reward | Programs value unique logic bugs over common injections |
| Self-XSS with no CSRF chain | Informative | Self-XSS alone is almost always informative |
| Info disclosure with no demonstrated exploitation | Informative or Low | Need to show what an attacker can DO with the info |
| Chained vulns demonstrating escalation | Higher chance of valid + higher severity | Chains demonstrate real-world attack scenarios |
