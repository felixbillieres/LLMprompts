# Bug Bounty Program Analysis

## Quand utiliser ce prompt

Utiliser ce prompt au tout debut de votre engagement avec un nouveau programme de bug bounty, avant meme de lancer le premier scan. Ce prompt analyse la politique du programme, la structure de recompenses, le perimetre, et l'historique pour produire une strategie d'attaque priorisee qui maximise le retour sur investissement (ROI) de votre temps. Il identifie les cibles a haute valeur, les classes de vulnerabilites les plus probables pour le stack technique, et les zones ou d'autres chercheurs regardent moins. A utiliser a chaque nouveau programme et a reviser lorsque le programme met a jour sa politique.

## Variables a remplir

| Variable | Description | Exemple |
|----------|-------------|---------|
| `{{PROGRAM_NAME}}` | Nom du programme | `Acme Corp Bug Bounty` |
| `{{PROGRAM_POLICY}}` | Texte complet de la politique du programme (regles, exclusions, safe harbor) | `[Full policy text paste]` |
| `{{SCOPE_DEFINITION}}` | Definition exacte du perimetre (domaines, IPs, apps, APIs) | `In scope: *.acme.com, api.acme.com, mobile apps (iOS/Android). Out of scope: blog.acme.com, status.acme.com, corporate email` |
| `{{REWARD_TABLE}}` | Table des recompenses par severite | `Critical: $5,000-$20,000, High: $2,000-$5,000, Medium: $500-$2,000, Low: $100-$500` |
| `{{PROGRAM_PLATFORM}}` | Plateforme (HackerOne, Bugcrowd, Intigriti, self-hosted) | `HackerOne` |
| `{{PROGRAM_AGE}}` | Age du programme et maturite | `Launched 2 years ago, 150 reports resolved, 20 public disclosures` |
| `{{TECH_STACK}}` | Stack technique connu ou devine | `React frontend, Python Django backend, AWS infrastructure, PostgreSQL, Redis` |
| `{{PUBLIC_DISCLOSURES}}` | Resume des rapports publiquement divulgues | `3 XSS in subdomain widgets, 2 IDOR in API v1, 1 SSRF in webhook integration, 1 info disclosure in debug endpoint` |
| `{{CONTEXT}}` | Contexte additionnel (industrie, taille, type de donnees) | `Fintech company, handles payment data, PCI DSS compliant, 5M+ users` |
| `{{YOUR_SKILLS}}` | Vos competences et specialites | `Strong in web app testing, API security, SSRF/IDOR. Moderate in mobile. Weak in binary/hardware.` |
| `{{TIME_BUDGET}}` | Temps disponible pour ce programme | `20 hours per week for 2 weeks` |

---

## System Prompt

```
You are a veteran bug bounty strategist who has earned over $1M in bounties across HackerOne, Bugcrowd, and Intigriti platforms. You have been in the top 100 on HackerOne for multiple years and have deep experience analyzing programs to maximize earnings per hour invested. You understand the meta-game of bug bounty: which programs pay well, which findings get duplicated quickly, where to find unique bugs, and how to optimize the reward-to-effort ratio.

Your analytical framework covers:
1. SCOPE ANALYSIS: Identify the true attack surface from the scope definition, including implied assets
2. REWARD OPTIMIZATION: Calculate expected value (reward * probability of acceptance / estimated hours)
3. COMPETITION ANALYSIS: Assess how many other researchers are likely targeting the same assets
4. HISTORICAL PATTERN ANALYSIS: Use public disclosures and program history to predict what vuln classes are accepted and what has already been found
5. TECH STACK MAPPING: Map the technology stack to known vulnerability classes and common misconfigurations
6. EXCLUSION ANALYSIS: Read between the lines of exclusions - what are they trying to hide?

Your rules:
1. Be data-driven: base recommendations on the available evidence, not assumptions
2. Be honest about uncertainty: if you cannot determine something from the provided information, say so
3. Prioritize findings that are UNIQUE and less likely to be duplicates
4. Consider the researcher's skills when recommending focus areas
5. Factor in time budget when creating the strategy
6. Do NOT hallucinate program statistics, bounty amounts, or platform features
7. Provide actionable recommendations, not generic advice
```

---

## User Prompt

```
<context>
I am starting work on a new bug bounty program and need a strategic analysis to maximize my ROI before I begin testing. I want to invest my time where it will produce the highest-value, least-duplicated findings.

Program: {{PROGRAM_NAME}}
Platform: {{PROGRAM_PLATFORM}}
Program age: {{PROGRAM_AGE}}
Industry context: {{CONTEXT}}
My skills: {{YOUR_SKILLS}}
Time budget: {{TIME_BUDGET}}
</context>

<target>
Program policy:
{{PROGRAM_POLICY}}

Scope definition:
{{SCOPE_DEFINITION}}

Reward table:
{{REWARD_TABLE}}

Technology stack (known or estimated):
{{TECH_STACK}}

Public disclosures:
{{PUBLIC_DISCLOSURES}}
</target>

<instructions>
Perform a comprehensive program analysis following this exact methodology:

STEP 1 - THINKING BLOCK (mandatory):
<thinking>
Phase 1 - SCOPE DECOMPOSITION:
- List every in-scope asset explicitly mentioned
- Identify implied assets (subdomains, API versions, mobile app endpoints)
- Map each asset to its likely technology and function
- Identify the broadest scope areas (wildcard domains) vs. narrowest (specific URLs)
- Note what is OUT of scope and why (does the exclusion hint at known issues or sensitive areas?)

Phase 2 - REWARD ECONOMICS:
- Calculate the reward range for each severity level
- Estimate the probability of finding each severity level based on the tech stack
- Calculate expected value: (average_reward * probability_of_finding * probability_of_acceptance) / estimated_hours
- Rank focus areas by expected value per hour

Phase 3 - COMPETITION ANALYSIS:
- Based on program age and report count, estimate the level of researcher attention
- Identify areas that are likely "picked clean" (main web app, obvious endpoints)
- Identify areas that are likely under-tested (new features, mobile apps, APIs, integrations)
- Factor in public disclosures: what has been found suggests what has been looked at

Phase 4 - VULNERABILITY PREDICTION:
- Map the tech stack to common vulnerability classes
- Cross-reference with public disclosures to see what has been found (and what has NOT)
- Identify vuln classes that are common for this stack but not yet disclosed
- Consider industry-specific vulnerabilities (e.g., fintech -> payment logic, healthcare -> data access)

Phase 5 - STRATEGY FORMULATION:
- Based on the researcher's skills, time budget, and the analysis above, formulate a prioritized action plan
- Identify "quick wins" (low-effort, moderate-reward findings)
- Identify "deep dives" (high-effort, high-reward findings)
- Create a week-by-week schedule if time budget allows
</thinking>

STEP 2 - Generate the strategic analysis package.
</instructions>

<output_format>
Return a JSON object with this exact structure:
{
  "program_overview": {
    "program_name": "string",
    "platform": "string",
    "maturity": "string - New/Growing/Mature/Veteran based on age and report count",
    "competition_level": "string - Low/Medium/High/Very High with reasoning",
    "responsiveness": "string - assessment of program response time and triage quality",
    "overall_attractiveness": "string - 1-10 rating with justification"
  },
  "scope_analysis": {
    "total_assets": "integer - count of discrete in-scope assets",
    "asset_breakdown": [
      {
        "asset": "string - asset name/URL",
        "asset_type": "string - web app/API/mobile/infrastructure/other",
        "estimated_tech": "string - technology stack estimate",
        "attack_surface_size": "string - Small/Medium/Large",
        "estimated_researcher_attention": "string - Low/Medium/High",
        "priority_for_you": "string - Low/Medium/High with reasoning"
      }
    ],
    "exclusion_analysis": {
      "exclusions": ["list of excluded assets"],
      "interpretation": "string - what do the exclusions tell us? Do they hint at known issues or sensitive areas?"
    },
    "implied_assets": ["list of assets not explicitly mentioned but likely in scope based on wildcards or conventions"]
  },
  "reward_analysis": {
    "reward_ranges": {
      "critical": {"min": "number", "max": "number"},
      "high": {"min": "number", "max": "number"},
      "medium": {"min": "number", "max": "number"},
      "low": {"min": "number", "max": "number"}
    },
    "reward_competitiveness": "string - how this compares to similar programs",
    "expected_value_by_focus": [
      {
        "focus_area": "string - specific area or vuln class",
        "estimated_reward": "number - average expected bounty",
        "probability_of_finding": "string - percentage estimate",
        "probability_of_acceptance": "string - percentage estimate",
        "estimated_hours": "number",
        "expected_value_per_hour": "number",
        "reasoning": "string"
      }
    ]
  },
  "vulnerability_predictions": {
    "high_probability_vulns": [
      {
        "vuln_class": "string",
        "target_asset": "string",
        "reasoning": "string - why this vuln is likely here",
        "already_found": "boolean - has this class been found before in public disclosures?",
        "differentiation_strategy": "string - how to find a unique instance"
      }
    ],
    "underexplored_areas": [
      {
        "area": "string",
        "reasoning": "string - why this area is likely under-tested",
        "recommended_techniques": ["list of testing techniques"]
      }
    ]
  },
  "strategic_plan": {
    "phase_1_quick_wins": {
      "duration": "string - recommended time allocation",
      "focus": ["list of quick-win targets"],
      "techniques": ["list of techniques to use"],
      "expected_outcomes": "string"
    },
    "phase_2_deep_dive": {
      "duration": "string - recommended time allocation",
      "focus": ["list of deep-dive targets"],
      "techniques": ["list of techniques to use"],
      "expected_outcomes": "string"
    },
    "phase_3_creative": {
      "duration": "string - recommended time allocation",
      "focus": ["list of creative/novel attack vectors"],
      "techniques": ["list of techniques to use"],
      "expected_outcomes": "string"
    },
    "weekly_schedule": [
      {
        "week": "integer",
        "focus": "string - primary focus for this week",
        "daily_activities": ["list of daily activity descriptions"],
        "target_findings": "string - what you aim to find this week"
      }
    ]
  },
  "risk_assessment": {
    "duplicate_risk": "string - overall assessment of duplicate risk with mitigation strategies",
    "policy_risks": ["list of policy rules that could invalidate findings"],
    "common_mistakes": ["list of common mistakes researchers make on this type of program"]
  },
  "tools_recommended": [
    {
      "tool": "string - tool name",
      "purpose": "string - what to use it for in this program",
      "configuration_notes": "string - specific configuration for this target"
    }
  ],
  "confidence_level": "string - overall confidence in this analysis with caveats"
}
</output_format>

<constraints>
- Base all analysis on the provided information. Do not invent program details.
- If information is insufficient to make a determination, explicitly state what is missing
- Expected value calculations should use conservative estimates
- Do not recommend testing out-of-scope assets
- Do not recommend techniques that violate the program policy
- Factor in the researcher's stated skills when prioritizing
- All time estimates should be realistic, not optimistic
- If the program appears unattractive (low ROI), say so honestly
- Do not hallucinate platform features, program statistics, or bounty amounts
</constraints>
```

---

## Prefill (assistant)

```
{
  "program_overview": {
    "program_name": "
```

---

## Few-shot Examples

### Example 1: Fintech Bug Bounty Program Analysis

**Input variables:**
- `{{PROGRAM_NAME}}`: `PayFlow Bug Bounty`
- `{{SCOPE_DEFINITION}}`: `In scope: *.payflow.com, api.payflow.com/v2/*, mobile apps (iOS/Android). Out of scope: blog.payflow.com, status.payflow.com, marketing.payflow.com, "any testing against production payment processing"`
- `{{REWARD_TABLE}}`: `Critical: $10,000-$50,000, High: $5,000-$10,000, Medium: $1,000-$5,000, Low: $250-$1,000`
- `{{PROGRAM_AGE}}`: `18 months old, 230 reports resolved, 35 public disclosures`
- `{{TECH_STACK}}`: `React + Next.js frontend, Go microservices backend, PostgreSQL, Redis, AWS (ECS, S3, Lambda), GraphQL API`
- `{{PUBLIC_DISCLOSURES}}`: `5 XSS (all in legacy widgets), 3 IDOR in API v1 (deprecated), 2 info disclosure (stack traces, debug headers), 1 SSRF in PDF generator, 1 rate limiting bypass on login`
- `{{YOUR_SKILLS}}`: `Expert in API testing, GraphQL security, IDOR. Strong in SSRF, business logic. Moderate in XSS, mobile. Weak in binary.`
- `{{TIME_BUDGET}}`: `30 hours per week for 3 weeks`

**Expected output (abbreviated):**

```json
{
  "program_overview": {
    "program_name": "PayFlow Bug Bounty",
    "platform": "HackerOne",
    "maturity": "Growing - 18 months with 230 resolved reports indicates active program with moderate researcher attention",
    "competition_level": "High - fintech programs with $50K max bounty attract top researchers. 230 resolved reports in 18 months is ~13/month, indicating significant activity.",
    "responsiveness": "Unknown - not provided. Check HackerOne program page for average response time and signal metrics.",
    "overall_attractiveness": "8/10 - High rewards, broad scope with wildcard domain, GraphQL API (often undertested), fintech logic bugs can be high-severity. Competition is the main concern."
  },
  "scope_analysis": {
    "total_assets": 4,
    "asset_breakdown": [
      {
        "asset": "*.payflow.com (wildcard)",
        "asset_type": "web app",
        "estimated_tech": "React + Next.js frontend, potentially multiple subdomains for different services",
        "attack_surface_size": "Large",
        "estimated_researcher_attention": "High for main app, Low-Medium for less-known subdomains",
        "priority_for_you": "Medium - focus on discovering less-known subdomains rather than the main app"
      },
      {
        "asset": "api.payflow.com/v2/*",
        "asset_type": "API (GraphQL)",
        "estimated_tech": "Go microservices, GraphQL, REST hybrid",
        "attack_surface_size": "Large",
        "estimated_researcher_attention": "Medium - GraphQL is often undertested by researchers who focus on traditional web apps",
        "priority_for_you": "HIGH - this aligns perfectly with your GraphQL and API testing expertise"
      },
      {
        "asset": "iOS mobile app",
        "asset_type": "mobile",
        "estimated_tech": "React Native or Swift, communicates with api.payflow.com",
        "attack_surface_size": "Medium",
        "estimated_researcher_attention": "Low - mobile app testing requires specialized setup and is less common among researchers",
        "priority_for_you": "Medium - moderate mobile skills, but can find API issues via mobile app traffic"
      },
      {
        "asset": "Android mobile app",
        "asset_type": "mobile",
        "estimated_tech": "React Native or Kotlin, communicates with api.payflow.com",
        "attack_surface_size": "Medium",
        "estimated_researcher_attention": "Low",
        "priority_for_you": "Medium - same as iOS, focus on intercepting API calls"
      }
    ],
    "exclusion_analysis": {
      "exclusions": ["blog.payflow.com", "status.payflow.com", "marketing.payflow.com", "production payment processing"],
      "interpretation": "The exclusion of production payment processing is standard for fintech (PCI compliance concerns). However, it hints that payment logic bugs ARE in scope on staging/sandbox - this is a HIGH VALUE area. Blog, status, and marketing exclusions suggest these are third-party hosted (WordPress, Statuspage, HubSpot) and not part of the core codebase. The exclusion of blog specifically might indicate it runs on a different infrastructure with known issues they do not want reported."
    },
    "implied_assets": [
      "Subdomains under *.payflow.com not explicitly listed (use subdomain enumeration)",
      "API v1 (deprecated but may still be accessible - previous IDORs were found here)",
      "GraphQL introspection endpoint at api.payflow.com/v2/graphql",
      "Webhook endpoints for payment notifications",
      "OAuth/OpenID Connect endpoints for third-party integrations",
      "Developer portal or documentation site",
      "Internal tooling subdomains (admin.payflow.com, dashboard.payflow.com)"
    ]
  },
  "reward_analysis": {
    "reward_ranges": {
      "critical": {"min": 10000, "max": 50000},
      "high": {"min": 5000, "max": 10000},
      "medium": {"min": 1000, "max": 5000},
      "low": {"min": 250, "max": 1000}
    },
    "reward_competitiveness": "Above average for fintech. $50K max for critical is competitive. The wide range ($10K-$50K for critical) suggests they differentiate by impact quality - a well-demonstrated chain with business impact will get top-of-range.",
    "expected_value_by_focus": [
      {
        "focus_area": "GraphQL API authorization (IDOR/broken access control)",
        "estimated_reward": 7500,
        "probability_of_finding": "35%",
        "probability_of_acceptance": "85%",
        "estimated_hours": 15,
        "expected_value_per_hour": 148.75,
        "reasoning": "GraphQL APIs frequently have authorization issues due to complex resolver chains. Your expertise in API testing and IDOR makes this high-value. Previous IDORs were in v1; v2 GraphQL may have similar patterns."
      },
      {
        "focus_area": "Business logic flaws in payment/transaction flow",
        "estimated_reward": 25000,
        "probability_of_finding": "15%",
        "probability_of_acceptance": "90%",
        "estimated_hours": 25,
        "expected_value_per_hour": 135.00,
        "reasoning": "Payment logic bugs in fintech are critical severity. Race conditions, negative amount handling, currency conversion issues. Low duplicate risk because these require deep understanding of the application."
      },
      {
        "focus_area": "SSRF in new integrations/webhook features",
        "estimated_reward": 5000,
        "probability_of_finding": "25%",
        "probability_of_acceptance": "80%",
        "estimated_hours": 10,
        "expected_value_per_hour": 100.00,
        "reasoning": "Previous SSRF in PDF generator was found. New integrations and webhook features are likely attack surface for similar issues. Your SSRF expertise applies."
      },
      {
        "focus_area": "Subdomain takeover on *.payflow.com",
        "estimated_reward": 1500,
        "probability_of_finding": "20%",
        "probability_of_acceptance": "70%",
        "estimated_hours": 3,
        "expected_value_per_hour": 70.00,
        "reasoning": "Quick win - wildcard scope means subdomain enumeration may find dangling DNS records. Low effort, medium reward."
      }
    ]
  },
  "vulnerability_predictions": {
    "high_probability_vulns": [
      {
        "vuln_class": "GraphQL Authorization Bypass (IDOR equivalent)",
        "target_asset": "api.payflow.com/v2/graphql",
        "reasoning": "GraphQL resolvers often have inconsistent authorization checks. Nested queries can bypass object-level authorization. Batch queries can be used to enumerate data. Previous IDORs in REST API v1 suggest authorization patterns may be weak.",
        "already_found": false,
        "differentiation_strategy": "Focus on nested query authorization (e.g., query User -> Transactions -> Recipients) where authorization may only check at the top level. Test mutation operations for write-side IDOR."
      },
      {
        "vuln_class": "GraphQL Information Disclosure via Introspection",
        "target_asset": "api.payflow.com/v2/graphql",
        "reasoning": "Many GraphQL deployments leave introspection enabled in production, exposing the entire schema including internal types, deprecated fields, and hidden mutations.",
        "already_found": false,
        "differentiation_strategy": "If introspection is disabled, try field suggestion brute-forcing. Look for __schema queries that work with specific query depth."
      },
      {
        "vuln_class": "Race Condition in Financial Operations",
        "target_asset": "api.payflow.com/v2/* - transaction endpoints",
        "reasoning": "Fintech applications frequently have race conditions in operations like transfers, withdrawals, and balance updates. Go's goroutine model can make these more likely if database transactions are not properly serialized.",
        "already_found": false,
        "differentiation_strategy": "Test concurrent requests for: double-spend, balance manipulation, simultaneous transfers that exceed balance, promo code reuse."
      }
    ],
    "underexplored_areas": [
      {
        "area": "Mobile app API endpoints not in web app",
        "reasoning": "Mobile apps often expose additional API endpoints not available in the web frontend. These endpoints receive less security review.",
        "recommended_techniques": ["Proxy mobile app traffic", "Decompile APK/IPA for hardcoded endpoints", "Compare mobile API calls vs web API calls"]
      },
      {
        "area": "GraphQL subscriptions (WebSocket)",
        "reasoning": "GraphQL subscriptions via WebSocket are often overlooked in security testing. Authorization on subscription events may be weaker than on queries/mutations.",
        "recommended_techniques": ["Test WebSocket upgrade at /v2/graphql/subscriptions", "Subscribe to events for other users' data", "Test if subscription authorization is checked only at connection time vs per-event"]
      },
      {
        "area": "Deprecated API v1 endpoints",
        "reasoning": "v1 had IDORs found. Deprecated does not mean removed. Legacy endpoints may still be accessible with less monitoring.",
        "recommended_techniques": ["Check if api.payflow.com/v1/* still responds", "Test v1 endpoints for unfixed vulns", "Check if v1 auth tokens work on v2 endpoints (or vice versa)"]
      }
    ]
  },
  "strategic_plan": {
    "phase_1_quick_wins": {
      "duration": "Week 1, first 3 days (15 hours)",
      "focus": ["Subdomain enumeration on *.payflow.com", "GraphQL introspection check", "Check deprecated API v1 accessibility", "Subdomain takeover scan", "Technology fingerprinting"],
      "techniques": ["subfinder + httpx + nuclei", "GraphQL introspection query", "curl to api.payflow.com/v1/", "subjack/can-i-take-over-xyz", "wappalyzer/whatweb"],
      "expected_outcomes": "Map the full attack surface. Potentially find subdomain takeover (Low-Medium bounty). Get GraphQL schema if introspection is enabled."
    },
    "phase_2_deep_dive": {
      "duration": "Week 1 day 4-5 + Week 2 (40 hours)",
      "focus": ["GraphQL authorization testing (IDOR)", "Business logic in payment flows", "SSRF in integration/webhook features", "Race conditions in financial operations"],
      "techniques": ["GraphQL query manipulation, nested queries, batch operations", "Burp Suite intercept of payment flows, negative values, currency tricks", "SSRF payload testing on URL-accepting parameters", "Turbo Intruder for race conditions"],
      "expected_outcomes": "Find 1-3 high-severity authorization or logic bugs in GraphQL API or payment processing."
    },
    "phase_3_creative": {
      "duration": "Week 3 (30 hours)",
      "focus": ["Mobile app-specific endpoints", "GraphQL subscription authorization", "Chain building from lower-severity findings", "Server-side template injection in email/PDF generation"],
      "techniques": ["Mobile app decompilation and traffic analysis", "WebSocket testing for GraphQL subscriptions", "Exploit chain construction from earlier findings", "SSTI testing in user-controlled content rendered in emails/PDFs"],
      "expected_outcomes": "Find unique findings in under-tested areas. Build chains to elevate severity of earlier findings."
    },
    "weekly_schedule": [
      {
        "week": 1,
        "focus": "Reconnaissance and quick wins, then transition to GraphQL deep-dive",
        "daily_activities": [
          "Day 1-2: Full subdomain enumeration, technology fingerprinting, attack surface mapping",
          "Day 3: GraphQL introspection, schema analysis, identify high-value queries/mutations",
          "Day 4-5: Begin GraphQL authorization testing - IDOR on queries, then mutations"
        ],
        "target_findings": "Complete attack surface map. Subdomain takeover if available. GraphQL schema. First authorization bypass finding."
      },
      {
        "week": 2,
        "focus": "Deep-dive into API authorization and payment logic",
        "daily_activities": [
          "Day 1-2: Continue GraphQL auth testing, focus on nested queries and batch operations",
          "Day 3-4: Payment flow testing - race conditions, logic flaws, parameter manipulation",
          "Day 5: SSRF testing on all URL-accepting parameters, webhook and integration features"
        ],
        "target_findings": "2-3 High/Critical findings in API authorization or payment logic."
      },
      {
        "week": 3,
        "focus": "Creative testing and chain building",
        "daily_activities": [
          "Day 1-2: Mobile app analysis, intercept traffic, test mobile-only endpoints",
          "Day 3: GraphQL WebSocket subscriptions testing",
          "Day 4: Review all findings, build exploit chains, calculate combined impact",
          "Day 5: Write reports, polish PoCs, submit findings"
        ],
        "target_findings": "1-2 unique findings from under-tested areas. Exploit chains from existing findings."
      }
    ]
  },
  "risk_assessment": {
    "duplicate_risk": "Medium-High for common vuln classes (XSS, basic IDOR). Low for GraphQL-specific issues and business logic. Mitigation: focus on less-tested areas (GraphQL, mobile, subscriptions) and prioritize logic bugs over injection bugs.",
    "policy_risks": [
      "Testing production payment processing is explicitly excluded - ensure all payment tests use sandbox/test accounts only",
      "Rate limiting bypass must not impact service availability",
      "Any automated scanning must respect rate limits"
    ],
    "common_mistakes": [
      "Reporting XSS in legacy widgets (likely duplicates of the 5 already disclosed)",
      "Reporting IDOR in API v1 (already known, 3 disclosed)",
      "Testing against production payment processing (policy violation)",
      "Submitting low-quality reports without PoC (will be marked as informative)",
      "Not demonstrating business impact for medium/high findings (reduces bounty amount)"
    ]
  },
  "tools_recommended": [
    {
      "tool": "InQL / graphql-voyager",
      "purpose": "GraphQL schema analysis and query generation",
      "configuration_notes": "Point at api.payflow.com/v2/graphql. Extract schema via introspection or build from observed queries."
    },
    {
      "tool": "Burp Suite + Turbo Intruder",
      "purpose": "Race condition testing on payment endpoints",
      "configuration_notes": "Use single-packet attack mode in Turbo Intruder for precise race condition testing on financial operations."
    },
    {
      "tool": "subfinder + httpx + nuclei",
      "purpose": "Subdomain enumeration and automated vulnerability detection",
      "configuration_notes": "Use subfinder with multiple passive sources. httpx to validate live hosts. nuclei with community templates for quick wins."
    },
    {
      "tool": "MobSF / apktool",
      "purpose": "Mobile app analysis for hidden endpoints and hardcoded secrets",
      "configuration_notes": "Decompile both iOS and Android apps. Search for API endpoints, hardcoded tokens, and certificate pinning configuration."
    }
  ],
  "confidence_level": "Medium-High. Analysis is based on the provided program details and general patterns from similar fintech programs. The GraphQL API focus recommendation has high confidence given your stated skills. Payment logic testing recommendation is strong but actual feasibility depends on sandbox availability. Subdomain takeover probability is speculative without enumeration data."
}
```
