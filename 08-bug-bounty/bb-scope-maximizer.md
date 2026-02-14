# Bug Bounty Scope Maximizer

## Quand utiliser ce prompt

Utiliser ce prompt apres l'analyse initiale du programme (bb-program-analysis.md) pour maximiser la couverture du perimetre autorise. Ce prompt vous aide a decouvrir des actifs caches, des endpoints non documentes, des fonctionnalites oubliees, et des surfaces d'attaque que les autres chercheurs ignorent. Il couvre l'enumeration de sous-domaines, la decouverte d'endpoints API, l'analyse de fichiers JavaScript, l'utilisation de Wayback Machine, l'analyse de source maps, et l'analyse d'applications mobiles. A utiliser en debut d'engagement apres l'analyse du programme mais avant le test de vulnerabilites.

## Variables a remplir

| Variable | Description | Exemple |
|----------|-------------|---------|
| `{{TARGET_DOMAIN}}` | Domaine principal en scope | `example.com` |
| `{{SCOPE_DEFINITION}}` | Definition exacte du perimetre | `*.example.com, api.example.com, mobile apps` |
| `{{KNOWN_ASSETS}}` | Actifs deja identifies | `www.example.com, api.example.com, app.example.com, docs.example.com` |
| `{{TECH_STACK}}` | Stack technique connue | `React, Node.js Express, AWS, PostgreSQL` |
| `{{TARGET}}` | Cible principale | `https://example.com` |
| `{{SCOPE}}` | Contraintes de perimetre | `No brute force exceeding 50 req/s, no DoS, no social engineering` |
| `{{CONTEXT}}` | Contexte additionnel | `SaaS platform, B2B, enterprise features, SSO integrations` |
| `{{DISCOVERED_ENDPOINTS}}` | Endpoints deja decouverts | `/api/v2/users, /api/v2/projects, /api/v2/billing` |
| `{{JS_FILES}}` | Fichiers JS identifies | `main.a1b2c3.js, vendor.d4e5f6.js, chunk-auth.g7h8i9.js` |

---

## System Prompt

```
You are an expert asset discovery specialist and attack surface mapping researcher. You have discovered hundreds of hidden assets, forgotten subdomains, undocumented APIs, and shadow IT resources during bug bounty programs. You are known for finding bugs where others have given up by discovering attack surface that other researchers miss.

Your discovery methodology covers:
1. PASSIVE RECONNAISSANCE: DNS records, certificate transparency logs, search engine dorking, public code repositories, Wayback Machine, web archives
2. ACTIVE ENUMERATION: Subdomain brute-forcing, virtual host discovery, port scanning, service fingerprinting
3. APPLICATION ANALYSIS: JavaScript file analysis, source map recovery, API endpoint extraction, GraphQL introspection, OpenAPI/Swagger discovery
4. MOBILE APP ANALYSIS: APK/IPA decompilation, traffic interception, hardcoded endpoint extraction, certificate pinning bypass
5. INFRASTRUCTURE ANALYSIS: Cloud resource enumeration (S3 buckets, Azure blobs, GCS), CDN origin discovery, WAF bypass to find origin IP
6. HISTORICAL ANALYSIS: Wayback Machine for removed features, deleted pages, old API versions, configuration files

Your rules:
1. ONLY recommend techniques that stay within the authorized scope
2. Distinguish between passive (no target interaction) and active (target interaction) techniques
3. Rate each technique by likelihood of discovering new assets and effort required
4. Provide exact commands and tool configurations, not generic advice
5. Prioritize techniques that find UNIQUE assets other researchers likely missed
6. Do NOT recommend techniques that constitute denial of service
7. Do NOT hallucinate tool names, flags, or capabilities
8. Flag any technique that might be perceived as out-of-scope or aggressive
```

---

## User Prompt

```
<context>
I am working on a bug bounty program and need to maximize my coverage of the authorized scope. I want to discover all possible assets, endpoints, and attack surface within the defined scope before beginning vulnerability testing.

Target domain: {{TARGET_DOMAIN}}
Scope: {{SCOPE_DEFINITION}}
Constraints: {{SCOPE}}
Context: {{CONTEXT}}
</context>

<target>
Known assets so far:
{{KNOWN_ASSETS}}

Known technology stack:
{{TECH_STACK}}

Already discovered endpoints:
{{DISCOVERED_ENDPOINTS}}

Known JavaScript files:
{{JS_FILES}}
</target>

<instructions>
Maximize scope coverage following this exact methodology:

STEP 1 - THINKING BLOCK (mandatory):
<thinking>
Phase 1 - CURRENT COVERAGE ASSESSMENT:
- What percentage of the scope do the known assets likely represent?
- What asset types are missing? (subdomains, APIs, mobile endpoints, internal tools)
- What discovery techniques have NOT yet been applied?
- Where are the gaps in the current asset inventory?

Phase 2 - DISCOVERY STRATEGY:
- Order techniques by: yield (expected new assets), effort (time required), risk (chance of being blocked/noticed)
- Separate passive (no target interaction) from active techniques
- Identify which techniques are best for each gap in coverage
- Consider the tech stack when selecting techniques (e.g., React apps have JS bundles with routes)

Phase 3 - PRIORITIZATION:
- Which newly discovered assets are most likely to have vulnerabilities?
- New features, complex functionality, file uploads, payment processing, admin panels
- APIs with different versions or authentication mechanisms
- Assets with less security review (internal tools, staging environments, development endpoints)
</thinking>

STEP 2 - Generate the discovery plan with exact commands and expected outputs.

STEP 3 - For each discovered asset category, provide a vulnerability likelihood ranking.
</instructions>

<output_format>
Return a JSON object with this exact structure:
{
  "coverage_assessment": {
    "estimated_current_coverage": "string - percentage estimate with reasoning",
    "coverage_gaps": [
      {
        "gap_type": "string - what category of assets is missing",
        "importance": "string - Critical/High/Medium/Low",
        "reasoning": "string - why this gap matters"
      }
    ]
  },
  "discovery_techniques": {
    "passive_reconnaissance": [
      {
        "technique_id": "string - DISC-P001, DISC-P002, etc.",
        "technique_name": "string",
        "description": "string - what this technique discovers",
        "commands": [
          {
            "tool": "string - tool name",
            "command": "string - exact command to run",
            "explanation": "string - what this command does",
            "expected_output": "string - what to look for in the output"
          }
        ],
        "estimated_yield": "string - Low/Medium/High with specifics",
        "estimated_time": "string - time to execute",
        "risk_level": "string - None/Low/Medium (passive should be None or Low)",
        "priority": "integer - 1 is highest priority"
      }
    ],
    "active_enumeration": [
      {
        "technique_id": "string - DISC-A001, DISC-A002, etc.",
        "technique_name": "string",
        "description": "string",
        "commands": [
          {
            "tool": "string",
            "command": "string - exact command",
            "explanation": "string",
            "expected_output": "string"
          }
        ],
        "estimated_yield": "string",
        "estimated_time": "string",
        "risk_level": "string - Low/Medium/High",
        "rate_limiting_notes": "string - how to stay within scope rate limits",
        "priority": "integer"
      }
    ],
    "application_analysis": [
      {
        "technique_id": "string - DISC-APP001, etc.",
        "technique_name": "string",
        "description": "string",
        "commands": [
          {
            "tool": "string",
            "command": "string",
            "explanation": "string",
            "expected_output": "string"
          }
        ],
        "estimated_yield": "string",
        "estimated_time": "string",
        "priority": "integer"
      }
    ],
    "mobile_analysis": [
      {
        "technique_id": "string - DISC-MOB001, etc.",
        "technique_name": "string",
        "description": "string",
        "commands": [
          {
            "tool": "string",
            "command": "string",
            "explanation": "string",
            "expected_output": "string"
          }
        ],
        "estimated_yield": "string",
        "estimated_time": "string",
        "priority": "integer"
      }
    ],
    "historical_analysis": [
      {
        "technique_id": "string - DISC-H001, etc.",
        "technique_name": "string",
        "description": "string",
        "commands": [
          {
            "tool": "string",
            "command": "string",
            "explanation": "string",
            "expected_output": "string"
          }
        ],
        "estimated_yield": "string",
        "estimated_time": "string",
        "priority": "integer"
      }
    ]
  },
  "asset_prioritization": [
    {
      "asset_category": "string - type of asset",
      "vulnerability_likelihood": "string - High/Medium/Low",
      "common_vuln_classes": ["list of vuln types commonly found on this asset type"],
      "reasoning": "string - why vulns are likely here",
      "recommended_testing_order": "integer - 1 is test first"
    }
  ],
  "discovery_workflow": {
    "step_by_step": [
      {
        "step": "integer",
        "action": "string - what to do",
        "technique_ids": ["list of technique IDs to use"],
        "time_estimate": "string",
        "feeds_into": "string - what the next step depends on from this step"
      }
    ],
    "total_estimated_time": "string",
    "expected_new_assets": "string - estimate of how many new assets this workflow will discover"
  },
  "scope_boundary_notes": [
    {
      "situation": "string - a discovery that might be at the edge of scope",
      "recommendation": "string - how to handle it (ask program, skip it, test carefully)",
      "risk": "string - what could go wrong"
    }
  ],
  "confidence_level": "string - overall confidence with caveats"
}
</output_format>

<constraints>
- All discovery techniques must stay within the authorized scope
- Rate limits must be respected - include throttling in all active scanning commands
- Passive techniques should be prioritized before active techniques
- Do not recommend social engineering, phishing, or physical access techniques
- Provide real, working commands with correct tool flags and syntax
- If a tool requires installation, mention it in the command section
- Flag any technique that might trigger WAF blocks or security alerts
- Do not hallucinate tool capabilities or command-line flags
- Estimate yields conservatively
- Note when a technique requires specific OS or setup (e.g., mobile analysis needs rooted device)
</constraints>
```

---

## Prefill (assistant)

```
{
  "coverage_assessment": {
    "estimated_current_coverage": "
```

---

## Few-shot Examples

### Example 1: SaaS Application Scope Maximization

**Input variables:**
- `{{TARGET_DOMAIN}}`: `example.com`
- `{{SCOPE_DEFINITION}}`: `*.example.com, api.example.com, mobile apps`
- `{{KNOWN_ASSETS}}`: `www.example.com, api.example.com, app.example.com, docs.example.com`
- `{{TECH_STACK}}`: `React, Node.js, AWS, PostgreSQL`
- `{{DISCOVERED_ENDPOINTS}}`: `/api/v2/users, /api/v2/projects, /api/v2/billing`
- `{{JS_FILES}}`: `main.a1b2c3.js, vendor.d4e5f6.js`

**Expected output (abbreviated, key sections):**

```json
{
  "coverage_assessment": {
    "estimated_current_coverage": "15-25% - Four known subdomains is likely a small fraction of total infrastructure for a SaaS platform. API endpoint discovery shows only 3 endpoints, which is minimal for a full-featured API. JS files have not been analyzed for hidden routes.",
    "coverage_gaps": [
      {
        "gap_type": "Subdomain enumeration",
        "importance": "Critical",
        "reasoning": "Wildcard scope means potentially dozens of subdomains. Only 4 known. Subdomains like staging, dev, admin, internal, jenkins, grafana, kibana are commonly exposed."
      },
      {
        "gap_type": "API endpoint discovery",
        "importance": "Critical",
        "reasoning": "Only 3 endpoints known from a full SaaS API. Likely 50-200+ endpoints exist. Hidden admin APIs, webhook handlers, file upload endpoints are prime targets."
      },
      {
        "gap_type": "JavaScript analysis",
        "importance": "High",
        "reasoning": "React SPA bundles contain all frontend routes and API calls. Analyzing main.a1b2c3.js will likely reveal dozens of API endpoints, including internal/admin routes."
      },
      {
        "gap_type": "Mobile app endpoints",
        "importance": "High",
        "reasoning": "Mobile apps in scope but no mobile-specific endpoints discovered. Mobile apps often use different API versions or endpoints not in the web app."
      },
      {
        "gap_type": "Cloud resource discovery",
        "importance": "Medium",
        "reasoning": "AWS infrastructure means potential S3 buckets, Lambda function URLs, CloudFront distributions that may be in scope under *.example.com."
      }
    ]
  },
  "discovery_techniques": {
    "passive_reconnaissance": [
      {
        "technique_id": "DISC-P001",
        "technique_name": "Certificate Transparency Log Enumeration",
        "description": "Query CT logs for all certificates issued to *.example.com to discover subdomains",
        "commands": [
          {
            "tool": "crt.sh / curl",
            "command": "curl -s 'https://crt.sh/?q=%25.example.com&output=json' | jq -r '.[].name_value' | sort -u | grep -v '\\*'",
            "explanation": "Queries crt.sh for all SSL certificates issued to any subdomain of example.com. Extracts unique domain names from the results.",
            "expected_output": "List of subdomains found in CT logs: staging.example.com, admin.example.com, mail.example.com, etc."
          }
        ],
        "estimated_yield": "High - typically discovers 10-50 subdomains",
        "estimated_time": "2 minutes",
        "risk_level": "None - no target interaction, querying public CT logs",
        "priority": 1
      },
      {
        "technique_id": "DISC-P002",
        "technique_name": "Multi-source Passive Subdomain Enumeration",
        "description": "Use subfinder to query multiple passive sources simultaneously (VirusTotal, SecurityTrails, Shodan, etc.)",
        "commands": [
          {
            "tool": "subfinder",
            "command": "subfinder -d example.com -all -silent | sort -u | tee subdomains_passive.txt",
            "explanation": "Queries 40+ passive data sources for subdomains of example.com. -all flag uses all available sources.",
            "expected_output": "Consolidated list of subdomains from all passive sources. Typically 20-100+ unique subdomains."
          },
          {
            "tool": "httpx",
            "command": "httpx -l subdomains_passive.txt -silent -status-code -title -tech-detect -o live_subdomains.txt",
            "explanation": "Validates which discovered subdomains are live, gets HTTP status codes, page titles, and technology detection.",
            "expected_output": "List of live subdomains with their HTTP status, title, and detected technologies."
          }
        ],
        "estimated_yield": "High - broadest passive coverage",
        "estimated_time": "5-10 minutes",
        "risk_level": "None for subfinder, Low for httpx (makes HTTP requests to discovered hosts)",
        "priority": 1
      },
      {
        "technique_id": "DISC-P003",
        "technique_name": "GitHub/GitLab Code Search for Endpoints and Secrets",
        "description": "Search public repositories for references to example.com, API endpoints, configuration files, and accidentally committed secrets",
        "commands": [
          {
            "tool": "github dorking (manual)",
            "command": "# Search queries to run on github.com:\n# 1. \"api.example.com\" language:javascript\n# 2. \"example.com\" filename:.env\n# 3. \"example.com\" filename:config\n# 4. org:examplecorp filename:docker-compose\n# 5. \"example.com\" password OR secret OR token OR api_key",
            "explanation": "Manual GitHub searches to find code referencing the target domain. Can reveal API endpoints, configuration details, internal hostnames, and leaked credentials.",
            "expected_output": "Code references containing API URLs, configuration files, environment variable names, internal service names."
          },
          {
            "tool": "trufflehog",
            "command": "trufflehog github --org=examplecorp --only-verified",
            "explanation": "Scans the organization's public GitHub repositories for verified secrets (API keys, tokens, passwords that are confirmed to be valid).",
            "expected_output": "List of verified secrets found in public repositories, including the file path and commit where they were introduced."
          }
        ],
        "estimated_yield": "Medium - depends on target's public code presence",
        "estimated_time": "30-60 minutes",
        "risk_level": "None - no target interaction",
        "priority": 2
      },
      {
        "technique_id": "DISC-P004",
        "technique_name": "Wayback Machine URL Extraction",
        "description": "Extract all URLs ever archived for the target domain to find deleted pages, old API endpoints, configuration files, and deprecated features",
        "commands": [
          {
            "tool": "waybackurls / gau",
            "command": "echo example.com | gau --threads 5 --subs | sort -u | tee wayback_urls.txt",
            "explanation": "Queries Wayback Machine, Common Crawl, OTX, and URLscan for all URLs ever seen for example.com and its subdomains.",
            "expected_output": "Potentially thousands of URLs including old API endpoints, admin panels, config files, backup files, etc."
          },
          {
            "tool": "grep/filter",
            "command": "grep -iE '\\.(json|xml|yaml|yml|conf|config|env|bak|backup|sql|log|txt)$' wayback_urls.txt | sort -u > interesting_files.txt",
            "explanation": "Filters the wayback URLs for interesting file extensions that may contain sensitive data or configuration.",
            "expected_output": "List of potentially sensitive files: config.json, .env, database.sql, application.yml, etc."
          }
        ],
        "estimated_yield": "High - Wayback often reveals deleted but still-accessible endpoints",
        "estimated_time": "10-15 minutes",
        "risk_level": "None for URL extraction, Low if you then check if the URLs are still accessible",
        "priority": 2
      }
    ],
    "active_enumeration": [
      {
        "technique_id": "DISC-A001",
        "technique_name": "DNS Subdomain Brute-Force",
        "description": "Brute-force subdomains using a wordlist to find subdomains not in passive sources",
        "commands": [
          {
            "tool": "puredns / massdns",
            "command": "puredns bruteforce /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt example.com -r resolvers.txt --rate-limit 50 | tee subdomains_brute.txt",
            "explanation": "Brute-forces subdomains using a 20K word list with DNS resolution validation. Rate limited to 50 queries/second to stay within scope.",
            "expected_output": "Additional subdomains not found in passive enumeration: dev.example.com, staging.example.com, internal.example.com, etc."
          }
        ],
        "estimated_yield": "Medium - finds subdomains not in CT logs or passive sources",
        "estimated_time": "15-30 minutes with rate limiting",
        "risk_level": "Low - DNS queries only, no HTTP interaction",
        "rate_limiting_notes": "50 queries/second is conservative. DNS brute-forcing is generally acceptable but produces DNS log entries.",
        "priority": 3
      },
      {
        "technique_id": "DISC-A002",
        "technique_name": "Virtual Host Discovery",
        "description": "Send requests with different Host headers to discovered IP addresses to find virtual hosts not resolvable via DNS",
        "commands": [
          {
            "tool": "ffuf",
            "command": "ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -u https://KNOWN_IP -H 'Host: FUZZ.example.com' -fs 0 -rate 20 -o vhost_results.json",
            "explanation": "Fuzzes the Host header to discover virtual hosts on the server's IP. Filters out zero-length responses. Rate limited to 20 req/sec.",
            "expected_output": "Virtual hosts that respond differently from the default, indicating real applications: admin.example.com, internal.example.com, api-v3.example.com"
          }
        ],
        "estimated_yield": "Medium - can find hidden vhosts not in DNS",
        "estimated_time": "10-15 minutes per IP",
        "risk_level": "Medium - actively probing the server, may trigger WAF alerts",
        "rate_limiting_notes": "20 req/sec is conservative. Monitor for 429 responses and back off if rate limited.",
        "priority": 4
      }
    ],
    "application_analysis": [
      {
        "technique_id": "DISC-APP001",
        "technique_name": "JavaScript Bundle Analysis for Routes and API Endpoints",
        "description": "Download and analyze the React application's JavaScript bundles to extract all frontend routes, API endpoint paths, and hidden functionality",
        "commands": [
          {
            "tool": "curl + custom analysis",
            "command": "curl -s https://app.example.com/static/js/main.a1b2c3.js -o main.js && grep -oP '(?<=[\"\\x27])/api/[a-zA-Z0-9/_-]+' main.js | sort -u",
            "explanation": "Downloads the main JS bundle and extracts all API endpoint paths using regex. React apps compile all routes and API calls into the bundle.",
            "expected_output": "Complete list of API endpoints referenced in the frontend: /api/v2/admin/users, /api/v2/internal/metrics, /api/v2/webhooks/test, /api/v2/export/csv, etc."
          },
          {
            "tool": "JS beautifier + manual review",
            "command": "js-beautify main.js > main_pretty.js && grep -n 'route\\|path\\|endpoint\\|url\\|fetch\\|axios\\|api' main_pretty.js | head -100",
            "explanation": "Beautifies the minified JS and searches for route definitions, API calls, and URL patterns. Manual review of surrounding code reveals authentication requirements and hidden features.",
            "expected_output": "React Router route definitions showing all pages, including admin-only routes. Axios/fetch calls showing all API interactions."
          }
        ],
        "estimated_yield": "Very High - React bundles contain the entire frontend application",
        "estimated_time": "1-2 hours for thorough analysis",
        "priority": 1
      },
      {
        "technique_id": "DISC-APP002",
        "technique_name": "Source Map Recovery",
        "description": "Check if JavaScript source maps are accessible in production, which would reveal the original unminified source code including comments, variable names, and internal documentation",
        "commands": [
          {
            "tool": "curl",
            "command": "curl -s -o /dev/null -w '%{http_code}' https://app.example.com/static/js/main.a1b2c3.js.map",
            "explanation": "Checks if the source map file is accessible by appending .map to the JS file URL. Source maps are often accidentally deployed to production.",
            "expected_output": "200 = source map accessible (HIGH VALUE - contains original source code). 404/403 = not accessible."
          },
          {
            "tool": "smap / source-map-explorer",
            "command": "# If source map is found:\ncurl -s https://app.example.com/static/js/main.a1b2c3.js.map -o main.js.map && npx source-map-explorer main.a1b2c3.js main.js.map",
            "explanation": "Downloads the source map and reconstructs the original source code. This reveals the complete frontend codebase with original variable names, comments, internal API documentation, and hidden features.",
            "expected_output": "Full original source code tree of the React application. This is equivalent to having access to the frontend repository."
          }
        ],
        "estimated_yield": "Very High if found - equivalent to source code access. Low probability (10-20%) but massive impact.",
        "estimated_time": "5 minutes to check, 2+ hours to analyze if found",
        "priority": 1
      },
      {
        "technique_id": "DISC-APP003",
        "technique_name": "API Documentation and Schema Discovery",
        "description": "Discover OpenAPI/Swagger documentation, GraphQL introspection, and other API schema endpoints",
        "commands": [
          {
            "tool": "ffuf / manual",
            "command": "ffuf -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt -u https://api.example.com/FUZZ -mc 200,301,302 -rate 20 -o api_discovery.json",
            "explanation": "Fuzzes common API documentation and schema paths: /swagger, /openapi.json, /api-docs, /graphql, /graphql/playground, etc.",
            "expected_output": "Discovered API documentation endpoints. Swagger UI at /swagger, GraphQL Playground at /graphql/playground, OpenAPI spec at /openapi.json"
          },
          {
            "tool": "manual check",
            "command": "for path in /swagger /swagger-ui /api-docs /openapi.json /swagger.json /graphql /graphql/playground /v2/api-docs /v3/api-docs /.well-known/openapi.json; do echo -n \"$path: \"; curl -s -o /dev/null -w '%{http_code}' \"https://api.example.com$path\"; echo; done",
            "explanation": "Checks common API documentation paths to find Swagger UI, OpenAPI specs, or GraphQL playgrounds.",
            "expected_output": "List of paths with HTTP status codes. 200 on any of these reveals the full API schema."
          }
        ],
        "estimated_yield": "High - API docs expose the entire API surface",
        "estimated_time": "10-15 minutes",
        "priority": 2
      }
    ],
    "mobile_analysis": [
      {
        "technique_id": "DISC-MOB001",
        "technique_name": "Android APK Decompilation and Endpoint Extraction",
        "description": "Decompile the Android app to extract hardcoded API endpoints, hidden features, and configuration details",
        "commands": [
          {
            "tool": "apktool + jadx",
            "command": "# Download APK from Google Play:\napkeep -a com.example.app -o example.apk\n# Decompile:\njadx -d example_decompiled example.apk\n# Extract URLs:\ngrep -rhoP 'https?://[a-zA-Z0-9._/-]+' example_decompiled/sources/ | sort -u | grep example.com",
            "explanation": "Downloads the APK, decompiles it to Java source, and extracts all URLs referencing the target domain. Mobile apps often hardcode API endpoints, staging URLs, and internal endpoints.",
            "expected_output": "List of all API endpoints used by the mobile app, including mobile-only endpoints not in the web app. May find staging/dev URLs, internal API versions, push notification endpoints."
          }
        ],
        "estimated_yield": "High - mobile apps frequently contain endpoints not in the web version",
        "estimated_time": "1-2 hours",
        "priority": 3
      }
    ],
    "historical_analysis": [
      {
        "technique_id": "DISC-H001",
        "technique_name": "Wayback Machine Diff Analysis for Removed Features",
        "description": "Compare current site with archived versions to identify removed features, deprecated endpoints, and old functionality that may still be accessible",
        "commands": [
          {
            "tool": "waybackurls + httpx",
            "command": "echo example.com | gau --subs | sort -u | httpx -silent -status-code -mc 200 | grep -v '\\.(css|js|png|jpg|gif|svg|woff|ttf)$' | tee still_alive_old_urls.txt",
            "explanation": "Gets all historically archived URLs and checks which ones still return 200 OK. Filters out static assets. Remaining URLs are pages/endpoints that exist but may not be linked from the current application.",
            "expected_output": "List of old but still-accessible URLs: deprecated API endpoints, old admin panels, forgotten upload handlers, test pages, debug endpoints."
          }
        ],
        "estimated_yield": "Medium-High - forgotten endpoints are common and less tested by other researchers",
        "estimated_time": "30-60 minutes",
        "priority": 2
      }
    ]
  },
  "asset_prioritization": [
    {
      "asset_category": "Hidden admin panels and internal tools",
      "vulnerability_likelihood": "High",
      "common_vuln_classes": ["Authentication bypass", "IDOR", "CSRF", "Privilege escalation", "Default credentials"],
      "reasoning": "Admin panels are often built quickly with less security review. Internal tools may lack authentication when previously only accessible from VPN.",
      "recommended_testing_order": 1
    },
    {
      "asset_category": "API endpoints not in web UI (mobile-only, deprecated, undocumented)",
      "vulnerability_likelihood": "High",
      "common_vuln_classes": ["Missing authentication", "IDOR", "Mass assignment", "Excessive data exposure", "Injection"],
      "reasoning": "Endpoints not visible in the web UI receive less security testing. Deprecated endpoints may have known-unfixed vulnerabilities.",
      "recommended_testing_order": 2
    },
    {
      "asset_category": "File upload and processing features",
      "vulnerability_likelihood": "High",
      "common_vuln_classes": ["Unrestricted file upload", "SSRF via file processing", "XXE in document parsing", "Path traversal", "RCE via file processing"],
      "reasoning": "File handling is complex and frequently contains vulnerabilities. Image processors, document converters, and CSV importers are common attack vectors.",
      "recommended_testing_order": 3
    },
    {
      "asset_category": "Staging/development subdomains",
      "vulnerability_likelihood": "High",
      "common_vuln_classes": ["Debug mode enabled", "Default credentials", "Verbose error messages", "Missing authentication", "Outdated software"],
      "reasoning": "Staging environments often mirror production with weaker security controls. Debug mode, stack traces, and default credentials are common.",
      "recommended_testing_order": 4
    },
    {
      "asset_category": "Integration and webhook endpoints",
      "vulnerability_likelihood": "Medium-High",
      "common_vuln_classes": ["SSRF", "Webhook abuse", "Authentication bypass via callback", "Injection in webhook parameters"],
      "reasoning": "Integration endpoints accept URLs or data from external sources, creating SSRF and injection opportunities.",
      "recommended_testing_order": 5
    }
  ],
  "discovery_workflow": {
    "step_by_step": [
      {
        "step": 1,
        "action": "Passive subdomain and URL enumeration (no target interaction)",
        "technique_ids": ["DISC-P001", "DISC-P002", "DISC-P004"],
        "time_estimate": "30 minutes",
        "feeds_into": "Comprehensive subdomain list for active validation"
      },
      {
        "step": 2,
        "action": "Validate live subdomains and fingerprint technologies",
        "technique_ids": ["DISC-P002 (httpx step)"],
        "time_estimate": "15 minutes",
        "feeds_into": "Live asset inventory with technology details"
      },
      {
        "step": 3,
        "action": "JavaScript and source map analysis",
        "technique_ids": ["DISC-APP001", "DISC-APP002"],
        "time_estimate": "2 hours",
        "feeds_into": "Complete API endpoint list and potential source code"
      },
      {
        "step": 4,
        "action": "API documentation and schema discovery",
        "technique_ids": ["DISC-APP003"],
        "time_estimate": "15 minutes",
        "feeds_into": "Full API schema if discovered"
      },
      {
        "step": 5,
        "action": "GitHub and code repository search",
        "technique_ids": ["DISC-P003"],
        "time_estimate": "1 hour",
        "feeds_into": "Additional endpoints, configuration details, potential secrets"
      },
      {
        "step": 6,
        "action": "Historical URL analysis for forgotten endpoints",
        "technique_ids": ["DISC-H001"],
        "time_estimate": "45 minutes",
        "feeds_into": "Deprecated but accessible endpoints for vulnerability testing"
      },
      {
        "step": 7,
        "action": "Mobile app decompilation and endpoint extraction",
        "technique_ids": ["DISC-MOB001"],
        "time_estimate": "2 hours",
        "feeds_into": "Mobile-only API endpoints not in web app"
      },
      {
        "step": 8,
        "action": "Active subdomain brute-forcing and vhost discovery",
        "technique_ids": ["DISC-A001", "DISC-A002"],
        "time_estimate": "1 hour",
        "feeds_into": "Final subdomain list including non-passive discoveries"
      }
    ],
    "total_estimated_time": "8-10 hours for comprehensive discovery",
    "expected_new_assets": "20-50 new subdomains, 30-100 new API endpoints, 5-10 hidden features/admin panels, 2-5 staging/dev environments"
  },
  "scope_boundary_notes": [
    {
      "situation": "Discovery of staging.example.com that appears to be a mirror of production with test data",
      "recommendation": "Staging is in scope under *.example.com. Test it, but be aware that staging may have different monitoring. Notify the program if you find real production data in staging.",
      "risk": "Staging may share databases with production. Be extra careful with any write operations."
    },
    {
      "situation": "Finding third-party services (e.g., Zendesk, Intercom) on subdomains like support.example.com",
      "recommendation": "Third-party hosted services may be technically in scope (under the wildcard) but programs often exclude them. Check the policy for third-party exclusions. If unclear, ask the program before testing.",
      "risk": "Testing third-party infrastructure could violate the third party's ToS and be considered out of scope even if the subdomain matches the wildcard."
    }
  ],
  "confidence_level": "High for passive techniques (reliable and well-tested tools). Medium for active techniques (results depend on target configuration and WAF behavior). JavaScript analysis confidence is high for React applications as the build process embeds all routes."
}
```
