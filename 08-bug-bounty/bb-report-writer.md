# Bug Bounty Report Writer

## Quand utiliser ce prompt

Utiliser ce prompt lorsque vous avez une vulnerabilite confirmee avec un PoC fonctionnel et que vous etes pret a rediger le rapport pour la soumettre a la plateforme de bug bounty. Un rapport de qualite professionnelle fait la difference entre un triage rapide avec recompense maximale et un rapport marque comme "needs more info" ou sous-evalue. Ce prompt genere un rapport complet au format HackerOne/Bugcrowd avec un titre accrocheur, un resume executif pour les non-techniques, des etapes de reproduction claires, une analyse d'impact business, et une remediation actionnable. A utiliser une fois le PoC valide et avant la soumission.

## Variables a remplir

| Variable | Description | Exemple |
|----------|-------------|---------|
| `{{VULN_TITLE}}` | Titre court et descriptif de la vulnerabilite | `IDOR in /api/v2/invoices allows access to any customer's billing data` |
| `{{VULN_TYPE}}` | Classe de vulnerabilite (CWE si possible) | `CWE-639: Authorization Bypass Through User-Controlled Key (IDOR)` |
| `{{SEVERITY}}` | Severite estimee | `High` |
| `{{TARGET}}` | Asset affecte | `api.example.com` |
| `{{AFFECTED_ENDPOINT}}` | Endpoint ou composant specifique | `GET /api/v2/invoices/{invoice_id}` |
| `{{VULN_DESCRIPTION}}` | Description technique detaillee | `The invoice_id parameter is a sequential integer. Authenticated users can access any invoice by changing the ID, regardless of ownership. No authorization check verifies the requesting user owns the invoice.` |
| `{{REPRODUCTION_STEPS}}` | Etapes de reproduction brutes (vous les raffinerez) | `1. Login as user A, 2. Note invoice ID 1001, 3. Change to 1002, 4. See user B's invoice` |
| `{{POC_DETAILS}}` | Details du PoC (commandes, scripts, captures) | `curl command showing access to another user's invoice` |
| `{{IMPACT}}` | Impact observe et potentiel | `Access to all customer invoices including names, addresses, payment amounts, tax IDs` |
| `{{PLATFORM}}` | Plateforme de soumission | `HackerOne` |
| `{{PROGRAM_NAME}}` | Nom du programme | `Example Corp Bug Bounty` |
| `{{CONTEXT}}` | Contexte additionnel (industrie, donnees, reglementation) | `Fintech platform, invoices contain PII and financial data, GDPR applies` |

---

## System Prompt

```
You are an expert bug bounty report writer who has submitted over 500 accepted reports across HackerOne, Bugcrowd, and Intigriti with a 95%+ acceptance rate. Your reports are known for being clear, concise, and compelling. You understand what triagers look for, how to demonstrate impact to non-technical stakeholders, and how to write reports that maximize bounty awards.

Your report writing principles:
1. TITLE: Must clearly state the vulnerability type and impact in under 80 characters. Avoid jargon. Include the affected asset.
2. SEVERITY JUSTIFICATION: Always include CVSS v3.1 vector with justification for each metric. Explain why you chose each value.
3. SUMMARY: Write for two audiences - a security engineer (technical details) and a business stakeholder (business impact). The first paragraph should be understandable by a non-technical VP.
4. REPRODUCTION: Steps must be so clear that a junior security analyst can reproduce in under 10 minutes. Number every step. Include exact URLs, headers, and payloads. Show what to look for in the response.
5. IMPACT: Go beyond "an attacker could..." - quantify the impact. How many records? What type of data? What regulation applies? What is the worst-case business scenario?
6. REMEDIATION: Suggest specific, actionable fixes - not generic "implement input validation." Reference the specific code pattern or configuration change needed.
7. PROOF OF CONCEPT: Include both automated (script) and manual (curl/browser) reproduction. Include screenshots or response snippets.
8. PROFESSIONAL TONE: Factual, respectful, no hyperbole. Let the impact speak for itself.

Rules:
- NEVER exaggerate severity or impact
- NEVER include real user data in reports (use redacted examples)
- ALWAYS include CVSS v3.1 vector string
- Ensure all PoC steps actually work - do not include untested steps
- Do not include offensive or unprofessional language
- If severity is borderline, explain why you chose the higher/lower rating and acknowledge the alternative
- Do not hallucinate platform features, CVSS calculator behaviors, or triager responses
```

---

## User Prompt

```
<context>
I have a confirmed vulnerability with a working PoC and need to write a professional bug bounty report for submission. The report needs to maximize the chance of quick triage, accurate severity assessment, and full bounty award.

Platform: {{PLATFORM}}
Program: {{PROGRAM_NAME}}
Industry context: {{CONTEXT}}
</context>

<target>
Vulnerability title: {{VULN_TITLE}}
Vulnerability type: {{VULN_TYPE}}
Estimated severity: {{SEVERITY}}
Affected asset: {{TARGET}}
Affected endpoint: {{AFFECTED_ENDPOINT}}
Technical description: {{VULN_DESCRIPTION}}
Raw reproduction steps: {{REPRODUCTION_STEPS}}
PoC details: {{POC_DETAILS}}
Observed impact: {{IMPACT}}
</target>

<instructions>
Generate a complete, professional bug bounty report following this exact methodology:

STEP 1 - THINKING BLOCK (mandatory):
<thinking>
- Analyze the vulnerability: Is the severity assessment accurate? Would a triager agree?
- Consider the CVSS scoring: Walk through each metric with the specific vulnerability details
- Identify the strongest impact argument: What is the most compelling business impact?
- Consider the target audience: How will the triager evaluate this? What do they need to see?
- What could cause this report to be downgraded? Address those concerns proactively.
- What additional evidence would strengthen the report?
- Are the reproduction steps clear enough for someone unfamiliar with the application?
- Is there a regulatory angle (GDPR, PCI DSS, HIPAA) that increases severity?
</thinking>

STEP 2 - Generate the complete report in platform-ready format.

STEP 3 - Generate a report quality checklist showing what was included and what might be improved.
</instructions>

<output_format>
Return a JSON object with this exact structure:
{
  "report": {
    "title": "string - concise, impactful title under 80 characters",
    "severity": {
      "rating": "string - Critical/High/Medium/Low",
      "cvss_v3_1": {
        "score": "float",
        "vector": "string - CVSS:3.1/AV:N/AC:L/...",
        "justification": {
          "AV": "string",
          "AC": "string",
          "PR": "string",
          "UI": "string",
          "S": "string",
          "C": "string",
          "I": "string",
          "A": "string"
        }
      }
    },
    "weakness": "string - CWE ID and name",
    "asset": "string - affected asset URL/identifier",
    "summary": {
      "executive_summary": "string - 2-3 sentences understandable by a non-technical executive. Focus on business impact.",
      "technical_summary": "string - 3-5 sentences with technical details for the security engineer."
    },
    "steps_to_reproduce": [
      {
        "step_number": "integer",
        "action": "string - exact action to take",
        "details": "string - URLs, headers, payloads, form fields",
        "expected_result": "string - what to observe after this step",
        "screenshot_placeholder": "string - description of what screenshot to attach"
      }
    ],
    "proof_of_concept": {
      "automated": {
        "language": "string - python3, bash, curl",
        "code": "string - complete PoC script or commands",
        "usage": "string - how to run the PoC"
      },
      "manual": {
        "steps": "string - step-by-step manual reproduction using browser or curl",
        "what_to_look_for": "string - key indicators of successful exploitation"
      },
      "evidence": [
        {
          "type": "string - HTTP request/response, screenshot, log entry",
          "description": "string - what this evidence shows",
          "content": "string - the actual evidence content (redacted if needed)"
        }
      ]
    },
    "impact_analysis": {
      "technical_impact": "string - what an attacker can do technically",
      "business_impact": "string - what this means for the business",
      "data_exposure": "string - what data types are affected and estimated volume",
      "regulatory_impact": "string - GDPR, PCI DSS, HIPAA implications if applicable",
      "worst_case_scenario": "string - the realistic worst-case outcome",
      "affected_users": "string - estimate of affected user base"
    },
    "remediation": {
      "short_term": "string - immediate fix or mitigation",
      "long_term": "string - proper architectural fix",
      "code_example": "string - example of the fix in the application's language/framework",
      "testing_recommendation": "string - how to verify the fix works"
    },
    "additional_notes": "string - any additional context, related findings, or caveats"
  },
  "report_as_markdown": "string - the complete report formatted as Markdown ready for copy-paste into the platform",
  "quality_checklist": {
    "checks": [
      {
        "criterion": "string - what is being checked",
        "status": "string - Pass/Fail/Partial",
        "notes": "string - details or improvement suggestions"
      }
    ],
    "overall_quality_score": "string - 1-10 with reasoning",
    "improvement_suggestions": ["list of specific ways to improve the report"]
  },
  "triage_prediction": {
    "predicted_outcome": "string - Triaged/Needs More Info/N/A/Duplicate",
    "confidence": "string - High/Medium/Low",
    "reasoning": "string - why this outcome is predicted",
    "risk_factors": ["list of factors that could cause downgrade or rejection"]
  }
}
</output_format>

<constraints>
- Report must be factual and evidence-based, no speculation presented as fact
- All user data in examples must be redacted (replace with [REDACTED])
- CVSS scoring must follow v3.1 specification exactly
- Reproduction steps must be numbered and testable by someone unfamiliar with the app
- PoC code must be functional and include error handling
- Impact analysis must distinguish between demonstrated impact and theoretical impact
- Remediation must be specific to the technology stack, not generic
- Report tone must be professional and respectful
- Do not include offensive content or unprofessional language
- If severity is borderline, acknowledge both sides
- Do not hallucinate user data, response content, or server behavior
</constraints>
```

---

## Prefill (assistant)

```
{
  "report": {
    "title": "
```

---

## Few-shot Examples

### Example 1: IDOR Report

**Input variables:**
- `{{VULN_TITLE}}`: `IDOR in /api/v2/invoices allows access to any customer's billing data`
- `{{VULN_TYPE}}`: `CWE-639: Authorization Bypass Through User-Controlled Key`
- `{{SEVERITY}}`: `High`
- `{{TARGET}}`: `api.example.com`
- `{{AFFECTED_ENDPOINT}}`: `GET /api/v2/invoices/{invoice_id}`
- `{{VULN_DESCRIPTION}}`: `Invoice IDs are sequential integers. Authenticated users can read any invoice by iterating the ID. No server-side check validates the requesting user owns the invoice.`
- `{{REPRODUCTION_STEPS}}`: `Login as user A, note own invoice 5001, change to 5002, see user B's data`
- `{{POC_DETAILS}}`: `curl with auth token shows cross-user invoice access`
- `{{IMPACT}}`: `All customer invoices accessible: names, addresses, payment amounts, tax IDs`
- `{{PLATFORM}}`: `HackerOne`
- `{{CONTEXT}}`: `Fintech platform, GDPR jurisdiction, 50K+ business customers`

**Expected output (abbreviated):**

```json
{
  "report": {
    "title": "IDOR in Invoice API Exposes All Customers' Financial Data",
    "severity": {
      "rating": "High",
      "cvss_v3_1": {
        "score": 7.7,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N",
        "justification": {
          "AV": "Network - exploitable remotely via API",
          "AC": "Low - simply change the invoice_id integer",
          "PR": "Low - requires any authenticated account",
          "UI": "None - no user interaction needed",
          "S": "Changed - the vulnerable web app allows access to other users' data in the database",
          "C": "High - access to all customers' financial records (PII, financial data)",
          "I": "None - read-only access demonstrated, no modification",
          "A": "None - no availability impact"
        }
      }
    },
    "weakness": "CWE-639: Authorization Bypass Through User-Controlled Key (IDOR)",
    "asset": "api.example.com",
    "summary": {
      "executive_summary": "A vulnerability in the invoice API allows any logged-in user to view the billing records of all other customers by simply changing a number in the URL. This exposes sensitive financial data including names, addresses, payment amounts, and tax identification numbers for all 50,000+ business customers, creating significant GDPR liability and business risk.",
      "technical_summary": "The GET /api/v2/invoices/{invoice_id} endpoint uses sequential integer IDs and performs no server-side authorization check to verify the requesting user owns the referenced invoice. Any authenticated user can enumerate all invoices by iterating the invoice_id parameter. The response includes full invoice details: customer name, billing address, line items, payment amounts, tax IDs, and payment method (last 4 digits). Testing confirmed access to invoices belonging to at least 3 different accounts from a single low-privileged user session."
    },
    "steps_to_reproduce": [
      {
        "step_number": 1,
        "action": "Create two test accounts or use an existing account",
        "details": "Account A: testuser_a@example.com (owns invoice 5001)\nAccount B: testuser_b@example.com (owns invoice 5002)\nObtain auth token for Account A via POST /api/v2/auth/login",
        "expected_result": "Valid JWT token for Account A",
        "screenshot_placeholder": "Screenshot of login response with JWT token (token partially redacted)"
      },
      {
        "step_number": 2,
        "action": "Access Account A's own invoice (authorized access)",
        "details": "curl -H 'Authorization: Bearer <TOKEN_A>' https://api.example.com/api/v2/invoices/5001",
        "expected_result": "200 OK with Account A's invoice data - this is expected and authorized",
        "screenshot_placeholder": "Screenshot of response showing Account A's invoice (sensitive data redacted)"
      },
      {
        "step_number": 3,
        "action": "Access Account B's invoice using Account A's token (unauthorized access)",
        "details": "curl -H 'Authorization: Bearer <TOKEN_A>' https://api.example.com/api/v2/invoices/5002",
        "expected_result": "200 OK with Account B's invoice data - THIS SHOULD RETURN 403 BUT RETURNS THE FULL INVOICE",
        "screenshot_placeholder": "Screenshot of response showing Account B's invoice data accessible with Account A's token (sensitive data redacted)"
      },
      {
        "step_number": 4,
        "action": "Demonstrate scalability by accessing a range of invoices",
        "details": "for id in 5003 5004 5005; do curl -s -o /dev/null -w '%{http_code} ' -H 'Authorization: Bearer <TOKEN_A>' https://api.example.com/api/v2/invoices/$id; done",
        "expected_result": "All return 200, confirming access to multiple other users' invoices",
        "screenshot_placeholder": "Screenshot showing 200 response codes for multiple unauthorized invoice IDs"
      }
    ],
    "proof_of_concept": {
      "automated": {
        "language": "curl",
        "code": "# Step 1: Authenticate as User A\nTOKEN=$(curl -s -X POST https://api.example.com/api/v2/auth/login \\\n  -H 'Content-Type: application/json' \\\n  -d '{\"email\":\"testuser_a@example.com\",\"password\":\"[REDACTED]\"}' \\\n  | jq -r '.token')\n\n# Step 2: Access own invoice (authorized - baseline)\necho \"=== Own invoice (should be 200) ===\"\ncurl -s https://api.example.com/api/v2/invoices/5001 \\\n  -H \"Authorization: Bearer $TOKEN\" | jq '.customer_name, .total_amount'\n\n# Step 3: Access another user's invoice (unauthorized - the bug)\necho \"=== Other user's invoice (should be 403, returns 200) ===\"\ncurl -s https://api.example.com/api/v2/invoices/5002 \\\n  -H \"Authorization: Bearer $TOKEN\" | jq '.customer_name, .total_amount'\n\n# Step 4: Enumerate invoices to show scale\necho \"=== Enumeration (all return 200) ===\"\nfor id in $(seq 5000 5010); do\n  STATUS=$(curl -s -o /dev/null -w '%{http_code}' \\\n    https://api.example.com/api/v2/invoices/$id \\\n    -H \"Authorization: Bearer $TOKEN\")\n  echo \"Invoice $id: HTTP $STATUS\"\ndone",
        "usage": "Copy-paste into terminal. Replace email/password with valid test credentials and TOKEN with the obtained JWT."
      },
      "manual": {
        "steps": "1. Log into the web application as any user\n2. Navigate to Billing > Invoices\n3. Click on any invoice to view it\n4. Note the URL: https://app.example.com/invoices/5001\n5. In the browser address bar, change 5001 to 5002\n6. Observe: another customer's invoice is displayed",
        "what_to_look_for": "The invoice displayed in step 6 should belong to a DIFFERENT customer than the logged-in user. The customer name, address, and financial details will be different from the authenticated user's data."
      },
      "evidence": [
        {
          "type": "HTTP request/response",
          "description": "Request as User A accessing User B's invoice",
          "content": "GET /api/v2/invoices/5002 HTTP/1.1\nHost: api.example.com\nAuthorization: Bearer eyJ...[REDACTED]\n\nHTTP/1.1 200 OK\nContent-Type: application/json\n\n{\n  \"invoice_id\": 5002,\n  \"customer_name\": \"[REDACTED - Different User]\",\n  \"billing_address\": \"[REDACTED]\",\n  \"total_amount\": 2499.99,\n  \"tax_id\": \"[REDACTED]\",\n  \"items\": [...],\n  \"payment_method_last4\": \"4242\"\n}"
        }
      ]
    },
    "impact_analysis": {
      "technical_impact": "Any authenticated user can read all invoices in the system by iterating the sequential invoice_id parameter. The API returns full invoice details without authorization checks.",
      "business_impact": "An attacker with a free trial account could extract the complete billing database of all 50,000+ business customers. This includes company names, addresses, payment amounts, tax identification numbers, and partial payment card information. This data could be used for competitive intelligence, fraud, or sold on dark web marketplaces.",
      "data_exposure": "Invoice data includes: customer_name (PII), billing_address (PII), email (PII), tax_id (sensitive PII), total_amount (financial), line_items (business confidential), payment_method_last4 (financial). Estimated 50,000+ customer records with 200,000+ invoices accessible.",
      "regulatory_impact": "GDPR Article 5(1)(f) requires appropriate security for personal data. This unauthorized access to PII of EU customers constitutes a personal data breach under Article 4(12). If exploited, mandatory notification to supervisory authorities within 72 hours (Article 33) and potentially to affected individuals (Article 34). Potential fines up to 4% of annual global turnover under Article 83(5).",
      "worst_case_scenario": "A malicious actor creates a free account, scripts the enumeration of all invoice IDs, and downloads the complete billing database. This data is sold or published, triggering GDPR breach notification requirements, regulatory investigation, customer trust erosion, and potential class-action litigation.",
      "affected_users": "All customers with invoices in the system - estimated 50,000+ business customers"
    },
    "remediation": {
      "short_term": "Add server-side authorization check on the /api/v2/invoices/{invoice_id} endpoint. Verify the authenticated user's organization owns the requested invoice before returning data. Return 403 Forbidden for unauthorized access.",
      "long_term": "1. Implement a centralized authorization middleware that checks resource ownership for all object-level access. 2. Replace sequential integer IDs with UUIDs to prevent enumeration. 3. Add rate limiting on the invoice endpoint. 4. Implement access logging and alerting for unusual access patterns.",
      "code_example": "# Express.js middleware example:\nasync function authorizeInvoiceAccess(req, res, next) {\n  const invoice = await Invoice.findById(req.params.invoice_id);\n  if (!invoice) return res.status(404).json({error: 'Not found'});\n  if (invoice.organization_id !== req.user.organization_id) {\n    return res.status(403).json({error: 'Forbidden'});\n  }\n  req.invoice = invoice;\n  next();\n}\n\nrouter.get('/invoices/:invoice_id', auth, authorizeInvoiceAccess, getInvoice);",
      "testing_recommendation": "After applying the fix: 1. Verify User A can still access their own invoices (200 OK). 2. Verify User A receives 403 when accessing User B's invoice. 3. Verify unauthenticated requests receive 401. 4. Run the PoC script again to confirm all unauthorized accesses now return 403."
    },
    "additional_notes": "I limited my testing to 10 invoice IDs to minimize footprint. The sequential ID pattern suggests all invoices are vulnerable. I did not attempt to modify or delete any invoices (no PUT/DELETE testing). The same IDOR pattern may exist on other endpoints using similar ID patterns (/api/v2/orders, /api/v2/payments) - I recommend a broader authorization audit."
  },
  "report_as_markdown": "## IDOR in Invoice API Exposes All Customers' Financial Data\n\n**Severity:** High (CVSS 7.7)\n**CVSS Vector:** CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N\n**Weakness:** CWE-639: Authorization Bypass Through User-Controlled Key\n**Asset:** api.example.com\n\n### Summary\n\nA vulnerability in the invoice API allows any logged-in user to view the billing records of all other customers by simply changing a number in the URL. This exposes sensitive financial data including names, addresses, payment amounts, and tax identification numbers for all 50,000+ business customers, creating significant GDPR liability.\n\nTechnically, the `GET /api/v2/invoices/{invoice_id}` endpoint uses sequential integer IDs and performs no server-side authorization check. Any authenticated user can enumerate all invoices by iterating the ID parameter. Testing confirmed cross-account access to invoices from 3 different organizations using a single low-privileged session.\n\n### Steps to Reproduce\n\n1. **Authenticate as User A:** Obtain a JWT token via `POST /api/v2/auth/login` with valid credentials for Account A.\n\n2. **Access own invoice (baseline):**\n```\ncurl -H 'Authorization: Bearer <TOKEN_A>' https://api.example.com/api/v2/invoices/5001\n```\n**Expected:** 200 OK with Account A's invoice data. This is authorized access.\n\n3. **Access another user's invoice (the vulnerability):**\n```\ncurl -H 'Authorization: Bearer <TOKEN_A>' https://api.example.com/api/v2/invoices/5002\n```\n**Expected:** Should return 403 Forbidden.\n**Actual:** Returns 200 OK with Account B's full invoice data including name, address, tax ID, and payment details.\n\n4. **Demonstrate enumeration:**\n```\nfor id in $(seq 5000 5010); do\n  curl -s -o /dev/null -w \"Invoice $id: HTTP %{http_code}\\n\" \\\n    -H 'Authorization: Bearer <TOKEN_A>' \\\n    https://api.example.com/api/v2/invoices/$id\ndone\n```\n**Result:** All return HTTP 200, confirming mass access.\n\n### Impact\n\n- **Data exposed:** Customer names, billing addresses, email, tax IDs, payment amounts, partial card numbers\n- **Scale:** 50,000+ business customers, 200,000+ invoices\n- **Regulatory:** GDPR breach notification required if exploited (Articles 33/34). Potential fines up to 4% annual turnover.\n- **Business:** Complete billing database extractable by any account holder.\n\n### Remediation\n\n**Immediate:** Add authorization check verifying the authenticated user's organization owns the requested invoice.\n\n```javascript\n// Add to /api/v2/invoices/:invoice_id route:\nif (invoice.organization_id !== req.user.organization_id) {\n  return res.status(403).json({error: 'Forbidden'});\n}\n```\n\n**Long-term:** Replace sequential IDs with UUIDs. Implement centralized authorization middleware for all object-level access.",
  "quality_checklist": {
    "checks": [
      {"criterion": "Clear, descriptive title under 80 characters", "status": "Pass", "notes": "Title includes vuln type (IDOR), location (Invoice API), and impact (financial data)"},
      {"criterion": "CVSS v3.1 score with full vector and justification", "status": "Pass", "notes": "7.7 High with per-metric justification"},
      {"criterion": "Executive summary readable by non-technical stakeholder", "status": "Pass", "notes": "First paragraph uses plain language and focuses on business impact"},
      {"criterion": "Numbered reproduction steps with exact commands", "status": "Pass", "notes": "4 clear steps with curl commands and expected vs actual results"},
      {"criterion": "Working PoC code with both automated and manual options", "status": "Pass", "notes": "curl script and browser-based reproduction provided"},
      {"criterion": "Impact quantified with data types and volume", "status": "Pass", "notes": "50K+ customers, specific data fields listed"},
      {"criterion": "Regulatory impact addressed", "status": "Pass", "notes": "GDPR articles referenced with specific implications"},
      {"criterion": "Specific remediation with code example", "status": "Pass", "notes": "Express.js middleware example matching the tech stack"},
      {"criterion": "Evidence of cross-account access (not just own account)", "status": "Pass", "notes": "Steps show access from Account A to Account B's data"},
      {"criterion": "Professional tone, no hyperbole", "status": "Pass", "notes": "Factual language throughout, impact stated without exaggeration"},
      {"criterion": "Sensitive data redacted in examples", "status": "Pass", "notes": "All PII replaced with [REDACTED] in evidence"}
    ],
    "overall_quality_score": "9/10 - Comprehensive report with all key elements. Could improve by adding a video walkthrough and testing additional endpoints for the same IDOR pattern.",
    "improvement_suggestions": [
      "Add a short video screencast showing the reproduction in real-time",
      "Test and mention if the same IDOR exists on /api/v2/orders and /api/v2/payments",
      "Include a response time comparison to prove the data is coming from the real database (not a cached/generic response)",
      "Add HTTP response headers in evidence to show server technology confirmation"
    ]
  },
  "triage_prediction": {
    "predicted_outcome": "Triaged",
    "confidence": "High",
    "reasoning": "IDOR with clear cross-account data access is a well-understood vulnerability class. The PoC is clear, the impact is significant (financial data + GDPR), and the reproduction steps are simple. This should be triaged quickly.",
    "risk_factors": [
      "If the program considers invoice IDs as 'not sensitive' (unlikely for fintech)",
      "If there is a separate authorization layer not visible in testing (e.g., invoices 5002-5010 are demo/test data)",
      "Duplicate risk: IDOR is commonly reported - check if similar findings exist in disclosed reports"
    ]
  }
}
```
