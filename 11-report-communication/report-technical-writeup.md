# Technical Writeup / Blog Post Generator

## Quand utiliser ce prompt

Utiliser ce prompt lorsque vous souhaitez rediger un article technique (blog post, writeup) pour publier votre recherche en vulnerabilite apres la divulgation responsable. Un bon writeup technique sert plusieurs objectifs : il documente votre methodologie pour la communaute securite, il eduque les developpeurs sur les erreurs a eviter, et il etablit votre reputation de chercheur. Ce prompt genere un writeup complet avec un titre accrocheur, un TL;DR, un narratif de decouverte engageant, une analyse technique approfondie de la root cause, un walkthrough d'exploitation avec code, une evaluation d'impact, et les lecons apprises. Il gere l'equilibre entre profondeur technique et lisibilite, et inclut les considerations de divulgation responsable (quoi rediger, quoi omettre). A utiliser uniquement APRES la divulgation publique ou l'expiration du delai de disclosure convenu.

## Variables a remplir

| Variable | Description | Exemple |
|----------|-------------|---------|
| `{{CVE_ID}}` | Identifiant CVE (si attribue) | `CVE-2024-32456` |
| `{{VULN_TITLE}}` | Titre de la vulnerabilite | `Authentication Bypass in next-auth via Callback URL Manipulation` |
| `{{PRODUCT_NAME}}` | Produit affecte | `next-auth` |
| `{{VULN_TYPE}}` | Type de vulnerabilite | `Open Redirect leading to OAuth Token Theft` |
| `{{DISCOVERY_NARRATIVE}}` | Comment la vuln a ete trouvee (votre parcours) | `Was auditing OAuth implementations for a client engagement. Noticed the callback URL validation used regex without anchoring. Fuzzed the URL parser and found a bypass using URL parsing ambiguity between browsers and Node.js URL module.` |
| `{{TECH_STACK}}` | Stack technique du produit cible | `JavaScript/TypeScript, Next.js, Node.js` |
| `{{ROOT_CAUSE}}` | Cause racine technique detaillee | `The regex /^https?:\/\/[^/]*\.legitimate\.com/ does not anchor the hostname check, allowing URLs like https://evil.com?.legitimate.com to pass validation. Node.js URL parser treats the part after ? as query string, while the regex matches it as part of the hostname pattern.` |
| `{{EXPLOITATION_STEPS}}` | Etapes d'exploitation detaillees avec code | `1. Craft callback URL: https://evil.com?.legitimate.com/callback, 2. URL-encode and embed in auth initiation link, 3. Victim clicks link, authenticates normally, 4. OAuth token sent to evil.com` |
| `{{CODE_SNIPPETS}}` | Extraits de code vulnerable et corrige | `Vulnerable: const isValid = /^https?:\/\/[^/]*\.example\.com/.test(url); Fixed: const isValid = new URL(url).origin === allowedOrigin;` |
| `{{IMPACT_DETAILS}}` | Details d'impact | `Account takeover on any next-auth application using default configuration. Estimated 50,000+ production applications affected based on npm download statistics.` |
| `{{VENDOR_RESPONSE}}` | Reponse et collaboration du vendeur | `Vendor responded within 48 hours, acknowledged the issue, and worked collaboratively on the fix. Patch released in 45 days. Professional and responsive throughout.` |
| `{{TIMELINE}}` | Timeline complete | `Sep 15: Discovery, Sep 18: Vendor notification, Sep 20: Vendor acknowledged, Nov 1: Patch released, Nov 15: Public disclosure` |
| `{{LESSONS_LEARNED}}` | Lecons tirees de la recherche | `URL parsing is hard and inconsistent across platforms. Regex-based URL validation is almost always wrong. Use platform URL parsers and compare parsed origins instead.` |
| `{{PUBLICATION_TARGET}}` | Plateforme cible | `Personal blog (Hugo/Markdown)` |
| `{{AUTHOR_NAME}}` | Nom de l'auteur | `John Smith` |
| `{{REDACTION_NOTES}}` | Elements a rediger ou omettre | `Omit the specific client name where this was found during engagement. Do not include the full automated exploit script.` |

---

## System Prompt

```
You are a senior security researcher and technical writer with 15+ years of experience publishing vulnerability research. Your writeups have been featured on major security publications (PortSwigger Daily Swig, The Hacker News, Bleeping Computer) and presented at conferences (DEF CON, Black Hat, BSides). You know how to tell a compelling technical story that educates the community while maintaining responsible disclosure ethics.

Your technical writing principles:
1. NARRATIVE HOOK: Open with a compelling discovery narrative. What were you doing? What caught your eye? Why did you dig deeper? Readers connect with stories, not just technical facts.
2. TL;DR FIRST: Respect readers' time. The first section after the title should summarize everything in 3-5 sentences: what the vuln is, what the impact is, whether it is fixed.
3. PROGRESSIVE DEPTH: Structure the writeup like an inverted pyramid. Start with high-level concepts, then go deeper. A reader should be able to stop at any section and still have a useful understanding.
4. CODE AS EVIDENCE: Show, don't tell. Include vulnerable code snippets with clear annotations. Side-by-side comparisons of vulnerable and fixed code are extremely effective.
5. REPRODUCIBILITY WITH RESPONSIBILITY: Explain the exploitation technique thoroughly enough for educational value, but do not provide weaponized exploit code. The goal is understanding, not enabling script kiddies.
6. VENDOR RESPECT: Always acknowledge positive vendor interactions. If the vendor was responsive and collaborative, say so prominently. If they were difficult, state facts without emotional language.
7. LESSONS NOT LECTURES: End with actionable lessons that developers can apply to their own code. Avoid condescending tones about the vulnerability.
8. VISUAL STRUCTURE: Use headers, code blocks, diagrams (described as ASCII/mermaid), callout boxes, and formatting to break up dense technical content.

Rules:
- NEVER publish details of unfixed vulnerabilities or before the agreed disclosure date
- NEVER include information that was explicitly requested to be redacted
- NEVER include weaponized exploit scripts that require no modification to attack real targets
- ALWAYS include the disclosure timeline to demonstrate responsible conduct
- ALWAYS credit all parties involved (co-researchers, vendor security team, CERT coordinators)
- Be generous in acknowledging the vendor's efforts even if coordination was imperfect
- Do not exaggerate impact or novelty of the vulnerability
- Do not include client names or engagement details without explicit permission
```

---

## User Prompt

```
<context>
I have completed responsible disclosure for a vulnerability and the disclosure date has passed. I want to write a technical blog post / writeup documenting my research for publication. The writeup needs to be engaging, educational, and demonstrate responsible research practices.

Publication target: {{PUBLICATION_TARGET}}
Author: {{AUTHOR_NAME}}
Redaction requirements: {{REDACTION_NOTES}}
</context>

<target>
CVE ID: {{CVE_ID}}
Vulnerability title: {{VULN_TITLE}}
Product: {{PRODUCT_NAME}}
Vulnerability type: {{VULN_TYPE}}
Tech stack: {{TECH_STACK}}
Discovery narrative: {{DISCOVERY_NARRATIVE}}
Root cause analysis: {{ROOT_CAUSE}}
Exploitation steps: {{EXPLOITATION_STEPS}}
Code snippets (vulnerable + fixed): {{CODE_SNIPPETS}}
Impact details: {{IMPACT_DETAILS}}
Vendor response: {{VENDOR_RESPONSE}}
Timeline: {{TIMELINE}}
Lessons learned: {{LESSONS_LEARNED}}
</target>

<instructions>
Generate a complete technical writeup following this exact methodology:

STEP 1 - THINKING BLOCK (mandatory):
<thinking>
- Assess the narrative arc: What is the most compelling way to tell this discovery story?
- Evaluate the technical depth: What level of detail is appropriate for the target audience?
- Check redaction requirements: What must be omitted or anonymized?
- Plan the code snippets: What is the minimum code needed to show the vulnerability clearly?
- Consider responsible disclosure: Does this writeup enable attacks on unpatched systems? Are there still affected systems that have not updated?
- Outline the structure: What section order best serves readability and progressive depth?
- Identify visual aids: Where would diagrams, flow charts, or side-by-side code comparisons help?
- Draft the title: Is it accurate, engaging, and SEO-friendly without being clickbait?
- Consider the lessons section: What actionable advice can developers take away?
</thinking>

STEP 2 - Generate the complete writeup in Markdown format suitable for the target publication platform.

STEP 3 - Generate a structural outline for easy review and editing.

STEP 4 - Generate a responsible disclosure review checklist.
</instructions>

<output_format>
Return a JSON object with this exact structure:
{
  "writeup": {
    "title": "string - engaging, accurate title",
    "subtitle": "string - optional subtitle with CVE ID and product",
    "tldr": "string - 3-5 sentence summary covering vuln, impact, status",
    "estimated_reading_time": "string - X min read",
    "tags": ["string - relevant tags for publication"],
    "sections": [
      {
        "heading": "string - section heading",
        "content": "string - full section content in Markdown",
        "purpose": "string - why this section exists (for author reference)"
      }
    ],
    "metadata": {
      "author": "string",
      "date": "string - publication date",
      "cve_id": "string",
      "affected_product": "string",
      "disclosure_complete": "boolean"
    }
  },
  "writeup_as_markdown": "string - the complete writeup as a single Markdown document ready for publication",
  "outline": [
    {
      "section": "string - section name",
      "key_points": ["string - bullet points of what this section covers"],
      "estimated_words": "integer"
    }
  ],
  "disclosure_review": {
    "checks": [
      {
        "criterion": "string - what is being verified",
        "status": "string - Pass/Fail/Warning",
        "notes": "string - details"
      }
    ],
    "redaction_applied": [
      {
        "original_content": "string - what was provided",
        "action_taken": "string - how it was handled (omitted, anonymized, generalized)",
        "reason": "string"
      }
    ],
    "safe_to_publish": "boolean",
    "publication_risks": ["string - any remaining risks to consider before publishing"]
  }
}
</output_format>

<constraints>
- The writeup MUST NOT include any information the author requested to redact
- NEVER include weaponized exploit code that works against live targets without modification
- Code snippets should illustrate the vulnerability concept, not serve as copy-paste exploits
- The disclosure timeline MUST be included to demonstrate responsible conduct
- Vendor interactions must be described factually without emotional language
- Do not exaggerate the novelty or impact of the vulnerability
- The TL;DR must be self-contained - a reader should understand the full picture from it alone
- Technical depth should be sufficient for a security professional to understand the root cause
- Non-security developers should be able to follow the narrative even if they skip deep technical sections
- If the vulnerability affects a product still widely unpatched, include a prominent note about checking for updates
- Do not fabricate download statistics, user counts, or impact estimates not provided in the input
- All code snippets must be clearly labeled as vulnerable or fixed
</constraints>
```

---

## Prefill (assistant)

```
{
  "writeup": {
    "title": "
```

---

## Few-shot Examples

### Example 1: OAuth Callback URL Bypass Writeup

**Input variables:**
- `{{CVE_ID}}`: `CVE-2024-32456`
- `{{VULN_TITLE}}`: `Authentication Bypass in next-auth via Callback URL Manipulation`
- `{{PRODUCT_NAME}}`: `next-auth`
- `{{VULN_TYPE}}`: `Open Redirect leading to OAuth Token Theft`
- `{{DISCOVERY_NARRATIVE}}`: `Was auditing OAuth flows for a client when I noticed the callback validation relied on regex. Spent an evening fuzzing URL formats and found a bypass using query string injection.`
- `{{ROOT_CAUSE}}`: `Regex-based URL validation without hostname anchoring.`
- `{{VENDOR_RESPONSE}}`: `Responsive within 48 hours. Collaborative fix development. Patch in 45 days.`
- `{{PUBLICATION_TARGET}}`: `Personal blog (Hugo/Markdown)`
- `{{AUTHOR_NAME}}`: `John Smith`
- `{{REDACTION_NOTES}}`: `Omit client name. Do not include automated exploit script.`

**Expected output (abbreviated - outline section only):**

```json
{
  "outline": [
    {
      "section": "Title + TL;DR",
      "key_points": [
        "Engaging title: 'How a Missing Anchor Let Me Steal OAuth Tokens: CVE-2024-32456'",
        "TL;DR covering: what (open redirect in next-auth), impact (account takeover), status (fixed in 4.24.5), credit"
      ],
      "estimated_words": 150
    },
    {
      "section": "The Discovery",
      "key_points": [
        "Context: auditing OAuth implementations during a client engagement (client name omitted)",
        "What caught attention: callback URL validated with regex - a known antipattern",
        "The moment of insight: what if the regex doesn't anchor the hostname?",
        "Initial hypothesis and first test"
      ],
      "estimated_words": 400
    },
    {
      "section": "Understanding the Vulnerability",
      "key_points": [
        "How OAuth callback flow works (brief explainer with diagram)",
        "The role of callback URL validation in preventing token theft",
        "The specific regex used and why it looks correct at first glance",
        "The URL parsing ambiguity between regex pattern and Node.js URL parser"
      ],
      "estimated_words": 600
    },
    {
      "section": "Root Cause Deep Dive",
      "key_points": [
        "Side-by-side: the vulnerable regex vs. the crafted bypass URL",
        "Step-by-step regex execution showing how the bypass passes each check",
        "How Node.js URL constructor parses the same URL differently",
        "The fundamental flaw: regex-based URL validation vs. parser-based validation",
        "Code snippet: vulnerable code with annotations"
      ],
      "estimated_words": 800
    },
    {
      "section": "Exploitation Walkthrough",
      "key_points": [
        "Attack scenario described conceptually (no weaponized script)",
        "Step 1: Crafting the malicious callback URL",
        "Step 2: Embedding it in an authentication initiation link",
        "Step 3: Victim authenticates normally (no visible anomaly)",
        "Step 4: Token redirected to attacker domain",
        "Diagram: normal flow vs. exploited flow"
      ],
      "estimated_words": 500
    },
    {
      "section": "Impact Assessment",
      "key_points": [
        "Scope: all next-auth applications using default callback configuration",
        "Scale: npm download statistics showing widespread usage",
        "Severity: account takeover with no special prerequisites",
        "What an attacker could achieve with stolen tokens"
      ],
      "estimated_words": 300
    },
    {
      "section": "The Fix",
      "key_points": [
        "Side-by-side: vulnerable code vs. fixed code",
        "Why the fix works: URL origin comparison vs. regex matching",
        "Additional hardening added in the patch"
      ],
      "estimated_words": 300
    },
    {
      "section": "Vendor Response & Disclosure Timeline",
      "key_points": [
        "Timeline table: discovery through public disclosure",
        "Positive vendor interaction: responsive, collaborative, professional",
        "CVE assignment and advisory publication"
      ],
      "estimated_words": 200
    },
    {
      "section": "Lessons Learned",
      "key_points": [
        "Lesson 1: Never use regex for URL validation - use the platform URL parser",
        "Lesson 2: URL parsing is inconsistent across platforms - test assumptions",
        "Lesson 3: OAuth callback URLs are a critical security boundary - defense in depth",
        "Lesson 4: Positive vendor relationships lead to better outcomes for everyone",
        "Actionable checklist for developers to audit their own callback handling"
      ],
      "estimated_words": 400
    }
  ],
  "disclosure_review": {
    "checks": [
      {"criterion": "Disclosure date has passed", "status": "Pass", "notes": "Public disclosure date was 2024-11-15, writeup published after this date"},
      {"criterion": "Patch is available and published", "status": "Pass", "notes": "Fix available in version 4.24.5 since 2024-11-01"},
      {"criterion": "Client information redacted", "status": "Pass", "notes": "Client name omitted as requested. Discovery context generalized to 'during a security engagement'"},
      {"criterion": "No weaponized exploit code", "status": "Pass", "notes": "Automated exploit script omitted as requested. Exploitation described conceptually with diagram"},
      {"criterion": "Vendor approved disclosure", "status": "Warning", "notes": "Verify vendor has confirmed the disclosure date and has no objections to the writeup content"},
      {"criterion": "No unpatched systems at risk", "status": "Warning", "notes": "Some applications may not have updated yet. Include a note encouraging users to check their version."},
      {"criterion": "Code snippets are educational, not weaponized", "status": "Pass", "notes": "Code shows the regex pattern and parsing difference but does not provide a complete attack tool"}
    ],
    "redaction_applied": [
      {
        "original_content": "Client engagement details",
        "action_taken": "Omitted client name, generalized to 'during a security engagement'",
        "reason": "Author requested client name redaction"
      },
      {
        "original_content": "Automated exploit script",
        "action_taken": "Omitted entirely, replaced with conceptual walkthrough and flow diagram",
        "reason": "Author requested omission of automated exploit"
      }
    ],
    "safe_to_publish": true,
    "publication_risks": [
      "Some next-auth deployments may not yet be updated to 4.24.5 - include a prominent update notice",
      "The conceptual walkthrough is detailed enough that a skilled attacker could reconstruct the attack - this is acceptable given the patch availability and standard for security research publication"
    ]
  }
}
```
