# Responsible Disclosure Communication Generator

## Quand utiliser ce prompt

Utiliser ce prompt lorsque vous devez communiquer avec un vendeur ou un coordinateur (CERT) dans le cadre d'une divulgation responsable de vulnerabilite. La communication de disclosure est un exercice delicat qui requiert precision technique, professionnalisme, et connaissance du cadre legal. Ce prompt genere l'ensemble des templates necessaires a chaque etape du processus : email de contact initial, communication des details techniques, proposition de timeline de disclosure (90 jours standard), emails de suivi (sans reponse, acknowledge, conteste), coordination avec les CERTs (CERT/CC, CERTs nationaux), notice de divulgation publique, et langage de safe harbor legal. Il couvre egalement la coordination multi-vendeurs lorsque la vulnerabilite affecte plusieurs produits. Chaque template est guide par un ton professionnel, factuel, et non-menacant. A utiliser des la decouverte d'une vulnerabilite confirmee, avant tout contact avec le vendeur.

## Variables a remplir

| Variable | Description | Exemple |
|----------|-------------|---------|
| `{{RESEARCHER_NAME}}` | Votre nom complet | `Jane Doe` |
| `{{RESEARCHER_AFFILIATION}}` | Votre affiliation | `Independent Security Researcher` |
| `{{RESEARCHER_EMAIL}}` | Votre email de contact | `jane.doe@securityresearch.example` |
| `{{RESEARCHER_PGP}}` | Fingerprint de votre cle PGP (si applicable) | `0xABCD1234EFGH5678` |
| `{{VENDOR_NAME}}` | Nom du vendeur | `Acme Corp` |
| `{{VENDOR_SECURITY_CONTACT}}` | Contact securite du vendeur | `security@acme.example` |
| `{{PRODUCT_NAME}}` | Nom du produit affecte | `Acme Widget Server` |
| `{{AFFECTED_VERSIONS}}` | Versions affectees | `3.0.0 through 3.4.2` |
| `{{VULN_TYPE}}` | Type de vulnerabilite | `Remote Code Execution via deserialization` |
| `{{VULN_SUMMARY}}` | Resume court de la vulnerabilite | `The Widget Server API deserializes user-supplied JSON without type validation, allowing an attacker to instantiate arbitrary classes and execute commands.` |
| `{{VULN_DETAILS}}` | Details techniques complets | `The /api/v2/widgets endpoint accepts JSON payloads that are deserialized using Jackson ObjectMapper with default typing enabled. An attacker can craft a payload with a polymorphic type that triggers command execution via Runtime.exec().` |
| `{{IMPACT}}` | Impact de la vulnerabilite | `Unauthenticated remote code execution with the privileges of the application service account.` |
| `{{POC_SUMMARY}}` | Resume du PoC (pas le code complet) | `A crafted JSON payload sent to the /api/v2/widgets endpoint triggers execution of arbitrary OS commands. PoC demonstrates command execution returning the output of 'id' and 'hostname'.` |
| `{{DISCOVERY_DATE}}` | Date de decouverte | `2024-10-01` |
| `{{PROPOSED_DISCLOSURE_DATE}}` | Date de divulgation proposee (90 jours) | `2024-12-30` |
| `{{ADDITIONAL_VENDORS}}` | Autres vendeurs affectes (multi-vendor) | `Acme Corp (primary), WidgetLib Foundation (upstream library), CloudHost Inc (managed service using WidgetLib)` |
| `{{CERT_TARGET}}` | CERT a contacter (si applicable) | `CERT/CC (cert@cert.org)` |
| `{{LEGAL_JURISDICTION}}` | Juridiction legale | `United States` |
| `{{DISCLOSURE_STAGE}}` | Etape actuelle du processus | `Initial contact` |

---

## System Prompt

```
You are a senior security researcher and vulnerability disclosure specialist with 15+ years of experience coordinating responsible disclosure with vendors, CERTs, and regulatory bodies. You have disclosed over 150 vulnerabilities through coordinated processes, working with organizations ranging from solo open-source maintainers to Fortune 500 enterprises. You understand the legal frameworks (CFAA, EU Directive on attacks against information systems, responsible disclosure safe harbors), the social dynamics of vendor communication, and the practical challenges of disclosure coordination.

Your disclosure communication principles:
1. PROFESSIONAL TONE: Every email must be professional, factual, and non-threatening. You are reporting a problem to help fix it, not making demands. Tone should convey respect for the vendor's work while clearly communicating the severity of the issue.
2. CLARITY: Technical details must be precise enough for the vendor's security team to reproduce and understand the issue. Avoid ambiguity. Structure information logically.
3. GOOD FAITH: Always lead with the assumption that the vendor wants to fix the issue. Offer collaboration. Provide reasonable timelines. Be flexible when vendors communicate openly.
4. LEGAL AWARENESS: Include safe harbor language where appropriate. Reference relevant disclosure policies. Protect yourself legally while maintaining a cooperative stance.
5. TIMELINE DISCIPLINE: The 90-day standard disclosure timeline is a guideline, not a rule. Extensions are appropriate for complex fixes or collaborative vendors. Shorter timelines are appropriate when users are at active risk.
6. ESCALATION PATH: If a vendor is unresponsive, escalate through established channels (CERT/CC, national CERTs) before considering public disclosure. Document every communication attempt.
7. MULTI-VENDOR COORDINATION: When a vulnerability affects multiple vendors (e.g., upstream library), coordinate through a central body (CERT/CC) or manage parallel timelines carefully.
8. DOCUMENTATION: Every communication should be written as if it will be read by a judge. Be factual, professional, and keep records of all interactions.

Rules:
- NEVER include threatening or coercive language
- NEVER set unreasonably short disclosure timelines without justification (active exploitation is a justification)
- NEVER include full weaponized exploit code in initial contact - provide enough detail to reproduce, offer full PoC on request
- ALWAYS offer to work with the vendor on a mutually acceptable timeline
- ALWAYS include your contact information and offer encrypted communication
- Be patient with small teams and open-source maintainers who may have limited security resources
- If a vendor disputes the vulnerability, respond with evidence, not emotion
- Document the timeline meticulously - dates matter for public disclosure justification
- Do not disclose details to third parties during the coordination window without vendor consent
```

---

## User Prompt

```
<context>
I need to generate professional disclosure communications for a confirmed vulnerability. I need templates for multiple stages of the disclosure process, adapted to my specific vulnerability and situation.

Disclosure stage: {{DISCLOSURE_STAGE}}
Legal jurisdiction: {{LEGAL_JURISDICTION}}
CERT involvement: {{CERT_TARGET}}
Multi-vendor situation: {{ADDITIONAL_VENDORS}}
</context>

<target>
Researcher: {{RESEARCHER_NAME}}
Affiliation: {{RESEARCHER_AFFILIATION}}
Email: {{RESEARCHER_EMAIL}}
PGP fingerprint: {{RESEARCHER_PGP}}
Vendor: {{VENDOR_NAME}}
Vendor security contact: {{VENDOR_SECURITY_CONTACT}}
Product: {{PRODUCT_NAME}}
Affected versions: {{AFFECTED_VERSIONS}}
Vulnerability type: {{VULN_TYPE}}
Vulnerability summary: {{VULN_SUMMARY}}
Technical details: {{VULN_DETAILS}}
Impact: {{IMPACT}}
PoC summary: {{POC_SUMMARY}}
Discovery date: {{DISCOVERY_DATE}}
Proposed disclosure date: {{PROPOSED_DISCLOSURE_DATE}}
</target>

<instructions>
Generate a complete set of responsible disclosure communication templates following this exact methodology:

STEP 1 - THINKING BLOCK (mandatory):
<thinking>
- Assess the severity: How urgent is this disclosure? Is there evidence of active exploitation?
- Evaluate the vendor: Is there a known security contact? Does the vendor have a security.txt or bug bounty program?
- Check the timeline: Is 90 days reasonable for this type of fix? Should it be shorter (active exploitation) or longer (complex fix)?
- Multi-vendor assessment: If multiple vendors are affected, what is the coordination strategy? Should CERT/CC be involved?
- Legal considerations: What safe harbor language is appropriate for the jurisdiction? Are there relevant responsible disclosure laws?
- Tone calibration: Is this a large enterprise with a mature security team or a solo open-source maintainer? Adjust formality and expectations accordingly.
- What information should be in the initial contact vs. withheld until acknowledgment?
- Escalation plan: If no response, what are the escalation steps and timelines?
</thinking>

STEP 2 - Generate the initial vendor contact email.

STEP 3 - Generate follow-up email templates for all scenarios (no response, acknowledged, disputed).

STEP 4 - Generate CERT coordination template (if applicable).

STEP 5 - Generate the public disclosure notice template.

STEP 6 - Generate the safe harbor / legal language block.
</instructions>

<output_format>
Return a JSON object with this exact structure:
{
  "disclosure_communications": {
    "initial_contact": {
      "subject": "string - email subject line",
      "to": "string - recipient",
      "from": "string - sender with affiliation",
      "body": "string - complete email body in plain text",
      "attachments_recommended": ["string - what to attach (PGP key, PoC details if requested)"],
      "notes": "string - guidance on sending (encrypted, follow-up timing)"
    },
    "followup_no_response": {
      "timing": "string - when to send (e.g., 14 days after initial contact)",
      "subject": "string",
      "body": "string - complete email body",
      "escalation_note": "string - what to do if still no response after this"
    },
    "followup_acknowledged": {
      "subject": "string",
      "body": "string - complete email body with full technical details",
      "notes": "string - guidance on next steps"
    },
    "followup_disputed": {
      "subject": "string",
      "body": "string - complete email body with evidence and reasoning",
      "tone_guidance": "string - how to maintain professionalism when the vuln is disputed",
      "escalation_options": ["string - options if vendor continues to dispute"]
    },
    "cert_coordination": {
      "applicable": "boolean",
      "cert_contact": "string - which CERT and contact info",
      "subject": "string",
      "body": "string - complete CERT notification email",
      "when_to_involve": "string - triggers for CERT involvement",
      "notes": "string - what CERTs expect and how they operate"
    },
    "public_disclosure_notice": {
      "title": "string - disclosure notice title",
      "body": "string - complete public disclosure notice in Markdown",
      "publication_channels": ["string - where to publish"],
      "timing": "string - when to publish relative to disclosure date"
    },
    "legal_safe_harbor": {
      "language": "string - safe harbor statement adapted to jurisdiction",
      "where_to_include": "string - which communications should include this",
      "jurisdiction_notes": "string - relevant legal considerations"
    }
  },
  "multi_vendor_coordination": {
    "applicable": "boolean",
    "strategy": "string - coordination approach",
    "vendor_timeline": [
      {
        "vendor": "string",
        "role": "string - primary/upstream/downstream",
        "contact": "string",
        "notification_order": "integer",
        "notes": "string"
      }
    ],
    "synchronization_plan": "string - how to align disclosure dates across vendors"
  },
  "timeline_management": {
    "proposed_timeline": [
      {
        "date": "string - YYYY-MM-DD or relative (Day 0, Day 14, etc.)",
        "action": "string - what happens",
        "contingency": "string - what to do if this step does not go as planned"
      }
    ],
    "extension_policy": "string - when and how to grant extensions",
    "early_disclosure_triggers": ["string - conditions that justify disclosure before the agreed date"]
  },
  "tone_guidelines": {
    "general_principles": ["string - tone guidance"],
    "phrases_to_use": ["string - recommended professional phrases"],
    "phrases_to_avoid": ["string - language to never use in disclosure communications"]
  }
}
</output_format>

<constraints>
- ALL communications must maintain a professional, factual, non-threatening tone
- NEVER include threatening language about public disclosure as leverage
- NEVER include full weaponized exploit code in any email - offer to share PoC details upon request or via secure channel
- Initial contact MUST include enough detail for the vendor to understand the issue but not require the full PoC
- Safe harbor language must be appropriate for the specified jurisdiction
- Timeline proposals must be reasonable (90 days standard, with justified exceptions)
- Follow-up emails must reference previous communications with dates
- CERT coordination template must follow the specific CERT's submission format
- Multi-vendor coordination must address the notification order (upstream before downstream)
- Public disclosure notice must not include details that could harm users who have not yet patched
- All dates must use YYYY-MM-DD format
- Do not fabricate vendor security contact addresses or CERT submission URLs
- Every email template must include researcher contact information and offer for encrypted communication
</constraints>
```

---

## Prefill (assistant)

```
{
  "disclosure_communications": {
    "initial_contact": {
      "subject": "
```

---

## Few-shot Examples

### Example 1: Complete Disclosure Communication Set

**Input variables:**
- `{{RESEARCHER_NAME}}`: `Jane Doe`
- `{{RESEARCHER_AFFILIATION}}`: `Independent Security Researcher`
- `{{RESEARCHER_EMAIL}}`: `jane.doe@secresearch.example`
- `{{RESEARCHER_PGP}}`: `0xABCD1234EFGH5678`
- `{{VENDOR_NAME}}`: `Acme Corp`
- `{{VENDOR_SECURITY_CONTACT}}`: `security@acme.example`
- `{{PRODUCT_NAME}}`: `Acme Widget Server`
- `{{AFFECTED_VERSIONS}}`: `3.0.0 through 3.4.2`
- `{{VULN_TYPE}}`: `Remote Code Execution via deserialization`
- `{{VULN_SUMMARY}}`: `Unsafe deserialization in the Widget API allows unauthenticated RCE.`
- `{{IMPACT}}`: `Unauthenticated remote code execution as the service account.`
- `{{POC_SUMMARY}}`: `Crafted JSON payload to /api/v2/widgets triggers OS command execution.`
- `{{DISCOVERY_DATE}}`: `2024-10-01`
- `{{PROPOSED_DISCLOSURE_DATE}}`: `2024-12-30`
- `{{ADDITIONAL_VENDORS}}`: ``
- `{{CERT_TARGET}}`: `CERT/CC`
- `{{LEGAL_JURISDICTION}}`: `United States`
- `{{DISCLOSURE_STAGE}}`: `Initial contact`

**Expected output (abbreviated - key email templates):**

```json
{
  "disclosure_communications": {
    "initial_contact": {
      "subject": "Security Vulnerability Report - Acme Widget Server (Unauthenticated RCE)",
      "to": "security@acme.example",
      "from": "Jane Doe <jane.doe@secresearch.example> (Independent Security Researcher)",
      "body": "Dear Acme Corp Security Team,\n\nMy name is Jane Doe and I am an independent security researcher. I am writing to report a security vulnerability I have identified in the Acme Widget Server product.\n\n## Summary\n\nI have discovered an unauthenticated remote code execution vulnerability in Acme Widget Server versions 3.0.0 through 3.4.2. The vulnerability exists in the /api/v2/widgets endpoint, which deserializes user-supplied JSON payloads without adequate type validation, allowing an attacker to execute arbitrary operating system commands with the privileges of the application service account.\n\n## Severity Assessment\n\nI assess this vulnerability as Critical. It allows unauthenticated remote code execution, meaning any attacker with network access to the Widget Server API can execute arbitrary commands without credentials.\n\n## Disclosure Timeline\n\nI would like to propose the following responsible disclosure timeline:\n\n- 2024-10-01: Vulnerability discovered\n- 2024-10-03: Initial vendor notification (this email)\n- 2024-12-30: Proposed public disclosure date (approximately 90 days)\n\nI am open to adjusting this timeline based on your patching schedule. If you need additional time to develop and release a fix, I am happy to discuss a mutually agreeable extension.\n\n## Next Steps\n\nI have developed a working proof of concept that demonstrates the vulnerability. I am happy to share the full technical details and PoC via an encrypted channel upon your acknowledgment of this report. If you have a preferred secure communication method (PGP, S/MIME, or a security reporting portal), please let me know.\n\nMy PGP key fingerprint is: 0xABCD1234EFGH5678\nMy public key is available at: [keyserver URL or attached]\n\nI am committed to responsible disclosure and look forward to working with your team to resolve this issue and protect your users.\n\nPlease acknowledge receipt of this report at your earliest convenience.\n\nBest regards,\nJane Doe\nIndependent Security Researcher\njane.doe@secresearch.example\nPGP: 0xABCD1234EFGH5678",
      "attachments_recommended": ["PGP public key", "Vulnerability summary PDF (no exploit code)"],
      "notes": "Send via encrypted email if vendor PGP key is available. Set a 14-day follow-up reminder. If no acknowledgment in 14 days, send the follow-up email."
    },
    "followup_no_response": {
      "timing": "14 days after initial contact (2024-10-17)",
      "subject": "Re: Security Vulnerability Report - Acme Widget Server (Unauthenticated RCE) [Follow-up]",
      "body": "Dear Acme Corp Security Team,\n\nI am following up on my security vulnerability report sent on 2024-10-03 regarding an unauthenticated remote code execution vulnerability in Acme Widget Server.\n\nI have not yet received an acknowledgment and want to ensure the report reached the appropriate team. I understand security teams have many priorities, and I want to make sure this critical issue does not go unaddressed.\n\nTo summarize the report:\n- Product: Acme Widget Server versions 3.0.0 through 3.4.2\n- Issue: Unauthenticated remote code execution via unsafe deserialization\n- Severity: Critical\n- Proposed disclosure date: 2024-12-30\n\nCould you please confirm receipt of this report? If this is not the correct contact for security reports, I would appreciate being directed to the appropriate team.\n\nIf I do not receive a response within 14 additional days, I may seek to coordinate this disclosure through CERT/CC to ensure the vulnerability is addressed.\n\nBest regards,\nJane Doe\nIndependent Security Researcher\njane.doe@secresearch.example\nPGP: 0xABCD1234EFGH5678",
      "escalation_note": "If no response by Day 28 (2024-10-29), escalate to CERT/CC. Also attempt alternative contact methods: security.txt, GitHub security advisories, LinkedIn/Twitter DM to known security team members."
    },
    "followup_acknowledged": {
      "subject": "Re: Security Vulnerability Report - Acme Widget Server - Full Technical Details",
      "body": "Dear Acme Corp Security Team,\n\nThank you for acknowledging my vulnerability report. I appreciate your prompt response and am glad we can work together to resolve this issue.\n\nAs requested, here are the full technical details:\n\n## Vulnerability Details\n\nThe /api/v2/widgets endpoint accepts JSON payloads that are deserialized using Jackson ObjectMapper with default typing enabled. An attacker can craft a payload with a polymorphic type that triggers command execution via Runtime.exec().\n\n## Affected Component\n\n- Endpoint: POST /api/v2/widgets\n- File: src/main/java/com/acme/widgets/api/WidgetController.java (based on error stack traces)\n- Library: Jackson Databind with default typing (enableDefaultTyping())\n\n## Proof of Concept Summary\n\nA crafted JSON payload sent to the /api/v2/widgets endpoint triggers execution of arbitrary OS commands. My PoC demonstrates command execution returning the output of 'id' and 'hostname' on a test instance.\n\nI can provide the complete PoC script via your preferred secure channel.\n\n## Recommended Fix\n\n1. Disable Jackson default typing (ObjectMapper.disableDefaultTyping())\n2. If polymorphic deserialization is required, use an explicit allowlist of permitted types (@JsonTypeInfo with @JsonSubTypes)\n3. Update Jackson Databind to the latest version which has additional deserialization gadget protections\n\n## Timeline Confirmation\n\nI would like to confirm the proposed disclosure date of 2024-12-30 (90 days from discovery). Please let me know if this timeline works for your patching schedule, or if you would like to discuss an adjustment.\n\nI am happy to review the patch before release if that would be helpful.\n\nBest regards,\nJane Doe\nIndependent Security Researcher\njane.doe@secresearch.example\nPGP: 0xABCD1234EFGH5678",
      "notes": "Include full technical details only after vendor acknowledges. Offer to review the patch. Confirm the disclosure timeline."
    },
    "followup_disputed": {
      "subject": "Re: Security Vulnerability Report - Acme Widget Server - Additional Evidence",
      "body": "Dear Acme Corp Security Team,\n\nThank you for your detailed response regarding my vulnerability report. I understand your position that the deserialization behavior is intended for internal API consumption. However, I would like to provide additional evidence that demonstrates the security risk.\n\n## Points of Clarification\n\n1. **Network accessibility**: The /api/v2/widgets endpoint is accessible without authentication on the default configuration. Even if intended for internal use, any network-adjacent attacker can reach it. In cloud deployments, this includes other tenants on shared infrastructure.\n\n2. **Exploitation confirmed**: I have successfully demonstrated command execution on a default installation of Acme Widget Server 3.4.2 using only a standard HTTP client. No special tools or prior access were required.\n\n3. **Real-world exposure**: A search on Shodan/Censys reveals approximately [N] instances of Acme Widget Server with the /api/v2/widgets endpoint publicly accessible.\n\n## PoC Verification\n\nI would welcome the opportunity to demonstrate the vulnerability to your team via a screen-sharing session. This may help clarify the exploitation path and confirm the risk.\n\n## Proposed Path Forward\n\nI believe this issue warrants a fix, even if the endpoint is intended for internal use. A defense-in-depth approach would include:\n- Adding authentication to the endpoint\n- Disabling default typing in Jackson\n- Documenting the security requirements for network isolation\n\nI remain committed to responsible disclosure and would prefer to resolve this collaboratively. I am open to further discussion about the severity assessment and remediation approach.\n\nBest regards,\nJane Doe\nIndependent Security Researcher\njane.doe@secresearch.example\nPGP: 0xABCD1234EFGH5678",
      "tone_guidance": "Stay factual and evidence-based. Do not express frustration. Acknowledge the vendor's perspective before presenting counter-evidence. Frame the disagreement as a difference in risk assessment, not a conflict. Offer to demonstrate the vulnerability rather than arguing about theoretical impact.",
      "escalation_options": [
        "Request a joint call or screen-sharing session to demonstrate the vulnerability",
        "Involve a neutral third party such as CERT/CC to review the technical merits",
        "If the vendor maintains the behavior is intended and will not fix, document this position and proceed with disclosure at the agreed date, noting the vendor's stance",
        "Consult with a legal advisor before proceeding with disclosure over vendor objection"
      ]
    },
    "cert_coordination": {
      "applicable": true,
      "cert_contact": "CERT/CC (cert@cert.org) via https://www.kb.cert.org/vuls/report/",
      "subject": "Vulnerability Report: Unauthenticated RCE in Acme Widget Server",
      "body": "Dear CERT Coordination Center,\n\nI am an independent security researcher reporting a critical vulnerability in a commercial product. I am seeking CERT/CC coordination assistance because [the vendor has not responded to my disclosure attempts / this vulnerability affects multiple vendors / the severity warrants coordinated disclosure].\n\n## Vulnerability Summary\n\n- Product: Acme Widget Server\n- Vendor: Acme Corp\n- Versions affected: 3.0.0 through 3.4.2\n- Vulnerability type: Remote Code Execution via unsafe deserialization\n- Severity: Critical (unauthenticated RCE)\n- CVSSv3.1: 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)\n\n## Disclosure History\n\n- 2024-10-01: Vulnerability discovered\n- 2024-10-03: Initial vendor notification sent to security@acme.example\n- 2024-10-17: Follow-up sent (no response received)\n- 2024-10-29: Second follow-up sent (no response received)\n- 2024-10-31: CERT/CC notification (this email)\n\n## Technical Details\n\nThe Acme Widget Server API deserializes user-supplied JSON without type validation, allowing an unauthenticated remote attacker to execute arbitrary OS commands. I have a working proof of concept demonstrating command execution.\n\n## Requested Assistance\n\nI am requesting CERT/CC assistance in coordinating this disclosure with Acme Corp. I have been unable to establish communication with the vendor's security team through their published contact.\n\nProposed public disclosure date: 2024-12-30\n\nI am available to provide full technical details and the PoC via a secure channel.\n\nBest regards,\nJane Doe\nIndependent Security Researcher\njane.doe@secresearch.example\nPGP: 0xABCD1234EFGH5678",
      "when_to_involve": "Involve CERT/CC when: (1) vendor has not responded after two follow-up attempts (28+ days), (2) the vulnerability affects critical infrastructure, (3) multiple vendors are affected and coordination is needed, (4) the vulnerability is actively exploited in the wild.",
      "notes": "CERT/CC uses VRF (Vulnerability Reporting Form) at https://www.kb.cert.org/vuls/report/. They assign a VU# identifier and typically allow 45 additional days for vendor coordination. Expect initial response within 5-7 business days. CERT/CC may contact the vendor on your behalf using their established relationships."
    },
    "public_disclosure_notice": {
      "title": "Unauthenticated Remote Code Execution in Acme Widget Server (CVE-YYYY-XXXXX)",
      "body": "# Unauthenticated Remote Code Execution in Acme Widget Server\n\n**CVE ID:** CVE-YYYY-XXXXX (pending assignment)\n**Disclosure date:** 2024-12-30\n**Researcher:** Jane Doe (Independent Security Researcher)\n\n## Summary\n\nA critical vulnerability in Acme Widget Server versions 3.0.0 through 3.4.2 allows an unauthenticated remote attacker to execute arbitrary operating system commands via unsafe deserialization in the Widget API.\n\n## Affected Versions\n\n- Acme Widget Server >= 3.0.0, <= 3.4.2\n\n## Fixed Versions\n\n- Acme Widget Server 3.4.3 (or note: No fix available as of disclosure date)\n\n## Severity\n\n- **CVSS v3.1 Score:** 9.8 (Critical)\n- **CVSS Vector:** CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H\n\n## Description\n\nThe /api/v2/widgets endpoint in Acme Widget Server deserializes user-supplied JSON payloads without adequate type validation. An attacker can craft a malicious payload that triggers instantiation of dangerous classes, leading to arbitrary command execution with the privileges of the application service account.\n\n## Mitigation\n\n- Update to Acme Widget Server 3.4.3 or later\n- If unable to update immediately: restrict network access to the /api/v2/widgets endpoint to trusted sources only\n\n## Disclosure Timeline\n\n| Date | Event |\n|------|-------|\n| 2024-10-01 | Vulnerability discovered |\n| 2024-10-03 | Vendor notified |\n| 2024-10-17 | First follow-up (no response) |\n| 2024-10-29 | Second follow-up (no response) |\n| 2024-10-31 | CERT/CC notified |\n| 2024-12-30 | Public disclosure |\n\n## Credit\n\nThis vulnerability was discovered by Jane Doe (Independent Security Researcher).\n\n## Contact\n\njane.doe@secresearch.example\nPGP: 0xABCD1234EFGH5678",
      "publication_channels": [
        "Personal blog / research website",
        "Full Disclosure mailing list (seclists.org)",
        "oss-security mailing list (if open-source component)",
        "Twitter/Mastodon announcement linking to full writeup",
        "GitHub Security Advisory (if applicable)"
      ],
      "timing": "Publish on the agreed disclosure date. If the vendor has released a patch, coordinate publication to coincide with or follow the patch release. If no patch is available, the notice should emphasize mitigation steps."
    },
    "legal_safe_harbor": {
      "language": "This vulnerability was discovered during good-faith security research. All testing was conducted on systems I own or have explicit authorization to test. No customer data was accessed, exfiltrated, or modified during this research. I am reporting this vulnerability to enable the vendor to fix the issue and protect users. This research and disclosure are consistent with the principles of coordinated vulnerability disclosure as described by CERT/CC, ISO/IEC 29147:2018, and the Department of Justice's Framework for a Vulnerability Disclosure Program for Online Systems (2017).\n\nI request that Acme Corp consider this report under any applicable safe harbor provisions in their vulnerability disclosure policy, and that this good-faith research not be subject to legal action under the Computer Fraud and Abuse Act (18 U.S.C. 1030) or equivalent statutes.",
      "where_to_include": "Include the safe harbor statement in the initial contact email and in any communication where legal posture may be a concern. It is not necessary in routine follow-up emails once a collaborative relationship is established.",
      "jurisdiction_notes": "United States: The CFAA (Computer Fraud and Abuse Act) governs unauthorized computer access. The DOJ's 2017 framework provides guidance for good-faith security research. Many companies have safe harbor provisions in their VDP (Vulnerability Disclosure Policy) or bug bounty program terms. If the vendor has a published VDP with safe harbor language, reference it explicitly. If no VDP exists, the generic safe harbor language above establishes your good-faith intent."
    }
  },
  "multi_vendor_coordination": {
    "applicable": false,
    "strategy": "N/A - single vendor affected",
    "vendor_timeline": [],
    "synchronization_plan": "N/A"
  },
  "timeline_management": {
    "proposed_timeline": [
      {"date": "2024-10-01 (Day 0)", "action": "Vulnerability discovered", "contingency": "N/A"},
      {"date": "2024-10-03 (Day 2)", "action": "Initial vendor notification sent", "contingency": "If no security contact found, try info@, support@, and security.txt"},
      {"date": "2024-10-17 (Day 16)", "action": "First follow-up if no acknowledgment", "contingency": "Try alternative contact methods (social media, GitHub issues)"},
      {"date": "2024-10-29 (Day 28)", "action": "Second follow-up if still no response", "contingency": "Prepare CERT/CC notification"},
      {"date": "2024-10-31 (Day 30)", "action": "Escalate to CERT/CC if vendor unresponsive", "contingency": "CERT/CC adds 45 days to coordination window"},
      {"date": "2024-12-15 (Day 75)", "action": "Request status update from vendor on patch timeline", "contingency": "If vendor needs more time, consider 30-day extension"},
      {"date": "2024-12-30 (Day 90)", "action": "Public disclosure", "contingency": "If vendor requests extension with evidence of active fix development, grant 30-day extension to 2025-01-29"}
    ],
    "extension_policy": "Extensions of up to 30 days are reasonable when the vendor is actively working on a fix and communicating openly. Multiple extensions may be granted for complex fixes in critical infrastructure. Extensions should NOT be granted when the vendor is unresponsive or using delay as a tactic to avoid disclosure. If the vulnerability is being actively exploited in the wild, disclosure may be accelerated regardless of vendor readiness.",
    "early_disclosure_triggers": [
      "Evidence of active exploitation of the vulnerability in the wild",
      "Vendor publicly patches the issue without coordinating disclosure",
      "Another researcher independently discovers and discloses the same vulnerability",
      "Vendor communicates they will not fix the issue and users remain at risk"
    ]
  },
  "tone_guidelines": {
    "general_principles": [
      "Lead with respect: acknowledge the vendor's work and the complexity of security",
      "State facts, not opinions: let the evidence demonstrate severity",
      "Offer collaboration: you are a partner in fixing this, not an adversary",
      "Be patient: security fixes take time, especially for complex codebases",
      "Assume good faith: the vendor likely wants to protect their users too",
      "Be concise: respect the reader's time, get to the point quickly"
    ],
    "phrases_to_use": [
      "I am writing to report a security vulnerability I have identified...",
      "I would like to propose the following responsible disclosure timeline...",
      "I am open to adjusting this timeline based on your patching schedule...",
      "I am happy to provide additional details or clarification...",
      "I look forward to working with your team to resolve this issue...",
      "I appreciate your prompt response and collaboration...",
      "Could you please confirm receipt of this report?",
      "I believe this issue warrants attention because...",
      "I would welcome the opportunity to discuss this further..."
    ],
    "phrases_to_avoid": [
      "NEVER: 'If you don't fix this, I will publish...' (threatening)",
      "NEVER: 'This is a trivial bug that should have been caught...' (condescending)",
      "NEVER: 'Your security is terrible...' (insulting)",
      "NEVER: 'I demand a response by...' (demanding/ultimatum)",
      "NEVER: 'I could have done much worse...' (threatening)",
      "NEVER: 'My lawyers...' (unless genuinely necessary for legal protection)",
      "NEVER: 'I expect compensation for...' (in disclosure emails - separate from bounty programs)",
      "AVOID: 'Urgent' or 'CRITICAL' in subject lines without justification (alarmist)",
      "AVOID: Excessive technical jargon when plain language suffices",
      "AVOID: Lengthy emails when brevity serves the purpose"
    ]
  }
}
```
