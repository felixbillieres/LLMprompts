# Authentication Bypass Analysis

## Quand utiliser ce prompt

- **Audit de code source** : Revue des mecanismes d'authentification (login, registration, password reset, MFA, session management, JWT, OAuth)
- **Black-box testing** : Test des flux d'authentification pour identifier des contournements, des failles logiques, ou des faiblesses cryptographiques
- **Bug bounty** : Recherche de bypass d'authentification sur des applications web (account takeover, auth bypass, session hijacking)
- **Security architecture review** : Evaluation de la robustesse de l'architecture d'authentification dans son ensemble
- **JWT/OAuth/SAML audit** : Analyse specifique des tokens, des flux OAuth/OIDC, et des assertions SAML

### Types de vulnerabilites couverts
- **Default/weak credentials** : credentials par defaut, mots de passe faibles, credentials dans le code
- **Brute force / Rate limiting bypass** : absence de rate limiting, bypass via headers, IP rotation
- **Password reset flaws** : tokens previsibles, host header injection, token leakage
- **MFA bypass** : absence de verification cote serveur, race conditions, backup code brute force
- **Session management** : fixation, prediction, insufficient expiration, insecure storage
- **JWT attacks** : none algorithm, key confusion (RS256 → HS256), weak secrets, header injection (jku/jwk/x5u)
- **OAuth/OIDC flaws** : open redirect in redirect_uri, state CSRF, PKCE bypass, token leakage, scope escalation
- **SAML attacks** : signature wrapping, XXE, comment injection, certificate confusion

---

## Variables a remplir

| Variable | Description | Exemple |
|----------|-------------|---------|
| `{{TARGET}}` | Code source auth, flux d'authentification capture, ou configuration JWT/OAuth | Code du controller login, configuration OAuth2, intercepted auth flow |
| `{{CONTEXT}}` | Contexte de la mission | `Bug bounty sur plateforme fintech avec auth JWT + OAuth Google` |
| `{{LANGUAGE}}` | Langage backend | `Python`, `Java`, `Node.js`, `PHP`, `Ruby`, `Go` |
| `{{FRAMEWORK}}` | Framework utilise | `Django`, `Spring Security`, `Express + Passport`, `Laravel` |
| `{{AUTH_STACK}}` | Stack d'authentification | `JWT + refresh tokens`, `Session-based + Redis`, `OAuth2 + SAML SSO` |

---

## System Prompt

```
Tu es un chercheur en securite offensive senior avec 15+ annees d'experience en securite applicative web, specialise dans les mecanismes d'authentification et de gestion de sessions. Tu as decouvert des dizaines de bypass d'authentification critiques sur des programmes de bug bounty majeurs, menant a des account takeover complets sur des plateformes financieres et healthcare. Tu es un expert reconnu en securite JWT (tu connais chaque attaque documentee et leurs variantes), OAuth 2.0/OIDC (tu as lu et compris chaque RFC), et SAML (tu maitrises les attaques de signature wrapping).

Tu connais parfaitement :
- Les failles classiques d'authentification : default credentials, brute force, insecure comparison, timing attacks
- Les attaques JWT : none algorithm, key confusion (RS256 → HS256), weak secrets (jwt-cracker), header injection (jku/jwk/x5u/kid), claim manipulation
- Les failles OAuth 2.0/OIDC : open redirect via redirect_uri manipulation, CSRF via state bypass, PKCE downgrade, token leakage via Referer, scope escalation, IdP confusion
- Les attaques SAML : XML signature wrapping (XSW), XXE injection, comment injection dans NameID, certificate confusion
- Les failles de password reset : token previsibilite (timestamp-based, sequential), host header poisoning, token dans l'URL (Referer leakage)
- Les bypass MFA : race conditions, response manipulation, backup code brute force, session persistence post-MFA, direct endpoint access
- Les failles de session management : fixation, prediction, insufficient entropy, missing expiration, insecure cookie attributes
- Les timing attacks : insecure comparison de tokens/passwords, oracle padding
- Les hardcoded credentials et secrets dans le code source

Tu analyses chaque mecanisme d'authentification avec la mentalite d'un attaquant cherchant a acceder a un compte arbitraire ou a bypasser completement l'authentification.
```

---

## User Prompt

```xml
<context>
Mission : {{CONTEXT}}
Langage : {{LANGUAGE}}
Framework : {{FRAMEWORK}}
Stack d'authentification : {{AUTH_STACK}}
Type d'analyse : audit de code source et/ou black-box
</context>

<target>
{{TARGET}}
</target>

<instructions>
Analyse le code source et/ou les flux d'authentification fournis pour detecter des vulnerabilites d'authentification. Suis ce processus rigoureux :

**Phase 1 - Credentials et secrets**
1. Recherche de credentials hardcodes :
   - Mots de passe par defaut dans le code ou la configuration
   - Cles secretes JWT hardcodees (surtout si symetriques : HS256)
   - API keys, OAuth client secrets dans le code source
   - Comptes de test/debug non supprimes en production
   - Backdoor accounts ou master passwords

2. Evaluation de la politique de mots de passe :
   - Longueur minimale, complexite requise
   - Blocklist de mots de passe courants
   - Protection contre la reutilisation

**Phase 2 - Brute force et Rate limiting**
3. Analyse des protections contre le brute force :
   - Rate limiting sur les endpoints de login, password reset, MFA verification
   - Account lockout apres X tentatives
   - Bypass possibles :
     * Headers manipulables : X-Forwarded-For, X-Real-IP, X-Originating-IP, True-Client-IP
     * Rotation entre email et username
     * Variation de case dans les identifiants
     * Null bytes ou espaces dans les parametres
     * Requetes distribuees via IP rotation

**Phase 3 - Password Reset**
4. Analyse du flux de reinitialisation de mot de passe :
   - Generation du token : est-il aleatoire (crypto-secure) ou previsible (timestamp, sequential, MD5(email+time)) ?
   - Longueur et entropie du token
   - Expiration : duree de validite ? Le token est-il invalide apres utilisation ?
   - Delivery : le token est-il dans l'URL (Referer leakage) ou dans le body du mail ?
   - Host header injection : le lien de reset utilise-t-il le header Host de la requete ?
     ```
     POST /api/password-reset HTTP/1.1
     Host: evil.com
     # Si le serveur genere le lien de reset avec le Host header :
     # https://evil.com/reset?token=SECRET_TOKEN
     ```
   - Token dans la reponse : le token est-il retourne dans la reponse HTTP ?
   - Reuse : le token peut-il etre utilise plusieurs fois ?

**Phase 4 - JWT Security**
5. Si JWT est utilise, analyse :

   a. **Algorithme** :
   - Le serveur accepte-t-il alg: "none" ? (CVE-2015-9235)
   - Le serveur accepte-t-il le changement RS256 → HS256 ? (key confusion)
   - Quel algorithme est configure ? (HS256 avec secret faible vs RS256/ES256)

   b. **Secret/cle** :
   - HS256 : le secret est-il suffisamment long et aleatoire ? (jwt-cracker, hashcat)
   - RS256 : la cle publique est-elle exposee ? (/jwks.json, /.well-known/jwks.json)
   - Le secret est-il hardcode dans le code source ?

   c. **Claims** :
   - Le serveur valide-t-il l'expiration (exp) ? Le issuer (iss) ? L'audience (aud) ?
   - Le sub ou user_id dans le token est-il utilise sans verification supplementaire ?
   - Des claims sensibles sont-ils dans le payload sans protection d'integrite supplementaire ?

   d. **Header injection** :
   - jku (JWK Set URL) : peut-on pointer vers un serveur controle avec notre propre cle ?
   - jwk (embedded JWK) : peut-on embedder notre propre cle publique dans le header ?
   - x5u (X.509 URL) : meme principe que jku avec un certificat
   - kid (Key ID) : injection SQL, path traversal, ou pointeur vers un fichier previsible

   e. **Refresh tokens** :
   - Rotation implementee ? (un refresh token utilise est-il invalide ?)
   - Stockage securise ? (cookie HttpOnly vs localStorage)
   - Revocation possible ? (logout invalide-t-il le refresh token ?)

**Phase 5 - OAuth 2.0 / OIDC**
6. Si OAuth/OIDC est utilise, analyse :

   a. **redirect_uri** :
   - Validation stricte ou matching partiel ?
   - Bypass : subdomain matching (evil.target.com), path traversal, fragment bypass, open redirect chaining
   - Difference entre la validation du serveur d'autorisation et l'application

   b. **State parameter** :
   - Present et valide ? (protection CSRF)
   - Suffisamment aleatoire ? Lie a la session ?

   c. **PKCE** :
   - Utilise pour les clients publics ? (SPA, mobile)
   - Peut-il etre downgrade (omis) ?
   - code_challenge_method: plain vs S256

   d. **Token leakage** :
   - Tokens dans l'URL (code d'autorisation dans les query params → Referer leakage)
   - Tokens dans les logs
   - Tokens dans le browser history

   e. **Scope escalation** :
   - Peut-on demander des scopes supplementaires non autorises ?
   - Le serveur valide-t-il les scopes demandes vs les scopes autorises ?

**Phase 6 - SAML**
7. Si SAML est utilise, analyse :
   - XML Signature Wrapping (XSW) : manipulation de la position de la signature dans le document XML
   - XXE injection dans les assertions SAML
   - Comment injection dans le NameID : user@evil.com<!---->@target.com
   - Certificate confusion : le SP valide-t-il que le certificat de signature correspond a l'IdP attendu ?
   - Response replay : les assertions ont-elles un ID unique et une verification anti-replay ?

**Phase 7 - MFA Bypass**
8. Si MFA est implemente :
   - Le code MFA est-il verifie cote serveur (pas uniquement cote client) ?
   - Rate limiting sur la verification MFA (brute force des codes a 6 chiffres = 1M combinaisons)
   - Peut-on acceder directement aux endpoints post-MFA sans passer par la verification ?
   - Race condition : soumettre plusieurs codes simultanement
   - Backup codes : sont-ils suffisamment longs et aleatoires ? Rate limited ?
   - Le MFA peut-il etre desactive sans re-verification ?
   - Response manipulation : changer {"success": false} en {"success": true}

**Phase 8 - Session Management**
9. Analyse de la gestion de sessions :
   - Entropie du session ID : est-il suffisamment aleatoire ?
   - Cookie attributes : HttpOnly, Secure, SameSite, Path, Domain
   - Expiration : duree de session, idle timeout, absolute timeout
   - Fixation : le session ID est-il regenere apres login ?
   - Revocation : le logout invalide-t-il reellement la session cote serveur ?
   - Concurrent sessions : limites ? Notification ?

**Phase 9 - Timing attacks et comparaisons**
10. Analyse des comparaisons de secrets :
    - Les tokens/passwords sont-ils compares avec === (timing-safe) ou avec des comparaisons sequentielles ?
    - Python : hmac.compare_digest() vs ==
    - Node.js : crypto.timingSafeEqual() vs ===
    - Java : MessageDigest.isEqual() vs Arrays.equals()
    - PHP : hash_equals() vs ===

Produis tes findings dans le format JSON specifie.
</instructions>

<output_format>
Retourne tes resultats au format JSON suivant :

{
  "findings": [
    {
      "id": "AUTH-001",
      "title": "Description concise de la vulnerabilite d'authentification",
      "severity": "Critical|High|Medium|Low|Info",
      "cvss_score": 0.0,
      "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
      "vulnerability_class": "CWE-287: Improper Authentication | CWE-384: Session Fixation | CWE-640: Weak Password Recovery | etc.",
      "confidence": "High|Medium|Low",
      "affected_component": "fichier:ligne ou endpoint/flux",
      "auth_mechanism": "JWT|OAuth|SAML|Session|Password Reset|MFA",
      "attack_type": "None algorithm|Key confusion|Token prediction|etc.",
      "description": "Description detaillee",
      "root_cause": "Cause technique racine",
      "proof_of_concept": "Requete HTTP ou script demontrant le bypass",
      "impact": "Impact concret (account takeover, auth bypass, etc.)",
      "remediation": "Correction specifique avec code",
      "references": ["CWE-xxx", "RFC-xxxx", "CVE similaires"]
    }
  ]
}
</output_format>

<constraints>
- Ne rapporte JAMAIS un bypass d'authentification dont tu n'es pas sur. Les mecanismes d'authentification sont souvent plus robustes qu'ils ne le paraissent a premiere vue.
- Verifie que les attaques JWT sont reellement applicables : la plupart des librairies modernes rejettent alg: "none" et la key confusion par defaut.
- Ne signale pas l'absence de rate limiting comme une vulnerabilite Critical - evalue l'impact reel (quels endpoints, quel impact en cas de brute force reussi).
- Pour le scoring CVSS :
  - Account takeover non authentifie = Critical (9.1-9.8)
  - Auth bypass non authentifie = Critical (9.1-9.8)
  - JWT none/key confusion = Critical (9.8) si exploitable, sinon non applicable
  - Password reset flaw menant a ATO = High (8.x)
  - MFA bypass = High (7.x-8.x)
  - Session fixation/prediction = High (7.x-8.x)
  - Absence de rate limiting = Low a Medium (3.x-5.x) selon le contexte
  - Timing attack sur comparaison = Low a Medium (difficile a exploiter en pratique sur le reseau)
- Ne confonds pas les fonctionnalites de securite desactivees en environnement de dev/test avec des vulnerabilites en production.
- Verifie la version des librairies JWT/OAuth utilisees avant de rapporter des vulnerabilites corrigees dans des versions recentes.
</constraints>
```

---

## Prefill (pour l'API Anthropic)

```json
{"findings": [
```

---

## Few-Shot Examples

### Exemple 1 : JWT None Algorithm Bypass

```xml
<examples>
Voici un exemple de finding attendu pour calibrer ton analyse :

**Code source analyse :**
```javascript
// middleware/auth.js
const jwt = require('jsonwebtoken');

const JWT_SECRET = process.env.JWT_SECRET || 'development-secret-key-change-me';

function authenticate(req, res, next) {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'No token provided' });

    try {
        // Vulnerable: algorithms not restricted
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded;
        next();
    } catch (err) {
        return res.status(401).json({ error: 'Invalid token' });
    }
}

// routes/auth.js
router.post('/login', async (req, res) => {
    const { email, password } = req.body;
    const user = await User.findOne({ where: { email } });

    if (!user || !bcrypt.compareSync(password, user.password_hash)) {
        return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign(
        { sub: user.id, email: user.email, role: user.role },
        JWT_SECRET,
        { algorithm: 'HS256', expiresIn: '24h' }
    );

    return res.json({ token });
});
```

**Finding 1 attendu :**
{
  "id": "AUTH-001",
  "title": "JWT secret par defaut hardcode permettant la forge de tokens arbitraires",
  "severity": "Critical",
  "cvss_score": 9.8,
  "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
  "vulnerability_class": "CWE-798: Use of Hard-coded Credentials",
  "confidence": "High",
  "affected_component": "middleware/auth.js:4 - JWT_SECRET fallback value",
  "auth_mechanism": "JWT",
  "attack_type": "Hardcoded secret / Weak secret",
  "description": "Le secret JWT utilise un fallback hardcode 'development-secret-key-change-me' si la variable d'environnement JWT_SECRET n'est pas definie. Ce secret est present dans le code source et est donc connu de tout attaquant ayant acces au repository. De plus, meme si JWT_SECRET est defini, le fallback reste dans le code et pourrait etre active en cas d'erreur de configuration en production. Avec ce secret, un attaquant peut forger des tokens JWT valides pour n'importe quel utilisateur, incluant les administrateurs.",
  "root_cause": "Utilisation d'un pattern `process.env.JWT_SECRET || 'default-value'` qui fournit un fallback en clair dans le code source. Le secret devrait etre obligatoire et l'application devrait refuser de demarrer sans lui.",
  "proof_of_concept": "# Forger un token admin avec le secret connu\nimport jwt\n\n# Secret hardcode trouve dans le code source\nsecret = 'development-secret-key-change-me'\n\n# Forger un token admin\ntoken = jwt.encode(\n    {'sub': 1, 'email': 'admin@target.com', 'role': 'admin', 'exp': 9999999999},\n    secret,\n    algorithm='HS256'\n)\n\nprint(f'Forged admin token: {token}')\n\n# Utiliser le token forge\ncurl -H 'Authorization: Bearer <forged_token>' https://target.com/api/admin/users",
  "impact": "Forge de tokens JWT arbitraires permettant l'usurpation de n'importe quel compte utilisateur, y compris les administrateurs. Acces complet a toutes les fonctionnalites de l'application sans authentification legitime. Account takeover de masse possible.",
  "remediation": "1. Rendre le secret JWT obligatoire et generer une erreur au demarrage s'il est absent :\n```javascript\nconst JWT_SECRET = process.env.JWT_SECRET;\nif (!JWT_SECRET) {\n    console.error('FATAL: JWT_SECRET environment variable is required');\n    process.exit(1);\n}\n```\n\n2. Utiliser un secret de haute entropie (256+ bits) :\n```bash\n# Generer un secret securise\nopenssl rand -base64 64\n```\n\n3. Migrer vers RS256 (asymetrique) pour separer la signature de la verification.\n\n4. Ajouter la restriction d'algorithmes dans jwt.verify() :\n```javascript\nconst decoded = jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] });\n```",
  "references": [
    "CWE-798: Use of Hard-coded Credentials",
    "CWE-321: Use of Hard-coded Cryptographic Key",
    "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/10-Testing_JSON_Web_Tokens",
    "https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/",
    "CVE-2015-9235 - JWT alg:none vulnerability in multiple libraries"
  ]
}

**Finding 2 attendu :**
{
  "id": "AUTH-002",
  "title": "JWT verification sans restriction d'algorithmes permettant le bypass via alg:none",
  "severity": "Critical",
  "cvss_score": 9.8,
  "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
  "vulnerability_class": "CWE-287: Improper Authentication",
  "confidence": "Medium",
  "affected_component": "middleware/auth.js:10 - jwt.verify() sans option algorithms",
  "auth_mechanism": "JWT",
  "attack_type": "None algorithm bypass",
  "description": "La fonction jwt.verify() est appelee sans l'option 'algorithms' qui restreint les algorithmes acceptes. Selon la version de la librairie jsonwebtoken, cela pourrait permettre l'acceptation de tokens avec alg:'none' (sans signature). NOTE : les versions recentes de jsonwebtoken (>= 9.0.0) rejettent alg:none par defaut, mais l'absence de restriction explicite reste une mauvaise pratique qui expose a d'autres attaques (key confusion si des cles asymetriques sont un jour ajoutees).",
  "root_cause": "Appel a jwt.verify(token, JWT_SECRET) sans le parametre {algorithms: ['HS256']}. Cela laisse la librairie decider quels algorithmes sont acceptes, ce qui depend de la version et de la configuration.",
  "proof_of_concept": "# Tenter le bypass alg:none (fonctionne si jsonwebtoken < 9.0.0)\nimport base64\nimport json\n\n# Header avec alg: none\nheader = base64.urlsafe_b64encode(json.dumps({'alg': 'none', 'typ': 'JWT'}).encode()).rstrip(b'=')\npayload = base64.urlsafe_b64encode(json.dumps({'sub': 1, 'email': 'admin@target.com', 'role': 'admin'}).encode()).rstrip(b'=')\n\n# Token sans signature\ntoken = header.decode() + '.' + payload.decode() + '.'\n\ncurl -H 'Authorization: Bearer <token>' https://target.com/api/admin/users\n\n# Verifier la version de jsonwebtoken dans package.json pour confirmer l'exploitabilite",
  "impact": "Si la version de jsonwebtoken est vulnerable, forge de tokens sans connaitre le secret. Account takeover de n'importe quel utilisateur. Meme si alg:none est bloque, l'absence de restriction d'algorithmes est une bombe a retardement.",
  "remediation": "Ajouter la restriction d'algorithmes :\n```javascript\nconst decoded = jwt.verify(token, JWT_SECRET, {\n    algorithms: ['HS256'],  // Restreindre explicitement\n    complete: true  // Optionnel: retourne aussi le header pour logging\n});\n```\n\nMettre a jour jsonwebtoken vers la derniere version (>= 9.0.0).",
  "references": [
    "CWE-287: Improper Authentication",
    "CVE-2015-9235: JWT alg:none bypass",
    "https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/",
    "https://portswigger.net/web-security/jwt/algorithm-confusion"
  ]
}
</examples>
```

### Exemple 2 : Password Reset Host Header Injection

```xml
<examples>
**Scenario :**
```python
# views/auth.py (Django)
from django.core.mail import send_mail

def password_reset(request):
    email = request.POST.get('email')
    user = User.objects.filter(email=email).first()
    if not user:
        return JsonResponse({'status': 'ok'})  # Prevent enumeration

    token = generate_secure_token()
    PasswordReset.objects.create(user=user, token=token, expires=now() + timedelta(hours=1))

    # VULNERABLE: Uses Host header from request
    reset_link = f"https://{request.get_host()}/reset-password?token={token}"

    send_mail(
        'Password Reset',
        f'Click here to reset your password: {reset_link}',
        'noreply@target.com',
        [email],
    )
    return JsonResponse({'status': 'ok'})
```

**Finding attendu :**
{
  "id": "AUTH-003",
  "title": "Password reset host header injection permettant le vol de tokens de reinitialisation",
  "severity": "High",
  "cvss_score": 8.1,
  "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N",
  "vulnerability_class": "CWE-640: Weak Password Recovery Mechanism for Forgotten Password",
  "confidence": "High",
  "affected_component": "views/auth.py:12 - request.get_host() dans le lien de reset",
  "auth_mechanism": "Password Reset",
  "attack_type": "Host header injection / Password reset poisoning",
  "description": "L'endpoint de password reset utilise request.get_host() pour construire le lien de reinitialisation envoye par email. Un attaquant peut manipuler le header Host de la requete pour que le lien de reset pointe vers un domaine controle. Quand la victime clique sur le lien dans l'email, le token de reinitialisation est envoye au serveur de l'attaquant.",
  "root_cause": "Utilisation de request.get_host() pour construire dynamiquement l'URL du lien de reinitialisation. Cette valeur provient du header Host de la requete HTTP, qui est controlable par l'attaquant.",
  "proof_of_concept": "# Envoyer une requete de password reset avec un Host header modifie\ncurl -X POST https://target.com/api/password-reset \\\n  -H 'Host: evil.com' \\\n  -H 'Content-Type: application/json' \\\n  -d '{\"email\": \"victim@example.com\"}'\n\n# L'email envoye a la victime contiendra :\n# https://evil.com/reset-password?token=REAL_SECRET_TOKEN\n\n# Quand la victime clique, le token est envoye a evil.com\n# L'attaquant capture le token et l'utilise sur le vrai site :\ncurl -X POST https://target.com/api/reset-password \\\n  -H 'Content-Type: application/json' \\\n  -d '{\"token\": \"CAPTURED_TOKEN\", \"new_password\": \"attacker123\"}'",
  "impact": "Account takeover de n'importe quel compte via le vol du token de reinitialisation. L'attaquant n'a besoin que de connaitre l'email de la victime. Le User Interaction est Required (la victime doit cliquer sur le lien), mais le scenario est credible car l'email provient du domaine legitime (noreply@target.com).",
  "remediation": "Utiliser une URL fixe en configuration au lieu du header Host :\n```python\nfrom django.conf import settings\n\ndef password_reset(request):\n    # ...\n    reset_link = f\"{settings.SITE_URL}/reset-password?token={token}\"\n    # ...\n```\n\nAvec dans settings.py :\n```python\nSITE_URL = os.environ.get('SITE_URL', 'https://target.com')\n```\n\nEn complement, configurer Django ALLOWED_HOSTS strictement et utiliser le middleware SecurityMiddleware.",
  "references": [
    "CWE-640: Weak Password Recovery Mechanism",
    "https://portswigger.net/web-security/host-header/exploiting/password-reset-poisoning",
    "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/09-Testing_for_Weak_Password_Change_or_Reset_Functionalities"
  ]
}
</examples>
```
