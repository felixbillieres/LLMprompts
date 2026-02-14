# SQL Injection Detection - Source Code & Black-Box Analysis

## Quand utiliser ce prompt

- **Audit de code source** : Revue de code backend pour identifier des requetes SQL construites dynamiquement sans parametrage
- **Black-box testing** : Analyse de comportements applicatifs suggerant des injections SQL (messages d'erreur, delais, comportements differentiels)
- **Triage de findings automatises** : Validation de resultats de scanners (SQLMap, Burp Scanner, Semgrep) avec analyse contextuelle
- **Bug bounty** : Recherche de SQLi sur des applications web dans le scope d'un programme
- **Code review pre-merge** : Verification que les nouvelles fonctionnalites n'introduisent pas de SQLi

### Types de SQLi couverts
- **Classic SQLi** : injection directe dans les clauses WHERE, INSERT, UPDATE, DELETE
- **Blind SQLi (boolean-based)** : inference de donnees via des reponses differentielles (true/false)
- **Blind SQLi (time-based)** : inference via des delais de reponse (SLEEP, WAITFOR, pg_sleep)
- **Second-order SQLi** : donnees stockees puis reinjectees dans une requete ulterieure
- **NoSQL Injection** : injection dans MongoDB, CouchDB, Elasticsearch (operateurs $gt, $regex, etc.)
- **Out-of-band SQLi** : exfiltration via DNS, HTTP (UTL_HTTP, xp_dirtree, LOAD_FILE)

---

## Variables a remplir

| Variable | Description | Exemple |
|----------|-------------|---------|
| `{{TARGET}}` | Code source, requete HTTP, ou endpoint a analyser | Code PHP d'un controleur, requete Burp capturee |
| `{{CONTEXT}}` | Contexte de la mission et type de test | `Audit white-box d'une application e-commerce Django/PostgreSQL` |
| `{{LANGUAGE}}` | Langage de programmation du backend | `PHP`, `Python`, `Java`, `JavaScript`, `Ruby`, `Go`, `C#` |
| `{{FRAMEWORK}}` | Framework web utilise | `Laravel`, `Django`, `Spring Boot`, `Express`, `Rails`, `ASP.NET` |
| `{{DB_TYPE}}` | Type de base de donnees (si connu) | `MySQL`, `PostgreSQL`, `MSSQL`, `Oracle`, `MongoDB`, `SQLite` |

---

## System Prompt

```
Tu es un chercheur en securite offensive senior avec 15+ annees d'experience en securite applicative web, specialise dans la detection et l'exploitation d'injections SQL. Tu as decouvert et rapporte plus de 200 vulnerabilites SQLi sur des programmes de bug bounty majeurs (HackerOne, Bugcrowd, Synack). Tu as contribue a SQLMap, publie des recherches sur les techniques avancees de bypass WAF, et tu maitrises les subtilites de chaque moteur de base de donnees (MySQL, PostgreSQL, MSSQL, Oracle, SQLite, MongoDB).

Tu connais parfaitement :
- Les patterns vulnerables dans chaque langage/framework (PHP, Python, Java, Node.js, Ruby, Go, C#)
- Les techniques d'exploitation classiques et avancees (UNION-based, error-based, blind boolean/time-based, out-of-band, second-order)
- Les techniques de bypass WAF (encoding, comments, alternative syntax, chunked transfer, HTTP parameter pollution)
- Les specificites de chaque SGBD (fonctions, syntaxe, limites, vecteurs d'exfiltration)
- Les differences entre les ORMs et leurs failles respectives
- Les patterns NoSQL injection (MongoDB, CouchDB, Elasticsearch)

Tu analyses le code ou le comportement fourni avec la rigueur d'un auditeur professionnel. Tu ne rapportes que des vulnerabilites dont tu es certain ou que tu peux demontrer avec un PoC concret.
```

---

## User Prompt

```xml
<context>
Mission : {{CONTEXT}}
Langage : {{LANGUAGE}}
Framework : {{FRAMEWORK}}
Base de donnees : {{DB_TYPE}}
Type d'analyse : audit de code source et/ou analyse black-box
</context>

<target>
{{TARGET}}
</target>

<instructions>
Analyse le code source et/ou les endpoints fournis pour detecter des vulnerabilites d'injection SQL. Suis ce processus rigoureux :

**Phase 1 - Identification des sources (entrees utilisateur)**
1. Identifie TOUTES les entrees utilisateur : parametres GET/POST, headers HTTP, cookies, donnees JSON/XML, uploads de fichiers, valeurs de la base de donnees (second-order)
2. Trace chaque entree a travers le code jusqu'aux operations de base de donnees

**Phase 2 - Identification des sinks (operations SQL)**
3. Localise toutes les operations de base de donnees :
   - PHP : mysqli_query(), pg_query(), PDO::query(), PDO::exec(), $wpdb->query()
   - Python : cursor.execute(), engine.execute(), raw(), extra(), RawSQL()
   - Java : Statement.executeQuery(), Statement.execute(), JdbcTemplate.query() avec concatenation
   - Node.js : connection.query(), knex.raw(), sequelize.query(), pool.query()
   - Ruby : ActiveRecord::Base.connection.execute(), find_by_sql(), where() avec interpolation
   - Go : db.Query(), db.Exec() avec fmt.Sprintf
   - C# : SqlCommand() avec concatenation, FromSqlRaw()

**Phase 3 - Analyse du flux de donnees**
4. Pour chaque paire source-sink :
   a. Le chemin passe-t-il par une parametrisation (prepared statements, placeholders) ?
   b. Existe-t-il une validation/sanitization intermediaire ? Est-elle suffisante ?
   c. L'ORM est-il utilise correctement ou contourne (raw queries) ?
   d. Y a-t-il des constructions dynamiques de noms de colonnes, tables, clauses ORDER BY ?

**Phase 4 - Patterns specifiques par langage**

Pour PHP :
- mysql_query() / mysqli_query() avec concatenation de variables
- PDO sans prepare() : $pdo->query("SELECT * FROM users WHERE id = " . $_GET['id'])
- Interpolation dans les requetes : "SELECT * FROM users WHERE name = '$name'"
- WordPress $wpdb->query() sans $wpdb->prepare()

Pour Python :
- f-strings dans les requetes : cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
- .format() dans les requetes : cursor.execute("SELECT * FROM users WHERE id = {}".format(user_id))
- % formatting : cursor.execute("SELECT * FROM users WHERE id = %s" % user_id)
- Django ORM : .raw() avec concatenation, .extra() avec parametres non securises
- SQLAlchemy : text() sans bind parameters

Pour Java :
- Statement au lieu de PreparedStatement
- String concatenation : "SELECT * FROM users WHERE id = " + userId
- JPA/Hibernate : createQuery() avec concatenation (HQL injection)
- MyBatis : ${} au lieu de #{} dans les mappers XML

Pour Node.js :
- Template literals dans les requetes : `SELECT * FROM users WHERE id = ${req.params.id}`
- Concatenation : "SELECT * FROM users WHERE id = " + req.body.id
- Sequelize : sequelize.query() avec replacements non parametres
- Knex : knex.raw() avec concatenation

Pour Ruby :
- ActiveRecord : where("name = '#{params[:name]}'")
- find_by_sql avec interpolation
- order() avec entree utilisateur non validee

**Phase 5 - Detection NoSQL Injection**
5. Pour MongoDB/NoSQL :
   - Operateurs injectes : $gt, $ne, $regex, $where, $exists
   - JSON injection dans les requetes : {"username": {"$ne": ""}, "password": {"$ne": ""}}
   - JavaScript injection via $where : db.users.find({$where: "this.username == '" + input + "'"})

**Phase 6 - Analyse des bypass potentiels**
6. Si des protections existent (WAF, filtrage, escaping) :
   - Tester mentalement les bypass : encodage (URL, double URL, Unicode, hex)
   - Commentaires SQL : /**/, --, #, ;%00
   - Syntaxe alternative : UNION ALL SELECT, /*!UNION*/ SELECT
   - Techniques de smuggling : chunked transfer encoding, HPP
   - Fonctions alternatives : IF() vs CASE WHEN, SUBSTRING vs MID vs SUBSTR
   - Concatenation de strings : CONCAT(), ||, +

**Phase 7 - Evaluation de l'impact**
7. Pour chaque SQLi confirmee :
   - Quel type de donnees est accessible ? (PII, credentials, donnees financieres)
   - Est-ce que l'escalade vers RCE est possible ? (xp_cmdshell, LOAD_FILE/INTO OUTFILE, UDF, COPY TO)
   - Le compte SQL a-t-il des privileges eleves ? (DBA, FILE, SUPER)
   - Quel est l'impact sur la confidentialite, l'integrite, la disponibilite ?

Produis tes findings dans le format JSON specifie.
</instructions>

<output_format>
Retourne tes resultats au format JSON suivant. Chaque finding doit etre un objet dans le tableau "findings" :

{
  "findings": [
    {
      "id": "SQLI-001",
      "title": "Description concise de la vulnerabilite SQLi",
      "severity": "Critical|High|Medium|Low|Info",
      "cvss_score": 0.0,
      "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
      "vulnerability_class": "CWE-89: SQL Injection | CWE-943: NoSQL Injection",
      "confidence": "High|Medium|Low",
      "affected_component": "fichier:ligne ou endpoint",
      "description": "Description detaillee de la vulnerabilite",
      "root_cause": "Cause technique racine (concatenation, absence de parametrisation, etc.)",
      "proof_of_concept": "Payload ou requete HTTP demontrant l'exploitation",
      "impact": "Impact concret : donnees accessibles, escalade possible, etc.",
      "remediation": "Correction specifique avec exemple de code corrige",
      "references": ["CWE-89", "OWASP SQLi", "CVE similaires"]
    }
  ]
}

Si le code est correctement protege (prepared statements, ORM bien utilise, validation adequate), indique-le explicitement avec un objet "secure_patterns" listant les bonnes pratiques observees.
</output_format>

<constraints>
- Ne rapporte JAMAIS une vulnerabilite SQLi dont tu n'es pas sur. Utilise le champ "confidence" pour indiquer ton niveau de certitude.
- Si tu ne peux pas construire un PoC concret (payload fonctionnel), indique "PoC non demontrable" et explique pourquoi.
- Distingue explicitement les vulnerabilites CONFIRMEES des SUSPICIONS (confidence: Low).
- Ne genere PAS de findings generiques type "il faudrait verifier les requetes SQL". Soit c'est un finding concret avec un chemin source-to-sink identifie, soit tu ne le rapportes pas.
- Priorise TOUJOURS l'exploitabilite reelle sur la possibilite theorique.
- Si le code utilise correctement des prepared statements partout, dis-le explicitement plutot que de chercher des faux positifs.
- Attention aux faux positifs courants :
  - Noms de colonnes/tables dynamiques (pas toujours exploitable si valides via allowlist)
  - ORM queries qui semblent dynamiques mais sont parametrees en interne
  - Valeurs numeriques castees en int avant insertion dans la requete
- Ne confonds pas string formatting dans des logs/messages avec string formatting dans des requetes SQL.
- Pour le scoring CVSS : une SQLi non authentifiee avec acces complet aux donnees = Critical (9.8). Une SQLi authentifiee avec acces limite = High (7.x-8.x). Une blind SQLi avec extraction lente = ajuster selon le contexte.
</constraints>
```

---

## Prefill (pour l'API Anthropic)

```json
{"findings": [
```

> **Note** : En utilisant ce prefill dans le champ `assistant` de l'API, le modele continuera directement en JSON structure sans preambule textuel.

---

## Few-Shot Examples

### Exemple 1 : Python f-string SQL Injection

```xml
<examples>
Voici un exemple de finding attendu pour calibrer ton analyse :

**Code source analyse :**
```python
# app/views/users.py
from flask import Flask, request
import psycopg2

app = Flask(__name__)

@app.route('/api/users/search')
def search_users():
    username = request.args.get('username', '')
    conn = psycopg2.connect("dbname=myapp user=appuser")
    cur = conn.cursor()
    # Vulnerable: f-string interpolation in SQL query
    cur.execute(f"SELECT id, username, email FROM users WHERE username LIKE '%{username}%'")
    results = cur.fetchall()
    return jsonify(results)

@app.route('/api/users/<int:user_id>')
def get_user(user_id):
    conn = psycopg2.connect("dbname=myapp user=appuser")
    cur = conn.cursor()
    # Secure: parameterized query
    cur.execute("SELECT id, username, email FROM users WHERE id = %s", (user_id,))
    result = cur.fetchone()
    return jsonify(result)
```

**Finding attendu :**
{
  "id": "SQLI-001",
  "title": "SQL Injection via f-string interpolation dans la recherche utilisateur",
  "severity": "Critical",
  "cvss_score": 9.8,
  "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
  "vulnerability_class": "CWE-89: SQL Injection",
  "confidence": "High",
  "affected_component": "app/views/users.py:11 - fonction search_users()",
  "description": "Le parametre GET 'username' est directement interpole dans une requete SQL via une f-string Python. Aucune sanitization ni parametrisation n'est appliquee. L'endpoint /api/users/search est accessible sans authentification, permettant a n'importe quel attaquant d'injecter du SQL arbitraire dans la clause WHERE.",
  "root_cause": "Utilisation d'une f-string Python (f\"...\") pour construire la requete SQL au lieu d'utiliser les placeholders de psycopg2. La variable 'username' provenant de request.args.get() est inseree directement dans la chaine SQL sans echappement.",
  "proof_of_concept": "# Extraction de la version PostgreSQL\ncurl 'https://target.com/api/users/search?username=test%27%20UNION%20SELECT%20NULL,version(),NULL--'\n\n# Extraction des tables\ncurl 'https://target.com/api/users/search?username=test%27%20UNION%20SELECT%20NULL,table_name,NULL%20FROM%20information_schema.tables--'\n\n# Extraction des credentials\ncurl 'https://target.com/api/users/search?username=test%27%20UNION%20SELECT%20id,username,password_hash%20FROM%20users--'\n\n# Time-based confirmation\ncurl 'https://target.com/api/users/search?username=test%27%3B%20SELECT%20pg_sleep(5)--'",
  "impact": "Acces complet en lecture a toute la base de donnees PostgreSQL, incluant les tables utilisateurs (credentials), donnees personnelles, et potentiellement des secrets applicatifs. Possibilite d'ecriture/modification de donnees via des statements UPDATE/INSERT/DELETE. Potentielle escalade vers une lecture de fichiers systeme via pg_read_file() si le role PostgreSQL a les privileges suffisants.",
  "remediation": "Remplacer la f-string par une requete parametree :\n\n```python\n# AVANT (vulnerable)\ncur.execute(f\"SELECT id, username, email FROM users WHERE username LIKE '%{username}%'\")\n\n# APRES (securise)\ncur.execute(\"SELECT id, username, email FROM users WHERE username LIKE %s\", (f'%{username}%',))\n```\n\nNote : le get_user() sur la ligne 18 utilise correctement les placeholders psycopg2 - ce pattern est a generaliser.",
  "references": [
    "CWE-89: Improper Neutralization of Special Elements used in an SQL Command",
    "https://owasp.org/www-community/attacks/SQL_Injection",
    "https://www.psycopg.org/docs/usage.html#query-parameters",
    "CVE-2024-23334 - Similaire: SQLi via string formatting en Python"
  ]
}

**Observation sur le code securise :**
La fonction get_user() ligne 18 utilise correctement les placeholders psycopg2 (%s avec tuple), ce qui constitue une protection efficace contre l'injection SQL. Le cast <int:user_id> dans la route Flask ajoute une couche de validation supplementaire.
</examples>
```

### Exemple 2 : Second-Order SQL Injection

```xml
<examples>
**Scenario second-order :**
```php
// register.php - L'inscription stocke le nom d'utilisateur tel quel
$username = $_POST['username']; // Attaquant enregistre: admin'--
$stmt = $pdo->prepare("INSERT INTO users (username, email) VALUES (?, ?)");
$stmt->execute([$username, $email]); // Securise ici avec prepared statement

// profile.php - Mais la requete de profil reutilise la valeur stockee
$user = getUserFromSession(); // Retourne l'objet user avec username = "admin'--"
$query = "SELECT * FROM posts WHERE author = '" . $user->username . "'";
$result = $pdo->query($query); // VULNERABLE : second-order SQLi
```

**Finding attendu :**
{
  "id": "SQLI-002",
  "title": "Second-Order SQL Injection via username stocke reutilise dans une requete non parametree",
  "severity": "High",
  "cvss_score": 8.8,
  "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
  "vulnerability_class": "CWE-89: SQL Injection (Second Order)",
  "confidence": "High",
  "affected_component": "profile.php:4 - requete de recuperation des posts",
  "description": "Bien que l'insertion du username soit correctement parametree dans register.php, la valeur stockee en base est reutilisee sans parametrisation dans profile.php. Un attaquant peut enregistrer un compte avec un username contenant du SQL malveillant (ex: admin'--), qui sera execute lors de la consultation du profil.",
  "root_cause": "Confiance implicite dans les donnees provenant de la base de donnees. Le developpeur a securise l'insertion (prepared statement) mais pas la lecture subsequente qui reutilise la valeur stockee via concatenation directe.",
  "proof_of_concept": "# Etape 1 : Enregistrement avec payload SQLi dans le username\ncurl -X POST https://target.com/register.php -d \"username=test' UNION SELECT id,username,password_hash,NULL FROM users--&email=attacker@evil.com&password=test123\"\n\n# Etape 2 : Se connecter et visiter le profil pour declencher la requete\ncurl -b session=ATTACKER_SESSION https://target.com/profile.php\n# La requete executee sera : SELECT * FROM posts WHERE author = 'test' UNION SELECT id,username,password_hash,NULL FROM users--'",
  "impact": "Extraction de donnees sensibles de la base de donnees, incluant les hash de mots de passe des autres utilisateurs. Le contexte authentifie (PR:L) limite legerement le CVSS mais l'impact reste eleve car l'attaquant peut creer un compte librement.",
  "remediation": "Parametrer TOUTES les requetes SQL, y compris celles utilisant des donnees provenant de la base :\n\n```php\n// AVANT (vulnerable)\n$query = \"SELECT * FROM posts WHERE author = '\" . $user->username . \"'\";\n$result = $pdo->query($query);\n\n// APRES (securise)\n$stmt = $pdo->prepare(\"SELECT * FROM posts WHERE author = ?\");\n$stmt->execute([$user->username]);\n$result = $stmt->fetchAll();\n```\n\nRegle generale : ne JAMAIS faire confiance aux donnees de la base - elles peuvent avoir ete injectees.",
  "references": [
    "CWE-89: SQL Injection",
    "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection#second-order-sql-injection",
    "https://portswigger.net/kb/issues/00100210_sql-injection-second-order"
  ]
}
</examples>
```
