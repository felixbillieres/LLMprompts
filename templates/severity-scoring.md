# Guide de Scoring CVSS 3.1 pour Findings LLM

## Référence Rapide

| Severity | Score Range | Exemples Typiques |
|----------|-------------|-------------------|
| **Critical** | 9.0 - 10.0 | RCE non-authentifié, SQLi avec accès DB complet, Auth bypass complet |
| **High** | 7.0 - 8.9 | RCE authentifié, SSRF vers metadata cloud, Privilege escalation |
| **Medium** | 4.0 - 6.9 | XSS stocké, IDOR, Information disclosure sensible |
| **Low** | 0.1 - 3.9 | XSS réfléchi avec interaction, Rate limiting absent, Headers manquants |
| **Info** | 0.0 | Bonnes pratiques, observations sans impact sécurité direct |

## Vecteur CVSS 3.1 - Aide Mémoire

```
CVSS:3.1/AV:[NALP]/AC:[LH]/PR:[NLH]/UI:[NR]/S:[UC]/C:[NLH]/I:[NLH]/A:[NLH]
```

### Attack Vector (AV)
| Valeur | Description | Exemples |
|--------|-------------|----------|
| **N** (Network) | Exploitable à distance via réseau | Web apps, APIs, services exposés |
| **A** (Adjacent) | Réseau local requis | Bluetooth, WiFi, LAN |
| **L** (Local) | Accès local requis | Malware, privilege escalation locale |
| **P** (Physical) | Accès physique requis | USB attacks, cold boot |

### Attack Complexity (AC)
| Valeur | Description |
|--------|-------------|
| **L** (Low) | Pas de conditions spéciales requises |
| **H** (High) | Race condition, config spécifique, MITM requis |

### Privileges Required (PR)
| Valeur | Description |
|--------|-------------|
| **N** (None) | Aucune authentification requise |
| **L** (Low) | Compte utilisateur standard |
| **H** (High) | Compte admin/privilégié |

### User Interaction (UI)
| Valeur | Description |
|--------|-------------|
| **N** (None) | Aucune interaction utilisateur |
| **R** (Required) | Clic, visite de page, ouverture de fichier |

### Scope (S)
| Valeur | Description |
|--------|-------------|
| **U** (Unchanged) | Impact limité au composant vulnérable |
| **C** (Changed) | Impact sur d'autres composants (ex: XSS affecte le navigateur) |

### Confidentiality / Integrity / Availability (C/I/A)
| Valeur | Description |
|--------|-------------|
| **N** (None) | Aucun impact |
| **L** (Low) | Impact partiel/limité |
| **H** (High) | Impact total |

## Patterns Courants en Bug Bounty

### Critical (9.0+)
```
# RCE non-authentifié
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H  → 9.8

# SQLi avec accès complet
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H  → 9.8

# Auth bypass complet
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N  → 9.1
```

### High (7.0-8.9)
```
# SSRF vers cloud metadata
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N  → 8.6

# Privilege escalation (user → admin)
CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H  → 8.8

# RCE authentifié (user standard)
CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H  → 8.8
```

### Medium (4.0-6.9)
```
# XSS stocké
CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N  → 5.4

# IDOR (accès données autres utilisateurs)
CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N  → 6.5

# Information disclosure (tokens, clés)
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N  → 5.3
```

## Règles pour les Prompts LLM

Quand tu scores un finding :

1. **Sois conservateur** : en cas de doute entre deux niveaux, choisis le plus bas
2. **L'exploitabilité prime** : un bug théorique High est un Medium pratique si l'exploitation est complexe
3. **Le contexte compte** : un XSS sur une page de login est plus critique qu'un XSS sur une page 404
4. **Chaînage** : mentionne si le score augmente via chaînage avec d'autres vulns (dans `exploitation_chain`)
5. **Prerequisites** : documente les conditions d'exploitation dans le champ `prerequisites`
