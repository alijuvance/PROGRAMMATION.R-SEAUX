# 📚 Guide Complet des Concepts Réseau — IDS

> **Objectif** : Comprendre chaque concept utilisé dans le projet pour pouvoir
> l'expliquer clairement lors de la présentation.

---

## Table des Matières

1. [Le Modèle TCP/IP et les Couches Réseau](#1-le-modèle-tcpip)
2. [Protocole TCP — La Poignée de Main](#2-protocole-tcp)
3. [Scan de Ports — Technique SYN Scan](#3-scan-de-ports)
4. [SYN Flood — Attaque par Déni de Service](#4-syn-flood)
5. [Protocole ARP](#5-protocole-arp)
6. [ARP Spoofing — Man-in-the-Middle](#6-arp-spoofing)
7. [Algorithme de Détection : Fenêtre Glissante](#7-fenêtre-glissante)
8. [Cooldown et Alert Fatigue](#8-cooldown)
9. [Qu'est-ce qu'un IDS ?](#9-quest-ce-quun-ids)
10. [Technologies Utilisées](#10-technologies)

---

## 1. Le Modèle TCP/IP

Le modèle TCP/IP organise les communications réseau en **4 couches** :

```
┌─────────────────────────────────┐
│   4. Application (HTTP, DNS)    │  ← Ce que l'utilisateur voit
├─────────────────────────────────┤
│   3. Transport (TCP, UDP)       │  ← Fiabilité, ports, SYN/ACK
├─────────────────────────────────┤
│   2. Internet (IP)              │  ← Adressage IP, routage
├─────────────────────────────────┤
│   1. Accès réseau (Ethernet)    │  ← Adresses MAC, ARP
└─────────────────────────────────┘
```

**Notre IDS opère sur les couches 1 à 3** :
- **Couche 1 (Ethernet/ARP)** : Détection ARP Spoofing
- **Couche 2 (IP)** : Identification des IPs sources
- **Couche 3 (TCP)** : Analyse des flags SYN pour scan et flood

### Termes clés
- **Paquet** : Unité de données transmise sur le réseau
- **Trame Ethernet** : Paquet au niveau de la couche liaison (contient les adresses MAC)
- **Segment TCP** : Paquet au niveau de la couche transport

---

## 2. Protocole TCP — La Poignée de Main

TCP (Transmission Control Protocol) établit des connexions **fiables** grâce à un processus en 3 étapes appelé **Three-Way Handshake** :

```
   Client                    Serveur
     │                          │
     │──── SYN (j'existe) ─────→│   Étape 1 : Le client initie
     │                          │
     │←── SYN-ACK (ok, moi aussi)│  Étape 2 : Le serveur accepte
     │                          │
     │──── ACK (c'est parti) ──→│   Étape 3 : Connexion établie
     │                          │
     │←────── Données ─────────→│   Communication bidirectionnelle
```

### Les Flags TCP
Un paquet TCP contient des **flags** (drapeaux) qui indiquent son rôle :

| Flag | Signification | Rôle |
|:---|:---|:---|
| **SYN** | Synchronize | Demande d'ouverture de connexion |
| **ACK** | Acknowledge | Confirmation de réception |
| **FIN** | Finish | Demande de fermeture propre |
| **RST** | Reset | Fermeture brutale / rejet |
| **PSH** | Push | Données urgentes à transmettre |

### Le Backlog TCP
Quand le serveur reçoit un SYN, il **réserve de la mémoire** pour cette connexion en attente.
Cette mémoire est stockée dans une structure appelée **TCB** (Transmission Control Block),
dans une file d'attente appelée **backlog**. C'est cette mécanique que le SYN flood exploite.

---

## 3. Scan de Ports — Technique SYN Scan

### Qu'est-ce qu'un scan de ports ?
Un attaquant envoie des paquets vers de nombreux ports d'une cible pour découvrir
quels **services** sont actifs (serveur web sur le port 80, SSH sur le port 22, etc.).

### Le SYN Scan (Half-Open Scan)
Technique utilisée par **nmap** (`nmap -sS`) :

```
   Scanner                   Cible
     │                         │
     │──── SYN ───────────────→│  "Est-ce que le port 80 est ouvert ?"
     │                         │
     │←── SYN-ACK ────────────│  Port OUVERT (le serveur répond)
     │                         │
     │──── RST ───────────────→│  On coupe immédiatement (pas d'ACK !)
     │                         │
     │──── SYN ───────────────→│  "Et le port 22 ?"
     │←── RST ────────────────│  Port FERMÉ (le serveur rejette)
```

**Pourquoi "half-open" ?** Parce que la poignée de main n'est **jamais terminée** :
le scanner envoie RST au lieu de ACK, donc la connexion n'est jamais établie.
Le serveur ne garde pas de trace complète → plus discret.

### Comment notre IDS détecte ça
**Signature : diversité de ports**

Peu importe que le scan soit half-open ou complet, le scanner doit **toujours**
commencer par envoyer un SYN. Notre détecteur :
1. Capture chaque paquet avec `flags == "S"` (SYN pur)
2. Enregistre `(port_destination, timestamp)` par IP source
3. Compte les ports **distincts** dans une fenêtre de 10 secondes
4. Si ≥ 15 ports distincts → **ALERTE SCAN**

---

## 4. SYN Flood — Attaque par Déni de Service

### Principe de l'attaque
L'attaquant envoie des **milliers de SYN** sans jamais compléter la poignée de main :

```
   Attaquant                 Serveur
     │──── SYN ──────────────→│  Le serveur alloue un TCB (mémoire)
     │──── SYN ──────────────→│  Le serveur alloue encore...
     │──── SYN ──────────────→│  Encore...
     │──── SYN ──────────────→│  Le backlog se remplit...
     │──── SYN ──────────────→│  
     │       ...               │  
     │──── SYN ──────────────→│  ❌ BACKLOG PLEIN !
     │                         │
     Utilisateur ── SYN ──────→│  ❌ Connexion refusée (DoS)
```

Le serveur attend les ACK qui ne viendront jamais, pendant que sa mémoire
se sature → les utilisateurs légitimes ne peuvent plus se connecter.

### Différence entre Scan et Flood

| Caractéristique | Scan de ports | SYN Flood |
|:---|:---|:---|
| **Objectif** | Reconnaissance (découvrir les services) | Déni de service (rendre indisponible) |
| **Signature** | Beaucoup de ports **différents** | Beaucoup de SYN sur **peu de ports** |
| **Volume** | Modéré (quelques centaines) | Massif (des milliers par seconde) |
| **Détection** | Diversité des ports ciblés | Volume brut de paquets SYN |

### Comment notre IDS détecte ça
**Signature : volume de SYN**
1. Compte le nombre **total** de SYN par IP source
2. Fenêtre de 5 secondes
3. Si ≥ 50 SYN dans la fenêtre → **ALERTE FLOOD**

---

## 5. Protocole ARP

### Rôle d'ARP
ARP (Address Resolution Protocol) fait le lien entre les **adresses IP** (couche 3)
et les **adresses MAC** (couche 2).

Pourquoi ? Parce que les switches Ethernet ne comprennent que les adresses MAC,
mais les applications utilisent des adresses IP.

### Fonctionnement

```
   PC-A (192.168.1.10)                    PC-B (192.168.1.20)
   MAC: AA:AA:AA:AA:AA:AA                 MAC: BB:BB:BB:BB:BB:BB
     │                                       │
     │── ARP Request (broadcast) ────────────→│  "Qui a 192.168.1.20 ?"
     │   (envoyé à ff:ff:ff:ff:ff:ff)        │  (tout le monde reçoit)
     │                                       │
     │←── ARP Reply (unicast) ──────────────│  "C'est moi ! MAC = BB:BB..."
     │                                       │
     │   [Cache ARP mis à jour]              │
     │   192.168.1.20 → BB:BB:BB:BB:BB:BB   │
```

### La table ARP (cache)
Chaque machine maintient un **cache ARP** : une table qui associe les IP aux MAC.
Elle évite de refaire une résolution ARP à chaque paquet envoyé.

```
> arp -a     (commande Windows)
192.168.1.1    →  AA:11:22:33:44:55  (routeur)
192.168.1.20   →  BB:BB:BB:BB:BB:BB  (PC-B)
```

---

## 6. ARP Spoofing — Man-in-the-Middle

### La faille structurelle d'ARP
**ARP n'a aucun mécanisme d'authentification.** N'importe qui peut envoyer
un ARP Reply en disant "l'IP X, c'est moi" — et les autres machines le croient.

### L'attaque

```
   Attaquant (192.168.1.99)
   MAC: CC:CC:CC:CC:CC:CC
     │
     │── Faux ARP Reply ──→ "192.168.1.1 (le routeur) = MAC CC:CC..."
     │                      (envoyé à tout le réseau)
     │
     │   Résultat : toutes les machines croient que le routeur
     │   a la MAC de l'attaquant → elles envoient leur trafic
     │   Internet vers l'attaquant au lieu du routeur !
     │
     │   C'est l'attaque Man-in-the-Middle (MITM)
```

### Comment notre IDS détecte ça
**Détection par table de référence** (inspiré d'**arpwatch**) :
1. Le script **apprend** les correspondances IP↔MAC au démarrage
2. Pour chaque ARP Reply reçu (`op == 2`), il compare la MAC annoncée
   avec celle qu'il a mémorisée
3. Si la MAC a changé → **ALERTE ARP SPOOFING**

---

## 7. Algorithme de Détection : Fenêtre Glissante

### Concept
Plutôt que de compter les événements depuis le début (ce qui serait inutile),
on ne regarde que les **N dernières secondes**. C'est la **fenêtre glissante** (sliding window).

### Fonctionnement

```
Temps:  [======== fenêtre de 10s ========]
        t-10s                            t (maintenant)
        
Événements dans la fenêtre :
  t-8s: SYN → port 80
  t-6s: SYN → port 443
  t-4s: SYN → port 22
  t-2s: SYN → port 21
  t-1s: SYN → port 25
  
→ 5 ports distincts (en dessous du seuil de 15)
→ Pas d'alerte

... un scan massif arrive ...

  t-3s: SYN → port 80...90 (11 ports)
  t-2s: SYN → port 91...100 (10 ports)
  
→ 21 ports distincts → ≥ 15 → ALERTE !
```

### Implémentation dans notre code

```python
def nettoyer(liste, fenetre):
    """Supprime les entrées trop vieilles."""
    limite = datetime.now() - timedelta(seconds=fenetre)
    return [t for t in liste if t > limite]
```

On **purge dynamiquement** les entrées obsolètes à chaque nouveau paquet reçu.

---

## 8. Cooldown et Alert Fatigue

### Le problème : Alert Fatigue
Si un attaquant fait un scan massif de 1000 ports, notre détecteur déclencherait
une alerte à chaque nouveau paquet après le seuil → **des centaines d'alertes identiques**.

C'est un vrai problème en sécurité opérationnelle : les opérateurs finissent par
**ignorer les alertes** parce qu'il y en a trop → les vraies menaces passent inaperçues.

### La solution : Cooldown
Après avoir émis une alerte pour une IP, on **bloque les alertes suivantes** pendant
N secondes (30s par défaut) pour la même IP et le même type d'alerte.

```python
COOLDOWN_ALERTE = 30  # secondes

# Avant d'alerter :
if derniere is None or (now - derniere).total_seconds() > COOLDOWN_ALERTE:
    alerter(...)  # OK, on alerte
    derniere_alerte[ip] = now
# Sinon : on ne fait rien (silence temporaire)
```

---

## 9. Qu'est-ce qu'un IDS ?

### Définition
Un **IDS** (Intrusion Detection System) est un système qui surveille le trafic
réseau pour détecter des activités suspectes ou malveillantes.

### Types d'IDS

| Type | Acronyme | Fonctionnement |
|:---|:---|:---|
| **Network IDS** | NIDS | Surveille le trafic réseau (notre projet) |
| **Host IDS** | HIDS | Surveille un seul système (logs, fichiers) |

### Méthodes de détection

| Méthode | Notre projet | Description |
|:---|:---|:---|
| **Par signature** | ✅ | Recherche de motifs connus (ex: beaucoup de SYN) |
| **Par anomalie** | ❌ | Détecte les écarts par rapport au comportement normal |
| **Par spécification** | ❌ | Vérifie le respect des protocoles |

Notre IDS utilise la **détection par signature** : on définit des règles
(seuils, patterns) qui correspondent à des attaques connues.

### IDS célèbres
- **Snort** : IDS open-source le plus utilisé (signatures)
- **Suricata** : Alternative moderne à Snort (multi-thread)
- **OSSEC** : IDS basé sur l'hôte (HIDS)

---

## 10. Technologies Utilisées

### Python + Scapy
**Scapy** est une bibliothèque Python de manipulation de paquets réseau.
Elle permet de :
- **Capturer** des paquets en temps réel (`sniff()`)
- **Analyser** les couches de chaque paquet (`paquet.haslayer(TCP)`)
- **Forger** des paquets personnalisés (`IP()/TCP()`)
- **Envoyer** des paquets bruts (`send()`, `sendp()`)

```python
# Capture avec callback
sniff(prn=analyser_paquet, iface="Wi-Fi", store=False)
```

`store=False` évite de garder tous les paquets en mémoire (important pour une capture longue durée).

### Npcap
Driver Windows nécessaire pour la capture de paquets bruts.
Remplace WinPcap (obsolète). Permet à Scapy d'accéder aux trames Ethernet.

### Flask + WebSocket
- **Flask** : Framework web Python léger pour le dashboard
- **Flask-SocketIO** : Extension WebSocket pour les mises à jour temps réel
- **WebSocket** : Protocole de communication bidirectionnelle (pas de polling HTTP)

```
   Navigateur ←──── WebSocket ────→ Serveur Flask
                    (temps réel,
                     push depuis
                     le serveur)
```

### Chart.js
Bibliothèque JavaScript pour les graphiques interactifs dans le navigateur.

---

## Résumé pour la Présentation

```
┌─────────────────────────────────────────────────────────┐
│                   NOTRE IDS DÉTECTE                      │
├──────────────┬──────────────┬───────────────────────────┤
│  SCAN        │  FLOOD       │  ARP SPOOFING             │
│  de ports    │  SYN / DoS   │  Man-in-the-Middle        │
├──────────────┼──────────────┼───────────────────────────┤
│  Couche 4    │  Couche 4    │  Couche 2-3               │
│  TCP         │  TCP         │  ARP                      │
├──────────────┼──────────────┼───────────────────────────┤
│  Signature : │  Signature : │  Signature :              │
│  diversité   │  volume      │  changement               │
│  de ports    │  de SYN      │  de MAC                   │
├──────────────┼──────────────┼───────────────────────────┤
│  ≥15 ports   │  ≥50 SYN     │  MAC ≠ MAC connue         │
│  en 10s      │  en 5s       │  pour une IP              │
└──────────────┴──────────────┴───────────────────────────┘
```
