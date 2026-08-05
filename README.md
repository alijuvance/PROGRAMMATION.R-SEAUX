# 🛡️ IDS Réseau — Système de Détection d'Intrusion

Un système de détection d'intrusion réseau (NIDS) léger, écrit en Python, avec dashboard web temps réel. Détecte les scans de ports, les SYN floods, et l'ARP spoofing en analysant le trafic réseau en direct.

---

## 🎯 Fonctionnalités

| Détection | Méthode | Seuil par défaut |
|:---|:---|:---|
| **Scan de ports** | Diversité de ports SYN (fenêtre glissante) | ≥ 15 ports en 10s |
| **SYN Flood / DoS** | Volume de paquets SYN | ≥ 50 SYN en 5s |
| **ARP Spoofing** | Changement de MAC pour une IP connue | Instantané |

**Bonus :**
- 🖥️ Dashboard web temps réel (Flask + WebSocket)
- 📊 Graphique d'activité et statistiques
- 📝 Logging structuré (texte + JSON)
- ⚙️ Configuration par arguments CLI

---

## 📁 Structure du Projet

```
PROGRAMMATION.R-SEAUX/
├── src/
│   ├── ids_detecteur.py        # Script IDS principal (scan + flood + ARP)
│   └── test_simulation.py      # Simulateur d'attaques pour tests
├── dashboard/
│   ├── app.py                  # Serveur Flask + WebSocket
│   ├── templates/
│   │   └── index.html          # Interface web du dashboard
│   └── static/
│       └── style.css           # Styles (thème cybersécurité)
├── logs/                       # Logs générés au runtime
│   ├── ids_alertes.log         # Log texte lisible
│   └── ids_alertes.jsonl       # Log JSON structuré (pour le dashboard)
├── docs/
│   └── concepts_reseau.md      # Guide de tous les concepts réseau
├── requirements.txt            # Dépendances Python
└── README.md                   # Ce fichier
```

---

## ⚙️ Prérequis & Installation

### 1. Système
- **OS** : Windows 10/11 ou Linux
- **Python** : 3.8 ou supérieur
- **Driver** : [Npcap](https://npcap.com/) (Windows uniquement, pour la capture brute)

### 2. Installation des dépendances

```bash
pip install -r requirements.txt
```

---

## 🚀 Utilisation

### Démarrer l'IDS

> ⚠️ Nécessite des **privilèges administrateur** (capture de paquets bruts).

```bash
# Interface réseau auto-détectée
python src/ids_detecteur.py

# Interface spécifique (ex: hotspot téléphone)
python src/ids_detecteur.py -i "Wi-Fi"

# Lister les interfaces disponibles
python src/ids_detecteur.py --list-interfaces

# Seuils personnalisés (pour démonstration)
python src/ids_detecteur.py --seuil-scan 10 --seuil-flood 30
```

### Démarrer le Dashboard Web

```bash
python dashboard/app.py
```
Puis ouvrir **http://localhost:5000** dans un navigateur.

### Tester avec le Simulateur

Depuis un **deuxième PC** (ou un autre terminal avec admin) :

```bash
# Simuler les 3 types d'attaques
python src/test_simulation.py -t <IP_CIBLE> -a all

# Simuler uniquement un scan
python src/test_simulation.py -t <IP_CIBLE> -a scan

# Simuler uniquement un flood
python src/test_simulation.py -t <IP_CIBLE> -a flood

# Simuler uniquement un ARP spoofing
python src/test_simulation.py -t <IP_CIBLE> -a arp
```

### Tester avec Nmap (depuis le 2ème PC)

```bash
# SYN scan (half-open) — nécessite admin
nmap -sS <IP_CIBLE>

# Scan de ports spécifiques
nmap -sS -p 1-100 <IP_CIBLE>
```

---

## 🏗️ Architecture Technique

```
┌──────────────────┐     ┌──────────────────────┐     ┌──────────────────┐
│   RÉSEAU          │     │  IDS DÉTECTEUR        │     │  DASHBOARD WEB   │
│   (paquets)       │────→│  (ids_detecteur.py)   │────→│  (app.py)        │
│                   │     │                      │     │                  │
│  SYN, ARP Reply   │     │  Capture → Analyse   │     │  Flask + SocketIO│
│  depuis le réseau │     │  → Détection → Log   │     │  → Navigateur    │
└──────────────────┘     └────────┬─────────────┘     └────────┬─────────┘
                                  │                            │
                                  ▼                            ▼
                         ┌──────────────────┐     ┌──────────────────────┐
                         │  FICHIERS LOGS    │     │  NAVIGATEUR          │
                         │  ids_alertes.log  │────→│  Alertes temps réel  │
                         │  ids_alertes.jsonl│     │  Stats + graphiques  │
                         └──────────────────┘     └──────────────────────┘
```

### Pipeline de détection
1. **Capture** : Scapy sniffe les trames Ethernet sur l'interface
2. **Filtrage** : Isolation des SYN TCP (`flags == "S"`) et ARP Reply (`op == 2`)
3. **Fenêtre glissante** : Maintenance d'un historique temporel par IP source
4. **Évaluation** : Comparaison aux seuils configurés
5. **Alerte** : Terminal + log texte + log JSON + push WebSocket

---

## 📖 Concepts Réseau

Un guide détaillé de **tous les concepts** utilisés dans ce projet est disponible dans :

📄 **[docs/concepts_reseau.md](docs/concepts_reseau.md)**

Couvre : TCP/IP, poignée de main TCP, SYN scan, SYN flood, ARP, ARP spoofing,
fenêtre glissante, cooldown, IDS, Scapy, Flask, WebSocket.

---

## 📊 Dashboard

Le dashboard web affiche en temps réel :
- **Compteurs animés** : alertes totales, scans, floods, ARP spoofing
- **Timeline** : flux d'alertes avec animations et codes couleur
- **Graphique** : activité sur les 30 dernières minutes
- **Top IPs** : classement des IPs les plus suspectes
- **Notification sonore** : bip subtil à chaque nouvelle alerte

---

## 🔧 Roadmap

- [x] Détection de scan de ports (SYN)
- [x] Détection de SYN flood / DoS
- [x] Détection d'ARP spoofing
- [x] Logging structuré (texte + JSON)
- [x] Dashboard web temps réel
- [x] CLI avec argparse (interface, seuils)
- [ ] Détection de scans furtifs (FIN, NULL, XMAS)
- [ ] Détection de balayage UDP
- [ ] Export des alertes en CSV / PDF
- [ ] Base de données SQLite pour l'historique
