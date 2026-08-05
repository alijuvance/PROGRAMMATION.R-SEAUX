#!/usr/bin/env python3
"""
IDS Réseau — Système de Détection d'Intrusion Léger
====================================================
Détecte en temps réel :
  • Scan de ports (SYN scan / TCP connect)
  • SYN Flood / DoS
  • ARP Spoofing (Man-in-the-Middle)

Usage :
  python src/ids_detecteur.py                         # Interface auto-détectée
  python src/ids_detecteur.py -i "Wi-Fi"              # Interface spécifique
  python src/ids_detecteur.py --list-interfaces       # Lister les interfaces
  python src/ids_detecteur.py --seuil-scan 10         # Seuil scan personnalisé
"""

from scapy.all import sniff, IP, TCP, ARP, get_if_list, conf
from collections import defaultdict
from datetime import datetime, timedelta
import logging
import argparse
import json
import os
import sys

# ═══════════════════════════════════════════════════════════
#  RÉSOLUTION DES CHEMINS
# ═══════════════════════════════════════════════════════════
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(SCRIPT_DIR)
LOGS_DIR = os.path.join(PROJECT_DIR, "logs")
os.makedirs(LOGS_DIR, exist_ok=True)

LOG_TEXT = os.path.join(LOGS_DIR, "ids_alertes.log")
LOG_JSON = os.path.join(LOGS_DIR, "ids_alertes.jsonl")

# ═══════════════════════════════════════════════════════════
#  CONFIGURATION DU LOGGING — UTF-8 EXPLICITE
# ═══════════════════════════════════════════════════════════
logging.basicConfig(
    filename=LOG_TEXT,
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    encoding="utf-8"
)

# ═══════════════════════════════════════════════════════════
#  PARAMÈTRES DE DÉTECTION (valeurs par défaut)
# ═══════════════════════════════════════════════════════════
FENETRE_SCAN = 10       # Fenêtre d'observation pour les scans (secondes)
SEUIL_PORTS  = 15       # Ports distincts → alerte scan
FENETRE_FLOOD = 5       # Fenêtre d'observation pour les floods (secondes)
SEUIL_SYN    = 50       # Nombre de SYN → alerte flood
COOLDOWN_ALERTE = 30    # Cooldown entre alertes du même type / même IP

# ═══════════════════════════════════════════════════════════
#  ÉTATS INTERNES (mémoire de travail du détecteur)
# ═══════════════════════════════════════════════════════════
historique_scan  = defaultdict(list)   # {ip: [(port, timestamp), ...]}
historique_flood = defaultdict(list)   # {ip: [timestamp, ...]}
derniere_alerte_scan  = {}             # {ip: datetime}
derniere_alerte_flood = {}             # {ip: datetime}
table_arp_connue      = {}             # {ip: mac} — table de référence
derniere_alerte_arp   = {}             # {ip: datetime}

# ═══════════════════════════════════════════════════════════
#  COMPTEURS DE SESSION
# ═══════════════════════════════════════════════════════════
stats = {
    "total": 0,
    "scans": 0,
    "floods": 0,
    "arp_spoofing": 0,
    "paquets_analyses": 0
}


# ───────────────────────────────────────────────────────────
#  FONCTIONS UTILITAIRES
# ───────────────────────────────────────────────────────────

def ecrire_alerte_json(type_alerte, ip, message, details=None):
    """
    Écrit une alerte structurée en JSON Lines (.jsonl)
    pour consommation par le dashboard temps réel.

    Format : une ligne JSON par alerte, avec timestamp, type,
    sévérité, IP source, message lisible, et détails techniques.
    """
    alerte = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "type": type_alerte,
        "severity": "WARNING",
        "ip": ip,
        "message": message,
        "details": details or {}
    }
    with open(LOG_JSON, "a", encoding="utf-8") as f:
        f.write(json.dumps(alerte, ensure_ascii=False) + "\n")


def alerter(message, type_alerte="SCAN", ip="unknown", details=None, niveau="warning"):
    """
    Point d'entrée centralisé pour toute alerte :
    1. Affiche dans le terminal (avec emoji 🚨)
    2. Écrit dans le log texte (ids_alertes.log)
    3. Écrit dans le log JSON (ids_alertes.jsonl)
    4. Incrémente les compteurs de session
    """
    print(f"🚨 {message}")
    if niveau == "warning":
        logging.warning(message)
    else:
        logging.info(message)
    ecrire_alerte_json(type_alerte, ip, message, details)
    stats["total"] += 1


def nettoyer(liste, fenetre):
    """
    Supprime les entrées plus vieilles que la fenêtre temporelle.
    
    Gère deux formats :
    - Tuples (port, timestamp) pour l'historique scan
    - Timestamps simples pour l'historique flood
    
    C'est le cœur de l'algorithme à fenêtre glissante :
    on ne garde que les événements récents pour l'analyse.
    """
    limite = datetime.now() - timedelta(seconds=fenetre)
    return [t for t in liste if (t[1] if isinstance(t, tuple) else t) > limite]


# ───────────────────────────────────────────────────────────
#  DÉTECTION : SCAN DE PORTS
# ───────────────────────────────────────────────────────────

def detecter_scan(ip):
    """
    Détecte un scan de ports par la DIVERSITÉ des ports ciblés.
    
    Signature : une IP contacte de nombreux ports distincts
    dans une courte fenêtre temporelle → reconnaissance réseau.
    
    Algorithme :
    1. Extraire les ports uniques depuis l'historique (set)
    2. Comparer la cardinalité au seuil
    3. Vérifier le cooldown pour éviter le spam d'alertes
    """
    ports_distincts = {port for (port, t) in historique_scan[ip]}
    if len(ports_distincts) >= SEUIL_PORTS:
        maintenant = datetime.now()
        derniere = derniere_alerte_scan.get(ip)
        if derniere is None or (maintenant - derniere).total_seconds() > COOLDOWN_ALERTE:
            alerter(
                f"SCAN DE PORTS suspecté depuis {ip} "
                f"({len(ports_distincts)} ports distincts en {FENETRE_SCAN}s)",
                type_alerte="SCAN", ip=ip,
                details={"ports_count": len(ports_distincts), "window": FENETRE_SCAN}
            )
            stats["scans"] += 1
            derniere_alerte_scan[ip] = maintenant


# ───────────────────────────────────────────────────────────
#  DÉTECTION : SYN FLOOD / DoS
# ───────────────────────────────────────────────────────────

def detecter_flood(ip):
    """
    Détecte un SYN flood par le VOLUME de paquets SYN.
    
    Signature : une IP envoie un grand nombre de SYN
    en très peu de temps → tentative de saturation du backlog TCP.
    
    Différence avec le scan :
    - Scan = diversité de ports (beaucoup de ports différents)
    - Flood = volume brut (beaucoup de SYN, même sur peu de ports)
    """
    if len(historique_flood[ip]) >= SEUIL_SYN:
        maintenant = datetime.now()
        derniere = derniere_alerte_flood.get(ip)
        if derniere is None or (maintenant - derniere).total_seconds() > COOLDOWN_ALERTE:
            alerter(
                f"SYN FLOOD / DoS suspecté depuis {ip} "
                f"({len(historique_flood[ip])} SYN en {FENETRE_FLOOD}s)",
                type_alerte="FLOOD", ip=ip,
                details={"syn_count": len(historique_flood[ip]), "window": FENETRE_FLOOD}
            )
            stats["floods"] += 1
            derniere_alerte_flood[ip] = maintenant


# ───────────────────────────────────────────────────────────
#  DÉTECTION : ARP SPOOFING
# ───────────────────────────────────────────────────────────

def detecter_arp_spoofing(ip, nouvelle_mac):
    """
    Détecte un changement de MAC pour une IP déjà connue.
    
    Principe (inspiré d'arpwatch) :
    1. On apprend les correspondances IP↔MAC au fil du temps
    2. Si une IP connue annonce soudain une MAC différente
       → possible ARP spoofing / Man-in-the-Middle
    
    Faille exploitée : ARP ne possède aucun mécanisme
    d'authentification — n'importe qui peut envoyer des
    ARP Reply avec de fausses informations.
    """
    if ip in table_arp_connue:
        mac_connue = table_arp_connue[ip]
        if mac_connue != nouvelle_mac:
            maintenant = datetime.now()
            derniere = derniere_alerte_arp.get(ip)
            if derniere is None or (maintenant - derniere).total_seconds() > COOLDOWN_ALERTE:
                alerter(
                    f"ARP SPOOFING : {ip} était connue avec la MAC {mac_connue}, "
                    f"mais on voit maintenant {nouvelle_mac} !",
                    type_alerte="ARP_SPOOF", ip=ip,
                    details={"mac_connue": mac_connue, "mac_nouvelle": nouvelle_mac}
                )
                stats["arp_spoofing"] += 1
                derniere_alerte_arp[ip] = maintenant
    else:
        # Première fois qu'on voit cette IP → on l'apprend
        table_arp_connue[ip] = nouvelle_mac
        message = f"Nouvelle IP apprise (ARP) : {ip} -> {nouvelle_mac}"
        print(f"[INFO] {message}")
        logging.info(message)


# ───────────────────────────────────────────────────────────
#  ANALYSE PRINCIPALE DE CHAQUE PAQUET
# ───────────────────────────────────────────────────────────

def analyser_paquet(paquet):
    """
    Point d'entrée appelé par Scapy pour chaque paquet capturé.
    
    Deux branches :
    - TCP (couche 4) : détection scan + flood via le flag SYN
    - ARP (couche 2-3) : détection spoofing via les Reply
    """
    stats["paquets_analyses"] += 1

    # ─── Branche TCP : scan + flood ───
    if paquet.haslayer(IP) and paquet.haslayer(TCP):
        if paquet[TCP].flags == "S":  # Flag SYN uniquement
            ip_src = paquet[IP].src
            port_dst = paquet[TCP].dport
            maintenant = datetime.now()

            # Enregistrer pour détection de scan (port + timestamp)
            historique_scan[ip_src].append((port_dst, maintenant))
            historique_scan[ip_src] = nettoyer(historique_scan[ip_src], FENETRE_SCAN)
            detecter_scan(ip_src)

            # Enregistrer pour détection de flood (timestamp seul)
            historique_flood[ip_src].append(maintenant)
            historique_flood[ip_src] = nettoyer(historique_flood[ip_src], FENETRE_FLOOD)
            detecter_flood(ip_src)

    # ─── Branche ARP : spoofing ───
    elif paquet.haslayer(ARP):
        if paquet[ARP].op == 2:  # op=2 → ARP Reply uniquement
            ip_annoncee = paquet[ARP].psrc
            mac_annoncee = paquet[ARP].hwsrc
            detecter_arp_spoofing(ip_annoncee, mac_annoncee)


# ───────────────────────────────────────────────────────────
#  UTILITAIRE : LISTE DES INTERFACES
# ───────────────────────────────────────────────────────────

def lister_interfaces():
    """Affiche toutes les interfaces réseau disponibles."""
    print("\n" + "=" * 48)
    print("   Interfaces reseau disponibles")
    print("=" * 48 + "\n")
    for i, iface in enumerate(get_if_list(), 1):
        marker = "  ← (défaut)" if iface == conf.iface else ""
        print(f"  {i:2d}. {iface}{marker}")
    print()


# ───────────────────────────────────────────────────────────
#  POINT D'ENTRÉE
# ───────────────────────────────────────────────────────────

def main():
    global SEUIL_PORTS, SEUIL_SYN

    parser = argparse.ArgumentParser(
        description="🛡️ IDS Réseau — Système de Détection d'Intrusion Léger",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples :
  python ids_detecteur.py                     Interface par défaut
  python ids_detecteur.py -i "Wi-Fi"          Interface Wi-Fi
  python ids_detecteur.py --list-interfaces   Lister les interfaces
  python ids_detecteur.py --seuil-scan 10     Seuil scan abaissé (démo)
        """
    )
    parser.add_argument(
        "-i", "--interface", default=None,
        help="Nom de l'interface réseau à surveiller (défaut: auto-détection)"
    )
    parser.add_argument(
        "--list-interfaces", action="store_true",
        help="Liste les interfaces réseau disponibles et quitte"
    )
    parser.add_argument(
        "--seuil-scan", type=int, default=SEUIL_PORTS,
        help=f"Seuil de ports distincts pour alerte scan (défaut: {SEUIL_PORTS})"
    )
    parser.add_argument(
        "--seuil-flood", type=int, default=SEUIL_SYN,
        help=f"Seuil de SYN pour alerte flood (défaut: {SEUIL_SYN})"
    )

    args = parser.parse_args()

    if args.list_interfaces:
        lister_interfaces()
        sys.exit(0)

    interface = args.interface or conf.iface
    SEUIL_PORTS = args.seuil_scan
    SEUIL_SYN = args.seuil_flood

    import sys
    sys.stdout.reconfigure(encoding="utf-8")

    # --- Banniere de demarrage ---
    print()
    print("=" * 58)
    print("   IDS RESEAU -- Systeme de Detection d'Intrusion")
    print("=" * 58)
    print(f"  Interface  : {interface}")
    print(f"  Scan       : {SEUIL_PORTS} ports distincts en {FENETRE_SCAN}s")
    print(f"  Flood      : {SEUIL_SYN} SYN en {FENETRE_FLOOD}s")
    print(f"  ARP        : detection par table de reference")
    print(f"  Cooldown   : {COOLDOWN_ALERTE}s")
    print(f"  Log texte  : logs/ids_alertes.log")
    print(f"  Log JSON   : logs/ids_alertes.jsonl")
    print("=" * 58)
    print("\n  En attente de paquets...\n")

    logging.info(f"Démarrage de l'IDS sur {interface}")

    try:
        sniff(prn=analyser_paquet, iface=interface, store=False)
    except KeyboardInterrupt:
        print(f"\n\n{'=' * 50}")
        print("  Statistiques de session")
        print(f"{'=' * 50}")
        print(f"  Paquets analyses : {stats['paquets_analyses']}")
        print(f"  Alertes totales  : {stats['total']}")
        print(f"    Scans          : {stats['scans']}")
        print(f"    Floods         : {stats['floods']}")
        print(f"    ARP spoofing   : {stats['arp_spoofing']}")
        print(f"\n  IDS arrete proprement.\n")
    except PermissionError:
        print("\nErreur : Privileges administrateur requis.")
        print("   Lancez le terminal en tant qu'administrateur.\n")
        sys.exit(1)


if __name__ == "__main__":
    main()
