from scapy.all import sniff, IP, TCP, ARP
from collections import defaultdict
from datetime import datetime, timedelta
import logging

# --- Configuration du logging (centralisé) ---
logging.basicConfig(
    filename="ids_alertes.log",
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)

# --- Configuration générale ---
INTERFACE = "Connexion au réseau local* 11"

# Scan de ports
FENETRE_SCAN = 10
SEUIL_PORTS = 15

# SYN flood
FENETRE_FLOOD = 5
SEUIL_SYN = 50

# ARP spoofing
COOLDOWN_ALERTE_ARP = 30

# Cooldown commun pour scan/flood
COOLDOWN_ALERTE = 30

# --- États internes ---
historique_scan = defaultdict(list)
historique_flood = defaultdict(list)
derniere_alerte_scan = {}
derniere_alerte_flood = {}

table_arp_connue = {}
derniere_alerte_arp = {}


def alerter(message, niveau="warning"):
    """Affiche et journalise une alerte de façon uniforme."""
    print(f"🚨 {message}")
    if niveau == "warning":
        logging.warning(message)
    else:
        logging.info(message)


def nettoyer(liste, fenetre):
    limite = datetime.now() - timedelta(seconds=fenetre)
    return [t for t in liste if (t[1] if isinstance(t, tuple) else t) > limite]


# --- Détection scan de ports ---
def detecter_scan(ip):
    ports_distincts = {port for (port, t) in historique_scan[ip]}
    if len(ports_distincts) >= SEUIL_PORTS:
        maintenant = datetime.now()
        derniere = derniere_alerte_scan.get(ip)
        if derniere is None or (maintenant - derniere).total_seconds() > COOLDOWN_ALERTE:
            alerter(f"SCAN DE PORTS suspecté depuis {ip} "
                    f"({len(ports_distincts)} ports distincts en {FENETRE_SCAN}s)")
            derniere_alerte_scan[ip] = maintenant


# --- Détection SYN flood ---
def detecter_flood(ip):
    if len(historique_flood[ip]) >= SEUIL_SYN:
        maintenant = datetime.now()
        derniere = derniere_alerte_flood.get(ip)
        if derniere is None or (maintenant - derniere).total_seconds() > COOLDOWN_ALERTE:
            alerter(f"SYN FLOOD / DoS suspecté depuis {ip} "
                    f"({len(historique_flood[ip])} SYN en {FENETRE_FLOOD}s)")
            derniere_alerte_flood[ip] = maintenant


# --- Détection ARP spoofing ---
def detecter_arp_spoofing(ip, nouvelle_mac):
    if ip in table_arp_connue:
        mac_connue = table_arp_connue[ip]
        if mac_connue != nouvelle_mac:
            maintenant = datetime.now()
            derniere = derniere_alerte_arp.get(ip)
            if derniere is None or (maintenant - derniere).total_seconds() > COOLDOWN_ALERTE_ARP:
                alerter(f"ARP SPOOFING : {ip} était connue avec la MAC {mac_connue}, "
                        f"mais on voit maintenant {nouvelle_mac} !")
                derniere_alerte_arp[ip] = maintenant
    else:
        table_arp_connue[ip] = nouvelle_mac
        message = f"Nouvelle IP apprise (ARP) : {ip} -> {nouvelle_mac}"
        print(f"[INFO] {message}")
        logging.info(message)


# --- Analyse principale de chaque paquet capturé ---
def analyser_paquet(paquet):
    # --- Branche TCP : scan + flood ---
    if paquet.haslayer(IP) and paquet.haslayer(TCP):
        if paquet[TCP].flags == "S":
            ip_src = paquet[IP].src
            port_dst = paquet[TCP].dport
            maintenant = datetime.now()

            historique_scan[ip_src].append((port_dst, maintenant))
            historique_scan[ip_src] = nettoyer(historique_scan[ip_src], FENETRE_SCAN)
            detecter_scan(ip_src)

            historique_flood[ip_src].append(maintenant)
            historique_flood[ip_src] = nettoyer(historique_flood[ip_src], FENETRE_FLOOD)
            detecter_flood(ip_src)

    # --- Branche ARP : spoofing ---
    elif paquet.haslayer(ARP):
        if paquet[ARP].op == 2:
            ip_annoncee = paquet[ARP].psrc
            mac_annoncee = paquet[ARP].hwsrc
            detecter_arp_spoofing(ip_annoncee, mac_annoncee)


# --- Démarrage ---
print(f"IDS actif sur l'interface : {INTERFACE}")
print(f"Scan  : {SEUIL_PORTS} ports distincts en {FENETRE_SCAN}s")
print(f"Flood : {SEUIL_SYN} SYN en {FENETRE_FLOOD}s")
print(f"ARP   : détection par table de référence")
print(f"Cooldown alertes : {COOLDOWN_ALERTE}s\n")

logging.info(f"Démarrage de l'IDS unifié sur {INTERFACE}")
sniff(prn=analyser_paquet, iface=INTERFACE, store=False)