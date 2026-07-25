from scapy.all import sniff, ARP
from datetime import datetime, timedelta
import logging

# --- Configuration du logging ---
logging.basicConfig(
    filename="ids_alertes.log",
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)

INTERFACE = "Connexion au réseau local* 11"
COOLDOWN_ALERTE_ARP = 30

table_arp_connue = {}
derniere_alerte_arp = {}

def detecter_arp_spoofing(ip, nouvelle_mac):
    if ip in table_arp_connue:
        mac_connue = table_arp_connue[ip]
        if mac_connue != nouvelle_mac:
            maintenant = datetime.now()
            derniere = derniere_alerte_arp.get(ip)
            if derniere is None or (maintenant - derniere).total_seconds() > COOLDOWN_ALERTE_ARP:
                message = (f"ALERTE ARP SPOOFING : {ip} était connue avec la MAC {mac_connue}, "
                           f"mais on voit maintenant {nouvelle_mac} !")
                print(f"🚨 {message}")
                logging.warning(message)
                derniere_alerte_arp[ip] = maintenant
    else:
        table_arp_connue[ip] = nouvelle_mac
        message = f"Nouvelle IP apprise : {ip} -> {nouvelle_mac}"
        print(f"[INFO] {message}")
        logging.info(message)

def analyser_arp(paquet):
    if paquet.haslayer(ARP):
        if paquet[ARP].op == 2:
            ip_annoncee = paquet[ARP].psrc
            mac_annoncee = paquet[ARP].hwsrc
            detecter_arp_spoofing(ip_annoncee, mac_annoncee)

print(f"Surveillance ARP active sur l'interface : {INTERFACE}\n")
logging.info(f"Démarrage de la surveillance ARP sur {INTERFACE}")
sniff(prn=analyser_arp, iface=INTERFACE, store=False, filter="arp")