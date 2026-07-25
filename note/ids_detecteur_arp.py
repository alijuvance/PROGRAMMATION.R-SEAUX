from scapy.all import sniff, ARP
from datetime import datetime, timedelta

INTERFACE = "Connexion au réseau local* 11"
COOLDOWN_ALERTE_ARP = 30

table_arp_connue = {}     # { ip: mac } — la première association vue, notre "référence"
derniere_alerte_arp = {}

def detecter_arp_spoofing(ip, nouvelle_mac):
    if ip in table_arp_connue:
        mac_connue = table_arp_connue[ip]
        if mac_connue != nouvelle_mac:
            maintenant = datetime.now()
            derniere = derniere_alerte_arp.get(ip)
            if derniere is None or (maintenant - derniere).total_seconds() > COOLDOWN_ALERTE_ARP:
                print(f"🚨 ALERTE ARP SPOOFING : {ip} était connue avec la MAC {mac_connue}, "
                      f"mais on voit maintenant {nouvelle_mac} !")
                derniere_alerte_arp[ip] = maintenant
            # Optionnel : on pourrait choisir de mettre à jour ou non la référence ici.
            # On NE met PAS à jour, pour continuer à détecter tant que l'usurpation persiste.
    else:
        # Première fois qu'on voit cette IP : on l'enregistre comme référence de confiance
        table_arp_connue[ip] = nouvelle_mac
        print(f"[INFO] Nouvelle IP apprise : {ip} -> {nouvelle_mac}")

def analyser_arp(paquet):
    if paquet.haslayer(ARP):
        if paquet[ARP].op == 2:
            ip_annoncee = paquet[ARP].psrc
            mac_annoncee = paquet[ARP].hwsrc
            detecter_arp_spoofing(ip_annoncee, mac_annoncee)

print(f"Surveillance ARP active sur l'interface : {INTERFACE}\n")
sniff(prn=analyser_arp, iface=INTERFACE, store=False, filter="arp")