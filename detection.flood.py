from scapy.all import sniff, IP, TCP
from collections import defaultdict
from datetime import datetime, timedelta

INTERFACE = "Connexion au réseau local* 11"

FENETRE_SCAN = 10
SEUIL_PORTS = 15
FENETRE_FLOOD = 5
SEUIL_SYN = 50

COOLDOWN_ALERTE = 30  # secondes de silence après une alerte pour la même IP/même type

historique_scan = defaultdict(list)
historique_flood = defaultdict(list)
derniere_alerte_scan = {}   # {ip: timestamp de la dernière alerte}
derniere_alerte_flood = {}

def nettoyer(liste, fenetre):
    limite = datetime.now() - timedelta(seconds=fenetre)
    return [t for t in liste if (t[1] if isinstance(t, tuple) else t) > limite]

def detecter_scan(ip):
    ports_distincts = {port for (port, t) in historique_scan[ip]}
    if len(ports_distincts) >= SEUIL_PORTS:
        maintenant = datetime.now()
        derniere = derniere_alerte_scan.get(ip)
        if derniere is None or (maintenant - derniere).total_seconds() > COOLDOWN_ALERTE:
            print(f"🚨 ALERTE SCAN : {ip} a contacté {len(ports_distincts)} ports distincts "
                  f"en {FENETRE_SCAN}s")
            derniere_alerte_scan[ip] = maintenant

def detecter_flood(ip):
    if len(historique_flood[ip]) >= SEUIL_SYN:
        maintenant = datetime.now()
        derniere = derniere_alerte_flood.get(ip)
        if derniere is None or (maintenant - derniere).total_seconds() > COOLDOWN_ALERTE:
            print(f"🚨 ALERTE FLOOD : {ip} a envoyé {len(historique_flood[ip])} SYN "
                  f"en {FENETRE_FLOOD}s (possible SYN flood / DoS)")
            derniere_alerte_flood[ip] = maintenant

def analyser_paquet(paquet):
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

print(f"Surveillance active sur l'interface : {INTERFACE}")
print(f"Scan  : {SEUIL_PORTS} ports distincts en {FENETRE_SCAN}s")
print(f"Flood : {SEUIL_SYN} SYN en {FENETRE_FLOOD}s")
print(f"Cooldown entre alertes répétées : {COOLDOWN_ALERTE}s\n")
sniff(prn=analyser_paquet, iface=INTERFACE, store=False)