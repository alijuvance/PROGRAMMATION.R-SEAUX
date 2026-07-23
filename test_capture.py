from scapy.all import sniff, IP, TCP
from collections import defaultdict
from datetime import datetime, timedelta

INTERFACE = "Ethernet"
FENETRE_SECONDES = 10
SEUIL_PORTS = 15

historique = defaultdict(list)

def nettoyer_historique(ip):
    limite = datetime.now() - timedelta(seconds=FENETRE_SECONDES)
    historique[ip] = [(port, t) for (port, t) in historique[ip] if t > limite]

def detecter_scan(ip):
    ports_distincts = {port for (port, t) in historique[ip]}
    if len(ports_distincts) >= SEUIL_PORTS:
        print(f"🚨 ALERTE : scan de ports suspecté depuis {ip} "
              f"({len(ports_distincts)} ports distincts en {FENETRE_SECONDES}s)")

def analyser_paquet(paquet):
    if paquet.haslayer(IP) and paquet.haslayer(TCP):
        flags = paquet[TCP].flags

        # On ne garde QUE les paquets SYN purs (tentative de connexion)
        # 0x02 = flag SYN seul (sans ACK)
        if flags == "S":
            ip_src = paquet[IP].src
            port_dst = paquet[TCP].dport

            historique[ip_src].append((port_dst, datetime.now()))
            nettoyer_historique(ip_src)
            detecter_scan(ip_src)

print(f"Surveillance active sur l'interface : {INTERFACE}")
print(f"Seuil : {SEUIL_PORTS} ports distincts (SYN) en {FENETRE_SECONDES}s\n")
sniff(prn=analyser_paquet, iface=INTERFACE, store=False)