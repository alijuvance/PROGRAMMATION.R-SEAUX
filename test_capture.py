from scapy.all import sniff

INTERFACE = "Ethernet"

def afficher_paquet(paquet):
    print(paquet.summary())

print(f"Capture sur l'interface : {INTERFACE}")
try:
    sniff(prn=afficher_paquet, count=10, timeout=15, iface=INTERFACE)
    print("Capture terminée.")
except Exception as e:
    print(f"ERREUR : {e}")