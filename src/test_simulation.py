#!/usr/bin/env python3
"""
Simulateur d'Attaques — Outil de Test pour l'IDS
==================================================
Simule les 3 types d'attaques détectées par l'IDS :
  • Scan de ports (SYN vers ports multiples)
  • SYN Flood (volume de SYN)
  • ARP Spoofing (faux ARP Reply)

⚠️  À utiliser UNIQUEMENT sur un réseau de test contrôlé.
    Nécessite des privilèges administrateur.

Usage : python src/test_simulation.py
"""

from scapy.all import Ether, ARP, IP, TCP, sendp, send, get_if_list, conf
import time
import argparse
import sys


def simuler_scan(ip_cible, interface, nb_ports=20):
    """
    Simule un scan de ports en envoyant des SYN vers des ports différents.
    
    C'est exactement ce que fait 'nmap -sS <ip>' :
    envoi de paquets TCP avec uniquement le flag SYN activé
    vers de nombreux ports différents pour identifier les services actifs.
    """
    print(f"\n{'-' * 50}")
    print(f"  [SCAN] Simulation SCAN DE PORTS")
    print(f"  Cible : {ip_cible} | Ports : 1-{nb_ports}")
    print(f"{'-' * 50}")
    
    for port in range(1, nb_ports + 1):
        paquet = IP(src="10.0.0.66", dst=ip_cible) / TCP(dport=port, flags="S")
        send(paquet, verbose=False)
        print(f"  > SYN envoye vers {ip_cible}:{port}")
        time.sleep(0.05)  # Petit délai pour simuler un vrai scan
    
    print(f"  [OK] Scan termine ({nb_ports} ports)\n")


def simuler_flood(ip_cible, interface, nb_paquets=60):
    """
    Simule un SYN flood en envoyant beaucoup de SYN sur le même port.
    
    Principe de l'attaque réelle :
    Chaque SYN reçu force le serveur à allouer de la mémoire (TCB)
    dans son backlog TCP. En saturant le backlog, les connexions
    légitimes ne peuvent plus être acceptées → déni de service.
    """
    print(f"\n{'-' * 50}")
    print(f"  [FLOOD] Simulation SYN FLOOD")
    print(f"  Cible : {ip_cible}:80 | Paquets : {nb_paquets}")
    print(f"{'-' * 50}")
    
    for i in range(nb_paquets):
        paquet = IP(src="10.0.0.66", dst=ip_cible) / TCP(dport=80, flags="S")
        send(paquet, verbose=False)
        if (i + 1) % 10 == 0:
            print(f"  > {i + 1}/{nb_paquets} SYN envoyes...")
        time.sleep(0.02)
    
    print(f"  [OK] Flood termine ({nb_paquets} SYN)\n")


def simuler_arp_spoofing(ip_cible, interface):
    """
    Simule un ARP spoofing en envoyant de faux ARP Reply.
    
    Principe :
    On annonce au réseau que l'IP cible correspond à une fausse MAC.
    Toute machine qui reçoit ce message va mettre à jour son cache
    ARP et envoyer son trafic vers la mauvaise destination.
    
    C'est la base de l'attaque Man-in-the-Middle (MITM).
    """
    FAUSSE_MAC = "02:11:22:33:44:55"
    VRAIE_MAC = "00:11:22:33:44:55" # Simule la vraie adresse MAC
    
    print(f"\n{'-' * 50}")
    print(f"  [ARP] Simulation ARP SPOOFING")
    print(f"  Cible : {ip_cible}")
    print(f"{'-' * 50}")
    
    # 1. Envoyer une annonce ARP "Légitime" pour que l'IDS apprenne l'IP
    print("  > Envoi d'une annonce ARP legitime pour initialiser l'IDS...")
    paquet_legitime = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(
        op=2, psrc=ip_cible, hwsrc=VRAIE_MAC, pdst=ip_cible, hwdst="ff:ff:ff:ff:ff:ff"
    )
    sendp(paquet_legitime, iface=interface, verbose=False)
    time.sleep(2)
    
    print(f"  > Changement de MAC (Spoofing) vers {FAUSSE_MAC} !")
    # 2. Envoyer les annonces ARP "Spoofées"
    for i in range(5):
        paquet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(
            op=2,               # op=2 → ARP Reply
            psrc=ip_cible,      # IP usurpée
            hwsrc=FAUSSE_MAC,   # Fausse MAC
            pdst=ip_cible,
            hwdst="ff:ff:ff:ff:ff:ff"
        )
        sendp(paquet, iface=interface, verbose=False)
        print(f"  > Faux ARP Reply #{i+1} envoye")
        time.sleep(1)
    
    print(f"  [OK] ARP spoofing termine (5 paquets)\n")


def main():
    parser = argparse.ArgumentParser(
        description="🧪 Simulateur d'attaques pour tester l'IDS"
    )
    parser.add_argument(
        "-t", "--target", required=True,
        help="IP cible de la simulation"
    )
    parser.add_argument(
        "-i", "--interface", default=None,
        help="Interface réseau (défaut: auto-détection)"
    )
    parser.add_argument(
        "-a", "--attack", choices=["scan", "flood", "arp", "all"],
        default="all",
        help="Type d'attaque à simuler (défaut: all)"
    )
    
    args = parser.parse_args()
    interface = args.interface or conf.iface
    
    print()
    print("=" * 48)
    print("  SIMULATEUR D'ATTAQUES -- Test IDS")
    print("=" * 48)
    print(f"  Cible     : {args.target}")
    print(f"  Interface : {interface}")
    print(f"  Attaque   : {args.attack}")
    print("=" * 48)
    
    try:
        if args.attack in ("scan", "all"):
            simuler_scan(args.target, interface)
            time.sleep(2)
        
        if args.attack in ("flood", "all"):
            simuler_flood(args.target, interface)
            time.sleep(2)
        
        if args.attack in ("arp", "all"):
            simuler_arp_spoofing(args.target, interface)
        
        print("=" * 50)
        print("  Simulation terminee -- verifiez l'IDS !")
        print("=" * 50)
        print()
    
    except PermissionError:
        print("\nErreur : Privileges administrateur requis.\n")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n\nSimulation interrompue.\n")


if __name__ == "__main__":
    main()
