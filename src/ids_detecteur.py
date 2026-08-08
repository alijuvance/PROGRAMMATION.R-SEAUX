#!/usr/bin/env python3
"""
IDS Réseau — Système de Détection d'Intrusion (Version OOP Pro)
================================================================
Détecte en temps réel :
  • Scan de ports (SYN scan / TCP connect)
  • SYN Flood (Déni de Service TCP)
  • ICMP Flood (Déni de Service Ping)
  • UDP Flood (Déni de Service UDP)
  • ARP Spoofing (Man-in-the-Middle)

Usage : python src/ids_detecteur.py
"""

import os
import sys
import json
import yaml
import logging
import requests
import subprocess
from datetime import datetime, timedelta
from collections import defaultdict
from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, wrpcap, conf

# ==============================================================================
# CONFIGURATION MANAGER
# ==============================================================================
class ConfigManager:
    def __init__(self, config_file="config.yaml"):
        self.config_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), config_file)
        self.config = self._load_config()

    def _load_config(self):
        if not os.path.exists(self.config_path):
            print(f"[!] Fichier de configuration introuvable : {self.config_path}")
            sys.exit(1)
        with open(self.config_path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f)

    def get_general(self, key, default=None):
        return self.config.get("general", {}).get(key, default)

    def get_rule(self, rule_name):
        return self.config.get("rules", {}).get(rule_name, {})

    def get_logging(self, key, default=None):
        return self.config.get("logging", {}).get(key, default)

    def get_forensics(self, key, default=None):
        return self.config.get("forensics", {}).get(key, default)

# ==============================================================================
# ALERT & LOGGING MANAGER
# ==============================================================================
class AlertManager:
    def __init__(self, config):
        self.config = config
        
        # Chemins des logs
        project_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.log_txt_path = os.path.join(project_dir, self.config.get_logging("log_file_text", "logs/ids_alertes.log"))
        self.log_json_path = os.path.join(project_dir, self.config.get_logging("log_file_json", "logs/ids_alertes.jsonl"))
        self.pcap_dir = os.path.join(project_dir, self.config.get_forensics("pcap_export_dir", "logs/pcap_exports"))

        # Création des dossiers si nécessaire
        os.makedirs(os.path.dirname(self.log_txt_path), exist_ok=True)
        os.makedirs(self.pcap_dir, exist_ok=True)

        # Configuration du logging natif Python
        logging.basicConfig(
            filename=self.log_txt_path,
            level=logging.INFO,
            format="%(asctime)s [%(levelname)s] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
            encoding="utf-8"
        )
        
        self.stats = {
            "total_alerts": 0,
            "port_scan": 0,
            "syn_flood": 0,
            "icmp_flood": 0,
            "udp_flood": 0,
            "arp_spoofing": 0
        }

    def trigger_alert(self, type_alerte, ip_source, message, details=None, raw_packet=None):
        """Déclenche une alerte (Terminal + Log texte + Log JSON + PCAP)"""
        # 1. Terminal
        print(f"🚨 [{type_alerte}] {message}")
        
        # 2. Log texte (logging)
        logging.warning(f"[{type_alerte}] {message}")
        
        # 2.5 - Geolocation & Active Defense
        geo_info = self.geolocate_ip(ip_source)
        is_blocked = False
        if type_alerte in ["PORT_SCAN", "SYN_FLOOD", "ICMP_FLOOD", "UDP_FLOOD"]:
            is_blocked = self.active_defense_block_ip(ip_source)
            
        if details is None:
            details = {}
        if geo_info:
            details["geo"] = geo_info
        if is_blocked:
            details["action"] = "BLOCKED_BY_FIREWALL"

        # 3. Log JSONL (pour le Dashboard)
        alerte = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "type": type_alerte,
            "severity": "CRITICAL" if type_alerte == "ARP_SPOOFING" else "WARNING",
            "ip": ip_source,
            "message": message,
            "details": details
        }
        with open(self.log_json_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(alerte, ensure_ascii=False) + "\n")
            
        # 4. Statistiques
        self.stats["total_alerts"] += 1
        stat_key = type_alerte.lower()
        if stat_key in self.stats:
            self.stats[stat_key] += 1
            
        # 5. Forensique (Export PCAP)
        if raw_packet and self.config.get_forensics("pcap_export_enabled", False):
            self.export_pcap(type_alerte, ip_source, raw_packet)

    def export_pcap(self, type_alerte, ip_source, packet):
        """Sauvegarde le paquet malveillant pour analyse ultérieure dans Wireshark"""
        timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
        ip_safe = ip_source.replace(".", "_")
        filename = f"{timestamp_str}_{type_alerte}_{ip_safe}.pcap"
        filepath = os.path.join(self.pcap_dir, filename)
        wrpcap(filepath, packet, append=True)

    def active_defense_block_ip(self, ip_source):
        """Bloque l'adresse IP de l'attaquant via le Pare-feu Windows (PowerShell)"""
        if not self.config.config.get("active_defense", {}).get("firewall_block_enabled", False):
            return False
            
        # Ne pas bloquer l'IP locale ou de loopback
        if ip_source in ["127.0.0.1", "0.0.0.0", "255.255.255.255"]:
            return False

        rule_name = f"IDS_BLOCK_{ip_source}"
        ps_command = f'New-NetFirewallRule -DisplayName "{rule_name}" -Direction Inbound -RemoteAddress {ip_source} -Action Block'
        
        try:
            # Exécution silencieuse de la commande PowerShell
            subprocess.run(["powershell", "-Command", ps_command], capture_output=True, text=True, check=True)
            self.log_info(f"🛡️ DÉFENSE ACTIVE : L'adresse IP {ip_source} a été bloquée par le pare-feu Windows.")
            return True
        except subprocess.CalledProcessError as e:
            logging.error(f"Échec de la défense active pour {ip_source} : {e.stderr.strip()}")
            return False
            
    def geolocate_ip(self, ip_source):
        """Récupère les informations géographiques d'une IP (si publique)"""
        if not self.config.config.get("threat_intel", {}).get("geoip_enabled", False):
            return None
            
        # Ignorer les IP privées
        if ip_source.startswith("192.168.") or ip_source.startswith("10.") or ip_source.startswith("172.") or ip_source == "127.0.0.1":
            return {"country": "Local", "city": "Réseau Interne", "isp": "LAN"}
            
        try:
            # Appel à l'API publique IP-API
            response = requests.get(f"http://ip-api.com/json/{ip_source}", timeout=2)
            if response.status_code == 200:
                data = response.json()
                if data.get("status") == "success":
                    return {
                        "country": data.get("country"),
                        "city": data.get("city"),
                        "isp": data.get("isp")
                    }
        except requests.RequestException:
            pass
        return None

    def log_info(self, message):
        """Log informatif standard"""
        print(f"[INFO] {message}")
        logging.info(message)


# ==============================================================================
# RULE ENGINE (Moteur de Détection)
# ==============================================================================
class RuleEngine:
    def __init__(self, config, alert_manager):
        self.config = config
        self.alert_manager = alert_manager
        
        # Paramètres
        self.cooldown = self.config.get_general("cooldown_alerte", 30)
        
        # Règles
        self.rule_scan = self.config.get_rule("port_scan")
        self.rule_syn = self.config.get_rule("syn_flood")
        self.rule_icmp = self.config.get_rule("icmp_flood")
        self.rule_udp = self.config.get_rule("udp_flood")
        self.rule_arp = self.config.get_rule("arp_spoofing")

        # États internes (Mémoire)
        self.history_scan = defaultdict(list)   # {ip: [(port, timestamp)]}
        self.history_syn = defaultdict(list)    # {ip: [timestamp]}
        self.history_icmp = defaultdict(list)   # {ip: [timestamp]}
        self.history_udp = defaultdict(list)    # {ip: [timestamp]}
        
        self.last_alerts = {}                   # {"TYPE_IP": datetime}
        self.arp_table = {}                     # {ip: mac}

    def _can_alert(self, alert_key):
        """Vérifie si le cooldown est passé pour ce type d'alerte et cette IP"""
        last_time = self.last_alerts.get(alert_key)
        if last_time is None or (datetime.now() - last_time).total_seconds() > self.cooldown:
            self.last_alerts[alert_key] = datetime.now()
            return True
        return False

    def _clean_history(self, history_list, window_seconds):
        """Garde uniquement les événements récents (fenêtre glissante)"""
        limit = datetime.now() - timedelta(seconds=window_seconds)
        return [t for t in history_list if (t[1] if isinstance(t, tuple) else t) > limit]

    def analyze_packet(self, packet):
        """Point d'entrée pour l'analyse de chaque paquet capturé"""
        try:
            # 1. Détection ARP
            if self.rule_arp.get("enabled", True) and packet.haslayer(ARP):
                self._check_arp(packet)
                
            # 2. Détections IP (TCP, UDP, ICMP)
            if packet.haslayer(IP):
                ip_src = packet[IP].src
                
                # Scan de ports & SYN Flood (TCP)
                if packet.haslayer(TCP) and packet[TCP].flags == "S":
                    if self.rule_scan.get("enabled", True):
                        self._check_port_scan(ip_src, packet[TCP].dport, packet)
                    if self.rule_syn.get("enabled", True):
                        self._check_syn_flood(ip_src, packet)
                        
                # ICMP Ping Flood
                if packet.haslayer(ICMP) and packet[ICMP].type == 8: # Echo request
                    if self.rule_icmp.get("enabled", True):
                        self._check_icmp_flood(ip_src, packet)
                        
                # UDP Flood
                if packet.haslayer(UDP):
                    if self.rule_udp.get("enabled", True):
                        self._check_udp_flood(ip_src, packet)
        except Exception as e:
            # Capturer les erreurs silencieusement pour ne pas planter le sniffer
            logging.error(f"Erreur d'analyse de paquet: {e}")

    def _check_port_scan(self, ip_src, dport, packet):
        window = self.rule_scan.get("window_seconds", 10)
        threshold = self.rule_scan.get("threshold_distinct_ports", 15)
        
        self.history_scan[ip_src].append((dport, datetime.now()))
        self.history_scan[ip_src] = self._clean_history(self.history_scan[ip_src], window)
        
        distinct_ports = {p for (p, t) in self.history_scan[ip_src]}
        if len(distinct_ports) >= threshold:
            if self._can_alert(f"SCAN_{ip_src}"):
                self.alert_manager.trigger_alert(
                    "PORT_SCAN", ip_src,
                    f"SCAN DE PORTS suspecté ({len(distinct_ports)} ports en {window}s)",
                    {"ports_count": len(distinct_ports)}, packet
                )

    def _check_syn_flood(self, ip_src, packet):
        window = self.rule_syn.get("window_seconds", 5)
        threshold = self.rule_syn.get("threshold_syn_count", 50)
        
        self.history_syn[ip_src].append(datetime.now())
        self.history_syn[ip_src] = self._clean_history(self.history_syn[ip_src], window)
        
        if len(self.history_syn[ip_src]) >= threshold:
            if self._can_alert(f"SYN_{ip_src}"):
                self.alert_manager.trigger_alert(
                    "SYN_FLOOD", ip_src,
                    f"SYN FLOOD suspecté ({len(self.history_syn[ip_src])} SYN en {window}s)",
                    {"syn_count": len(self.history_syn[ip_src])}, packet
                )

    def _check_icmp_flood(self, ip_src, packet):
        window = self.rule_icmp.get("window_seconds", 5)
        threshold = self.rule_icmp.get("threshold_ping_count", 50)
        
        self.history_icmp[ip_src].append(datetime.now())
        self.history_icmp[ip_src] = self._clean_history(self.history_icmp[ip_src], window)
        
        if len(self.history_icmp[ip_src]) >= threshold:
            if self._can_alert(f"ICMP_{ip_src}"):
                self.alert_manager.trigger_alert(
                    "ICMP_FLOOD", ip_src,
                    f"PING FLOOD suspecté ({len(self.history_icmp[ip_src])} Pings en {window}s)",
                    {"ping_count": len(self.history_icmp[ip_src])}, packet
                )

    def _check_udp_flood(self, ip_src, packet):
        window = self.rule_udp.get("window_seconds", 5)
        threshold = self.rule_udp.get("threshold_udp_count", 100)
        
        self.history_udp[ip_src].append(datetime.now())
        self.history_udp[ip_src] = self._clean_history(self.history_udp[ip_src], window)
        
        if len(self.history_udp[ip_src]) >= threshold:
            if self._can_alert(f"UDP_{ip_src}"):
                self.alert_manager.trigger_alert(
                    "UDP_FLOOD", ip_src,
                    f"UDP FLOOD suspecté ({len(self.history_udp[ip_src])} paquets UDP en {window}s)",
                    {"udp_count": len(self.history_udp[ip_src])}, packet
                )

    def _check_arp(self, packet):
        if packet.op in (1, 2):  # ARP Request ou Reply
            ip_src = packet.psrc
            mac_src = packet.hwsrc
            
            if ip_src in self.arp_table:
                if self.arp_table[ip_src] != mac_src:
                    if self._can_alert(f"ARP_{ip_src}"):
                        self.alert_manager.trigger_alert(
                            "ARP_SPOOFING", ip_src,
                            f"Usurpation ARP : L'IP {ip_src} a changé de MAC ({self.arp_table[ip_src]} -> {mac_src})",
                            {"old_mac": self.arp_table[ip_src], "new_mac": mac_src}, packet
                        )
            else:
                self.arp_table[ip_src] = mac_src
                self.alert_manager.log_info(f"Nouvelle IP apprise (ARP) : {ip_src} -> {mac_src}")


# ==============================================================================
# NETWORK SNIFFER (Couche Capture)
# ==============================================================================
class NetworkSniffer:
    def __init__(self, config, rule_engine):
        self.config = config
        self.rule_engine = rule_engine
        self.interface = self.config.get_general("interface") or None
        self.packets_analyzed = 0

    def start(self):
        print(f"\n{'=' * 60}")
        print("  🚀 IDS RÉSEAU PRO -- Moteur d'Analyse (OOP)")
        print(f"{'=' * 60}")
        
        iface_display = self.interface if self.interface else conf.iface
        print(f"  Interface d'écoute : {iface_display}")
        print("  Règles actives :")
        for rule in ["port_scan", "syn_flood", "icmp_flood", "udp_flood", "arp_spoofing"]:
            status = "Actif" if self.config.get_rule(rule).get("enabled", False) else "Inactif"
            print(f"    - {rule.replace('_', ' ').title().ljust(20)} : {status}")
        print(f"{'=' * 60}\n")
        print("  En attente de paquets (Appuyez sur Ctrl+C pour arrêter)...\n")
        
        try:
            sniff(prn=self._process_packet, iface=self.interface, store=False)
        except KeyboardInterrupt:
            self.stop()
        except PermissionError:
            print("\n[ERREUR] Privilèges administrateur requis pour capturer le trafic.")
            print("Veuillez relancer le script en tant qu'Administrateur.\n")
            sys.exit(1)

    def _process_packet(self, packet):
        self.packets_analyzed += 1
        self.rule_engine.analyze_packet(packet)

    def stop(self):
        print(f"\n\n{'=' * 50}")
        print("  📊 Statistiques de session IDS")
        print(f"{'=' * 50}")
        print(f"  Paquets analysés : {self.packets_analyzed}")
        stats = self.rule_engine.alert_manager.stats
        print(f"  Alertes totales  : {stats['total_alerts']}")
        print(f"    - Port Scan    : {stats['port_scan']}")
        print(f"    - SYN Flood    : {stats['syn_flood']}")
        print(f"    - ICMP Flood   : {stats['icmp_flood']}")
        print(f"    - UDP Flood    : {stats['udp_flood']}")
        print(f"    - ARP Spoofing : {stats['arp_spoofing']}")
        print(f"\n  Fermeture de l'IDS... Terminé.\n")


# ==============================================================================
# ENTRY POINT
# ==============================================================================
def main():
    # 1. Charger la configuration
    config = ConfigManager("config.yaml")
    
    # 2. Initialiser le gestionnaire d'alertes
    alert_manager = AlertManager(config)
    
    # 3. Initialiser le moteur de règles
    rule_engine = RuleEngine(config, alert_manager)
    
    # 4. Lancer le sniffer
    sniffer = NetworkSniffer(config, rule_engine)
    sniffer.start()

if __name__ == "__main__":
    main()
