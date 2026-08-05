#!/usr/bin/env python3
"""
IDS Réseau — Dashboard Web Temps Réel
======================================
Interface de surveillance avec WebSocket pour visualiser
les alertes de l'IDS en temps réel.

Usage : python dashboard/app.py
        → Ouvrir http://localhost:5000

Le dashboard :
  1. Charge les alertes existantes depuis logs/ids_alertes.jsonl
  2. Surveille le fichier en continu (tail -f)
  3. Pousse chaque nouvelle alerte au navigateur via WebSocket
  4. Affiche statistiques, timeline, graphique d'activité
"""

from flask import Flask, render_template, jsonify
from flask_socketio import SocketIO, emit
import json
import os
import threading
import time
from datetime import datetime

# ═══════════════════════════════════════════════════════════
#  CONFIGURATION
# ═══════════════════════════════════════════════════════════
app = Flask(__name__)
app.config["SECRET_KEY"] = "ids-reseau-dashboard-2026"
app.config["TEMPLATES_AUTO_RELOAD"] = True
app.config["SEND_FILE_MAX_AGE_DEFAULT"] = 0
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

# Chemins
PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOGS_DIR = os.path.join(PROJECT_DIR, "logs")
LOG_JSON = os.path.join(LOGS_DIR, "ids_alertes.jsonl")

# ═══════════════════════════════════════════════════════════
#  STOCKAGE EN MÉMOIRE
# ═══════════════════════════════════════════════════════════
alerts = []
stats = {"total": 0, "scans": 0, "floods": 0, "arp_spoofing": 0}
ip_counts = {}
lock = threading.Lock()


# ───────────────────────────────────────────────────────────
#  LOGIQUE MÉTIER
# ───────────────────────────────────────────────────────────

def update_stats(alert):
    """Met à jour les compteurs et le classement des IPs."""
    stats["total"] += 1
    alert_type = alert.get("type", "")
    if alert_type == "SCAN":
        stats["scans"] += 1
    elif alert_type == "FLOOD":
        stats["floods"] += 1
    elif alert_type == "ARP_SPOOF":
        stats["arp_spoofing"] += 1

    ip = alert.get("ip", "unknown")
    ip_counts[ip] = ip_counts.get(ip, 0) + 1


def get_top_ips(n=10):
    """Retourne les N IPs les plus suspectes, triées par nombre d'alertes."""
    sorted_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)
    return [{"ip": ip, "count": count} for ip, count in sorted_ips[:n]]


def load_existing_alerts():
    """Charge les alertes existantes depuis le fichier JSONL au démarrage."""
    if not os.path.exists(LOG_JSON):
        return
    with open(LOG_JSON, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                alert = json.loads(line)
                alerts.append(alert)
                update_stats(alert)
            except json.JSONDecodeError:
                continue
    print(f"  📂 {len(alerts)} alertes existantes chargées")


def watch_log_file():
    """
    Thread de surveillance du fichier JSONL.
    
    Fonctionne comme 'tail -f' : se positionne à la fin du fichier
    et lit les nouvelles lignes au fur et à mesure qu'elles arrivent.
    Quand une nouvelle alerte est détectée, elle est poussée à tous
    les clients WebSocket connectés.
    """
    # Attendre que le fichier existe
    while not os.path.exists(LOG_JSON):
        time.sleep(1)

    with open(LOG_JSON, "r", encoding="utf-8") as f:
        # Se positionner à la fin (on a déjà chargé l'historique)
        f.seek(0, 2)

        while True:
            line = f.readline()
            if line:
                line = line.strip()
                if line:
                    try:
                        alert = json.loads(line)
                        with lock:
                            alerts.append(alert)
                            update_stats(alert)
                        # Pousser à tous les clients connectés
                        socketio.emit("new_alert", {
                            "alert": alert,
                            "stats": stats.copy(),
                            "top_ips": get_top_ips()
                        })
                    except json.JSONDecodeError:
                        pass
            else:
                time.sleep(0.5)  # Polling toutes les 500ms


# ───────────────────────────────────────────────────────────
#  ROUTES HTTP
# ───────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/alerts")
def api_alerts():
    """Retourne toutes les alertes en JSON."""
    with lock:
        return jsonify(alerts)


@app.route("/api/stats")
def api_stats():
    """Retourne les statistiques actuelles."""
    with lock:
        return jsonify({
            "stats": stats.copy(),
            "top_ips": get_top_ips(),
            "total_alerts": len(alerts)
        })


# ───────────────────────────────────────────────────────────
#  ÉVÉNEMENTS WEBSOCKET
# ───────────────────────────────────────────────────────────

@socketio.on("connect")
def handle_connect():
    """Envoie l'état complet au client qui vient de se connecter."""
    with lock:
        emit("init", {
            "alerts": alerts[-200:],  # Dernières 200 alertes
            "stats": stats.copy(),
            "top_ips": get_top_ips()
        })


# ───────────────────────────────────────────────────────────
#  POINT D'ENTRÉE
# ───────────────────────────────────────────────────────────

if __name__ == "__main__":
    os.makedirs(LOGS_DIR, exist_ok=True)

    import sys
    sys.stdout.reconfigure(encoding="utf-8")

    print()
    print("=" * 52)
    print("   IDS RESEAU -- Dashboard Web")
    print("=" * 52)
    print(f"   URL : http://localhost:5001")
    print(f"   Log : {os.path.basename(LOG_JSON)}")
    print("=" * 52)
    print()

    load_existing_alerts()

    # Démarrer la surveillance du fichier en arrière-plan
    watcher = threading.Thread(target=watch_log_file, daemon=True)
    watcher.start()
    print("  [OK] Surveillance du fichier de log activee")
    print("  [OK] Serveur demarre -- ouvrez votre navigateur\n")

    socketio.run(app, host="0.0.0.0", port=5001, debug=False, allow_unsafe_werkzeug=True)
