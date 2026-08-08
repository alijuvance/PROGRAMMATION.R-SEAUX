#!/usr/bin/env python3
"""
IDS Réseau — Dashboard Web Temps Réel (Version Pro avec SQLite)
================================================================
Interface de surveillance avec WebSocket pour visualiser
les alertes de l'IDS en temps réel et historiser dans SQLite.

Usage : python dashboard/app.py
        → Ouvrir http://localhost:5000
"""

from flask import Flask, render_template, jsonify, send_file
from flask_socketio import SocketIO, emit
import json
import os
import threading
import time
import sqlite3
import csv
from datetime import datetime

# ==============================================================================
#  CONFIGURATION
# ==============================================================================
app = Flask(__name__)
app.config["SECRET_KEY"] = "ids-reseau-dashboard-2026-pro"
app.config["TEMPLATES_AUTO_RELOAD"] = True
app.config["SEND_FILE_MAX_AGE_DEFAULT"] = 0
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

# Chemins
PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOGS_DIR = os.path.join(PROJECT_DIR, "logs")
LOG_JSON = os.path.join(LOGS_DIR, "ids_alertes.jsonl")
DB_PATH = os.path.join(LOGS_DIR, "ids_history.db")
EXPORT_DIR = os.path.join(LOGS_DIR, "exports")

os.makedirs(LOGS_DIR, exist_ok=True)
os.makedirs(EXPORT_DIR, exist_ok=True)

# ═══════════════════════════════════════════════════════════
#  BASE DE DONNÉES SQLITE
# ═══════════════════════════════════════════════════════════
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            type TEXT,
            severity TEXT,
            ip TEXT,
            message TEXT,
            details TEXT
        )
    ''')
    conn.commit()
    conn.close()

def insert_alert(alert):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        INSERT INTO alerts (timestamp, type, severity, ip, message, details)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (
        alert.get("timestamp"),
        alert.get("type"),
        alert.get("severity"),
        alert.get("ip"),
        alert.get("message"),
        json.dumps(alert.get("details", {}))
    ))
    conn.commit()
    conn.close()

def get_recent_alerts(limit=50):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute('SELECT * FROM alerts ORDER BY id DESC LIMIT ?', (limit,))
    rows = c.fetchall()
    conn.close()
    
    parsed_rows = []
    for row in rows:
        d = dict(row)
        try:
            d["details"] = json.loads(d.get("details", "{}"))
        except:
            d["details"] = {}
        parsed_rows.append(d)
    return parsed_rows

def get_stats_from_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    c.execute('SELECT COUNT(*) FROM alerts')
    total = c.fetchone()[0]
    
    c.execute('SELECT type, COUNT(*) FROM alerts GROUP BY type')
    type_counts = dict(c.fetchall())
    
    c.execute('SELECT ip, COUNT(*) as c FROM alerts GROUP BY ip ORDER BY c DESC LIMIT 10')
    top_ips = [{"ip": row[0], "count": row[1]} for row in c.fetchall()]
    
    conn.close()
    
    stats = {
        "total": total,
        "scans": type_counts.get("PORT_SCAN", 0),
        "floods": type_counts.get("SYN_FLOOD", 0) + type_counts.get("ICMP_FLOOD", 0) + type_counts.get("UDP_FLOOD", 0),
        "arp_spoofing": type_counts.get("ARP_SPOOFING", 0)
    }
    return stats, top_ips

# ═══════════════════════════════════════════════════════════
#  SYNCHRONISATION ET WATCHER
# ═══════════════════════════════════════════════════════════
def sync_jsonl_to_db():
    """Au démarrage, on s'assure que toutes les alertes du JSONL sont en BDD."""
    if not os.path.exists(LOG_JSON):
        return
        
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT COUNT(*) FROM alerts')
    db_count = c.fetchone()[0]
    
    alerts_to_insert = []
    with open(LOG_JSON, "r", encoding="utf-8") as f:
        lines = f.readlines()
        if len(lines) > db_count:
            # Insérer seulement les nouvelles lignes
            for line in lines[db_count:]:
                line = line.strip()
                if line:
                    try:
                        alert = json.loads(line)
                        alerts_to_insert.append((
                            alert.get("timestamp"),
                            alert.get("type"),
                            alert.get("severity"),
                            alert.get("ip"),
                            alert.get("message"),
                            json.dumps(alert.get("details", {}))
                        ))
                    except json.JSONDecodeError:
                        pass
    if alerts_to_insert:
        c.executemany('''
            INSERT INTO alerts (timestamp, type, severity, ip, message, details)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', alerts_to_insert)
        conn.commit()
    conn.close()
    print(f"  📂 Synchronisation DB : {len(alerts_to_insert)} nouvelles alertes ajoutées.")

def watch_log_file():
    """Surveille le fichier JSONL en temps réel et pousse sur WebSocket."""
    while not os.path.exists(LOG_JSON):
        time.sleep(1)

    with open(LOG_JSON, "r", encoding="utf-8") as f:
        f.seek(0, 2)
        while True:
            line = f.readline()
            if line:
                line = line.strip()
                if line:
                    try:
                        alert = json.loads(line)
                        insert_alert(alert) # Persistance
                        
                        stats, top_ips = get_stats_from_db()
                        
                        socketio.emit("new_alert", {
                            "alert": alert,
                            "stats": stats,
                            "top_ips": top_ips
                        })
                    except json.JSONDecodeError:
                        pass
            else:
                time.sleep(0.5)

# ───────────────────────────────────────────────────────────
#  ROUTES HTTP
# ───────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/alerts")
def api_alerts():
    """Retourne les 50 dernières alertes pour initialiser le dashboard."""
    return jsonify(get_recent_alerts(50))

@app.route("/api/stats")
def api_stats():
    """Retourne les statistiques globales actuelles."""
    stats, top_ips = get_stats_from_db()
    return jsonify({"stats": stats, "top_ips": top_ips})

@app.route("/api/history")
def api_history():
    """Retourne l'historique complet pour la vue Data Table."""
    return jsonify(get_recent_alerts(1000))

@app.route("/api/export/csv")
def export_csv():
    """Génère et télécharge un rapport CSV des alertes."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filepath = os.path.join(EXPORT_DIR, f"ids_report_{timestamp}.csv")
    
    alerts = get_recent_alerts(5000)
    if not alerts:
        return "Pas de données à exporter", 404
        
    keys = ["id", "timestamp", "type", "severity", "ip", "message", "details"]
    with open(filepath, "w", newline='', encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=keys)
        writer.writeheader()
        writer.writerows(alerts)
        
    return send_file(filepath, as_attachment=True)

# ───────────────────────────────────────────────────────────
#  DÉMARRAGE
# ───────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("\n" + "="*50)
    print("  🌐 DÉMARRAGE DU DASHBOARD IDS PRO")
    print("  Lien : http://localhost:5000")
    print("="*50 + "\n")
    
    init_db()
    sync_jsonl_to_db()
    
    watcher_thread = threading.Thread(target=watch_log_file, daemon=True)
    watcher_thread.start()
    
    # Mode debug=False requis si host="0.0.0.0" pour éviter le double thread
    socketio.run(app, host="0.0.0.0", port=5000, debug=True, use_reloader=False)
