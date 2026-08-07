#!/bin/bash

echo "==================================================="
echo "    LANCEMENT IDS RESEAU (Dashboard + Detecteur)"
echo "==================================================="

# Verifier les droits root (necessaires pour scapy/sniffing)
if [ "$EUID" -ne 0 ]; then
  echo "[!] ERREUR : Ce script doit etre lance en tant que root (sudo)."
  echo "    Veuillez executer : sudo ./start.sh"
  exit 1
fi

# Installer les dependances
echo "[*] Verification des dependances..."
pip3 install -r requirements.txt -q

# Lancer le Dashboard en arriere-plan
echo "[*] Lancement du Dashboard (Port 5000)..."
python3 dashboard/app.py &
DASHBOARD_PID=$!

echo "[*] Dashboard lance avec le PID $DASHBOARD_PID"
echo "[*] Lancement de l'IDS (Moteur de detection)..."
echo ""

# Capturer le signal Ctrl+C pour fermer le dashboard en quittant
trap "echo -e '\n[*] Arret du Dashboard...'; kill $DASHBOARD_PID; exit" INT

# Lancer l'IDS
python3 src/ids_detecteur.py
