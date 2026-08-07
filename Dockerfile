FROM python:3.10-slim

WORKDIR /app

# Copie des fichiers requis
COPY requirements.txt .

# Installation des dépendances
RUN pip install --no-cache-dir -r requirements.txt

# Copie du code du dashboard
COPY dashboard/ dashboard/
COPY logs/ logs/
COPY config.yaml .

# Port d'écoute du dashboard
EXPOSE 5000

# Commande de lancement
CMD ["python", "dashboard/app.py"]
