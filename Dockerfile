# Choisissez explicitement bullseye ou bookworm selon votre image debian-slim
FROM python:3.9-slim-bullseye

WORKDIR /app
COPY . /app

# 1) Installer les outils nécessaires pour gérer les clefs GPG
# 2) Installer debian-archive-keyring (et debian-keyring pour couvrir tous les cas)
# 3) Mettre à jour la liste et installer openssl
# 4) Nettoyer le cache apt
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      gnupg2 dirmngr ca-certificates \
      debian-keyring debian-archive-keyring \
 && apt-get update \
 && apt-get install -y --no-install-recommends openssl \
 && rm -rf /var/lib/apt/lists/*

# 5) Générer le certificat TLS si besoin
RUN openssl req -x509 -newkey rsa:4096 \
      -keyout server.key -out server.crt \
      -days 365 -nodes \
      -subj "/CN=HoneyFTP"

# 6) Installer les dépendances Python
RUN pip install --no-cache-dir \
        twisted \
        requests \
        service-identity \
        pyOpenSSL \
        cryptography \
        pillow \
        openpyxl \
        python-docx \
        fpdf2

# 7) Ne pas tourner en root
USER nobody

EXPOSE 2121
CMD ["python", "honeypot.py"]
