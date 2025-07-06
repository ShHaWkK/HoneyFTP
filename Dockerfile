FROM python:3.9-slim

WORKDIR /app
COPY . /app

#  Mettre à jour la liste des paquets et installer temporairement le keyring
RUN apt-get update \
 && apt-get install -y --no-install-recommends debian-archive-keyring \
 # Refaire un update une fois le keyring en place
 && apt-get update \
 # Installer openssl et nettoyer le cache apt
 && apt-get install -y --no-install-recommends openssl \
 && rm -rf /var/lib/apt/lists/* \
 # Générer le certificat TLS
 && openssl req -x509 -newkey rsa:4096 \
       -keyout server.key -out server.crt \
       -days 365 -nodes \
       -subj "/CN=HoneyFTP"

# Installer les dépendances Python
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

# Exécuter le process sous un utilisateur non-privilégié
USER nobody

EXPOSE 2121
CMD ["python", "honeypot.py"]
