# HoneyFTP

HoneyFTP is a high-interaction FTP honeypot implemented with Twisted. It logs
authentication attempts, commands and file transfers. Uploaded files are
quarantined with MD5 and SHA256 hashes. The honeypot checks IP addresses
against the Tor exit list, detects brute-force attacks, and creates realistic
lure files with canary triggers. Sensitive actions can generate alerts via
Slack or SMTP. Each connection has its own session log for forensic analysis.

## Requirements

- Python 3
- `twisted`, `requests`, `pyOpenSSL`

## Setup

```bash
# Generate SSL certificate
openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt -days 365 -nodes

# (Optional) create a virtual environment
python3 -m venv honeypot-env
source honeypot-env/bin/activate
pip install twisted requests pyOpenSSL

# Run the honeypot
nohup python honeypot.py &
```

The server listens on port `2121` by default and writes logs to `honeypot.log`.
Set `HONEYFTP_PORT`, `SLACK_WEBHOOK` or `SMTP_SERVER` environment variables to
enable alerts or change the port.

## Deployment on Proxmox

1. Créez un conteneur ou une VM Debian/Ubuntu sur votre hôte Proxmox.
2. Installez Python 3 et git :

   ```bash
   apt update && apt install -y python3 python3-venv git
   ```

3. Clonez ce dépôt ou copiez les fichiers et suivez les étapes d'installation
   ci-dessus pour générer le certificat et installer les dépendances.
4. Lancez le script en tâche de fond :

   ```bash
   HONEYFTP_PORT=2121 SLACK_WEBHOOK=<url_webhook> nohup python honeypot.py &
   ```

Le service sera alors exposé sur le port choisi à l'intérieur de la VM ou du
conteneur Proxmox. Vous pouvez rediriger le port depuis Proxmox si nécessaire.

