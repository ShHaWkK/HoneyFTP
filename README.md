# HoneyFTP

HoneyFTP is a high-interaction FTP honeypot implemented with Twisted. It logs
authentication attempts, commands and file transfers. Uploaded files are
quarantined with MD5 and SHA256 hashes. The honeypot checks IP addresses
against the Tor exit list, detects brute-force attacks, and creates realistic
lure files with canary triggers. Sensitive actions can generate alerts via
Slack or SMTP. Each connection has its own session log for forensic analysis.

## Requirements

- Python 3.8 or newer
- `twisted`, `requests`, `pyOpenSSL`, `service_identity`

## Setup

```bash
# Generate SSL certificate
openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt -days 365 -nodes

# (Optional) create a virtual environment
python3 -m venv honeypot-env
source honeypot-env/bin/activate
pip install twisted requests pyOpenSSL service_identity

# Run the honeypot
nohup python honeypot.py &
```

The server listens on port `2121` by default and writes logs to `honeypot.log`.
Set `HONEYFTP_PORT`, `SLACK_WEBHOOK` or `SMTP_SERVER` environment variables to
enable alerts or change the port.

By default the real server only starts after a UDP knock sequence on ports
`4020`, `4021` puis `4022` depuis la même IP.

Ensure the port is open in your firewall:

```bash
sudo ufw allow 2121/tcp
```

## Deployment on Proxmox

1. Créez un conteneur ou une VM Debian/Ubuntu sur votre hôte Proxmox.
2. Installez Python 3.8+ et git :

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

## Systemd Service

Pour un démarrage automatique, copiez `honeyftp.service` vers
`/etc/systemd/system/` puis activez le service :

```bash
sudo cp honeyftp.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now honeyftp.service
```
Adaptez le chemin de `ExecStart` dans le fichier si vous installez les scripts
ailleurs.

Le service attendra la séquence de knock UDP `4020`, `4021`, `4022` avant de
libérer le port FTP.

