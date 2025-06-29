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

Data connections use a passive range of **60000‑60100**. If those ports are
blocked, commands like `NLST` or `RETR` will hang with a timeout. Make sure the
range is reachable, especially when testing locally with the attacker script.

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

## Attacker Client

Le script `attaquant.py` permet de vérifier l'accès au honeypot et d'exécuter
différentes commandes FTPS. Lancez-le ainsi :

```bash
python attaquant.py --host <ip> --port 2121
```

Le menu interactif accepte les valeurs **0 à 18** :

| Choix | Action |
|------:|--------|
|0|Envoyer la séquence de knock et tester la connexion|
|1|Connexion anonyme|
|2|`NLST` – liste des fichiers|
|3|`RETR` – télécharger un fichier|
|4|`STOR` – téléverser un fichier|
|5|`CWD ../..` – tentative de traversal|
|6|`SITE EXEC` – commande shell|
|7|`SITE BOF` – payload overflow|
|8|`SITE HELP` – liste des sous-commandes|
|9|`SITE VERSION` – version du serveur|
|10|`SITE GETLOG` – extraire un log|
|11|`RNFR`/`RNTO` – renommage|
|12|`DELE` – suppression|
|13|`MKD`/`RMD` – gestion de répertoires|
|14|Récupérer le journal de session|
|15|Script de reconnaissance automatisé|
|16|Script d'attaque automatisé|
|17|Rejouer une liste de commandes|

L'option `18` quitte le client.

