#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Attacker FTPS implicite — script plus complet et robuste.

Features :
 - Implicit FTPS (wrap_socket dès connect)
 - Multi-utilisateurs / multi-passwords via CLI
 - Téléchargement de 'passwords.txt' + autres canaries
 - Upload de fichier de test (--upload)
 - Mesure de latence
 - Sorties colorées avec colorama
 - Logging local dans un dossier écrivable
 - Résumé des succès/échecs
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

# — Bootstrap colorama si nécessaire
try:
    from colorama import init, Fore, Style
except ImportError:
    subprocess.check_call([sys.executable, "-m", "pip", "install", "--upgrade", "colorama"])
    from colorama import init, Fore, Style
init(autoreset=True)

# — CLI
parser = argparse.ArgumentParser(description="Attacker FTPS implicite")
parser.add_argument("-H","--host",    default="192.168.100.51", help="IP du honeypot")
parser.add_argument("-P","--port",    default=2121, type=int,    help="Port FTPS")
parser.add_argument("-U","--users",   nargs="+",                required=True,
                    help="Liste d'utilisateurs à tester")
parser.add_argument("-W","--pwds",    nargs="+",                required=True,
                    help="Liste de passwords (1:1 avec --users)")
parser.add_argument("-d","--download",default="ftp_downloads",
                    help="Dossier local pour les téléchargements")
parser.add_argument("-u","--upload",  help="Chemin local d'un fichier à uploader")
parser.add_argument("-l","--log",     help="Chemin du fichier de log")
args = parser.parse_args()

# — Prépare dossier de download
DOWNLOAD_DIR = os.path.expanduser(args.download)
os.makedirs(DOWNLOAD_DIR, exist_ok=True)

# — Détermine où écrire le log
if args.log:
    log_path = os.path.expanduser(args.log)
else:
    # par défaut : ~/HoneyFTP/attacker.log si possible
    default_dir = os.path.expanduser("~/HoneyFTP")
    if os.access(default_dir, os.W_OK):
        os.makedirs(default_dir, exist_ok=True)
        log_path = os.path.join(default_dir, "attacker.log")
    else:
        # fallback dans ~/.cache
        cache_dir = os.path.expanduser("~/.cache")
        os.makedirs(cache_dir, exist_ok=True)
        log_path = os.path.join(cache_dir, "attacker.log")

# — Logging
logger = logging.getLogger("attacker")
logger.setLevel(logging.INFO)
ch = logging.StreamHandler(sys.stdout)
ch.setLevel(logging.INFO)
formatter = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
ch.setFormatter(formatter)
logger.addHandler(ch)

# FileHandler optionnel
try:
    fh = logging.FileHandler(log_path)
    fh.setLevel(logging.INFO)
    fh.setFormatter(formatter)
    logger.addHandler(fh)
    logger.info(f"Logging to {log_path}")
except PermissionError as e:
    logger.warning(f"Impossible d’écrire le log dans {log_path}: {e}")
    logger.info("Continuing without file logging.")

# — Canaries connus
CANARY_FILES = ["passwords.txt", "secrets/ssh_key"]

def try_user(user: str, pwd: str):
    start = time.time()
    logger.info(Fore.CYAN + f"Test {user!r}/{pwd!r} sur {args.host}:{args.port}")
    try:
        raw = socket.create_connection((args.host, args.port), timeout=10)
        ctx = ssl._create_unverified_context()
        ss  = ctx.wrap_socket(raw, server_hostname=args.host)

        ftp = FTP()
        ftp.sock          = ss
        ftp.file          = ss.makefile('r', encoding='utf-8', newline='\r\n')
        ftp.af            = ss.family
        ftp.passiveserver = True

        banner = ftp.getresp().strip()
        logger.info(Fore.YELLOW + banner)

        resp = ftp.login(user, pwd)
        logger.info(Fore.GREEN + f"LOGIN OK: {resp}")

        files = ftp.nlst(".")
        files = [f.lstrip("./") for f in files]
        logger.info(Fore.MAGENTA + f"NLST: {files}")

        # téléchargement des canaries
        for cf in CANARY_FILES:
            if cf in files:
                out = os.path.join(DOWNLOAD_DIR, f"{user}_{cf}")
                logger.info(Fore.BLUE + f"↓ DL {cf} → {out}")
                with open(out, "wb") as fd:
                    ftp.retrbinary(f"RETR {cf}", fd.write)
                logger.info(Fore.GREEN + "   ✓ DL réussi")

        # upload si demandé
        if args.upload:
            base = os.path.basename(args.upload)
            logger.info(Fore.BLUE + f"↑ UPLOAD {args.upload} → /{base}")
            with open(os.path.expanduser(args.upload), "rb") as rd:
                ftp.storbinary(f"STOR {base}", rd)
            logger.info(Fore.GREEN + "   ✓ Upload réussi")

        ftp.quit()
        return True, time.time() - start

    except error_perm as e:
        logger.warning(Fore.RED + f"Perm error for {user}: {e}")
    except Exception as e:
        logger.error(Fore.RED + f"Erreur pour {user}: {e}", exc_info=True)

    return False, time.time() - start

def main():
    logger.info("[*] Début Attacker")
    results = []
    for i, user in enumerate(args.users):
        pwd = args.pwds[i] if i < len(args.pwds) else ""
        ok, dur = try_user(user, pwd)
        results.append((user, ok, dur))
    logger.info("[*] Résumé:")
    for user, ok, dur in results:
        status = Fore.GREEN + "OK" if ok else Fore.RED + "KO"
        logger.info(f" - {user:10s} : {status} en {dur:.2f}s")
    logger.info(f"Téléchargements dans {DOWNLOAD_DIR}")
    logger.info("Fin Attacker")

if __name__ == "__main__":
    main()
