#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Attacker Implicit FTPS — script amélioré avec valeurs par défaut.

Features :
 - Implicit FTPS (wrap_socket dès le connect)
 - Defaults : anonymous/"" et attacker/secret
 - Téléchargement de passwords.txt et autres canaries
 - Upload éventuel (--upload)
 - Couleurs (colorama), argparse, logging avec fallback
 - Résumé final
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

# — Colorama (installation automatique si manquant) —
try:
    from colorama import init, Fore, Style
except ImportError:
    subprocess.check_call([sys.executable, "-m", "pip", "install", "colorama"])
    from colorama import init, Fore, Style
init(autoreset=True)

# — CLI avec defaults —————————————————————————————————————————
p = argparse.ArgumentParser(description="Attacker Implicit FTPS")
p.add_argument("-H","--host",    default="192.168.100.51", help="IP du honeypot")
p.add_argument("-P","--port",    default=2121, type=int,    help="Port FTPS")
p.add_argument("-U","--users",   nargs="+",
               default=["anonymous","attacker"],
               help="Liste d'utilisateurs (défaut: anonymous attacker)")
p.add_argument("-W","--pwds",    nargs="+",
               default=["","secret"],
               help="Liste de mots de passe (défaut: '' secret)")
p.add_argument("-d","--download",
               default="ftp_downloads",
               help="Dossier local pour téléchargements")
p.add_argument("-u","--upload",
               help="Chemin local d'un fichier à uploader")
p.add_argument("-l","--log",
               help="Chemin du fichier de log (fallback ~/.cache)")
args = p.parse_args()

# — Prépare dossier de download —
DOWNLOAD_DIR = os.path.expanduser(args.download)
os.makedirs(DOWNLOAD_DIR, exist_ok=True)

# — Détermine le chemin du log —
if args.log:
    log_path = os.path.expanduser(args.log)
else:
    default_dir = os.path.expanduser("~/HoneyFTP")
    if os.access(default_dir, os.W_OK):
        os.makedirs(default_dir, exist_ok=True)
        log_path = os.path.join(default_dir, "attacker.log")
    else:
        cache = os.path.expanduser("~/.cache")
        os.makedirs(cache, exist_ok=True)
        log_path = os.path.join(cache, "attacker.log")

# — Logging console + fichier (optional) —
logger = logging.getLogger("attacker")
logger.setLevel(logging.INFO)
fmt = logging.Formatter("%(asctime)s %(levelname)s %(message)s")

ch = logging.StreamHandler(sys.stdout)
ch.setFormatter(fmt)
logger.addHandler(ch)

try:
    fh = logging.FileHandler(log_path)
    fh.setFormatter(fmt)
    logger.addHandler(fh)
    logger.info(f"Logging in {log_path}")
except PermissionError as e:
    logger.warning(f"Cannot write log at {log_path}: {e}")

# — Canaries connues —
CANARY_FILES = ["passwords.txt", "secrets/ssh_key"]

def try_user(user, pwd):
    start = time.time()
    logger.info(Fore.CYAN + f"Test {user!r}/{pwd!r} on {args.host}:{args.port}")
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

        # Télécharger les canaries si présentes
        for cf in CANARY_FILES:
            if cf in files:
                out = os.path.join(DOWNLOAD_DIR, f"{user}_{cf}")
                logger.info(Fore.BLUE + f"↓ DL {cf} -> {out}")
                with open(out, "wb") as fd:
                    ftp.retrbinary(f"RETR {cf}", fd.write)
                logger.info(Fore.GREEN + "   ✓ DL succeeded")

        # Upload si demandé
        if args.upload:
            base = os.path.basename(args.upload)
            logger.info(Fore.BLUE + f"↑ UPLOAD {args.upload} -> /{base}")
            with open(os.path.expanduser(args.upload), "rb") as rd:
                ftp.storbinary(f"STOR {base}", rd)
            logger.info(Fore.GREEN + "   ✓ Upload succeeded")

        ftp.quit()
        return True, time.time() - start

    except error_perm as e:
        logger.warning(Fore.RED + f"Permission error for {user}: {e}")
    except Exception as e:
        logger.error(Fore.RED + f"Error for {user}: {e}", exc_info=True)

    return False, time.time() - start

def main():
    logger.info("[*] START Attacker")
    results = []
    for idx, user in enumerate(args.users):
        pwd = args.pwds[idx] if idx < len(args.pwds) else ""
        ok, dt = try_user(user, pwd)
        results.append((user, ok, dt))

    logger.info("[*] SUMMARY")
    for user, ok, dt in results:
        status = Fore.GREEN + "OK" if ok else Fore.RED + "KO"
        logger.info(f" - {user:10s}: {status} in {dt:.2f}s")

    logger.info(f"Downloads in {DOWNLOAD_DIR}")
    logger.info("END Attacker")

if __name__ == "__main__":
    main()
