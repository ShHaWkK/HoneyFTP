#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Attacker Implicit FTPS — script complet et robuste.

– TLS implicite (handshake dès la connexion)  
– LOGIN anonymous/"" et attacker/secret par défaut  
– NLST "." + retrbinary pour passwords.txt & autres canaries  
– Upload optionnel (--upload)  
– Couleurs (colorama), argparse, logging avec fallback  
– Dossier de download dans ~/ftp_downloads ou /tmp/ftp_downloads  
– Résumé final  
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

# 1) Colorama
try:
    from colorama import init, Fore, Style
except ImportError:
    subprocess.check_call([sys.executable, "-m", "pip", "install", "colorama"])
    from colorama import init, Fore, Style
init(autoreset=True)

# 2) CLI avec defaults
p = argparse.ArgumentParser(description="Attacker Implicit FTPS")
p.add_argument("-H","--host", default="192.168.100.51",
               help="IP ou hostname du honeypot")
p.add_argument("-P","--port", default=2121, type=int,
               help="Port FTPS implicit")
p.add_argument("-U","--users", nargs="+",
               default=["anonymous","attacker"],
               help="Utilisateurs à tester (défaut: anonymous attacker)")
p.add_argument("-W","--pwds", nargs="+",
               default=["","secret"],
               help="Passwords correspondants (défaut: '' secret)")
p.add_argument("-d","--download", default="~/ftp_downloads",
               help="Dossier local pour DL (défaut: ~/ftp_downloads)")
p.add_argument("-u","--upload",
               help="Chemin local d'un fichier à uploader")
p.add_argument("-l","--log",
               help="Chemin du fichier de log (fichier unique)")
args = p.parse_args()

# 3) Prépare dossier de download avec expanduser + fallback
dl = os.path.expanduser(args.download)
try:
    os.makedirs(dl, exist_ok=True)
except PermissionError:
    dl = "/tmp/ftp_downloads"
    os.makedirs(dl, exist_ok=True)
    print(Fore.YELLOW + f"[WARNING] permission denied on {args.download}, using {dl}")
DOWNLOAD_DIR = dl

# 4) Logging console + fichier (optionnel)
logger = logging.getLogger("attacker")
logger.setLevel(logging.INFO)
fmt = logging.Formatter("%(asctime)s %(levelname)s %(message)s")

# console handler
ch = logging.StreamHandler(sys.stdout)
ch.setFormatter(fmt)
logger.addHandler(ch)

# file handler
if args.log:
    log_path = os.path.expanduser(args.log)
else:
    # default under home or fallback to /tmp
    home = os.path.expanduser("~")
    if os.access(home, os.W_OK):
        log_path = os.path.join(home, "attacker.log")
    else:
        log_path = "/tmp/attacker.log"
try:
    fh = logging.FileHandler(log_path)
    fh.setFormatter(fmt)
    logger.addHandler(fh)
    logger.info(f"Logging to {log_path}")
except PermissionError:
    logger.warning(f"Cannot write log to {log_path}, continuing without file log")

# 5) Canaries connues
CANARY_FILES = ["passwords.txt", "secrets/ssh_key"]

def try_user(user, pwd):
    t0 = time.time()
    logger.info(Fore.CYAN + f"Testing {user!r}/{pwd!r} on {args.host}:{args.port}")
    try:
        # TCP + TLS implicite
        raw = socket.create_connection((args.host, args.port), timeout=10)
        ctx = ssl._create_unverified_context()
        ss  = ctx.wrap_socket(raw, server_hostname=args.host)

        # On greffe ftplib.FTP sur la socket chiffrée
        ftp = FTP()
        ftp.sock          = ss
        ftp.file          = ss.makefile('r', encoding='utf-8', newline='\r\n')
        ftp.af            = ss.family
        ftp.passiveserver = True

        # Bannière
        ban = ftp.getresp().strip()
        logger.info(Fore.YELLOW + ban)

        # LOGIN
        resp = ftp.login(user, pwd)
        logger.info(Fore.GREEN + f"LOGIN OK: {resp}")

        # NLST avec "."
        files = ftp.nlst(".")
        files = [f.lstrip("./") for f in files]
        logger.info(Fore.MAGENTA + f"FILES: {files}")

        # DL des canaries
        for cf in CANARY_FILES:
            if cf in files:
                out = os.path.join(DOWNLOAD_DIR, f"{user}_{cf}")
                logger.info(Fore.BLUE + f"↓ DL {cf} -> {out}")
                with open(out, "wb") as fd:
                    ftp.retrbinary(f"RETR {cf}", fd.write)
                logger.info(Fore.GREEN + "   ✓ DL succeeded")

        # Upload éventuel
        if args.upload:
            base = os.path.basename(args.upload)
            logger.info(Fore.BLUE + f"↑ UPLOAD {args.upload} -> /{base}")
            with open(os.path.expanduser(args.upload),"rb") as rd:
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
