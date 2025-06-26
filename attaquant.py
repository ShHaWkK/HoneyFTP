#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Attacker Implicit-FTPS — écrit toujours dans votre home réel,
même si vous lancez avec sudo.
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

# — Colorama (auto-install) —
try:
    from colorama import init, Fore, Style
except ImportError:
    subprocess.check_call([sys.executable, "-m", "pip", "install", "colorama"])
    from colorama import init, Fore, Style
init(autoreset=True)

# — CLI avec defaults —
p = argparse.ArgumentParser(description="Attacker Implicit-FTPS")
p.add_argument("-H","--host",    default="192.168.100.51",
               help="IP du honeypot")
p.add_argument("-P","--port",    default=2121, type=int,
               help="Port FTPS implicite")
p.add_argument("-U","--users",   nargs="+",
               default=["anonymous","attacker"],
               help="Utilisateurs à tester")
p.add_argument("-W","--pwds",    nargs="+",
               default=["","secret"],
               help="Passwords correspondants")
p.add_argument("-u","--upload",
               help="Chemin local d'un fichier à uploader")
args = p.parse_args()

# — Détecte le vrai home si on est en sudo —
sudo_user = os.environ.get("SUDO_USER")
if sudo_user:
    home_dir = os.path.expanduser(f"~{sudo_user}")
else:
    home_dir = os.path.expanduser("~")

# — Crée ftp_downloads dans ce home —
DOWNLOAD_DIR = os.path.join(home_dir, "ftp_downloads")
try:
    os.makedirs(DOWNLOAD_DIR, exist_ok=True)
except PermissionError:
    DOWNLOAD_DIR = os.path.join("/tmp", "ftp_downloads")
    os.makedirs(DOWNLOAD_DIR, exist_ok=True)
    print(Fore.YELLOW + f"[WARN] fallback to {DOWNLOAD_DIR}")

# — Configure logging dans le vrai home —
logger = logging.getLogger("attacker")
logger.setLevel(logging.INFO)
fmt = logging.Formatter("%(asctime)s %(levelname)s %(message)s")

# console handler
ch = logging.StreamHandler(sys.stdout)
ch.setFormatter(fmt)
logger.addHandler(ch)

# file handler
LOG_PATH = os.path.join(home_dir, "attacker.log")
try:
    fh = logging.FileHandler(LOG_PATH)
    fh.setFormatter(fmt)
    logger.addHandler(fh)
    logger.info(f"Logging to {LOG_PATH}")
except PermissionError:
    logger.warning(f"Cannot write log to {LOG_PATH}, skipping file log")

CANARY_FILES = ["passwords.txt", "secrets/ssh_key"]

def try_user(user, pwd):
    t0 = time.time()
    logger.info(Fore.CYAN + f"Testing {user!r}/{pwd!r} on {args.host}:{args.port}")
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
        logger.info(Fore.MAGENTA + f"FILES: {files}")

        # download canaries
        for cf in CANARY_FILES:
            if cf in files:
                out = os.path.join(DOWNLOAD_DIR, f"{user}_{cf}")
                logger.info(Fore.BLUE + f"↓ DL {cf} → {out}")
                with open(out, "wb") as fd:
                    ftp.retrbinary(f"RETR {cf}", fd.write)
                logger.info(Fore.GREEN + "   ✓ DL succeeded")

        # upload if requested
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
    for i, user in enumerate(args.users):
        pwd = args.pwds[i] if i < len(args.pwds) else ""
        ok, dt = try_user(user, pwd)
        results.append((user, ok, dt))
    logger.info("[*] SUMMARY")
    for user, ok, dt in results:
        status = Fore.GREEN + "OK" if ok else Fore.RED + "KO"
        logger.info(f" - {user:10s}: {status} in {dt:.2f}s")
    logger.info(f"Downloads in {DOWNLOAD_DIR}")
    logger.info("END Attacker")

if __name__=="__main__":
    main()
