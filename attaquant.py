#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Attacker Implicit-FTPS — Menu interactif

Usage:
  ./attacker_menu.py [--host HOST] [--port PORT]

Menu:
 1) Connexion anonymous / ""
 2) Connexion attacker / secret
 3) Connexion custom (user+pwd)
 4) Lister fichiers (NLST)
 5) Télécharger un fichier
 6) Uploader un fichier
 7) Quitter
"""

import os
import ssl
import socket
import argparse
from ftplib import FTP, error_perm

# colorama pour la couleur
try:
    from colorama import init, Fore, Style
except ImportError:
    import subprocess, sys
    subprocess.check_call([sys.executable, "-m", "pip", "install", "colorama"])
    from colorama import init, Fore, Style
init(autoreset=True)

def make_ftps(host, port):
    """
    Connexion FTPS implicite : 
    - TCP → wrap TLS → greffe FTP dessus
    - renvoie un objet ftplib.FTP prêt à l'emploi
    """
    raw = socket.create_connection((host, port), timeout=10)
    ctx = ssl._create_unverified_context()
    ss  = ctx.wrap_socket(raw, server_hostname=host)
    ftp = FTP()
    ftp.sock          = ss
    ftp.file          = ss.makefile('r', encoding='utf-8', newline='\r\n')
    ftp.af            = ss.family
    ftp.passiveserver = True
    banner = ftp.getresp().strip()
    print(Fore.YELLOW + "← Bannière :", banner)
    return ftp

def do_login(ftp, user, pwd):
    """Envoie USER/PASS et affiche le résultat."""
    try:
        resp = ftp.login(user, pwd)
        print(Fore.GREEN + "← LOGIN OK :", resp)
        return True
    except error_perm as e:
        print(Fore.RED + "× AUTH FAILED :", e)
        return False

def do_nlst(ftp):
    """Affiche le contenu du répertoire courant."""
    try:
        files = ftp.nlst(".")
        files = [f.lstrip("./") for f in files]
        print(Fore.CYAN + "← FILES :", files)
    except Exception as e:
        print(Fore.RED + "× NLST fail :", e)

def do_retr(ftp):
    """Prompt pour RETR puis téléchargement."""
    fn = input("Nom du fichier à télécharger > ").strip()
    if not fn:
        print("Abandon.")
        return
    dest = input("Chemin local de destination > ").strip() or fn
    try:
        with open(os.path.expanduser(dest), "wb") as fd:
            ftp.retrbinary(f"RETR {fn}", fd.write)
        print(Fore.GREEN + f"✓ {fn} → {dest}")
    except Exception as e:
        print(Fore.RED + "× RETR fail :", e)

def do_stor(ftp):
    """Prompt pour STOR puis upload."""
    src = input("Chemin local du fichier à uploader > ").strip()
    src = os.path.expanduser(src)
    if not os.path.isfile(src):
        print("Fichier invalide.")
        return
    remote = input("Nom distant (STOR) > ").strip() or os.path.basename(src)
    try:
        with open(src, "rb") as f:
            ftp.storbinary(f"STOR {remote}", f)
        print(Fore.GREEN + f"✓ Uploaded {src} → /{remote}")
    except Exception as e:
        print(Fore.RED + "× STOR fail :", e)

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--host", default="192.168.100.51", help="Honeypot IP")
    p.add_argument("--port", default=2121, type=int, help="Port FTPS implicite")
    args = p.parse_args()

    ftp = None
    print(Fore.YELLOW + "=== Attacker Implicit-FTPS Menu ===")
    while True:
        print("""
1) Connexion anonymous/""
2) Connexion attacker/secret
3) Connexion custom
4) Lister fichiers (NLST)
5) Télécharger un fichier
6) Uploader un fichier
7) Quitter
""")
        cmd = input("Votre choix > ").strip()
        if cmd == "1":
            if ftp: ftp.close()
            ftp = make_ftps(args.host, args.port)
            if not do_login(ftp, "anonymous", ""):
                ftp.close(); ftp = None
        elif cmd == "2":
            if ftp: ftp.close()
            ftp = make_ftps(args.host, args.port)
            if not do_login(ftp, "attacker", "secret"):
                ftp.close(); ftp = None
        elif cmd == "3":
            user = input("User > ").strip()
            pwd  = input("Password > ").strip()
            if ftp: ftp.close()
            ftp = make_ftps(args.host, args.port)
            if not do_login(ftp, user, pwd):
                ftp.close(); ftp = None
        elif cmd == "4":
            if not ftp:
                print("→ Veuillez vous connecter d'abord.")
            else:
                do_nlst(ftp)
        elif cmd == "5":
            if not ftp:
                print("→ Veuillez vous connecter d'abord.")
            else:
                do_retr(ftp)
        elif cmd == "6":
            if not ftp:
                print("→ Veuillez vous connecter d'abord.")
            else:
                do_stor(ftp)
        elif cmd == "7":
            if ftp:
                try: ftp.quit()
                except: pass
            print("Bye !")
            break
        else:
            print("Choix inconnu.")

if __name__ == "__main__":
    main()
