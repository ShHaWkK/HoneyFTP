#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Attacker Implicit-FTPS Interactive Menu

Usage: python3 attacker_menu.py [--host HOST] [--port PORT]

Menu:
 1) Connexion anonymous/""
 2) Connexion attacker/secret
 3) Connexion custom (user+pwd)
 4) Lister fichiers (NLST)
 5) Télécharger un fichier
 6) Uploader un fichier
 7) Déconnexion et quitter
"""

import os
import sys
import ssl
import socket
import argparse
from ftplib import FTP, error_perm

def make_ftps(host, port):
    """Crée et renvoie une instance ftplib.FTP sur TLS implicite."""
    raw = socket.create_connection((host, port), timeout=10)
    ctx = ssl._create_unverified_context()
    ss  = ctx.wrap_socket(raw, server_hostname=host)
    ftp = FTP()
    ftp.sock = ss
    ftp.file = ss.makefile('r', encoding='utf-8', newline='\r\n')
    ftp.af = ss.family
    ftp.passiveserver = True
    banner = ftp.getresp().strip()
    print("← Bannière :", banner)
    return ftp

def do_login(ftp, user, pwd):
    """Effectue USER/PASS."""
    try:
        resp = ftp.login(user, pwd)
        print("← LOGIN OK :", resp)
        return True
    except error_perm as e:
        print("× AUTH FAILED :", e)
        return False

def do_nlst(ftp):
    """Liste le répertoire courant."""
    try:
        files = ftp.nlst(".")
        files = [f.lstrip("./") for f in files]
        print("← FILES:", files)
    except Exception as e:
        print("× NLST failed:", e)

def do_retr(ftp):
    """Demande à l’utilisateur un nom de fichier et le télécharge."""
    fn = input("Nom du fichier à télécharger > ").strip()
    if not fn:
        print("Abandon.")
        return
    out = input("Chemin local de destination > ").strip() or fn
    try:
        with open(os.path.expanduser(out), "wb") as f:
            ftp.retrbinary(f"RETR {fn}", f.write)
        print(f"✓ {fn} → {out}")
    except Exception as e:
        print("× RETR failed:", e)

def do_stor(ftp):
    """Demande un chemin local et l’upload."""
    local = input("Chemin local du fichier à uploader > ").strip()
    if not local or not os.path.isfile(os.path.expanduser(local)):
        print("Fichier invalide, abandon.")
        return
    remote = input("Nom distant (STOR) > ").strip() or os.path.basename(local)
    try:
        with open(os.path.expanduser(local), "rb") as f:
            ftp.storbinary(f"STOR {remote}", f)
        print(f"✓ Uploaded {local} → /{remote}")
    except Exception as e:
        print("× STOR failed:", e)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="192.168.100.51",
                        help="IP ou hostname du honeypot")
    parser.add_argument("--port", default=2121, type=int,
                        help="Port FTPS implicite")
    args = parser.parse_args()

    ftp = None
    connected_user = None

    while True:
        print("""
===== MENU FTPS ATTACKER =====
1) Connexion anonymous / ""
2) Connexion attacker / secret
3) Connexion custom
4) Lister fichiers (NLST)
5) Télécharger un fichier
6) Uploader un fichier
7) Déconnexion et quitter
""")
        choice = input("Votre choix > ").strip()
        if choice == "1":
            if ftp: ftp.close()
            ftp = make_ftps(args.host, args.port)
            if do_login(ftp, "anonymous", ""):
                connected_user = "anonymous"
            else:
                ftp.close(); ftp = None
        elif choice == "2":
            if ftp: ftp.close()
            ftp = make_ftps(args.host, args.port)
            if do_login(ftp, "attacker", "secret"):
                connected_user = "attacker"
            else:
                ftp.close(); ftp = None
        elif choice == "3":
            u = input("User > ").strip()
            p = input("Password > ").strip()
            if ftp: ftp.close()
            ftp = make_ftps(args.host, args.port)
            if do_login(ftp, u, p):
                connected_user = u
            else:
                ftp.close(); ftp = None
        elif choice == "4":
            if not ftp:
                print("► Veuillez vous connecter d'abord.")
            else:
                do_nlst(ftp)
        elif choice == "5":
            if not ftp:
                print("► Veuillez vous connecter d'abord.")
            else:
                do_retr(ftp)
        elif choice == "6":
            if not ftp:
                print("► Veuillez vous connecter d'abord.")
            else:
                do_stor(ftp)
        elif choice == "7":
            if ftp:
                try: ftp.quit()
                except: pass
            print("Bye.")
            break
        else:
            print("Choix invalide, réessayez.")

if __name__ == "__main__":
    main()
