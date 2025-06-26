#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Client Implicit-FTPS pour tester le honeypot.

– TLS implicite dès la connexion TCP  
– LOGIN anonymous et attacker/secret  
– NLST "." pour Twisted  
– Téléchargement de passwords.txt dans ~/ftp_downloads  
"""

import os
import socket
import ssl
from ftplib import FTP

# ← Remplacez par l’IP de votre VM honeypot
HOST, PORT = "192.168.100.51", 2121

# Dossier local où on a le droit d’écrire
DOWNLOAD_DIR = os.path.expanduser("~/ftp_downloads")
os.makedirs(DOWNLOAD_DIR, exist_ok=True)

def try_user(user: str, pw: str):
    print(f"\n[*] Connexion en tant que {user!r}")
    try:
        # 1) TCP + TLS implicite
        raw = socket.create_connection((HOST, PORT))
        ctx = ssl._create_unverified_context()
        ss  = ctx.wrap_socket(raw, server_hostname=HOST)

        # 2) On “monte” FTP sur cette socket chiffrée
        ftp = FTP()
        ftp.sock         = ss
        ftp.file         = ss.makefile('r', encoding='utf-8', newline='\r\n')
        ftp.af           = ss.family
        ftp.passiveserver = True

        # 3) Bannière
        ban = ftp.getresp().strip()
        print("  > Bannière:", ban)

        # 4) LOGIN
        resp = ftp.login(user, pw)
        print("  > LOGIN  :", resp)

        # 5) NLST avec argument "."
        files = ftp.nlst(".")
        files = [f.lstrip("./") for f in files]
        print("  > NLST   :", files)

        # 6) Télécharger passwords.txt si présent
        if "passwords.txt" in files:
            out = os.path.join(DOWNLOAD_DIR, f"{user}_passwords.txt")
            print("  > Téléchargement →", out)
            with open(out, "wb") as f:
                ftp.retrbinary("RETR passwords.txt", f.write)
            print("  > OK DL")

        ftp.quit()

    except Exception as e:
        print("  ! Erreur:", e)

if __name__ == "__main__":
    print("[*] DEBUT Attaquant")
    try_user("anonymous", "")
    try_user("attacker", "secret")
    print("[*] FIN Attaquant")
