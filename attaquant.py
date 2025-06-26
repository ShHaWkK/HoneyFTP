#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Client Implicit-FTPS — TLS implicite dès le connect — 
Télécharge passwords.txt dans un dossier écrivable.
"""

import os
import socket
import ssl
from ftplib import FTP

# IP et port de la VM honeypot
HOST, PORT = "192.168.100.51", 2121

# Choisir un dossier de downloads où l'utilisateur peut écrire
HOME = os.path.expanduser("~")
DOWNLOAD_DIR = os.path.join(HOME, "ftp_downloads")
os.makedirs(DOWNLOAD_DIR, exist_ok=True)

def try_user(user, pw):
    print(f"\n[*] Connexion en tant que {user!r}")
    try:
        # 1) TCP + TLS implicite
        raw = socket.create_connection((HOST, PORT))
        ctx = ssl._create_unverified_context()
        ss  = ctx.wrap_socket(raw, server_hostname=HOST)

        # 2) “Monter” FTP sur le socket chiffré
        ftp = FTP()
        ftp.sock = ss
        ftp.file = ss.makefile('r', encoding='utf-8', newline='\r\n')
        # nécessaire pour nlst/retrbinary en passive mode
        ftp.af = ss.family
        ftp.passiveserver = True

        # 3) Bannière
        banner = ftp.getresp().strip()
        print("  > Bannière:", banner)

        # 4) LOGIN
        resp = ftp.login(user, pw)
        print("  > LOGIN  :", resp)

        # 5) NLST avec argument “.”
        files = ftp.nlst(".")
        # nettoyer le “.” devant
        files = [f.lstrip("./") for f in files]
        print("  > NLST   :", files)

        # 6) Télécharger passwords.txt si présent
        if "passwords.txt" in files:
            local = os.path.join(DOWNLOAD_DIR, f"{user}_passwords.txt")
            print("  > Téléchargement →", local)
            with open(local, "wb") as fd:
                ftp.retrbinary("RETR passwords.txt", fd.write)
            print("  > OK DL")

        ftp.quit()

    except Exception as e:
        print("  ! Erreur:", e)

if __name__ == "__main__":
    print("[*] DÉBUT Attacker")
    try_user("anonymous", "")
    try_user("attacker", "secret")
    print("[*] FIN Attacker")
