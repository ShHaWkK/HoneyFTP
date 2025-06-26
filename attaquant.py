#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Client Implicit-FTPS (TLS implicite dès le connect) pour votre honeypot.
"""

import socket, ssl
from ftplib import FTP

HOST, PORT = "192.168.100.51", 2121   # ← mettez ici l’IP réelle de votre honeypot

def try_user(user, pw):
    print(f"\n[*] Essayage en tant que {user!r}")
    try:
        # 1) Connexion TCP + TLS implicite
        raw = socket.create_connection((HOST, PORT))
        ctx = ssl._create_unverified_context()
        ss = ctx.wrap_socket(raw, server_hostname=HOST)

        # 2) On “monte” FTP sur ce socket chiffré
        ftp = FTP()
        ftp.sock = ss
        ftp.file = ss.makefile('r', encoding='utf-8', newline='\r\n')
        # Obligatoire pour passive-mode et nlst()
        ftp.af = ss.family
        ftp.passiveserver = True

        # 3) Lire la bannière
        banner = ftp.getresp()
        print("  > Bannière:", banner.strip())

        # 4) LOGIN
        resp = ftp.login(user, pw)
        print("  > LOGIN  :", resp)

        # 5) LIST
        files = ftp.nlst()
        print("  > NLST   :", files)

        # 6) DOWNLOAD passwords.txt s’il existe
        if "passwords.txt" in files:
            fn = f"{user}_passwords.txt"
            print("  > Téléchargement →", fn)
            with open(fn, "wb") as f:
                ftp.retrbinary("RETR passwords.txt", f.write)
            print("  > OK DL")

        ftp.quit()
    except Exception as e:
        print("  ! Erreur:", e)

if __name__ == "__main__":
    print("[*] DÉBUT Attacker")
    try_user("anonymous", "")
    try_user("attacker", "secret")
    print("[*] FIN Attacker")
