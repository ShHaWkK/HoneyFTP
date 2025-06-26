#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Client Implicit-FTPS (TLS implicite dès le connect) pour votre honeypot.
Envoie NLST avec un argument '.' pour éviter l’erreur.
"""

import socket, ssl
from ftplib import FTP

HOST, PORT = "192.168.100.51", 2121   # ← IP de la VM honeypot

def try_user(user, pw):
    print(f"\n[*] Connexion en tant que {user!r}")
    try:
        # 1) TCP + TLS implicite
        raw = socket.create_connection((HOST, PORT))
        ctx = ssl._create_unverified_context()
        ss  = ctx.wrap_socket(raw, server_hostname=HOST)

        # 2) "Monter" FTP sur la socket chiffrée
        ftp = FTP()
        ftp.sock = ss
        ftp.file = ss.makefile('r', encoding='utf-8', newline='\r\n')
        ftp.af = ss.family
        ftp.passiveserver = True

        # 3) Bannière
        print("  > Bannière:", ftp.getresp().strip())

        # 4) LOGIN
        print("  > LOGIN  :", ftp.login(user, pw))

        # 5) NLST avec un argument pour Twisted
        files = ftp.nlst(".")
        # on retire le "." de début de listing
        files = [f.lstrip("./") for f in files]
        print("  > NLST   :", files)

        # 6) Télécharger passwords.txt si présent
        if "passwords.txt" in files:
            out = f"{user}_passwords.txt"
            print("  > Téléchargement →", out)
            with open(out, "wb") as fd:
                ftp.retrbinary("RETR passwords.txt", fd.write)
            print("  > OK DL")

        ftp.quit()
    except Exception as e:
        print("  ! Erreur:", e)

if __name__=="__main__":
    print("[*] DÉBUT Attacker")
    try_user("anonymous", "")
    try_user("attacker", "secret")
    print("[*] FIN Attacker")
