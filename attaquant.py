#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Client Implicit-FTPS (TLS implicite dès le connect) pour tester le honeypot.
"""

import socket, ssl
from ftplib import FTP

HOST, PORT = "192.168.100.51", 2121  # adaptez l'IP

def try_login(user, pw):
    print(f"\n[*] Connexion en tant que {user!r} …")
    try:
        raw = socket.create_connection((HOST, PORT))
        ctx = ssl._create_unverified_context()
        ss  = ctx.wrap_socket(raw, server_hostname=HOST)

        ftp = FTP()
        ftp.sock = ss
        ftp.file = ss.makefile('r', encoding='utf-8', newline='\r\n')
        # ces attributs sont nécessaires pour nlst()/retrbinary()
        ftp.af = ss.family
        ftp.timeout = ss.gettimeout()
        ftp.passiveserver = True

        banner = ftp.getresp()
        print("  > Bannière :", banner.strip())

        resp = ftp.login(user, pw)
        print("  > LOGIN   :", resp)

        files = ftp.nlst()
        print("  > NLST    :", files)

        if "passwords.txt" in files:
            fn = f"{user}_passwords.txt"
            print("  > Téléchargement →", fn)
            with open(fn, "wb") as f:
                ftp.retrbinary("RETR passwords.txt", f.write)
            print("  > Téléchargement terminé")

        ftp.quit()

    except Exception as e:
        print(f"  ! Échec pour {user!r} :", e)

if __name__ == "__main__":
    print("[*] Début Attaquant")
    try_login("anonymous", "")
    try_login("attacker", "secret")
    print("[*] Fin Attaquant")
