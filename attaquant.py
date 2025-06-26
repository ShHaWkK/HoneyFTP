#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Client Implicit FTPS (TLS implicite sur le port) pour votre honeypot.
"""

import socket
import ssl
from ftplib import FTP

HOST = "192.168.100.51"   # ← changez ceci pour l'IP de votre honeypot
PORT = 2121

def test_login(user, pw):
    print(f"\n[*] Tentative de connexion en tant que {user!r} …", flush=True)
    try:
        # 1) Connexion TCP
        print("  > Création de la socket TCP …", flush=True)
        raw = socket.create_connection((HOST, PORT))

        # 2) Enveloppement TLS implicite
        print("  > Enveloppement TLS implicite …", flush=True)
        ctx = ssl._create_unverified_context()
        ssock = ctx.wrap_socket(raw, server_hostname=HOST)

        # 3) Initialiser ftplib.FTP sur cette socket chiffrée
        ftp = FTP()
        ftp.sock = ssock
        ftp.file = ssock.makefile('rb')
        # lire la bannière de bienvenue
        welcome = ftp.getresp()
        print(f"    >>> Bannière : {welcome.strip()!r}", flush=True)

        # 4) LOGIN
        print("  > Envoi de USER/PASS …", flush=True)
        resp = ftp.login(user, pw)
        print(f"    >>> Réponse login : {resp!r}", flush=True)

        # 5) Sécuriser le canal de données
        print("  > Activation du mode prot_p() …", flush=True)
        ftp.prot_p()

        print(f"[+] Connexion réussie : {user!r}", flush=True)

        # 6) LISTING
        files = ftp.nlst()
        print("    Contenu du répertoire racine :", files, flush=True)

        # 7) Téléchargement du canary
        if "passwords.txt" in files:
            local = f"{user}_passwords.txt"
            print(f"  > Téléchargement de passwords.txt → {local}", flush=True)
            with open(local, "wb") as f:
                ftp.retrbinary("RETR passwords.txt", f.write)
            print("[+] Téléchargement terminé", flush=True)

        ftp.quit()

    except Exception as e:
        print(f"[-] Échec pour {user!r} :", e, flush=True)

def main():
    print("[*] Début du script attacker.py", flush=True)
    test_login("anonymous", "")
    test_login("attacker", "secret")
    print("[*] Fin du script", flush=True)

if __name__ == "__main__":
    main()
