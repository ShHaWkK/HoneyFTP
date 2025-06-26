#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Client Implicit FTPS (TLS dès la connexion) vers votre honeypot.
Affiche chaque étape, sans prot_p(), pour éviter l'erreur 'FTP' object has no attribute 'prot_p'.
"""

import socket
import ssl
from ftplib import FTP

HOST = "192.168.100.51"   # ← remplacez par l'IP de votre honeypot
PORT = 2121

def test_login(user, pw):
    print(f"\n[*] Tentative de connexion en tant que {user!r} …", flush=True)
    try:
        # 1) TCP
        print("  > Création de la socket TCP…", flush=True)
        raw = socket.create_connection((HOST, PORT))

        # 2) TLS implicite
        print("  > Enveloppement TLS implicite…", flush=True)
        ctx = ssl._create_unverified_context()
        ssock = ctx.wrap_socket(raw, server_hostname=HOST)

        # 3) On monte ftplib.FTP sur cette socket chiffrée
        ftp = FTP()
        ftp.sock = ssock
        # file en mode texte pour que getresp() retourne str
        ftp.file = ssock.makefile('r', encoding='utf-8', newline='\r\n')

        # 4) Bannière
        banner = ftp.getresp()
        print(f"    >>> Bannière : {banner.strip()!r}", flush=True)

        # 5) USER/PASS
        print("  > Envoi de USER/PASS…", flush=True)
        resp = ftp.login(user, pw)
        print(f"    >>> Réponse login : {resp!r}", flush=True)

        # 6) LISTING (sans prot_p)
        print("  > NLST…", flush=True)
        files = ftp.nlst()
        print("    Contenu racine :", files, flush=True)

        # 7) TÉLÉCHARGER passwords.txt si présent
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
