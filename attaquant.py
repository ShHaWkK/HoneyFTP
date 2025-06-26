#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Client Implicit FTPS (TLS dès le connect) pour votre honeypot.
Affiche chaque étape et corrige l’erreur bytes/str.
"""

import socket
import ssl
from ftplib import FTP

HOST = "192.168.100.51"   # ← Mettez ici l’IP de votre honeypot
PORT = 2121

def test_login(user, pw):
    print(f"\n[*] Tentative de connexion en tant que {user!r} …", flush=True)
    try:
        # 1) Connexion TCP brute
        print("  > Création socket TCP…", flush=True)
        raw = socket.create_connection((HOST, PORT))

        # 2) TLS implicite dès la connexion
        print("  > Enveloppement TLS implicite…", flush=True)
        ctx = ssl._create_unverified_context()
        ssock = ctx.wrap_socket(raw, server_hostname=HOST)

        # 3) Initialiser ftplib.FTP sur cette socket chiffrée
        ftp = FTP()
        ftp.sock = ssock
        # **Important** : ouvrir le .file en mode texte pour que getresp() retourne str, pas bytes
        ftp.file = ssock.makefile('r', encoding='utf-8', newline='\r\n')

        # 4) Lire la bannière
        welcome = ftp.getresp()
        print(f"    >>> Bannière : {welcome.strip()!r}", flush=True)

        # 5) LOGIN USER/PASS
        print("  > Envoi de USER/PASS…", flush=True)
        resp = ftp.login(user, pw)
        print(f"    >>> Réponse login : {resp!r}", flush=True)

        # 6) Sécuriser le canal de données
        print("  > Activation PROT P…", flush=True)
        ftp.prot_p()

        print(f"[+] Connexion réussie : {user!r}", flush=True)

        # 7) LISTER
        files = ftp.nlst()
        print("    Contenu racine :", files, flush=True)

        # 8) TÉLÉCHARGER passwords.txt si présent
        if "passwords.txt" in files:
            local = f"{user}_passwords.txt"
            print(f"  > Récupération de passwords.txt → {local}", flush=True)
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
