#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Script de test Implicit FTPS (TLS implicite sur le port) vers le honeypot.
Affiche chaque étape pour déboguer.
"""

import ssl
from ftplib import FTP_TLS

HOST = "192.168.100.51"  # ← mettez ici l’IP de votre honeypot
PORT = 2121

def test_login(user, pw):
    print(f"\n[*] Tentative de connexion en tant que {user!r} …")
    try:
        # 1) on crée un contexte qui ignore le certif auto-signé
        ctx = ssl._create_unverified_context()

        # 2) on instancie FTP_TLS (mais on ne fera pas AUTH TLS explicite)
        ftps = FTP_TLS(context=ctx)

        # 3) on ouvre la connexion TCP
        print("  > connect() …")
        ftps.connect(HOST, PORT)

        # 4) on wrap directement la socket pour faire du TLS implicite
        print("  > wrapping socket pour TLS implicite …")
        ftps.sock = ctx.wrap_socket(ftps.sock, server_hostname=HOST)
        ftps.file = ftps.sock.makefile('rb')  # adapter le file handle interne

        # 5) on peut maintenant envoyer USER/PASS
        print("  > login() …")
        ftps.login(user, pw)

        # 6) on passe le canal de données en TLS également
        print("  > prot_p() …")
        ftps.prot_p()

        print(f"[+] Connexion réussie : {user!r}")
        files = ftps.nlst()
        print("    Contenu :", files)

        if "passwords.txt" in files:
            local = f"{user}_passwords.txt"
            print(f"    Téléchargement de passwords.txt → {local}")
            with open(local, "wb") as f:
                ftps.retrbinary("RETR passwords.txt", f.write)
            print("[+] Téléchargement terminé")

        ftps.quit()

    except Exception as e:
        print(f"[-] Échec pour {user!r} :", e)

def main():
    print("[*] Début du script attacker.py")
    test_login("anonymous", "")
    test_login("attacker", "secret")
    print("[*] Fin du script")

if __name__ == "__main__":
    main()
