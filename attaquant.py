#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Script de test FTPS implicite (TLS dès la connexion) vers le honeypot.
Affiche chaque étape pour déboguer.
"""

import ssl
from ftplib import FTP_TLS

HOST = "192.168.100.51"  # ← remplacez par l'IP de votre honeypot
PORT = 2121

def test_login(user, pw):
    print(f"\n[*] Tentative de connexion en tant que {user!r} …")
    try:
        # Contexte qui ignore le certificat auto-signé
        ctx = ssl._create_unverified_context()
        ftps = FTP_TLS(context=ctx)        # implicit FTPS
        print("  > connect() …")
        ftps.connect(HOST, PORT)          # handshake TLS immédiat
        print("  > login() …")
        ftps.login(user, pw)              # USER/PASS
        print("  > prot_p() …")
        ftps.prot_p()                     # sécurise le canal de données
        print(f"[+] Connexion réussie : {user!r}")
        files = ftps.nlst()
        print("    Contenu :", files)
        if "passwords.txt" in files:
            local = f"{user}_passwords.txt"
            print(f"    Téléchargement → {local}")
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
