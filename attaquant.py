#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Script de test FTPS implicite (TLS dès connect) vers le honeypot.
"""

import ssl
from ftplib import FTP_TLS

HOST = "192.168.100.51"  # ← remplacez par l'IP de votre honeypot
PORT = 2121

def test_login(user, pw):
    try:
        # Contexte TLS qui ignore le certif auto-signé
        ctx = ssl._create_unverified_context()
        ftps = FTP_TLS(context=ctx)        # implicit FTPS
        ftps.connect(HOST, PORT)          # handshake TLS immédiat
        ftps.login(user, pw)              # USER/PASS
        ftps.prot_p()                     # sécurise le canal de données
        print(f"[+] Connexion réussie: {user!r}")
        files = ftps.nlst()
        print("    Contenu :", files)
        if "passwords.txt" in files:
            local = f"{user}_passwords.txt"
            with open(local, "wb") as f:
                ftps.retrbinary("RETR passwords.txt", f.write)
            print(f"[+] Téléchargé passwords.txt → {local}")
        ftps.quit()
    except Exception as e:
        print(f"[-] Échec connexion {user!r} : {e}")

def main():
    # on teste anonymement puis attacker/secret
    test_login("anonymous", "")
    test_login("attacker", "secret")

if __name__ == "__main__":
    main()
