#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Script de test FTPS/TLS implicite vers le honeypot.
"""

import ssl
from ftplib import FTP_TLS

HOST = "IP"  
PORT = 2121

def test_login(user, passwd):
    try:
        # Contexte qui ignore le certificat auto-signé
        ctx = ssl._create_unverified_context()
        ftps = FTP_TLS(context=ctx)
        ftps.connect(HOST, PORT)
        ftps.auth()               # passe en mode TLS explicite si nécessaire
        ftps.login(user, passwd)
        ftps.prot_p()             # sécurise le canal de données
        print(f"[+] Connexion réussie en tant que : {user!r}")
        files = ftps.nlst()
        print("    Contenu :", files)
        if "passwords.txt" in files:
            local = f"{user}_passwords.txt"
            with open(local, "wb") as f:
                ftps.retrbinary("RETR passwords.txt", f.write)
            print(f"[+] Téléchargé passwords.txt → {local}")
        ftps.quit()
    except Exception as e:
        print(f"[-] Échec {user!r} : {e}")

def main():
    for user, pw in [("anonymous", ""), ("attacker", "secret")]:
        test_login(user, pw)

if __name__ == "__main__":
    main()
