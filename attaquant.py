#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Attacker Implicit-FTPS Interactive Menu

1) Connexion anonymous/""
2) Connexion attacker/secret
3) Connexion custom (user/pwd)
4) Lister (NLST)
5) Télécharger (RETR)
6) Uploader (STOR)
7) Quitter

Affiche bien en couleur, gère TLS implicite, mémorise la session.
"""

import os, ssl, socket, argparse
from ftplib import FTP, error_perm

# colorama auto-install
try:
    from colorama import init, Fore, Style
except ImportError:
    import subprocess, sys
    subprocess.check_call([sys.executable, "-m", "pip", "install", "colorama"])
    from colorama import init, Fore, Style
init(autoreset=True)

def make_ftps(host, port):
    raw = socket.create_connection((host, port), timeout=10)
    ctx = ssl._create_unverified_context()
    ss  = ctx.wrap_socket(raw, server_hostname=host)
    ftp = FTP()
    ftp.sock          = ss
    ftp.file          = ss.makefile('r', encoding='utf-8', newline='\r\n')
    ftp.af            = ss.family
    ftp.passiveserver = True
    banner = ftp.getresp().strip()
    print(Fore.YELLOW + "← Bannière :", banner)
    return ftp

def do_login(ftp, user, pwd):
    try:
        resp = ftp.login(user, pwd)
        print(Fore.GREEN + f"← LOGIN OK : {resp}")
        return True
    except error_perm as e:
        print(Fore.RED + f"× AUTH FAILED : {e}")
        return False

def do_nlst(ftp):
    try:
        files = ftp.nlst(".")
        files = [f.lstrip("./") for f in files]
        print(Fore.CYAN + "← FILES:")
        for i, fn in enumerate(files, 1):
            print(Fore.CYAN + f"  {i:2d}) {fn}")
    except Exception as e:
        print(Fore.RED + "× NLST failed:", e)

def do_retr(ftp):
    fn = input("Nom du fichier à télécharger > ").strip()
    if not fn:
        print("Abandon.")
        return
    out = input("Chemin local (ou press Enter pour même nom) > ").strip() or fn
    try:
        with open(os.path.expanduser(out), "wb") as f:
            ftp.retrbinary(f"RETR {fn}", f.write)
        print(Fore.GREEN + f"✓ {fn} → {out}")
        print(Fore.YELLOW + "(check the file for fake data if any)")
    except Exception as e:
        print(Fore.RED + "× RETR failed:", e)

def do_stor(ftp):
    src = input("Fichier local à uploader > ").strip()
    src = os.path.expanduser(src)
    if not os.path.isfile(src):
        print("Fichier invalide.")
        return
    remote = input("Nom distant (STOR) > ").strip() or os.path.basename(src)
    try:
        with open(src,"rb") as f:
            ftp.storbinary(f"STOR {remote}", f)
        print(Fore.GREEN + f"✓ Uploaded {src} → /{remote}")
    except Exception as e:
        print(Fore.RED + "× STOR failed:", e)

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--host", default="192.168.100.51")
    p.add_argument("--port", default=2121, type=int)
    args = p.parse_args()

    ftp = None
    print(Fore.YELLOW + "=== Attacker Implicit-FTPS ===")
    while True:
        print("""
1) Connexion anonymous/""
2) Connexion attacker/secret
3) Connexion custom
4) Lister (NLST)
5) Télécharger (RETR)
6) Uploader (STOR)
7) Quitter
""")
        cmd = input("Votre choix > ").strip()
        if cmd == "1":
            if ftp: ftp.close()
            ftp = make_ftps(args.host, args.port)
            if not do_login(ftp, "anonymous", ""):
                ftp.close(); ftp = None
        elif cmd == "2":
            if ftp: ftp.close()
            ftp = make_ftps(args.host, args.port)
            if not do_login(ftp, "attacker", "secret"):
                ftp.close(); ftp = None
        elif cmd == "3":
            u = input("User > ").strip()
            p = input("Password > ").strip()
            if ftp: ftp.close()
            ftp = make_ftps(args.host, args.port)
            if not do_login(ftp, u, p):
                ftp.close(); ftp = None
        elif cmd == "4":
            if not ftp:
                print("→ Connectez-vous d’abord.")
            else:
                do_nlst(ftp)
        elif cmd == "5":
            if not ftp:
                print("→ Connectez-vous d’abord.")
            else:
                do_retr(ftp)
        elif cmd == "6":
            if not ftp:
                print("→ Connectez-vous d’abord.")
            else:
                do_stor(ftp)
        elif cmd == "7":
            if ftp:
                try: ftp.quit()
                except: pass
            print("Au revoir !")
            break
        else:
            print("Choix invalide.")

if __name__ == "__main__":
    main()
