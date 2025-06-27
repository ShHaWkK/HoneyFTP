#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Attacker Implicit-FTPS — Menu interactif (14 options)

Ajout de l’option « 0) Knock sequence » pour débloquer le FTPS via UDP-knocking.
"""

import os
import ssl
import socket
import argparse
from ftplib import FTP, error_perm

# colorama pour la couleur
try:
    from colorama import init, Fore
except ImportError:
    import subprocess, sys
    subprocess.check_call([sys.executable, "-m", "pip", "install", "colorama"])
    from colorama import init, Fore

init(autoreset=True)


def do_knock(host):
    """Envoie la séquence de port-knocking UDP 4020, 4021, 4022."""
    print(Fore.MAGENTA + "→ Envoi du port-knock sequence…")
    for p in (4020, 4021, 4022):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.sendto(b'', (host, p))
        s.close()
    print(Fore.MAGENTA + "← Knock envoyés. Attendez quelques instants…\n")


def make_ftps(host, port):
    """Établit la connexion FTPS implicite."""
    raw = socket.create_connection((host, port), timeout=10)
    ctx = ssl._create_unverified_context()
    ss = ctx.wrap_socket(raw, server_hostname=host)
    ftp = FTP()
    ftp.sock = ss
    ftp.file = ss.makefile('r', encoding='utf-8', newline='\r\n')
    ftp.af = ss.family
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
        print(Fore.CYAN + "← FILES:")
        for i, f in enumerate(files, 1):
            print(f"   {i:2d}. {f}")
    except Exception as e:
        print(Fore.RED + "× NLST error:", e)


def do_retr(ftp):
    fn = input("Fichier à RETR > ").strip()
    dst = input("Local dest (~/...) > ").strip() or fn
    dst = os.path.expanduser(dst)
    os.makedirs(os.path.dirname(dst) or ".", exist_ok=True)
    try:
        print(Fore.YELLOW + f"→ RETR {fn}")
        with open(dst, "wb") as f:
            ftp.retrbinary(f"RETR {fn}", f.write)
        print(Fore.GREEN + f"✓ saved to {dst}")
    except Exception as e:
        print(Fore.RED + "× RETR fail:", e)


def do_stor(ftp):
    src = input("Local file to STOR > ").strip()
    src = os.path.expanduser(src)
    if not os.path.isfile(src):
        print(Fore.RED + "Invalid file.")
        return
    remote = input("Remote name > ").strip() or os.path.basename(src)
    try:
        with open(src, "rb") as f:
            ftp.storbinary(f"STOR {remote}", f)
        print(Fore.GREEN + f"✓ Uploaded {src} → /{remote}")
    except Exception as e:
        print(Fore.RED + "× STOR fail:", e)


def do_cwd_traverse(ftp):
    try:
        resp = ftp.sendcmd("CWD ../..")
        print(Fore.GREEN + "←", resp.replace("\r", ""))
    except Exception as e:
        print(Fore.RED + "× CWD fail:", e)


def do_site_exec(ftp):
    cmd = input("Commande shell > ").strip()
    try:
        resp = ftp.sendcmd(f"SITE EXEC {cmd}")
        print(Fore.GREEN + "←", resp)
    except Exception as e:
        print(Fore.RED + "× SITE EXEC fail:", e)


def do_site_bof(ftp):
    length = int(input("Taille payload > ").strip() or "1024")
    payload = "A" * length
    try:
        resp = ftp.sendcmd(f"SITE BOF {payload}")
        # tronque l’affichage à 200 caractères
        end = "…" if len(resp) > 200 else ""
        print(Fore.GREEN + "←", resp[:200] + end)
    except Exception as e:
        print(Fore.RED + "× SITE BOF fail:", e)


def do_rnfr_rnto(ftp):
    old = input("RNFR file > ").strip()
    new = input("RNTO name > ").strip()
    try:
        r1 = ftp.sendcmd(f"RNFR {old}")
        print(Fore.GREEN + "←", r1)
        r2 = ftp.sendcmd(f"RNTO {new}")
        print(Fore.GREEN + "←", r2)
    except Exception as e:
        print(Fore.RED + "× RNFR/RNTO fail:", e)


def do_dele(ftp):
    fn = input("DELE file > ").strip()
    try:
        resp = ftp.delete(fn)
        print(Fore.GREEN + "←", resp)
    except Exception as e:
        print(Fore.RED + "× DELE fail:", e)


def do_mkd_rmd(ftp):
    d = input("MKD directory > ").strip()
    try:
        resp = ftp.sendcmd(f"MKD {d}")
        print(Fore.GREEN + "←", resp)
    except Exception as e:
        print(Fore.RED + "× MKD fail:", e)
    r = input("RMD directory > ").strip()
    try:
        resp = ftp.sendcmd(f"RMD {r}")
        print(Fore.GREEN + "←", resp)
    except Exception as e:
        print(Fore.RED + "× RMD fail:", e)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--host", default="127.0.0.1", help="Honeypot IP")
    p.add_argument("--port", default=2121, type=int, help="Port FTPS implicite")
    args = p.parse_args()

    ftp = None
    print(Fore.YELLOW + "=== Attacker Implicit-FTPS Menu ===")
    while True:
        print("""
 0) Knock sequence (unlock FTPS)
 1) anonymous/""
 2) attacker/secret
 3) custom
 4) NLST
 5) RETR
 6) STOR
 7) CWD ../..
 8) SITE EXEC /bin/bash
 9) SITE BOF payload
10) RNFR/RNTO
11) DELE
12) MKD/RMD
13) Quitter
""")
        cmd = input("Votre choix > ").strip()
        if cmd == "0":
            do_knock(args.host)
            continue

        if cmd in ("1", "2", "3"):
            if ftp:
                try: ftp.quit()
                except: pass
            ftp = make_ftps(args.host, args.port)
            if cmd == "1":
                ok = do_login(ftp, "anonymous", "")
            elif cmd == "2":
                ok = do_login(ftp, "attacker", "secret")
            else:
                u = input("User > ").strip()
                pw = input("Pass > ").strip()
                ok = do_login(ftp, u, pw)
            if not ok:
                try: ftp.close()
                except: pass
                ftp = None

        elif cmd == "4"  and ftp: do_nlst(ftp)
        elif cmd == "5"  and ftp: do_retr(ftp)
        elif cmd == "6"  and ftp: do_stor(ftp)
        elif cmd == "7"  and ftp: do_cwd_traverse(ftp)
        elif cmd == "8"  and ftp: do_site_exec(ftp)
        elif cmd == "9"  and ftp: do_site_bof(ftp)
        elif cmd == "10" and ftp: do_rnfr_rnto(ftp)
        elif cmd == "11" and ftp: do_dele(ftp)
        elif cmd == "12" and ftp: do_mkd_rmd(ftp)

        elif cmd == "13":
            if ftp:
                try: ftp.quit()
                except: pass
            print("Bye !")
            break

        else:
            print("→ Choix invalide ou pas de connexion active.")

if __name__ == "__main__":
    main()
