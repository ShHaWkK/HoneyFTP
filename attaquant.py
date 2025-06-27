#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Attacker Implicit-FTPS — Menu interactif avec listing visuel (Rich)

Fonctionnalités :
– TLS implicite  
– Login anonymous/"" + attacker/secret + custom  
– NLST + affichage en tableau Rich  
– RETR/STOR interactif  
– Couleurs (colorama)  
– Menu simple
"""

import os, sys, ssl, socket, argparse
from ftplib import FTP, error_perm

# ─── Bootstrap Rich & Colorama ────────────────────────────────────────────
def ensure(pkg, imp=None):
    try: __import__(imp or pkg)
    except ImportError:
        subprocess.check_call([sys.executable,"-m","pip","install","--upgrade",pkg])

import subprocess
ensure("rich")
ensure("colorama")
from rich.console import Console
from rich.table import Table
from colorama import init, Fore, Style

init(autoreset=True)
console = Console()

# ─── Fonctions FTPS implicite ─────────────────────────────────────────────
def make_ftps(host, port):
    raw = socket.create_connection((host, port), timeout=10)
    ctx = ssl._create_unverified_context()
    ss  = ctx.wrap_socket(raw, server_hostname=host)
    ftp = FTP(); ftp.sock=ss
    ftp.file = ss.makefile('r', encoding='utf-8', newline='\r\n')
    ftp.af, ftp.passiveserver = ss.family, True
    banner = ftp.getresp().strip()
    console.print(f"[yellow]← Bannière[/] [bold]{banner}[/]")
    return ftp

def do_login(ftp, u, pw):
    try:
        r = ftp.login(u, pw)
        console.print(f"[green]← LOGIN OK[/] [bold]{r}[/]")
        return True
    except error_perm as e:
        console.print(f"[red]× AUTH FAILED[/] {e}")
        return False

def do_nlst(ftp):
    try:
        files = ftp.nlst(".")
        files = [f.lstrip("./") for f in files]
        tbl = Table(show_header=True, header_style="bold magenta")
        tbl.add_column("#", style="dim", width=4)
        tbl.add_column("Fichier / Répertoire")
        for i,f in enumerate(files, 1):
            tbl.add_row(str(i), f)
        console.print(tbl)
    except Exception as e:
        console.print(f"[red]× NLST error:[/] {e}")

def do_retr(ftp):
    fn = console.input("Nom du fichier à télécharger > ")
    out= console.input("Chemin local destination > ")
    out = out.strip() or fn
    try:
        with open(os.path.expanduser(out),"wb") as fd:
            ftp.retrbinary(f"RETR {fn}", fd.write)
        console.print(f"[green]✓[/] {fn} → {out}")
    except Exception as e:
        console.print(f"[red]× RETR failed:[/] {e}")

def do_stor(ftp):
    src = console.input("Chemin local à uploader > ")
    src = os.path.expanduser(src)
    if not os.path.isfile(src):
        console.print("[red]× Fichier invalide[/]"); return
    dst = console.input("Nom distant (STOR) > ").strip() or os.path.basename(src)
    try:
        with open(src,"rb") as f:
            ftp.storbinary(f"STOR {dst}", f)
        console.print(f"[green]✓[/] Uploaded {src} → /{dst}")
    except Exception as e:
        console.print(f"[red]× STOR failed:[/] {e}")

# ─── Menu interactif ───────────────────────────────────────────────────────
def main():
    p = argparse.ArgumentParser()
    p.add_argument("-H","--host", default="192.168.100.51")
    p.add_argument("-P","--port", default=2121, type=int)
    args = p.parse_args()

    ftp = None
    console.print("[bold yellow]=== Attacker Implicit-FTPS Menu ===[/]\n")
    while True:
        console.print("\n[cyan]1)[/] anonymous/\"\"\n[cyan]2)[/] attacker/secret\n[cyan]3)[/] custom\n[cyan]4)[/] NLST\n[cyan]5)[/] RETR\n[cyan]6)[/] STOR\n[cyan]7)[/] Quitter\n")
        cmd = console.input("Votre choix > ").strip()
        if cmd=="1":
            if ftp: ftp.close()
            ftp = make_ftps(args.host,args.port)
            if not do_login(ftp,"anonymous",""): ftp=None
        elif cmd=="2":
            if ftp: ftp.close()
            ftp = make_ftps(args.host,args.port)
            if not do_login(ftp,"attacker","secret"): ftp=None
        elif cmd=="3":
            u=console.input("User > ").strip()
            p=console.input("Password > ").strip()
            if ftp: ftp.close()
            ftp = make_ftps(args.host,args.port)
            if not do_login(ftp,u,p): ftp=None
        elif cmd=="4":
            if not ftp: console.print("[red]→ Connectez-vous d’abord[/]")
            else: do_nlst(ftp)
        elif cmd=="5":
            if not ftp: console.print("[red]→ Connectez-vous d’abord[/]")
            else: do_retr(ftp)
        elif cmd=="6":
            if not ftp: console.print("[red]→ Connectez-vous d’abord[/]")
            else: do_stor(ftp)
        elif cmd=="7":
            if ftp:
                try: ftp.quit()
                except: pass
            break
        else:
            console.print("[red]Choix invalide[/]")

if __name__=="__main__":
    main()
