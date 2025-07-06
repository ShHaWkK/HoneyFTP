#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Attacker Implicit-FTPS — Menu interactif (21 options)

Ce client offre un ensemble de commandes unitaires pour tester le honeypot FTPS
mais aussi quelques scripts prédéfinis qui enchaînent plusieurs actions.
Un rapport de session peut être généré à partir du log retourné par
``SITE DEBUG``.
"""

import os
import ssl
import socket
import argparse
import time
from ftplib import FTP, FTP_TLS, error_perm

# colorama pour la couleur
try:
    from colorama import init, Fore
except ImportError:
    import subprocess, sys
    subprocess.check_call([sys.executable, "-m", "pip", "install", "colorama"])
    from colorama import init, Fore

init(autoreset=True)

# Indique si la séquence de port-knocking a été envoyée
unlocked = False
# Fichier de sortie pour les rapports de session
REPORT_FILE = "session_report.txt"


def do_knock(host, port=2121):
    """Envoie la séquence de port-knocking UDP 4020, 4021, 4022 et vérifie l'accès FTPS."""
    print(Fore.MAGENTA + "→ Envoi du port-knock sequence…")
    for p in (4020, 4021, 4022):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.sendto(b"", (host, p))
        s.close()
    global unlocked
    unlocked = True
    print(Fore.MAGENTA + "← Knock envoyés. Attendez quelques instants…")
    time.sleep(1)
    check_access(host, port)


def make_ftps(host, port, retries=3):
    """Établit la connexion FTPS implicite."""
    ctx = ssl._create_unverified_context()
    for i in range(retries):
        try:
            raw = socket.create_connection((host, port), timeout=10)
            break
        except OSError:
            if i == retries - 1:
                raise
            time.sleep(1)
    ss = ctx.wrap_socket(raw, server_hostname=host)
    ftp = FTP_TLS(context=ctx)
    ftp.sock = ss
    ftp.file = ss.makefile('r', encoding='utf-8', newline='\r\n')
    ftp.af = ss.family
    ftp.host = host
    ftp.passiveserver = True
    banner = ftp.getresp().strip()
    print(Fore.YELLOW + "← Bannière :", banner)
    return ftp


def check_access(host, port):
    """Tente une connexion rapide pour confirmer l'accès FTPS."""
    try:
        ftp = make_ftps(host, port, retries=1)
        ftp.close()
        print(Fore.GREEN + "✓ Honeypot accessible\n")
        return True
    except Exception as e:
        print(Fore.RED + f"× Connexion impossible : {e}\n")
        return False


def do_login(ftp, user, pwd):
    try:
        resp = ftp.login(user, pwd)
        if isinstance(ftp, FTP_TLS):
            try:
                ftp.prot_p()
            except Exception:
                pass
        print(Fore.GREEN + f"← LOGIN OK : {resp}")
        return True
    except error_perm as e:
        print(Fore.RED + f"× AUTH FAILED : {e}")
        return False


def do_nlst(ftp):
    try:
        # Pass an empty string so the server lists the root directory by
        # default instead of the current directory indicator ``.'.``
        files = ftp.nlst('')
        print(Fore.CYAN + "← FILES:")
        for i, f in enumerate(files, 1):
            print(f"   {i:2d}. {f}")
    except Exception as e:
        print(Fore.RED + "× NLST error:", e)


def do_retr(ftp):
    fn = input("Fichier à RETR > ").strip()
    dst = input("Local dest (~/...) > ").strip() or fn
    dst = os.path.expanduser(dst)
    os.makedirs(os.path.dirname(dst) or '.', exist_ok=True)
    try:
        print(Fore.YELLOW + f"→ RETR {fn}")
        with open(dst, 'wb') as f:
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
        with open(src, 'rb') as f:
            ftp.storbinary(f"STOR {remote}", f)
        print(Fore.GREEN + f"✓ Uploaded {src} → /{remote}")
    except Exception as e:
        print(Fore.RED + "× STOR fail:", e)


def do_cwd_traverse(ftp):
    try:
        resp = ftp.sendcmd('CWD ../..')
        print(Fore.GREEN + "←", resp.replace('\r', ''))
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
    length = int(input("Taille payload > ").strip() or '1024')
    payload = 'A' * length
    try:
        resp = ftp.sendcmd(f"SITE BOF {payload}")
        print(Fore.GREEN + "←", resp[:200] + ('…' if len(resp) > 200 else ''))
    except Exception as e:
        print(Fore.RED + "× SITE BOF fail:", e)


def do_site_help(ftp):
    try:
        resp = ftp.sendcmd('SITE HELP')
        print(Fore.GREEN + "←", resp)
    except Exception as e:
        print(Fore.RED + "× SITE HELP fail:", e)


def do_site_version(ftp):
    try:
        resp = ftp.sendcmd('SITE VERSION')
        print(Fore.GREEN + "←", resp)
    except Exception as e:
        print(Fore.RED + "× SITE VERSION fail:", e)


def do_site_uptime(ftp):
    try:
        resp = ftp.sendcmd('SITE UPTIME')
        print(Fore.GREEN + "←", resp)
    except Exception as e:
        print(Fore.RED + "× SITE UPTIME fail:", e)


def do_site_stats(ftp):
    try:
        ftp.putcmd('SITE STATS')
        resp = ftp.getmultiline()
    except Exception as e:
        print(Fore.RED + "× SITE STATS fail:", e)
        return
    lines = resp.splitlines()
    if lines and lines[0].startswith('200-'):
        lines = lines[1:]
    if lines and lines[-1].startswith('200'):
        lines = lines[:-1]
    for l in lines:
        print(l)


def do_site_getlog(ftp):
    sess = input("Session ID (blank for global) > ").strip()
    cmd = f"SITE GETLOG {sess}" if sess else 'SITE GETLOG'
    try:
        ftp.putcmd(cmd)
        resp = ftp.getmultiline()
    except Exception as e:
        print(Fore.RED + "× SITE GETLOG fail:", e)
        return
    lines = resp.splitlines()
    if lines and lines[0].startswith('200-'):
        lines = lines[1:]
    if lines and lines[-1].startswith('200'):
        lines = lines[:-1]
    for l in lines:
        print(l)


def do_rnfr_rnto(ftp):
    old = input("RNFR file > ").strip()
    new = input("RNTO name > ").strip()
    try:
        print(Fore.GREEN + "←", ftp.sendcmd(f"RNFR {old}"))
        print(Fore.GREEN + "←", ftp.sendcmd(f"RNTO {new}"))
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
        print(Fore.GREEN + "←", ftp.sendcmd(f"MKD {d}"))
    except Exception as e:
        print(Fore.RED + "× MKD fail:", e)
    r = input("RMD directory > ").strip()
    try:
        print(Fore.GREEN + "←", ftp.sendcmd(f"RMD {r}"))
    except Exception as e:
        print(Fore.RED + "× RMD fail:", e)


def fetch_report(ftp):
    """Récupère le log de session via ``SITE DEBUG`` et génère un rapport."""
    try:
        ftp.putcmd('SITE DEBUG')
        resp = ftp.getmultiline()
    except Exception as e:
        print(Fore.RED + "× DEBUG fail:", e)
        return
    lines = resp.splitlines()
    if lines and lines[0].startswith('200-'):
        lines = lines[1:]
    if lines and lines[-1].startswith('200'):
        lines = lines[:-1]
    data = '\n'.join(lines).strip()
    try:
        with open(REPORT_FILE, 'w') as f:
            f.write(data + '\n')
    except Exception as e:
        print(Fore.RED + "× Write report fail:", e)
        return
    downloads = [l[5:] for l in lines if l.startswith('RETR ')]
    print(Fore.GREEN + f"✓ Rapport sauvegardé dans {REPORT_FILE}")
    if lines:
        print(Fore.CYAN + "Commandes enregistrées:")
        for l in lines:
            print("  " + l)
    if downloads:
        print(Fore.CYAN + "Fichiers téléchargés:")
        for d in downloads:
            print("  " + d)


def script_enum(host, port):
    """Connexion anonyme et quelques commandes de reconnaissance."""
    if not unlocked:
        do_knock(host, port)
    ftp = make_ftps(host, port)
    if not do_login(ftp, 'anonymous', ''):
        ftp.quit()
        return
    do_nlst(ftp)
    do_cwd_traverse(ftp)
    fetch_report(ftp)
    ftp.quit()


def script_attack(host, port):
    """Exploitation automatisée via une connexion ``anonymous``."""
    if not unlocked:
        do_knock(host, port)
    ftp = make_ftps(host, port)
    if not do_login(ftp, 'anonymous', ''):
        ftp.quit()
        return
    do_nlst(ftp)
    tmp = os.path.join(os.path.dirname(__file__), 'exploit.txt')
    with open(tmp, 'w') as f:
        f.write('exploit')
    try:
        with open(tmp, 'rb') as f:
            ftp.storbinary('STOR exploit.txt', f)
        print(Fore.GREEN + "✓ Uploaded exploit.txt")
    finally:
        try:
            os.remove(tmp)
        except OSError:
            pass
    try:
        ftp.retrbinary('RETR root.txt', lambda b: None)
        print(Fore.GREEN + "✓ RETR root.txt")
    except Exception as e:
        print(Fore.RED + "× RETR root.txt:", e)
    try:
        ftp.sendcmd('SITE EXEC id')
    except Exception:
        pass
    fetch_report(ftp)
    ftp.quit()


def script_demo(host, port):
    """Connexion anonyme et enchaînement complet de commandes."""
    if not unlocked:
        do_knock(host, port)
    ftp = make_ftps(host, port)
    if not do_login(ftp, 'anonymous', ''):
        ftp.quit()
        return
    print(Fore.CYAN + 'PWD ' + ftp.pwd())
    do_nlst(ftp)
    tmp = os.path.join(os.path.dirname(__file__), 'demo_temp.txt')
    with open(tmp, 'w') as f:
        f.write('demo')
    with open(tmp, 'rb') as f:
        print(Fore.GREEN + '←', ftp.storbinary('STOR demo.txt', f))
    do_nlst(ftp)
    with open('retr_demo.txt', 'wb') as f:
        print(Fore.GREEN + '←', ftp.retrbinary('RETR demo.txt', f.write))
    do_cwd_traverse(ftp)
    try:
        print(Fore.GREEN + '←', ftp.mkd('demo_dir'))
        print(Fore.GREEN + '←', ftp.rmd('demo_dir'))
    except Exception as e:
        print(Fore.RED + '× MKD/RMD:', e)
    do_site_version(ftp)
    do_site_uptime(ftp)
    do_site_stats(ftp)
    do_site_help(ftp)
    do_site_getlog(ftp)
    try:
        do_site_exec(ftp)
    except Exception:
        pass
    try:
        print(Fore.GREEN + '←', ftp.sendcmd('RNFR demo.txt'))
        print(Fore.GREEN + '←', ftp.sendcmd('RNTO demo2.txt'))
        print(Fore.GREEN + '←', ftp.delete('demo2.txt'))
    except Exception as e:
        print(Fore.RED + '× RNFR/RNTO/DELE:', e)
    ftp.quit()
    try:
        os.remove(tmp)
    except OSError:
        pass


def script_replay(host, port, path=None):
    """Rejoue des commandes depuis ``replay.txt`` ou un fichier donné."""
    if not unlocked:
        do_knock(host, port)
    ftp = make_ftps(host, port)
    if not do_login(ftp, 'anonymous', ''):
        ftp.quit()
        return
    if path is None:
        path = input("Fichier de commandes > ").strip() or 'replay.txt'
    try:
        with open(path) as f:
            cmds = [l.strip() for l in f if l.strip()]
    except Exception as e:
        print(Fore.RED + "× Lecture fail:", e)
        ftp.quit()
        return
    for c in cmds:
        try:
            print(Fore.CYAN + "→ " + c)
            resp = ftp.sendcmd(c)
            print(Fore.GREEN + "←", resp)
        except Exception as e:
            print(Fore.RED + f"× {c} : {e}")
    ftp.quit()


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--host", default="127.0.0.1", help="Honeypot IP")
    p.add_argument("--port", default=2121, type=int, help="Port FTPS implicite")
    p.add_argument("--script", choices=["enum", "attack", "demo"], help="Exécute un script prédéfini puis quitte")
    p.add_argument("--commands", help="Rejoue les commandes d'un fichier et quitte")
    args = p.parse_args()

    if args.script == "enum":
        script_enum(args.host, args.port)
        return
    if args.script == "attack":
        script_attack(args.host, args.port)
        return
    if args.script == "demo":
        script_demo(args.host, args.port)
        return
    if args.commands:
        script_replay(args.host, args.port, args.commands)
        return

    ftp = None
    while True:
        status = "UNLOCKED" if unlocked else "LOCKED"
        print(Fore.YELLOW + f"=== Menu Attacker Implicit-FTPS ({status}) ===")
        print("""
0) Knock sequence (unlock FTPS)
1) anonymous/""
2) NLST
3) RETR
4) STOR
5) CWD ../..
6) SITE EXEC /bin/bash
7) SITE BOF payload
8) SITE HELP
9) SITE VERSION
10) SITE GETLOG
11) RNFR/RNTO
12) DELE
13) MKD/RMD
14) Session report
15) Script reconnaissance
16) Script attaque
17) Replay commands
18) Quitter
19) SITE UPTIME
20) SITE STATS
21) Demo complet
""")
        cmd = input("Votre choix > ").strip()

        if cmd == "0":
            do_knock(args.host, args.port)
        elif cmd == "1":
            if not unlocked:
                do_knock(args.host, args.port)
            if ftp:
                try:
                    ftp.quit()
                except:
                    pass
            ftp = make_ftps(args.host, args.port)
            if not do_login(ftp, 'anonymous', ''):
                ftp = None
        elif cmd == "2" and ftp:
            do_nlst(ftp)
        elif cmd == "3" and ftp:
            do_retr(ftp)
        elif cmd == "4" and ftp:
            do_stor(ftp)
        elif cmd == "5" and ftp:
            do_cwd_traverse(ftp)
        elif cmd == "6" and ftp:
            do_site_exec(ftp)
        elif cmd == "7" and ftp:
            do_site_bof(ftp)
        elif cmd == "8" and ftp:
            do_site_help(ftp)
        elif cmd == "9" and ftp:
            do_site_version(ftp)
        elif cmd == "10" and ftp:
            do_site_getlog(ftp)
        elif cmd == "11" and ftp:
            do_rnfr_rnto(ftp)
        elif cmd == "12" and ftp:
            do_dele(ftp)
        elif cmd == "13" and ftp:
            do_mkd_rmd(ftp)
        elif cmd == "14" and ftp:
            fetch_report(ftp)
        elif cmd == "15":
            script_enum(args.host, args.port)
        elif cmd == "16":
            script_attack(args.host, args.port)
        elif cmd == "17":
            script_replay(args.host, args.port)
        elif cmd == "18":
            if ftp:
                try:
                    ftp.quit()
                except:
                    pass
            print("Bye !")
            break
        elif cmd == "19" and ftp:
            do_site_uptime(ftp)
        elif cmd == "20" and ftp:
            do_site_stats(ftp)
        elif cmd == "21":
            script_demo(args.host, args.port)
        else:
            print(Fore.RED + "→ Choix invalide ou pas de connexion active.")

if __name__ == "__main__":
    main()
