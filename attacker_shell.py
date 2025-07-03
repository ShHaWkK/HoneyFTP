#!/usr/bin/env python3
# coding: utf-8
"""Client interactif FTPS pour le honeypot HoneyFTP.

Ce script se comporte comme un mini client FileZilla en ligne de commande.
Il utilise le module ``cmd`` pour offrir un shell ``ftp>`` avec des
commandes usuelles : ``ls``, ``cd``, ``pwd``, ``get``, ``put``, ``site``,
ou ``raw`` pour envoyer des commandes arbitraires.
La séquence de port-knocking est envoyée automatiquement lors de la
connexion.
"""

import subprocess
import sys

def ensure(pkg):
    try:
        __import__(pkg)
    except ImportError:
        try:
            subprocess.check_call(
                [sys.executable, "-m", "pip", "install", "--root-user-action=ignore", pkg],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except subprocess.CalledProcessError:
            pass
        try:
            __import__(pkg)
        except ImportError:
            print(f"[!] unable to install {pkg}")

ensure("rich")

import ssl
import socket
import argparse
from ftplib import FTP_TLS, error_perm
from cmd import Cmd
from pathlib import Path
from typing import Optional
from rich import print as rprint
from rich.progress import Progress

# Comptes supportés
ACCOUNTS = {
    "anonymous": "",
    "ftpman": "ftpman",
    "attacker": "secret",
}

KNOCK_SEQ = [4020, 4021, 4022]


def knock(host: str):
    """Envoie la séquence UDP nécessaire pour débloquer le honeypot."""
    for p in KNOCK_SEQ:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.sendto(b"", (host, p))
        finally:
            s.close()


def make_ftps(host: str, port: int) -> FTP_TLS:
    """Établit une connexion FTPS implicite en ignorant le certificat."""
    ctx = ssl._create_unverified_context()
    raw = socket.create_connection((host, port), timeout=10)
    ss = ctx.wrap_socket(raw, server_hostname=host)
    ftp = FTP_TLS(context=ctx)
    ftp.sock = ss
    ftp.file = ss.makefile("r", encoding="utf-8", newline="\r\n")
    ftp.af = ss.family
    ftp.host = host
    ftp.passiveserver = True
    banner = ftp.getresp().strip()
    print(f"< {banner}")
    return ftp


class FtpShell(Cmd):
    intro = "Tapez 'help' pour la liste des commandes."
    prompt = "ftp> "

    def __init__(self, host: str, port: int):
        super().__init__()
        self.host = host
        self.port = port
        self.ftp: Optional[FTP_TLS] = None
        self.logged = False

    # --- gestion de la connexion -------------------------------------------------
    def do_open(self, arg):
        """open [host] [port]
Ouvre la connexion FTPS (avec port-knocking automatique)."""
        if self.ftp:
            print("Déjà connecté. Utilisez 'close' d'abord.")
            return
        parts = arg.split()
        if parts:
            self.host = parts[0]
        if len(parts) > 1:
            self.port = int(parts[1])
        print(f"Knock sur {self.host}:{self.port}…")
        knock(self.host)
        try:
            self.ftp = make_ftps(self.host, self.port)
        except Exception as e:
            print(f"Erreur connexion : {e}")
            self.ftp = None
            return
        print("Knock OK, FTPS démarré")
        self.logged = False

    def do_login(self, arg):
        """login [user] [password]
Authentifie l'utilisateur (anonymous par défaut)."""
        if not self.ftp:
            print("Pas de connexion ouverte. Utilisez 'open'.")
            return
        parts = arg.split()
        user = parts[0] if parts else "anonymous"
        pwd = parts[1] if len(parts) > 1 else ACCOUNTS.get(user, "")
        try:
            resp = self.ftp.login(user, pwd)
            self.ftp.prot_p()
            self.logged = True
            print(f"< {resp}")
            print("230 Login OK")
        except error_perm as e:
            print(f"Authentification échouée : {e}")

    def do_close(self, arg):
        """Ferme la connexion."""
        if self.ftp:
            try:
                self.ftp.quit()
            except Exception:
                pass
            self.ftp = None
            self.logged = False

    # --- commandes FTP de base ---------------------------------------------------
    def precmd(self, line: str) -> str:
        return line.strip()

    def _ensure_login(self) -> bool:
        if not self.ftp or not self.logged:
            print("Vous devez d'abord 'open' puis 'login'.")
            return False
        return True

    def do_ls(self, arg):
        """ls [dossier]
Liste les fichiers du répertoire courant ou indiqué."""
        if not self._ensure_login():
            return
        path = arg or "."
        try:
            for name in self.ftp.nlst(path):
                icon = "\U0001F4C1" if "." not in name else "\U0001F4C4"
                rprint(f"{icon} {name}")
        except Exception as e:
            print(f"Erreur NLST : {e}")

    def do_cd(self, arg):
        """cd <répertoire>"""
        if not self._ensure_login():
            return
        try:
            resp = self.ftp.cwd(arg)
            print(f"< {resp}")
        except Exception as e:
            print(f"Erreur CWD : {e}")

    def do_pwd(self, arg):
        """Affiche le répertoire courant."""
        if not self._ensure_login():
            return
        try:
            print(self.ftp.pwd())
        except Exception as e:
            print(f"Erreur PWD : {e}")

    def do_get(self, arg):
        """get <fichier> [dest]"""
        if not self._ensure_login():
            return
        parts = arg.split()
        if not parts:
            print("Usage: get <fichier> [dest]")
            return
        src = parts[0]
        dst = Path(parts[1]) if len(parts) > 1 else Path(src)
        try:
            size = self.ftp.size(src) or 0
            with open(dst, "wb") as f, Progress() as p:
                task = p.add_task(f"GET {src}", total=size or None)
                def cb(data):
                    f.write(data)
                    p.update(task, advance=len(data))
                self.ftp.retrbinary(f"RETR {src}", cb)
            print(f"Téléchargé vers {dst}")
        except Exception as e:
            print(f"Erreur RETR : {e}")

    def do_put(self, arg):
        """put <fichier_local> [remote]"""
        if not self._ensure_login():
            return
        parts = arg.split()
        if not parts:
            print("Usage: put <fichier_local> [remote]")
            return
        local = Path(parts[0])
        if not local.is_file():
            print("Fichier introuvable")
            return
        remote = parts[1] if len(parts) > 1 else local.name
        try:
            with open(local, "rb") as f:
                self.ftp.storbinary(f"STOR {remote}", f)
            print("Upload terminé")
        except Exception as e:
            print(f"Erreur STOR : {e}")

    def do_cat(self, arg):
        """cat <fichier> - affiche le contenu texte"""
        if not self._ensure_login():
            return
        if not arg:
            print("Usage: cat <fichier>")
            return
        buf = bytearray()
        try:
            self.ftp.retrbinary(f"RETR {arg}", buf.extend)
            print(buf.decode("utf-8", errors="replace"))
        except Exception as e:
            print(f"Erreur CAT : {e}")

    def do_grep(self, arg):
        """grep <motif> <fichier>"""
        if not self._ensure_login():
            return
        parts = arg.split()
        if len(parts) < 2:
            print("Usage: grep <motif> <fichier>")
            return
        pat, src = parts[0], parts[1]
        buf = bytearray()
        try:
            self.ftp.retrbinary(f"RETR {src}", buf.extend)
            for line in buf.decode("utf-8", errors="ignore").splitlines():
                if pat in line:
                    rprint(line)
        except Exception as e:
            print(f"Erreur GREP : {e}")

    def do_site(self, arg):
        """site <commande>
Envoie une commande SITE arbitraire."""
        if not self._ensure_login():
            return
        try:
            resp = self.ftp.sendcmd(f"SITE {arg}")
            print(f"< {resp}")
        except Exception as e:
            print(f"Erreur SITE : {e}")

    def do_raw(self, arg):
        """raw <commande>
Envoie une commande brute non gérée autrement."""
        if not self._ensure_login():
            return
        try:
            resp = self.ftp.sendcmd(arg)
            print(f"< {resp}")
        except Exception as e:
            print(f"Erreur : {e}")

    # --- autocomplétions dynamiques ---------------------------------------
    def _complete_remote(self, text):
        if not self.ftp or not self.logged:
            return []
        try:
            return [n for n in self.ftp.nlst() if n.startswith(text)]
        except Exception:
            return []

    complete_ls = complete_cd = complete_get = complete_cat = complete_grep = _complete_remote

    def do_quit(self, arg):
        """Quitte le shell."""
        self.do_close(arg)
        print("Bye")
        return True


def main():
    p = argparse.ArgumentParser()
    p.add_argument("host", nargs="?", default="192.168.100.51")
    p.add_argument("port", nargs="?", type=int, default=2121)
    p.add_argument("--mode", choices=["cli", "web"], default="cli")
    args = p.parse_args()

    if args.mode == "cli":
        FtpShell(args.host, args.port).cmdloop()
    else:
        ensure("flask")
        from flask import Flask, render_template_string
        app = Flask(__name__)
        base = Path(__file__).resolve().parent
        sess_dir = base / "sessions"
        op_log = base / "operations.log"

        def parse_stats():
            stats = {
                "uploads": 0,
                "downloads": 0,
                "deletes": 0,
                "renames": 0,
                "ls": 0,
                "cd": 0,
            }
            if op_log.exists():
                with open(op_log) as f:
                    for line in f:
                        for k in stats:
                            if k.upper() in line.upper():
                                stats[k] += 1
            return stats

        @app.route("/")
        def index():
            sessions = []
            logs = {}
            if sess_dir.is_dir():
                for fp in sess_dir.glob("*.log"):
                    sid = fp.stem
                    sessions.append(sid)
                    try:
                        with open(fp) as f:
                            logs[sid] = f.read().splitlines()[-10:]
                    except Exception:
                        logs[sid] = []
            stats = parse_stats()
            tpl = """
            <h1>HoneyFTP Dashboard</h1>
            <h2>Sessions</h2>
            <ul>{% for s in sessions %}<li>{{s}}</li>{% endfor %}</ul>
            <h2>Logs</h2>
            {% for s,l in logs.items() %}
            <h3>{{s}}</h3>
            <pre>{{ '\n'.join(l) }}</pre>
            {% endfor %}
            <h2>Attaques</h2>
            <ul>
            {% for k,v in stats.items() %}<li>{{k}}: {{v}}</li>{% endfor %}
            </ul>
            """
            return render_template_string(tpl, sessions=sessions, logs=logs, stats=stats)

        app.run(host="0.0.0.0", port=8000)


if __name__ == "__main__":
    main()
