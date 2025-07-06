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
import io
import os
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
    def do_connect(self, arg):
        """connect [host] [port] [user] [password]
Ouvre la connexion puis se log automatiquement."""
        if self.ftp:
            print("Déjà connecté. Utilisez 'close' d'abord.")
            return
        parts = arg.split()
        if parts:
            self.host = parts[0]
        if len(parts) > 1:
            self.port = int(parts[1])
        user = parts[2] if len(parts) > 2 else "anonymous"
        pwd = parts[3] if len(parts) > 3 else ACCOUNTS.get(user, "")
        print(f"Knock sur {self.host}:{self.port}…")
        knock(self.host)
        try:
            self.ftp = make_ftps(self.host, self.port)
            resp = self.ftp.login(user, pwd)
            self.ftp.prot_p()
            self.logged = True
            print("Knock OK, FTPS démarré et connecté")
            print(f"< {resp}")
        except Exception as e:
            print(f"Erreur connexion : {e}")
            self.ftp = None
            self.logged = False

    # Alias for backward compatibility
    do_open = do_connect

    def do_login(self, arg):
        """login [user] [password]
Authentifie l'utilisateur (anonymous par défaut)."""
        if not self.ftp:
            print("Pas de connexion ouverte. Utilisez 'connect'.")
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
            print("Vous devez d'abord 'connect'.")
            return False
        return True

    def do_ls(self, arg):
        """ls [dossier]
Liste les fichiers du répertoire courant ou indiqué."""
        if not self._ensure_login():
            return
        # When no argument is supplied, send an empty string so the server
        # lists the root directory rather than ``."``.
        path = arg or ""
        try:
            lines = []
            resp = self.ftp.retrlines(f"LIST {path}", lines.append)
            for line in lines:
                print(line)
            print(f"< {resp}")
        except Exception as e:
            print(f"Erreur LIST : {e}")

    def do_cd(self, arg):
        """cd <répertoire>"""
        if not self._ensure_login():
            return
        path = arg or ""
        try:
            # ``ftplib`` replaces an empty string with ``'.'`` when using
            # ``cwd()``. Use ``sendcmd`` directly so the server receives an
            # truly empty argument when requested.
            if path == "":
                resp = self.ftp.sendcmd("CWD")
            else:
                resp = self.ftp.cwd(path)
            print(f"< {resp}")
        except Exception as e:
            print(f"Erreur CWD : {e}")

    def do_mkdir(self, arg):
        """mkdir <répertoire>"""
        if not self._ensure_login():
            return
        if not arg:
            print("Usage: mkdir <répertoire>")
            return
        try:
            resp = self.ftp.mkd(arg)
            print(f"< {resp}")
        except Exception as e:
            print(f"Erreur MKD : {e}")

    def do_rmdir(self, arg):
        """rmdir <répertoire>"""
        if not self._ensure_login():
            return
        if not arg:
            print("Usage: rmdir <répertoire>")
            return
        try:
            resp = self.ftp.rmd(arg)
            print(f"< {resp}")
        except Exception as e:
            print(f"Erreur RMD : {e}")

    def do_rm(self, arg):
        """rm <fichier> - supprime un fichier"""
        if not self._ensure_login():
            return
        if not arg:
            print("Usage: rm <fichier>")
            return
        try:
            resp = self.ftp.delete(arg)
            print(f"< {resp}")
        except Exception as e:
            print(f"Erreur DELETE : {e}")

    def do_mv(self, arg):
        """mv <ancien> <nouveau> - renomme un fichier"""
        if not self._ensure_login():
            return
        parts = arg.split()
        if len(parts) != 2:
            print("Usage: mv <ancien> <nouveau>")
            return
        old, new = parts
        try:
            resp = self.ftp.rename(old, new)
            print(f"< {resp}")
        except Exception as e:
            print(f"Erreur RNFR/RNTO : {e}")

    def do_touch(self, arg):
        """touch <fichier> - crée un fichier vide"""
        if not self._ensure_login():
            return
        if not arg:
            print("Usage: touch <fichier>")
            return
        try:
            resp = self.ftp.storbinary(f"STOR {arg}", io.BytesIO(b""))
            print(f"< {resp}")
        except Exception as e:
            print(f"Erreur TOUCH : {e}")

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
            size = local.stat().st_size
            with open(local, "rb") as f, Progress() as p:
                task = p.add_task(f"PUT {remote}", total=size or None)

                def cb(data):
                    p.update(task, advance=len(data))

                resp = self.ftp.storbinary(f"STOR {remote}", f, callback=cb)
            print(f"< {resp}")
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

    complete_ls = (
        complete_cd
    ) = (
        complete_get
    ) = (
        complete_cat
    ) = (
        complete_grep
    ) = (
        complete_mkdir
    ) = (
        complete_rmdir
    ) = (
        complete_rm
    ) = (
        complete_mv
    ) = (
        complete_touch
    ) = _complete_remote

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


def _selftest() -> None:
    """Exécute des vérifications rapides sur les commandes principales."""
    from unittest.mock import MagicMock

    mock = MagicMock()
    shell = FtpShell("localhost", 21)
    shell.ftp = mock
    shell.logged = True

    mock.retrlines.return_value = "226 OK"
    shell.do_ls("")
    assert mock.retrlines.call_args[0][0] == "LIST "

    mock.sendcmd.return_value = "250 OK"
    shell.do_cd("")
    assert mock.sendcmd.call_args[0][0] == "CWD"

    mock.rename.return_value = "250 OK"
    shell.do_mv("a b")
    assert mock.rename.call_args[0] == ("a", "b")

    mock.delete.return_value = "250 OK"
    shell.do_rm("file")
    assert mock.delete.call_args[0][0] == "file"

    mock.storbinary.return_value = "226 OK"
    shell.do_touch("file")
    assert mock.storbinary.call_args[0][0] == "STOR file"

    print("Self-test OK")


if __name__ == "__main__":
    if os.getenv("HONEYFTP_TEST"):
        _selftest()
    else:
        main()
