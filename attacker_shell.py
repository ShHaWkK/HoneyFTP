# coding: utf-8
"""Client interactif FTPS pour le honeypot HoneyFTP.

Ce script se comporte comme un mini client FileZilla en ligne de commande.
Il utilise le module ``cmd`` pour offrir un shell ``ftp>`` avec des
commandes usuelles : ``ls``, ``cd``, ``pwd``, ``get``, ``put``, ``site``,
ou ``raw`` pour envoyer des commandes arbitraires.
La séquence de port-knocking est envoyée automatiquement lors de la
connexion.
"""

import ssl
import socket
import argparse
from ftplib import FTP_TLS, error_perm
from cmd import Cmd
from pathlib import Path
from typing import Optional

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
                print(name)
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
            with open(dst, "wb") as f:
                self.ftp.retrbinary(f"RETR {src}", f.write)
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

    def do_quit(self, arg):
        """Quitte le shell."""
        self.do_close(arg)
        print("Bye")
        return True


def main():
    p = argparse.ArgumentParser()
    p.add_argument("host", nargs="?", default="127.0.0.1")
    p.add_argument("port", nargs="?", type=int, default=2121)
    args = p.parse_args()
    FtpShell(args.host, args.port).cmdloop()


if __name__ == "__main__":
    main()
