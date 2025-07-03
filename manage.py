#!/usr/bin/env python3
"""Petite interface pour démarrer ou arrêter le honeypot."""

import os
import subprocess
import sys
import time
from pathlib import Path

BASE = Path(__file__).resolve().parent
PID_FILE = BASE / "honeypot.pid"
SESS_DIR = BASE / "sessions"
LOG_FILE = BASE / "honeypot.log"
OP_LOG = BASE / "operations.log"


def _pid_running() -> int | None:
    if PID_FILE.exists():
        try:
            pid = int(PID_FILE.read_text())
            os.kill(pid, 0)
            return pid
        except Exception:
            try:
                PID_FILE.unlink()
            except Exception:
                pass
    return None


def start():
    if _pid_running():
        print("Honeypot déjà lancé")
        return
    p = subprocess.Popen([sys.executable, str(BASE / "honeypot.py")])
    print(f"Honeypot démarré (pid={p.pid})")


def stop():
    pid = _pid_running()
    if not pid:
        print("Honeypot non démarré")
        return
    try:
        os.kill(pid, 15)
        time.sleep(1)
    except Exception as e:
        print(f"Erreur lors de l'arrêt : {e}")
    else:
        print("Honeypot arrêté")


def show_sessions():
    if not SESS_DIR.exists():
        print("Aucune session")
        return
    for p in sorted(SESS_DIR.glob("*.log")):
        print(p.stem)


def show_attacks():
    counts = {}
    if OP_LOG.exists():
        for line in OP_LOG.read_text().splitlines():
            parts = line.split()
            if len(parts) > 1:
                action = parts[1]
                counts[action] = counts.get(action, 0) + 1
    if not counts:
        print("Aucune attaque enregistrée")
        return
    for act, c in counts.items():
        print(f"{act}: {c}")


def show_logs():
    if LOG_FILE.exists():
        print(LOG_FILE.read_text())
    else:
        print("Pas de logs")


def menu():
    actions = {
        "1": start,
        "2": stop,
        "3": show_sessions,
        "4": show_attacks,
        "5": show_logs,
    }
    while True:
        print("\n1. Start\n2. Stop\n3. Voir sessions\n4. Types d'attaques\n5. Voir les logs\n0. Quitter")
        choice = input("> ")
        if choice == "0":
            break
        action = actions.get(choice)
        if action:
            action()
        else:
            print("Choix invalide")


if __name__ == "__main__":
    menu()
