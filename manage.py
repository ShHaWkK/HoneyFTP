#!/usr/bin/env python3
import argparse, os, signal, subprocess, sys

BASE = os.path.dirname(os.path.abspath(__file__))
PID_FILE = os.path.join(BASE, 'honeypot.pid')
LOG_FILE = os.path.join(BASE, 'honeypot.log')

def start():
    if os.path.exists(PID_FILE):
        print('Honeypot already running')
        return
    p = subprocess.Popen([sys.executable, 'honeypot.py'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    with open(PID_FILE, 'w') as f:
        f.write(str(p.pid))
    print(f'Started honeypot pid {p.pid}')


def stop():
    if not os.path.exists(PID_FILE):
        print('Not running')
        return
    with open(PID_FILE) as f:
        pid = int(f.read().strip())
    try:
        os.kill(pid, signal.SIGTERM)
        print('Stopped honeypot')
    except ProcessLookupError:
        print('Process not found')
    os.remove(PID_FILE)


def logs():
    if os.path.exists(LOG_FILE):
        subprocess.call(['tail', '-n', '20', LOG_FILE])
    else:
        print('No log file')


def sessions():
    sess_dir = os.path.join(BASE, 'sessions')
    if not os.path.isdir(sess_dir):
        print('No sessions directory')
        return
    for name in os.listdir(sess_dir):
        if name.endswith('.log'):
            print(name)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('cmd', choices=['start', 'stop', 'logs', 'sessions'])
    args = ap.parse_args()
    if args.cmd == 'start':
        start()
    elif args.cmd == 'stop':
        stop()
    elif args.cmd == 'logs':
        logs()
    elif args.cmd == 'sessions':
        sessions()


if __name__ == '__main__':
    main()
