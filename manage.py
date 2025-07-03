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


def sessions_cmd():
    sess_dir = os.path.join(BASE, 'sessions')
    if not os.path.isdir(sess_dir):
        print('No sessions directory')
        return
    for name in os.listdir(sess_dir):
        if name.endswith('.log'):
            print(name)


def run_client(mode):
    cmd = [sys.executable, 'attacker_shell.py', '--mode', mode]
    subprocess.call(cmd)


def honeypot_shell():
    subprocess.call([sys.executable, 'honeypot.py', '--shell'])


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest='cmd', required=True)

    rp = sub.add_parser('run', help='start attacker client or dashboard')
    rp.add_argument('--mode', choices=['cli', 'web'], default='cli')

    sub.add_parser('honeypot', help='start honeypot with admin shell')
    sub.add_parser('start', help='start honeypot in background')
    sub.add_parser('stop', help='stop honeypot')
    sub.add_parser('logs', help='tail honeypot log')
    sub.add_parser('sessions', help='list session files')

    args = ap.parse_args()

    if args.cmd == 'run':
        run_client(args.mode)
    elif args.cmd == 'honeypot':
        honeypot_shell()
    elif args.cmd == 'start':
        start()
    elif args.cmd == 'stop':
        stop()
    elif args.cmd == 'logs':
        logs()
    elif args.cmd == 'sessions':
        sessions_cmd()


if __name__ == '__main__':
    main()
