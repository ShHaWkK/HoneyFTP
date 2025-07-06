#!/usr/bin/env python3
"""Demonstration script executing most FTP commands to showcase HoneyFTP."""
from attaquant import script_demo


def run_demo(host: str = "127.0.0.1", port: int = 2121) -> None:
    """Wrapper calling ``script_demo`` from ``attaquant.py``."""
    script_demo(host, port)


if __name__ == "__main__":
    run_demo()
