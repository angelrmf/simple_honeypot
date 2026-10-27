# Simple honeypot(inspired by cowrie)

IN PROGRESS

### What is it?
honeypot.py - a small, low-interaction SSH honeypot.

It speaks real SSH, so normal SSH clients and real attack bots can connect.
It asks for a password, records every username and password tried, and
always answers "wrong password". Nobody ever gets in, and there is no shell
behind it to get into.


It writes two logs:
  honeypot_auth.log  sshd-style lines in the same format as loggen.py, so
                     detect.py and the dashboard can read them directly
  honeypot.jsonl     one JSON object per event, with the extra details:
                     passwords tried, the attacker's SSH software, sessions

SAFETY: by default it only listens on 127.0.0.1, meaning only your own
computer can reach it. Use --host 0.0.0.0 only inside a VM or an isolated
lab network, and only once you understand what you're exposing.

Needs:  pip install paramiko

Examples:
    python honeypot.py                         # listen on 127.0.0.1:2222
    ssh -p 2222 root@127.0.0.1                 # in another terminal: try it!
    python detect.py honeypot_auth.log --threshold 3
"""
