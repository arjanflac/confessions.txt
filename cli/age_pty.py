#!/usr/bin/env python3
"""Private age bridge, isolated from HStego/numpy threads.

Request arrives over an anonymous pipe, never argv/environment. stdout contains
only a success/failure status; passwords and age's terminal transcript stay here.
"""
import importlib.util
import json
from pathlib import Path
import signal
import sys


def interrupted(signum, frame):
    raise KeyboardInterrupt


def main():
    signal.signal(signal.SIGTERM, interrupted)
    spec = importlib.util.spec_from_file_location('confess_age_bridge', Path(__file__).with_name('confess.py'))
    core = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(core)
    request = json.loads(sys.stdin.read(32768))
    core._run_age_pty(request['cmd'], request['passphrase'], request['confirm'])


if __name__ == '__main__':
    try:
        main()
    except (Exception, KeyboardInterrupt):
        sys.exit(1)
