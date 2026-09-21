#!/usr/bin/env python3
"""Install the verified v0.5 reader beside current HStego's native libraries.

This dependency is used only for explicitly requested legacy extraction.
Upstream source and its MIT notice stay in the virtual environment, not the repo.
"""
import hashlib
import os
from pathlib import Path
import sys
import sysconfig
import tempfile
import urllib.request

REVISION = 'ca43b9f3ddd53757da0ae636331f12c3cbc64091'
FILES = {
    'hstegolib.py': ('confess_hstego_v05.py', 'dd4147b79f64f4dda84d18a323ad817aa1ea5727136f4c67b5f962b2370fd9da'),
    'LICENSE.txt': ('confess_hstego_v05.LICENSE.txt', '4eb7d75485884abccaf54ac83ac7eec516b4dd06380dbcb8fcbe11505c5222b3'),
}


def main():
    if sys.prefix == sys.base_prefix:
        raise SystemExit('Activate the project virtual environment first.')
    destination = Path(sysconfig.get_path('purelib'))
    for source, (name, expected) in FILES.items():
        url = f'https://raw.githubusercontent.com/daniellerch/hstego/{REVISION}/{source}'
        with urllib.request.urlopen(url, timeout=30) as response:
            data = response.read(1024 * 1024 + 1)
        if hashlib.sha256(data).hexdigest() != expected:
            raise SystemExit(f'Legacy dependency checksum mismatch: {source}')
        target = destination / name
        if target.is_symlink():
            raise SystemExit('Refusing symlink dependency destination.')
        with tempfile.TemporaryDirectory(prefix='.confess-legacy-', dir=destination) as temporary:
            staged = Path(temporary) / name
            staged.write_bytes(data)
            staged.chmod(0o600)
            os.replace(staged, target)
    print('Verified HStego v0.5 compatibility reader installed (explicit extraction only).')


if __name__ == '__main__':
    main()
