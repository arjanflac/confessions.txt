"""Explicit, bounded access to old HStego images; never used for new seals."""
import hashlib
import importlib.util
from pathlib import Path
import sys

LEGACY_SHA256 = 'dd4147b79f64f4dda84d18a323ad817aa1ea5727136f4c67b5f962b2370fd9da'


def load_legacy(current):
    source = Path(current.__file__).with_name('confess_hstego_v05.py')
    if not source.is_file() or hashlib.sha256(source.read_bytes()).hexdigest() != LEGACY_SHA256:
        raise RuntimeError('Verified legacy reader missing. Run .venv/bin/python scripts/install_legacy_hstego.py from the repository.')
    name = '_confess_hstego_v05'
    module = sys.modules.get(name)
    if module is None:
        spec = importlib.util.spec_from_file_location(name, source)
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        try:
            spec.loader.exec_module(module)
        except BaseException:
            sys.modules.pop(name, None)
            raise
        # v0.5 passes an unauthenticated length to native code before checking it.
        # The current implementation checks the length before native extraction.
        # The native extension ABI is identical across these pinned releases.
        module.Stego.unhide_stc = current.Stego.unhide_stc
        module.Stego.unhide = current.Stego.unhide
    return module
