"""Opt-in native integration tests. All testimony and credentials are synthetic."""
import importlib.util
import os
from pathlib import Path
import shutil
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

SPEC=importlib.util.spec_from_file_location('confess_integration',Path(__file__).parents[1]/'cli/confess.py')
c=importlib.util.module_from_spec(SPEC);sys.modules[SPEC.name]=c;SPEC.loader.exec_module(c)

@unittest.skipUnless(os.environ.get('CONFESS_NATIVE_TESTS')=='1','Set CONFESS_NATIVE_TESTS=1 with age/HStego installed')
class NativeTests(unittest.TestCase):
    def test_jpeg_and_png_seal_extract_checksum_decrypt(self):
        import numpy as np
        from PIL import Image
        for suffix in ['.jpg','.png']:
            with self.subTest(suffix=suffix), tempfile.TemporaryDirectory() as d:
                root=Path(d)
                cover=root/('cover'+suffix)
                Image.fromarray(np.random.default_rng(7).integers(0,256,(384,384,3),dtype=np.uint8)).save(cover)
                text=root/'synthetic testimony.txt';text.write_text('Only a synthetic integration-test record.\n')
                out=root/('locked'+suffix)
                args=c._build_parser().parse_args(['seal','--image',str(cover),'--text',str(text),'--out',str(out),
                    '--age-pass','synthetic-private-passphrase-✅','--stego-pass','synthetic-public-password'])
                self.assertEqual(c._seal(args),0)
                self.assertFalse((root/'payload.tar.gz').exists())
                self.assertEqual((root/'payload.age').stat().st_mode & 0o777,0o600)
                # Browser download instructions use .jpg; identify actual bytes.
                downloaded=root/'downloaded.jpg';shutil.copyfile(out,downloaded)
                extracted=root/'extracted.age'
                c._hstego_extract(downloaded,extracted,'synthetic-public-password')
                self.assertEqual(c._sha512_file(extracted),c._sha512_file(root/'payload.age'))
                archive=root/'decrypted.tar.gz'
                args=c._build_parser().parse_args(['verify','--file',str(extracted),'--csha',c._sha512_file(extracted),
                    '--decrypt','--out',str(archive),'--age-pass','synthetic-private-passphrase-✅'])
                self.assertEqual(c._verify(args),0)
                self.assertEqual(archive.stat().st_mode & 0o777,0o600)
                with tarfile.open(archive) as t:
                    self.assertEqual(t.getnames(),[text.name])
                    self.assertEqual(t.extractfile(text.name).read(),text.read_bytes())
                self.assertFalse(list(root.glob('.confess-*')))
                with self.assertRaises(RuntimeError):
                    c._age_decrypt(extracted,root/'bad','synthetic-public-password')
