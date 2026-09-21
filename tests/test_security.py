import contextlib
import hashlib
import importlib.util
import io
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('confess', Path(__file__).parents[1] / 'cli/confess.py')
c = importlib.util.module_from_spec(SPEC)
sys.modules['confess'] = c
SPEC.loader.exec_module(c)


class WorkspaceTestCase(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.cwd = Path.cwd()
        os.chdir(self.temp.name)
        self.addCleanup(os.chdir, self.cwd)
        self.addCleanup(self.temp.cleanup)

    def args(self, *argv):
        return c._build_parser().parse_args(argv)


class FileSafetyTests(WorkspaceTestCase):
    def test_verify_refusal_preserves_existing_plaintext(self):
        Path('payload.age').write_bytes(b'encrypted test fixture')
        Path('payload.tar.gz').write_bytes(b'existing archive MUST survive')
        digest = c._sha512_file(Path('payload.age'))
        result = c._verify(self.args('verify', '--csha', digest, '--decrypt', '--age-pass', 'test'))
        self.assertEqual(result, 1)
        self.assertEqual(Path('payload.tar.gz').read_bytes(), b'existing archive MUST survive')

    def test_failed_forced_decryption_preserves_existing_output(self):
        Path('payload.age').write_bytes(b'encrypted test fixture')
        Path('payload.tar.gz').write_bytes(b'existing archive MUST survive')
        digest = c._sha512_file(Path('payload.age'))
        with patch.object(c, '_age_decrypt', side_effect=RuntimeError('wrong password')):
            result = c._verify(self.args('verify', '--csha', digest, '--decrypt', '--age-pass', 'test', '--force'))
        self.assertEqual(result, 1)
        self.assertEqual(Path('payload.tar.gz').read_bytes(), b'existing archive MUST survive')

    def test_extract_cannot_overwrite_input_even_with_force(self):
        Path('cover.jpg').write_bytes(b'original cover')
        with patch.object(c, '_hstego_extract', side_effect=RuntimeError('test')):
            result = c._extract(self.args('extract', '--image', 'cover.jpg', '--out', 'cover.jpg', '--force', '--stego-pass', 'test'))
        self.assertEqual(result, 1)
        self.assertEqual(Path('cover.jpg').read_bytes(), b'original cover')

    def test_archive_is_private_even_with_permissive_umask(self):
        Path('testimony.txt').write_text('synthetic test testimony')
        old = os.umask(0)
        try:
            c._write_payload_tar(Path('testimony.txt'), Path('archive.tar.gz'))
        finally:
            os.umask(old)
        self.assertEqual(Path('archive.tar.gz').stat().st_mode & 0o777, 0o600)

    def test_equal_split_secrets_are_rejected(self):
        args = self.args('seal', '--image', 'c.jpg', '--text', 't.txt', '--age-pass', 'a' * 32, '--stego-pass', 'a' * 32)
        with self.assertRaises(RuntimeError):
            c._resolve_seal_passwords(args)

    def test_control_chars_in_encryption_passphrase_are_rejected(self):
        args = self.args('seal', '--image', 'c.jpg', '--text', 't.txt', '--single-pass', 'long-test-password\nsecond-line')
        with self.assertRaises(RuntimeError):
            c._resolve_seal_passwords(args)

    def test_ardrive_does_not_mistake_arbitrary_id_for_file_data(self):
        self.assertIsNone(c._extract_ardrive_data_tx('{"bundleTxId":"' + 'a' * 43 + '"}'))


class AdditionalSafetyTests(WorkspaceTestCase):
    def test_old_hstego_cannot_be_used_for_new_seals(self):
        from types import SimpleNamespace
        with patch.dict(sys.modules, {'hstegolib': SimpleNamespace()}):
            with self.assertRaisesRegex(RuntimeError, '0.6.1'):
                c._load_hstegolib()
        supported_format = SimpleNamespace(HEADER_MAGIC=b'HS2\x00', SCRYPT_N=2**18)
        with patch.dict(sys.modules, {'hstegolib': supported_format}), patch('importlib.metadata.version', return_value='0.6'):
            with self.assertRaisesRegex(RuntimeError, '0.6.1'):
                c._load_hstegolib()

    def test_extraction_resource_error_is_a_clean_failure(self):
        from types import SimpleNamespace
        def reject(_):
            raise ValueError('Image exceeds resource limits')
        with patch.object(c, '_load_hstegolib', return_value=SimpleNamespace(validate_image_resource=reject)):
            with self.assertRaisesRegex(RuntimeError, 'resource limits'):
                c._hstego_extract(Path('cover.png'), Path('out.age'), 'synthetic')

    def test_hstego_payload_estimate_matches_compressed_envelope(self):
        import zlib
        data = b'synthetic encrypted data' * 20
        Path('payload.age').write_bytes(data)
        self.assertEqual(c._hstego_wrapped_payload_size(Path('payload.age')), 60 + len(zlib.compress(data, 9)))

    def test_mint_preserves_titles_that_resemble_metadata_fields(self):
        for title in ['AR : autobiography', 'TITLE: a title', 'HASH : notes']:
            with self.subTest(title=title), contextlib.redirect_stdout(io.StringIO()) as output:
                args = self.args('mint', '--title', title, '--txid', 'a' * 43, '--csha', 'b' * 128)
                self.assertEqual(c._mint(args), 0)
            self.assertIn('TITLE:' + title + ' | ARTXID:', output.getvalue())

    def test_atomic_publish_does_not_clobber_a_file_created_after_preflight(self):
        with self.assertRaises(RuntimeError):
            with c._staged_output(Path('output'), False) as staged:
                staged.write_bytes(b'new')
                Path('output').write_bytes(b'other operation')
        self.assertEqual(Path('output').read_bytes(), b'other operation')

    def test_output_symlink_is_refused_even_with_force(self):
        Path('input').write_text('original')
        Path('output').symlink_to('input')
        with self.assertRaises(RuntimeError):
            with c._staged_output(Path('output'), True) as staged:
                staged.write_text('replacement')
        self.assertEqual(Path('input').read_text(), 'original')

    def test_output_hardlink_to_input_is_refused(self):
        Path('input').write_text('original')
        os.link('input', 'output')
        with self.assertRaises(RuntimeError):
            c._check_output(Path('output'), True, (Path('input'),))

    def test_temporary_files_removed_on_keyboard_interrupt(self):
        with self.assertRaises(KeyboardInterrupt):
            with c._staged_output(Path('output'), False) as staged:
                parent=staged.parent
                staged.write_text('private')
                raise KeyboardInterrupt
        self.assertFalse(parent.exists())
        self.assertFalse(Path('output').exists())

    def test_generated_passwords_never_go_to_redirected_stdout(self):
        args=self.args('seal','--text','t','--image','i','--gen-split-pass')
        with patch('sys.stdin.isatty',return_value=False), patch('sys.stdout.isatty',return_value=False):
            with self.assertRaises(RuntimeError):
                c._store_generated_secrets(args,'secret-one','secret-two','split-generated')

    def test_generated_secrets_file_is_private_and_never_overwritten(self):
        args=self.args('seal','--text','t','--image','i','--gen-split-pass','--secrets-file','test.secrets.json')
        c._store_generated_secrets(args,'secret-one','secret-two','split-generated')
        self.assertEqual(Path('test.secrets.json').stat().st_mode & 0o777,0o600)
        with self.assertRaises(RuntimeError):
            c._store_generated_secrets(args,'replacement','replacement','split-generated')
        self.assertIn('secret-one',Path('test.secrets.json').read_text())

    def test_seal_cannot_destroy_testimony_with_force(self):
        Path('cover.jpg').write_bytes(b'cover');Path('payload.age').write_text('testimony')
        args=self.args('seal','--text','payload.age','--image','cover.jpg','--gen-split-pass','--force')
        self.assertEqual(c._seal(args),1)
        self.assertEqual(Path('payload.age').read_text(),'testimony')

    def test_mint_requires_public_disclosure_acknowledgement(self):
        args=self.args('mint','--title','test','--txid','a'*43,'--csha','b'*128,'--steg','public')
        self.assertEqual(c._mint(args),1)

    def test_upload_rejects_plaintext_before_invoking_wallet_tool(self):
        Path('test.txt').write_text('synthetic private testimony')
        args=self.args('push','--file','test.txt','--folder-id','unused','--ack-permanent-upload')
        with patch.object(c,'_ardrive_upload') as upload:
            self.assertEqual(c._push(args),1)
            upload.assert_not_called()

    def test_file_receipt_data_id_is_used(self):
        receipt='progress\n{"created":[{"type":"file","dataTxId":"'+'a'*43+'","metadataTxId":"'+'b'*43+'"}]}'
        self.assertEqual(c._extract_ardrive_data_tx(receipt),'a'*43)

    def test_payload_change_during_password_prompt_is_rejected(self):
        Path('payload.age').write_bytes(b'original encrypted fixture')
        expected=c._sha512_file(Path('payload.age'))
        args=self.args('verify','--csha',expected,'--decrypt','--age-pass-prompt')
        def changed(*a,**kw):
            Path('payload.age').write_bytes(b'replaced fixture')
            return 'synthetic-passphrase'
        with patch.object(c,'_prompt_secret',side_effect=changed),patch.object(c,'_age_decrypt') as decrypt:
            self.assertEqual(c._verify(args),1)
            decrypt.assert_not_called()
        self.assertFalse(Path('payload.tar.gz').exists())

    def test_hidden_prompt_fails_closed_without_terminal(self):
        import getpass, warnings
        def fallback(*a,**kw):
            warnings.warn('echo fallback',getpass.GetPassWarning)
            return 'secret'
        with patch.object(c.getpass,'getpass',side_effect=fallback):
            with self.assertRaises(RuntimeError):
                c._prompt_secret('Test')


if __name__ == '__main__':
    unittest.main()
