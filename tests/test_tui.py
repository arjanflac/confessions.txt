import contextlib
import importlib.util
import io
from pathlib import Path
import subprocess
import sys
from unittest.mock import patch
from test_security import c, WorkspaceTestCase

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('tui', ROOT / 'cli/tui.py')
tui = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = tui
spec.loader.exec_module(tui)


class TerminalMenuTests(WorkspaceTestCase):
    def run_menu(self, replies, dispatch=None):
        with contextlib.redirect_stdout(io.StringIO()), \
                patch('sys.stdin.isatty', return_value=True), patch('sys.stdout.isatty', return_value=True), \
                patch('builtins.input', side_effect=replies), \
                patch.object(c, '_dispatch', side_effect=dispatch, return_value=0) as handler:
            return tui.run(c), handler

    def test_noninteractive_menu_is_rejected(self):
        with patch('sys.stdin.isatty', return_value=False):
            self.assertEqual(tui.run(c), 1)

    def test_generated_split_secrets_and_checksum_carry_into_verification(self):
        Path('cover image.png').touch()
        Path('testimony.txt').touch()
        def dispatch(args):
            if args.cmd == 'seal':
                Path('payload.age').write_bytes(b'synthetic ciphertext')
            return 0
        code, handler = self.run_menu(
            ['1', '"cover image.png"', 'testimony.txt', '', '', '', 'yes', '3', '', '', '', '0'], dispatch)
        self.assertEqual(code, 0)
        seal, verify = [call.args[0] for call in handler.call_args_list]
        self.assertTrue(seal.gen_split_pass)
        self.assertFalse(seal.force)
        self.assertEqual(seal.out, 'locked_artifact.png')
        self.assertEqual(seal.secrets_file, 'locked_artifact.secrets.json')
        self.assertIsNone(seal.age_pass)
        self.assertIsNone(seal.stego_pass)
        self.assertEqual(verify.csha, c._sha512_file(Path('payload.age')))
        self.assertFalse(verify.decrypt)

    def test_missing_cover_never_prompts_for_secrets_or_dispatches(self):
        code, handler = self.run_menu(['1', 'missing.png', '0'])
        self.assertEqual(code, 0)
        handler.assert_not_called()

    def test_upload_declined_never_calls_wallet_operation(self):
        Path('cover.jpg').touch()
        code, handler = self.run_menu(['8', 'cover.jpg', 'folder', 'no', '0'])
        self.assertEqual(code, 0)
        handler.assert_not_called()

    def test_cancel_at_menu_exits(self):
        self.assertEqual(self.run_menu([KeyboardInterrupt])[0], 130)

    def test_cancel_inside_operation_returns_to_menu(self):
        code, handler = self.run_menu(['1', KeyboardInterrupt, '0'])
        self.assertEqual(code, 0)
        handler.assert_not_called()

    def test_path_starting_with_dash_is_data(self):
        Path('--force').touch()
        code, handler = self.run_menu(['2', '--force', 'out.age', '0'])
        self.assertEqual(code, 0)
        args = handler.call_args.args[0]
        self.assertEqual(args.image, '--force')
        self.assertFalse(args.force)

    def test_extract_clears_previous_records_checksum(self):
        Path('other.png').touch()
        state = tui.Session(csha='a' * 128)
        with patch('builtins.input', side_effect=['other.png', 'other.age']), patch.object(c, '_dispatch', return_value=0):
            tui._operation(c, state, '2')
        self.assertEqual(state.payload, 'other.age')
        self.assertEqual(state.csha, '')

    def test_public_lookup_delimits_untrusted_reference(self):
        with patch('builtins.input', return_value='--help'), patch.object(tui.subprocess, 'run') as run:
            tui._operation(c, tui.Session(), '4')
        self.assertEqual(run.call_args.args[0][-3:], ['verify', '--', '--help'])

    def test_launcher_preserves_working_directory_and_arguments(self):
        Path('payload.age').write_bytes(b'synthetic ciphertext')
        result = subprocess.run([str(ROOT / 'confess'), 'verify', '--csha', c._sha512_file(Path('payload.age'))],
                                capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('CSHA match: YES', result.stdout)

    def test_launcher_does_not_hang_without_a_terminal(self):
        result = subprocess.run([str(ROOT / 'confess')], stdin=subprocess.DEVNULL,
                                capture_output=True, text=True, timeout=15)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('usage:', result.stderr)
