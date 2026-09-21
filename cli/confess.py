#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
from contextlib import contextmanager, redirect_stderr, redirect_stdout
import getpass
import hashlib
import json
import os
import platform
import re
import select
import secrets
import shutil
import subprocess
import sys
import tarfile
import tempfile
import warnings
import time
import threading
import urllib.error
import urllib.request
from pathlib import Path
from typing import Optional, Tuple

try:
    import pty
except Exception:  # pragma: no cover - pty may be missing on non-posix
    pty = None

CONFIG_DIR = Path(".confess")
CONFIG_PATH = CONFIG_DIR / "config.json"
ARWEAVE_URL_PREFIX = "https://arweave.net/"
WINSTON_PER_AR = 1_000_000_000_000
ARWEAVE_TXID_RE = re.compile(r"^[a-zA-Z0-9_-]{43}$")
CSHA_RE = re.compile(r"^[0-9a-fA-F]{128}$")
CONTROL_CHARS_RE = re.compile(r"[\x00-\x1f\x7f-\x9f\u202a-\u202e\u2066-\u2069]")


def _err(msg: str) -> None:
    try:
        sys.stdout.flush()
    except OSError:
        pass
    print(msg, file=sys.stderr, flush=True)


def _run(cmd: list[str], env: Optional[dict] = None) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, env=env)


def _which(name: str) -> Optional[str]:
    return shutil.which(name)


def _load_config() -> dict:
    if CONFIG_PATH.exists():
        try:
            data = json.loads(CONFIG_PATH.read_text())
            if not isinstance(data, dict) or ("wallet_path" in data and not isinstance(data["wallet_path"], str)):
                raise RuntimeError("Invalid config; run confess init.")
            return data
        except json.JSONDecodeError:
            raise RuntimeError("Invalid config JSON; run confess init.") from None
    return {}


def _save_wallet_path(wallet_path: Path) -> None:
    if CONFIG_DIR.is_symlink():
        raise RuntimeError("Refusing a symlink configuration directory.")
    CONFIG_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(CONFIG_DIR, 0o700)
    with _staged_output(CONFIG_PATH, True) as staged:
        staged.write_text(json.dumps({"wallet_path": str(wallet_path.resolve())}, indent=2))


def _sha512_file(path: Path) -> str:
    h = hashlib.sha512()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _format_bytes(size: int) -> str:
    if size < 1024:
        return f"{size} B"
    units = ("KB", "MB", "GB")
    value = size / 1024
    unit = units[0]
    for unit in units:
        if value < 1024 or unit == units[-1]:
            break
        value /= 1024
    return f"{value:.1f} {unit}" if value < 100 else f"{value:.0f} {unit}"


def _validate_arweave_txid(value: str) -> bool:
    return bool(ARWEAVE_TXID_RE.fullmatch(value.strip()))


def _validate_csha(value: str) -> bool:
    return bool(CSHA_RE.fullmatch(value.strip()))


def _has_control_chars(value: str) -> bool:
    return bool(CONTROL_CHARS_RE.search(value))


def _same_path(left: Path, right: Path) -> bool:
    try:
        return left.resolve() == right.resolve() or (left.exists() and right.exists() and left.samefile(right))
    except OSError:
        return left.absolute() == right.absolute()


def _warn_literal_secret_arg(flag: str, prompt_flag: str) -> None:
    _err(f"Warning: {flag} can be visible in shell history and process lists. Prefer {prompt_flag}.")


def _prompt_secret(label: str, confirm: bool = False) -> str:
    # getpass otherwise falls back to echoed stdin when no terminal exists.
    def read(prompt):
        with warnings.catch_warnings():
            warnings.simplefilter("error", getpass.GetPassWarning)
            try:
                return getpass.getpass(prompt)
            except getpass.GetPassWarning:
                raise RuntimeError("A private terminal is required for hidden password entry.") from None
    secret = read(f"{label}: ")
    if not secret:
        raise RuntimeError(f"{label} cannot be empty.")
    _validate_secret(secret)
    if confirm:
        repeated = read(f"Confirm {label}: ")
        if repeated != secret:
            raise RuntimeError(f"{label} values did not match.")
    return secret


def _validate_secret(secret: str, creating: bool = False) -> None:
    if not secret or _has_control_chars(secret) or len(secret.encode("utf-8")) > 1024:
        raise RuntimeError("Passphrases must be nonempty, at most 1024 UTF-8 bytes, and contain no control characters.")
    if creating and len(secret) < 20:
        raise RuntimeError("New AGE passphrases require at least 20 characters. Prefer --gen-split-pass; length alone does not ensure strength.")


def _check_output(path: Path, force: bool, inputs=()) -> None:
    if any(_same_path(path, source) for source in inputs):
        raise RuntimeError(f"Output must differ from all inputs: {path}")
    if path.is_symlink():
        raise RuntimeError(f"Refusing symlink output: {path}")
    if path.exists() and (not force or not path.is_file()):
        raise RuntimeError(f"Output already exists: {path}. Use --force to replace a regular file after success.")
    if not path.parent.is_dir():
        raise RuntimeError(f"Output directory does not exist: {path.parent}")


def _publish_output(staged: Path, target: Path, force: bool) -> None:
    """Publish only complete files; never truncate the previous output on failure."""
    _check_output(target, force)
    os.chmod(staged, 0o600)
    if force:
        os.replace(staged, target)
    else:
        # Atomic no-clobber, including a file created after preflight.
        os.link(staged, target)
        staged.unlink()


@contextmanager
def _staged_output(target: Path, force: bool, inputs=()):
    _check_output(target, force, inputs)
    with tempfile.TemporaryDirectory(prefix=".confess-", dir=target.absolute().parent) as directory:
        staged = Path(directory) / target.name
        yield staged
        if not staged.is_file():
            raise RuntimeError("Operation produced no output.")
        _publish_output(staged, target, force)



def _write_payload_tar(text_path: Path, payload_tar: Path) -> None:
    stat = text_path.stat()
    info = tarfile.TarInfo(name=text_path.name)
    info.size = stat.st_size
    info.mode = 0o600
    info.mtime = 0
    info.uid = 0
    info.gid = 0
    info.uname = ""
    info.gname = ""
    fd = os.open(payload_tar, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as archive:
        with tarfile.open(fileobj=archive, mode="w:gz") as tar:
            with text_path.open("rb") as f:
                tar.addfile(info, f)


def _base64url_decode(data: str) -> bytes:
    pad = "=" * ((4 - len(data) % 4) % 4)
    return base64.urlsafe_b64decode(data + pad)


def _base64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")


def _wallet_address_from_jwk(wallet_path: Path) -> Optional[str]:
    try:
        jwk = json.loads(wallet_path.read_text())
        n = jwk.get("n")
        if not n:
            return None
        n_bytes = _base64url_decode(n)
        digest = hashlib.sha256(n_bytes).digest()
        return _base64url_encode(digest)
    except Exception:
        return None


def _fetch_wallet_balance_winston(address: str, timeout: float = 8.0) -> Optional[int]:
    url = f"https://arweave.net/wallet/{address}/balance"
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            value = resp.read().decode("utf-8").strip()
        winston = int(value)
        return winston if winston >= 0 else None
    except (urllib.error.URLError, ValueError, OSError):
        return None


def _format_ar_from_winston(winston: int) -> str:
    amount = winston / WINSTON_PER_AR
    return f"{amount:.12f}".rstrip("0").rstrip(".")


def _print_install_hints() -> None:
    print("Quick setup:")
    print("  macOS:")
    print("    bash scripts/bootstrap_mac.sh")
    print("    ./confess")
    print("  Linux: see docs/cli.md for Python 3.12 and native build prerequisites.")
    print("  Public lookup: install Node.js 22 or newer.")
    print("  Optional upload tool: npm install -g ardrive-cli")


def _binary_version(cmd: list[str]) -> Optional[str]:
    try:
        res = _run(cmd)
    except FileNotFoundError:
        return None
    if res.returncode != 0:
        return None
    output = (res.stdout.strip() or res.stderr.strip()).splitlines()
    return output[0] if output else None


def _check_hstego() -> Tuple[bool, str]:
    try:
        hstegolib = _load_hstegolib()
    except SystemExit:
        return False, "native extensions missing"
    except Exception as e:
        return False, str(e)
    return True, "authenticated v2 format; scrypt N=2^18"

def _in_venv() -> bool:
    return getattr(sys, "base_prefix", sys.prefix) != sys.prefix or hasattr(sys, "real_prefix")


def _find_jpeglib_header() -> Optional[Path]:
    candidates = [
        "/opt/homebrew/opt/jpeg/include/jpeglib.h",
        "/usr/local/opt/jpeg/include/jpeglib.h",
        "/opt/homebrew/opt/libjpeg-turbo/include/jpeglib.h",
        "/usr/local/opt/libjpeg-turbo/include/jpeglib.h",
        "/opt/homebrew/opt/libjpeg/include/jpeglib.h",
        "/usr/local/opt/libjpeg/include/jpeglib.h",
    ]
    for candidate in candidates:
        path = Path(candidate)
        if path.exists():
            return path
    return None


def _xcode_clt_status() -> Tuple[bool, Optional[str]]:
    if _which("xcode-select") is None:
        return False, "xcode-select missing"
    res = _run(["xcode-select", "-p"])
    if res.returncode != 0:
        return False, "not installed"
    if _which("xcrun") is None:
        return False, "xcrun missing"
    sdk_res = _run(["xcrun", "--sdk", "macosx", "--show-sdk-path"])
    if sdk_res.returncode != 0:
        return False, "sdk not found"
    sdk = sdk_res.stdout.strip()
    if not sdk:
        return False, "sdk not found"
    cstdio_sdk = Path(sdk) / "usr" / "include" / "c++" / "v1" / "cstdio"
    cstdio_clt = Path("/Library/Developer/CommandLineTools/usr/include/c++/v1/cstdio")
    if not cstdio_sdk.exists() and not cstdio_clt.exists():
        if Path("/Applications/Xcode.app/Contents/Developer").exists():
            return False, "missing C++ headers (try xcode-select --switch /Applications/Xcode.app/Contents/Developer)"
        return False, "missing C++ headers (run xcode-select --install)"
    return True, sdk


def _doctor() -> int:
    warnings: list[str] = []

    print("confess doctor")
    print("--------------")
    print(f"Python: {sys.version.split()[0]}")
    if sys.version_info < (3, 9):
        warnings.append("Python 3.9+ is required.")
    elif sys.version_info[:2] != (3, 12):
        warnings.append("Python 3.12 is required for the pinned and tested HStego environment.")

    venv_ok = _in_venv()
    print(f"virtualenv: {'OK' if venv_ok else 'MISSING'}")
    if not venv_ok:
        warnings.append(
            "Not inside a virtual environment. Create one with: "
            "$(brew --prefix python@3.12)/bin/python3.12 -m venv .venv && source .venv/bin/activate"
        )

    arch = platform.machine()
    print(f"arch: {arch}")

    age_path = _which("age")
    age_version = _binary_version(["age", "--version"]) if age_path else None
    print(f"age: {'OK' if age_path else 'MISSING'}" + (f" ({age_version})" if age_version else ""))
    if not age_path:
        warnings.append("age CLI missing.")

    hstego_ok, hstego_info = _check_hstego()
    print(f"hstego (hstegolib): {'OK' if hstego_ok else 'MISSING'}" + (f" ({hstego_info})" if hstego_info else ""))
    if not hstego_ok:
        warnings.append("HStego missing or not importable.")

    ardrive_path = _which("ardrive")
    ardrive_version = _binary_version(["ardrive", "--version"]) if ardrive_path else None
    print(
        f"ardrive: {'OK' if ardrive_path else 'MISSING'}"
        + (f" ({ardrive_version})" if ardrive_version else "")
    )
    if not ardrive_path:
        warnings.append("ArDrive CLI missing (needed only for uploading; local sealing and verification still work).")

    if platform.system() == "Darwin":
        clt_ok, clt_info = _xcode_clt_status()
        print(
            f"Xcode CLT: {'OK' if clt_ok else 'MISSING'}"
            + (f" ({clt_info})" if clt_info else "")
        )
        if not clt_ok:
            warnings.append("Install Xcode Command Line Tools: xcode-select --install")
        if arch == "arm64" and not hstego_ok:
            warnings.append(
                "Apple Silicon detected. Use scripts/install_hstego_mac.sh (patches SSE intrinsics via sse2neon)."
            )
        if sys.version_info[:2] != (3, 12) and _which("python3.12") is None:
            warnings.append("python3.12 not on PATH. Use: $(brew --prefix python@3.12)/bin/python3.12")
        jpeg_header = _find_jpeglib_header()
        print(
            f"libjpeg headers: {'OK' if jpeg_header else 'MISSING'}"
            + (f" ({jpeg_header})" if jpeg_header else "")
        )
        if not jpeg_header:
            warnings.append("Install libjpeg headers: brew install jpeg")

    print("")
    if warnings:
        print("Action items:")
        for item in warnings:
            print(f"  - {item}")
    else:
        print("Action items:")
        print("  - None. Environment looks ready.")

    print("")
    _print_install_hints()
    return 0


def _validate_wallet_json(wallet_path: Path) -> bool:
    try:
        data = json.loads(wallet_path.read_text())
        return isinstance(data, dict) and data.get("kty") == "RSA" and all(
            isinstance(data.get(key), str) and re.fullmatch(r"[A-Za-z0-9_-]+", data[key])
            for key in ("n", "e", "d", "p", "q", "dp", "dq", "qi")
        )
    except Exception:
        return False


def _init() -> int:
    print("Arweave wallet.json path:")
    user_input = input("> ").strip()
    if not user_input:
        _err("Wallet path is required.")
        return 1

    wallet_path = Path(user_input).expanduser()
    if not wallet_path.exists():
        _err(f"Wallet file not found: {wallet_path}")
        return 1
    if not _validate_wallet_json(wallet_path):
        _err("Wallet must be an Arweave RSA private JWK, not an arbitrary JSON file.")
        return 1

    _save_wallet_path(wallet_path)
    print(f"Saved wallet path to {CONFIG_PATH}")

    address = _wallet_address_from_jwk(wallet_path)
    if address:
        print(f"Wallet address: {address}")
        balance_winston = _fetch_wallet_balance_winston(address)
        if balance_winston is None:
            print("On-chain balance check unavailable (network/API).")
            print("If upload fails for insufficient funds, fund this address and retry.")
        else:
            print(f"On-chain balance: {_format_ar_from_winston(balance_winston)} AR")
            if balance_winston > 0:
                print("Wallet appears funded and ready for upload.")
            else:
                print("No AR detected yet. Fund this address before upload.")
    else:
        print("Wallet loaded. Address unavailable (could not derive locally).")
    return 0


def _generate_passphrase() -> str:
    raw = secrets.token_bytes(32)
    return base64.urlsafe_b64encode(raw).decode("utf-8").rstrip("=")


def _sanitize_age_output(output: str, passphrase: str) -> str:
    if not output:
        return ""
    safe = output.replace(passphrase, "[REDACTED]")
    safe = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", safe)
    safe = safe.replace("\r", "")
    lines = [line for line in safe.splitlines() if line.strip()]
    if not lines:
        return ""
    return "\n".join(lines[-4:])


def _looks_like_age_ciphertext(path: Path) -> bool:
    try:
        with path.open("rb") as f:
            head = f.read(32)
    except OSError:
        return False
    return head.startswith(b"age-encryption.org/v1")


def _hstego_wrapped_payload_size(payload: Path) -> int:
    # v0.6.1: salt + nonce + authentication tag, then the compressed envelope.
    import zlib
    with payload.open("rb") as source:
        data = source.read(64 * 1024 * 1024 + 1)
    if len(data) > 64 * 1024 * 1024:
        raise RuntimeError("Encrypted payload exceeds HStego's 64 MiB limit.")
    return 48 + 12 + len(zlib.compress(data, level=9))


def _hstego_capacity(cover: Path, hstegolib, algo: str) -> int:
    if algo == "j-uniward":
        jpg = hstegolib.jpeg_load(str(cover))
        return hstegolib.jpg_capacity(jpg)

    try:
        import imageio.v2 as imageio  # type: ignore
    except Exception:
        import imageio  # type: ignore

    hstegolib.validate_image_resource(str(cover))
    image = imageio.imread(str(cover))
    if image.ndim == 3 and image.shape[2] in (3, 4):
        image = image[:, :, :3]  # HStego preserves alpha but embeds only in RGB.
    elif image.ndim != 2:
        raise RuntimeError("Spatial covers must be grayscale, RGB, or RGBA images.")
    return hstegolib.spatial_capacity(image)


def _print_embed_preflight(cover: Path, payload: Path, hstegolib, algo: str) -> None:
    payload_size = payload.stat().st_size
    wrapped_size = _hstego_wrapped_payload_size(payload)
    capacity = _hstego_capacity(cover, hstegolib, algo)
    usage = wrapped_size / capacity if capacity else 1

    print("HStego preflight:")
    print(f"  Cover image: {cover} ({_format_bytes(cover.stat().st_size)})")
    print(f"  Encrypted payload: {_format_bytes(payload_size)}")
    print(f"  Embedded payload budget: {_format_bytes(capacity)}")
    print(f"  Estimated payload use: {usage:.1%} of HStego's conservative budget")

    if wrapped_size > capacity:
        raise RuntimeError(
            "Encrypted payload is too large for this cover image. "
            f"HStego needs about {_format_bytes(wrapped_size)}, but this cover's budget is {_format_bytes(capacity)}. "
            "Use a larger or more detailed cover image, or reduce the testimony size."
        )

    if usage >= 0.75:
        print("")
        print("Stego detectability warning:")
        print("  Payload use is high for this cover. The artifact may still be created,")
        print("  but statistical concealment is weaker and stego-analysis may be easier.")
        print("  Confidentiality still comes from age encryption. For lower detectability,")
        print("  use a larger or more detailed cover image, or shorten the testimony.")
    elif usage >= 0.5:
        print("")
        print("Stego detectability note:")
        print("  Payload use is moderate. The artifact can be created, but a larger or")
        print("  more detailed cover image gives HStego more room to hide changes.")


def _quiet_juniward_cost_debug(stego_obj, hstegolib) -> None:
    def _quiet_cost_polarization(rho, coeffs, spatial, quant):
        m = 0.65
        precover = hstegolib.scipy.signal.wiener(spatial, (3, 3))
        coeffs_estim = hstegolib.compress(precover, quant)

        s = hstegolib.np.sign(coeffs_estim - coeffs)
        rho_m1 = rho.copy()
        rho_p1 = rho.copy()
        rho_p1[s > 0] = m * rho_p1[s > 0]
        rho_m1[s < 0] = m * rho_m1[s < 0]

        rho_p1[rho_p1 > hstegolib.INF] = hstegolib.INF
        rho_p1[hstegolib.np.isnan(rho_p1)] = hstegolib.INF
        rho_p1[coeffs > 1023] = hstegolib.INF

        rho_m1[rho_m1 > hstegolib.INF] = hstegolib.INF
        rho_m1[hstegolib.np.isnan(rho_m1)] = hstegolib.INF
        rho_m1[coeffs < -1023] = hstegolib.INF

        return rho_m1, rho_p1

    stego_obj.cost_polarization = _quiet_cost_polarization


def _resolve_seal_passwords_unchecked(args: argparse.Namespace) -> Tuple[str, str, str]:
    single_pass = args.single_pass
    single_prompt = args.single_pass_prompt
    generated_single = args.gen_single_pass
    age_pass = args.age_pass
    stego_pass = args.stego_pass
    split_prompt = args.split_pass_prompt
    generated_split = args.gen_split_pass

    single_mode_count = int(bool(single_pass)) + int(bool(single_prompt)) + int(bool(generated_single))
    split_manual_any = bool(age_pass) or bool(stego_pass)
    split_mode_count = int(bool(generated_split)) + int(bool(split_prompt)) + int(bool(split_manual_any))

    if single_mode_count > 1:
        raise RuntimeError("Choose only one single-pass option: --single-pass, --single-pass-prompt, or --gen-single-pass.")

    if split_mode_count > 1:
        raise RuntimeError("Choose only one split-pass option: --gen-split-pass, --split-pass-prompt, or --age-pass + --stego-pass.")

    if single_mode_count and split_mode_count:
        raise RuntimeError(
            "Choose either single-pass mode (--single-pass/--gen-single-pass) or split-pass mode (--gen-split-pass or --age-pass + --stego-pass)."
        )

    if generated_single:
        generated_pass = _generate_passphrase()
        return generated_pass, generated_pass, "single-generated"

    if single_pass:
        return single_pass, single_pass, "single"

    if single_prompt:
        prompted_pass = _prompt_secret("Single passphrase", confirm=True)
        return prompted_pass, prompted_pass, "single-prompt"

    if generated_split:
        return _generate_passphrase(), _generate_passphrase(), "split-generated"

    if split_prompt:
        prompted_age_pass = _prompt_secret("AGE passphrase", confirm=True)
        prompted_stego_pass = _prompt_secret("STEGO passphrase", confirm=True)
        return prompted_age_pass, prompted_stego_pass, "split-prompt"

    if split_manual_any:
        if not age_pass or not stego_pass:
            raise RuntimeError("Split mode requires both --age-pass and --stego-pass.")
        return age_pass, stego_pass, "split"

    raise RuntimeError(
        "Password options required: use --single-pass-prompt, --gen-single-pass, --gen-split-pass, --split-pass-prompt, or explicit pass flags."
    )


def _resolve_seal_passwords(args: argparse.Namespace) -> Tuple[str, str, str]:
    age_pass, stego_pass, mode = _resolve_seal_passwords_unchecked(args)
    _validate_secret(age_pass, creating=True)
    _validate_secret(stego_pass)
    if mode.startswith("split") and age_pass == stego_pass:
        raise RuntimeError("Split mode requires different AGE and STEGO passphrases.")
    return age_pass, stego_pass, mode


def _run_age_with_passphrase(cmd: list[str], passphrase: str, confirm: bool) -> None:
    _validate_secret(passphrase)
    if _which("age") is None:
        raise RuntimeError("age CLI not found. Install age first.")
    # HStego starts native threads. Fork a PTY only in a fresh, single-threaded
    # interpreter, to avoid fork-after-numpy deadlocks in repeated TUI use.
    helper = Path(__file__).resolve().with_name("age_pty.py")
    proc = subprocess.Popen([sys.executable, "-I", str(helper)], stdin=subprocess.PIPE,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, text=True,
                            start_new_session=True)
    try:
        proc.communicate(json.dumps({"cmd": cmd, "passphrase": passphrase, "confirm": confirm}), timeout=125)
        if proc.returncode != 0:
            raise RuntimeError("age failed: incorrect passphrase, damaged payload, or unsupported age format.")
    except subprocess.TimeoutExpired:
        raise RuntimeError("age timed out; operation cancelled.") from None
    finally:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()


def _run_age_pty(cmd: list[str], passphrase: str, confirm: bool) -> None:
    _validate_secret(passphrase)
    if _which("age") is None:
        raise RuntimeError("age CLI not found. Install age first.")
    if pty is None:
        raise RuntimeError("A POSIX terminal is required for age passphrase mode.")
    import signal
    import termios

    pid, fd = pty.fork()
    if pid == 0:
        try:
            attrs = termios.tcgetattr(0)
            attrs[3] &= ~(termios.ECHO | termios.ECHONL)
            termios.tcsetattr(0, termios.TCSANOW, attrs)
            os.execvp(cmd[0], cmd)
        except Exception:
            os._exit(127)
    transcript = b""
    prompts_sent = 0
    deadline = time.monotonic() + 120
    reaped = False
    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise RuntimeError("age timed out; operation cancelled.")
            ready, _, _ = select.select([fd], [], [], min(remaining, 0.2))
            if not ready:
                continue
            try:
                chunk = os.read(fd, 4096)
            except OSError:
                break
            if not chunk:
                break
            transcript = (transcript + chunk)[-16384:]
            expected = b"Enter passphrase" if prompts_sent == 0 else b"Confirm passphrase"
            if prompts_sent < (2 if confirm else 1) and expected in transcript:
                # Wait until age has actually disabled echo before sending secrets.
                if not termios.tcgetattr(fd)[3] & termios.ECHO:
                    os.write(fd, (passphrase + "\n").encode("utf-8"))
                    prompts_sent += 1
                    transcript = b""
        _, status = os.waitpid(pid, 0)
        reaped = True
        if os.waitstatus_to_exitcode(status) != 0:
            # Child diagnostics may contain secrets or terminal control sequences.
            raise RuntimeError("age failed: incorrect passphrase, damaged payload, or unsupported age format.")
    finally:
        os.close(fd)
        if not reaped:
            try:
                os.kill(pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            os.waitpid(pid, 0)


def _age_encrypt(input_path: Path, output_path: Path, passphrase: str) -> None:
    cmd = ["age", "-p", "-o", str(output_path.absolute()), str(input_path.absolute())]
    _run_age_with_passphrase(cmd, passphrase, confirm=True)


def _age_decrypt(input_path: Path, output_path: Path, passphrase: str) -> None:
    cmd = ["age", "-d", "-o", str(output_path.absolute()), str(input_path.absolute())]
    _run_age_with_passphrase(cmd, passphrase, confirm=False)


def _load_hstegolib():
    try:
        import hstegolib  # type: ignore
    except SystemExit:
        raise RuntimeError("HStego native extensions missing. Reinstall hstego with compiled extensions.")
    except Exception as e:
        raise RuntimeError(f"HStego not available: {e}")
    if (getattr(hstegolib, "HEADER_MAGIC", None) != b"HS2\x00"
            or getattr(hstegolib, "SCRYPT_N", 0) < 2**18):
        raise RuntimeError("HStego 0.6.1 or newer is required. Run bash scripts/bootstrap_mac.sh to upgrade. Older records use extract --legacy-hstego.")
    from importlib.metadata import PackageNotFoundError, version
    try:
        installed = tuple(int(part) for part in version("hstego").split("."))
    except (PackageNotFoundError, ValueError):
        raise RuntimeError("Cannot verify the HStego version. Reinstall the pinned environment.") from None
    if installed < (0, 6, 1):
        raise RuntimeError("HStego 0.6.1 or newer is required. Run bash scripts/bootstrap_mac.sh to upgrade.")
    return hstegolib


def _is_spatial_image(path: Path, hstegolib) -> bool:
    ext = path.suffix.lower().lstrip(".")
    spatial_exts = {"png", "pgm", "tif", "tiff"}
    if hasattr(hstegolib, "SPATIAL_EXT"):
        try:
            spatial_exts.update({e.lower() for e in hstegolib.SPATIAL_EXT})
        except Exception:
            pass
    return ext in spatial_exts


def _is_jpeg_image(path: Path) -> bool:
    ext = path.suffix.lower().lstrip(".")
    return ext in {"jpg", "jpeg", "jpe"}


def _with_heartbeat(label: str, fn, interval: float = 15.0, detail: Optional[str] = None):
    stop = threading.Event()
    start = time.monotonic()

    def _beat() -> None:
        while not stop.wait(interval):
            elapsed = int(time.monotonic() - start)
            suffix = f" {detail}" if detail else ""
            print(f"{label} still working... ({elapsed}s elapsed).{suffix}", flush=True)

    thread = threading.Thread(target=_beat, daemon=True)
    thread.start()
    try:
        return fn()
    finally:
        stop.set()
        thread.join(timeout=0.1)


@contextmanager
def _suppress_native_output():
    devnull_fd: Optional[int] = None
    saved_stdout_fd: Optional[int] = None
    saved_stderr_fd: Optional[int] = None
    devnull_stream = None
    try:
        devnull_fd = os.open(os.devnull, os.O_WRONLY)
        saved_stdout_fd = os.dup(1)
        saved_stderr_fd = os.dup(2)
        devnull_stream = open(os.devnull, "w")
    except OSError:
        for fd in (saved_stdout_fd, saved_stderr_fd, devnull_fd):
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    pass
        # Best effort: if fd redirection fails, continue without suppression.
        yield
        return

    try:
        os.dup2(devnull_fd, 1)
        os.dup2(devnull_fd, 2)
        with redirect_stdout(devnull_stream), redirect_stderr(devnull_stream):
            yield
    finally:
        try:
            os.dup2(saved_stdout_fd, 1)
            os.dup2(saved_stderr_fd, 2)
        finally:
            if devnull_stream is not None:
                try:
                    devnull_stream.close()
                except OSError:
                    pass
            for fd in (saved_stdout_fd, saved_stderr_fd, devnull_fd):
                if fd is not None:
                    try:
                        os.close(fd)
                    except OSError:
                        pass


def _hstego_embed(cover: Path, payload: Path, output: Path, password: str, algo: str) -> None:
    hstegolib = _load_hstegolib()

    algo = (algo or "auto").lower()
    if algo == "auto":
        algo = "j-uniward" if _is_jpeg_image(cover) else "s-uniward"
    if algo not in {"j-uniward", "s-uniward"}:
        raise RuntimeError("Unknown stego algorithm. Use auto, j-uniward, or s-uniward.")

    try:
        if algo == "j-uniward":
            if not _is_jpeg_image(cover):
                raise RuntimeError("J-UNIWARD requires a JPEG cover image.")
            stego = hstegolib.J_UNIWARD()
            _quiet_juniward_cost_debug(stego, hstegolib)
            label = "J-UNIWARD (JPEG)"
        else:
            if not (_is_spatial_image(cover, hstegolib) or _is_jpeg_image(cover)):
                raise RuntimeError("Cover image format not supported (use .jpg or .png).")
            stego = hstegolib.S_UNIWARD()
            label = "S-UNIWARD (spatial)"

        _print_embed_preflight(cover, payload, hstegolib, algo)

        print(
            f"HStego embedding {label} started.",
            flush=True,
        )
        print("First run on a new machine can take 5-10 minutes while native code compiles.", flush=True)
        print("Progress updates print every 15 seconds. Keep this terminal open.", flush=True)
        start = time.monotonic()
        _with_heartbeat(
            "HStego embedding",
            lambda: stego.embed(str(cover), str(payload), password, str(output)),
            detail="This is normal for the flagship embedding path.",
        )
        elapsed = time.monotonic() - start
        print(f"HStego embedding complete in {elapsed:.1f}s.", flush=True)
    except SystemExit:
        raise RuntimeError("payload too large for cover; use larger image or smaller payload.")
    except RuntimeError:
        raise
    except Exception as e:
        raise RuntimeError(f"HStego embed failed: {e}")

    if not output.exists():
        raise RuntimeError("payload too large for cover; use larger image or smaller payload.")


def _hstego_extract(stego_image: Path, output: Path, password: str, legacy: bool = False) -> None:
    invalid_secret_msg = "HStego extract failed: wrong stego password, damaged image, or different format. For an old record, explicitly choose --legacy-hstego."

    def _extract(stego_obj) -> None:
        stego_obj.extract(str(stego_image), password, str(output))

    try:
        hstegolib = _load_hstegolib()
        hstegolib.validate_image_resource(str(stego_image))
        if legacy:
            import importlib.util
            spec = importlib.util.spec_from_file_location("confess_legacy_loader", Path(__file__).with_name("hstego_legacy.py"))
            loader = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(loader)
            hstegolib = loader.load_legacy(hstegolib)
        with _suppress_native_output():
            stego = None
            try:
                with stego_image.open("rb") as source:
                    signature = source.read(8)
                if signature == b"\x89PNG\r\n\x1a\n":
                    stego = hstegolib.S_UNIWARD()
                    _with_heartbeat("HStego extract", lambda: _extract(stego))
                elif signature.startswith(b"\xff\xd8\xff"):
                    stego = hstegolib.J_UNIWARD()
                    _with_heartbeat("HStego extract", lambda: _extract(stego))
                else:
                    raise RuntimeError("Stego image format not supported (use .jpg or .png).")
            finally:
                stego = None
    except SystemExit:
        raise RuntimeError(invalid_secret_msg)
    except Exception as e:
        raise RuntimeError(f"HStego extract failed: {e}")

    if not output.exists() or output.stat().st_size == 0 or not _looks_like_age_ciphertext(output):
        raise RuntimeError(invalid_secret_msg)


def _store_generated_secrets(args, age_pass: str, stego_pass: str, mode: str) -> None:
    if "generated" not in mode:
        if args.secrets_file:
            raise RuntimeError("--secrets-file is only for generated passphrases.")
        return
    secret_text = json.dumps({"age_passphrase": age_pass, "stego_passphrase": stego_pass}, indent=2) + "\n"
    if args.secrets_file:
        path = Path(args.secrets_file).expanduser()
        with _staged_output(path, False) as staged:
            fd = os.open(staged, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w") as f:
                f.write(secret_text)
        print(f"Generated secrets saved privately to: {path}")
    else:
        if not sys.stdin.isatty() or not sys.stdout.isatty():
            raise RuntimeError("Generated secrets require an interactive terminal or --secrets-file PATH. They are never printed to redirected output.")
        with open("/dev/tty", "w") as terminal:
            terminal.write("Store these secrets in your password manager:\n" + secret_text)
            terminal.flush()


def _seal(args: argparse.Namespace) -> int:
    cover = Path(args.image).expanduser()
    text_path = Path(args.text).expanduser()
    extension = ".jpg" if _is_jpeg_image(cover) and args.algo != "s-uniward" else ".png"
    output_image = Path(args.out or ("locked_artifact" + extension)).expanduser()
    payload_age = output_image.parent / "payload.age"
    try:
        if not cover.is_file() or not text_path.is_file():
            raise RuntimeError("Cover image and testimony must both be regular files.")
        if extension == ".jpg" and not _is_jpeg_image(output_image):
            raise RuntimeError("JPEG embedding requires a .jpg or .jpeg output.")
        if extension == ".png" and output_image.suffix.lower() != ".png":
            raise RuntimeError("Spatial embedding requires a lossless .png output.")
        for target in (payload_age, output_image):
            _check_output(target, args.force, (cover, text_path))
        if _same_path(payload_age, output_image):
            raise RuntimeError("Artifact and encrypted payload paths must differ.")
        if args.secrets_file:
            _check_output(Path(args.secrets_file).expanduser(), False, (cover, text_path, payload_age, output_image))
        _load_hstegolib()
        age_pass, stego_pass, pass_mode = _resolve_seal_passwords(args)
        _store_generated_secrets(args, age_pass, stego_pass, pass_mode)
        print(f"Password mode: {pass_mode}.")
        if pass_mode.startswith("single"):
            print("WARNING: publishing this STEG password would also disclose the AGE decryption password.")
        with _staged_output(output_image, args.force, (cover, text_path)) as staged_image:
            # The private directory contains every intermediate, including plaintext.
            payload_tar = staged_image.parent / "payload.tar.gz"
            staged_age = staged_image.parent / "payload.age"
            print("Packing testimony in a private temporary directory...")
            _write_payload_tar(text_path, payload_tar)
            try:
                print("Encrypting with age...")
                _age_encrypt(payload_tar, staged_age, age_pass)
            finally:
                payload_tar.unlink(missing_ok=True)
            csha = _sha512_file(staged_age)
            _hstego_embed(cover, staged_age, staged_image, stego_pass, args.algo)
            print("Checking artifact extraction before publishing local outputs...")
            checked = staged_image.parent / "roundtrip.age"
            _hstego_extract(staged_image, checked, stego_pass)
            if _sha512_file(checked) != csha:
                raise RuntimeError("Artifact round-trip checksum failed. Outputs were not published.")
            _publish_output(staged_age, payload_age, args.force)
        print(f"Locked artifact: {output_image}")
        print(f"CSHA (sha512 of payload.age): {csha}")
        print(f"Payload file: {payload_age}")
        return 0
    except (RuntimeError, OSError, tarfile.TarError) as e:
        _err(str(e))
        return 1


def _extract_ardrive_data_tx(output: str) -> Optional[str]:
    # Only a typed file receipt may supply the data transaction. Never guess a
    # 43-character ID (it could be the wallet, bundle, drive, or metadata ID).
    decoder = json.JSONDecoder()
    for index, char in enumerate(output):
        if char != "{":
            continue
        try:
            data, _ = decoder.raw_decode(output[index:])
        except ValueError:
            continue
        if not isinstance(data, dict) or not isinstance(data.get("created"), list):
            continue
        ids = [item.get("dataTxId") for item in data["created"]
               if isinstance(item, dict) and item.get("type") == "file"]
        ids = [value for value in ids if isinstance(value, str) and _validate_arweave_txid(value)]
        if len(ids) == 1:
            return ids[0]
    return None


def _ardrive_upload(file_path: Path, wallet_path: Path, folder_id: str, dest_name: Optional[str]) -> str:
    cmd = [
        "ardrive",
        "upload-file",
        "--wallet-file",
        str(wallet_path),
        "--parent-folder-id",
        folder_id,
        "--local-path",
        str(file_path),
    ]
    if dest_name:
        cmd.extend(["--dest-file-name", dest_name])

    res = _run(cmd)
    if res.returncode != 0:
        raise RuntimeError("ArDrive upload failed. Check wallet balance, destination folder, and network. Raw wallet-tool output was withheld.")

    txid = _extract_ardrive_data_tx(res.stdout + "\n" + res.stderr)
    if not txid:
        raise RuntimeError("ArDrive upload succeeded but no dataTxId was found in output.")
    return txid


def _push(args: argparse.Namespace) -> int:
    if not args.ack_permanent_upload:
        _err("Arweave uploads spend wallet funds and are permanent. Review the file and use --ack-permanent-upload.")
        return 1
    file_path = Path(args.file).expanduser()
    if not file_path.exists():
        _err(f"File not found: {file_path}")
        return 1

    if file_path.suffix.lower() not in {".jpg", ".jpeg", ".png"} or not file_path.is_file():
        _err("Upload requires a sealed JPEG or PNG artifact. Plaintext, archives, and wallet files must stay local.")
        return 1
    with file_path.open("rb") as image:
        header = image.read(8)
    if not (header.startswith(b"\xff\xd8\xff") or header == b"\x89PNG\r\n\x1a\n"):
        _err("Artifact does not have a JPEG or PNG signature.")
        return 1
    cfg = _load_config()
    wallet_path_str = cfg.get("wallet_path")
    if not wallet_path_str:
        _err("Wallet path not configured. Run `confess init`.")
        return 1
    wallet_path = Path(wallet_path_str).expanduser()
    if _same_path(file_path, wallet_path):
        _err("Refusing to upload a wallet file.")
        return 1
    if not wallet_path.exists():
        _err(f"Wallet file not found: {wallet_path}")
        return 1

    folder_id = args.folder_id or os.environ.get("ARDRIVE_PARENT_FOLDER_ID") or os.environ.get("ARDRIVE_FOLDER_ID")
    if not folder_id:
        _err(
            "ArDrive parent folder id is required. Use the `entityId` from the `created` item where "
            "`type` is `folder` in `ardrive create-drive` output, then pass it via --folder-id."
        )
        _err("See README.md > Operator Workflow for the create-drive and upload-file examples.")
        return 1

    try:
        txid = _ardrive_upload(file_path, wallet_path, folder_id, args.dest_name)
    except RuntimeError as e:
        _err(str(e))
        return 1

    url = f"{ARWEAVE_URL_PREFIX}{txid}"
    print(f"Arweave TXID: {txid}")
    print(f"URL: {url}")
    print("\nReceipt:")
    print("--------")
    print(f"TXID: {txid}")
    print(f"URL: {url}")
    print(f"FILE: {file_path.name}")
    return 0


def _mint(args: argparse.Namespace) -> int:
    title = args.title.strip()
    if not title:
        _err("Title is required.")
        return 1
    if "|" in title or "\n" in title:
        _err("Title cannot include '|' or newlines.")
        return 1
    if _has_control_chars(title):
        _err("Title cannot include control characters.")
        return 1

    if "|" in args.txid or "\n" in args.txid:
        _err("TXID cannot include '|' or newlines.")
        return 1
    txid = args.txid.strip()
    if not _validate_arweave_txid(txid):
        _err("--txid must be a 43-character Arweave transaction id.")
        return 1

    csha = args.csha.strip().lower()
    if not _validate_csha(csha):
        _err("--csha must be a 128-character hex sha512 value.")
        return 1

    if (args.steg is not None or args.steg_prompt) and not args.ack_public_steg:
        _err("Publishing STEG is permanent. If it is also the AGE password, the testimony becomes public. Use --ack-public-steg only after checking they are different.")
        return 1
    if args.steg is not None and args.steg_prompt:
        _err("Choose either --steg or --steg-prompt, not both.")
        return 1

    try:
        steg = _prompt_secret("STEG passphrase to publish", confirm=True) if args.steg_prompt else args.steg
    except RuntimeError as e:
        _err(str(e))
        return 1

    if steg is not None and not steg:
        _err("STEG cannot be empty.")
        return 1
    if steg and ("|" in steg or "\n" in steg):
        _err("STEG cannot include '|' or newlines.")
        return 1
    if steg and _has_control_chars(steg):
        _err("STEG cannot include control characters.")
        return 1

    if steg and steg != steg.strip():
        _err("STEG cannot start or end with whitespace; verifiers trim field separators.")
        return 1
    reserved = {"TITLE", "ARTXID", "AR", "CSHA", "STEG", "CID", "IPFS", "PROOF", "SHA", "HASH"}
    encoded_title = f"TITLE:{title}" if title.split(":", 1)[0].strip().upper() in reserved and ":" in title else title
    metadata_parts = [encoded_title, f"ARTXID:{txid}", f"CSHA:{csha}"]
    if steg:
        metadata_parts.append(f"STEG:{steg}")
    metadata = " | ".join(metadata_parts)
    if len(metadata.encode("utf-8")) > 16384:
        _err("Metadata exceeds the 16 KiB protocol limit.")
        return 1
    data_hex = "0x" + metadata.encode("utf-8").hex()

    print("Metadata string:")
    print(metadata)
    print("\nHex (paste into tx input data):")
    print(data_hex)
    print("\nManual broadcast:")
    print("  Network: Base")
    print("  Wallet: Rabby recommended")
    print("  Send: 0 ETH")
    print("  To: null address (0x0000000000000000000000000000000000000000) or self")
    print("  Data field: paste 0x... above")
    if steg:
        print("\nNote:")
        print("  STEG is public on-chain when included. Anyone can extract payload.age from the locked artifact.")
        if args.steg:
            print("  Warning: --steg can be visible in shell history and process lists. Prefer --steg-prompt.")
    return 0


def _extract(args: argparse.Namespace) -> int:
    stego_image = Path(args.image).expanduser()
    output_path = Path(args.out or "payload.age").expanduser()
    try:
        if not stego_image.is_file():
            raise RuntimeError(f"Locked artifact not found: {stego_image}")
        _check_output(output_path, args.force, (stego_image,))
        if args.single_pass_prompt:
            password = _prompt_secret("Single passphrase")
        elif args.stego_pass_prompt:
            password = _prompt_secret("STEGO passphrase")
        else:
            password = args.single_pass or args.stego_pass
            _warn_literal_secret_arg("passphrase arguments", "--stego-pass-prompt")
        _validate_secret(password)
        with _staged_output(output_path, args.force, (stego_image,)) as staged:
            _hstego_extract(stego_image, staged, password, legacy=args.legacy_hstego)
        print(f"Extracted payload: {output_path}")
        return 0
    except (RuntimeError, OSError) as e:
        _err(str(e))
        return 1


def _verify(args: argparse.Namespace) -> int:
    payload_path = Path(args.file or "payload.age").expanduser()
    if not payload_path.exists():
        _err(f"Payload file not found: {payload_path}")
        return 1

    passphrase_supplied = bool(args.single_pass or args.age_pass or args.single_pass_prompt or args.age_pass_prompt)
    if not args.decrypt and passphrase_supplied:
        _err("Passphrase options only apply with --decrypt. Omit the passphrase for checksum-only verification.")
        return 1
    if not args.decrypt and args.out:
        _err("--out only applies with --decrypt.")
        return 1

    expected = args.csha.strip().lower()
    if not _validate_csha(expected):
        _err("--csha must be a 128-character hex sha512 value.")
        return 1
    actual = _sha512_file(payload_path)

    print(f"Expected CSHA: {expected}")
    print(f"Actual CSHA:   {actual}")

    ok = actual.lower() == expected
    print(f"CSHA match: {'YES' if ok else 'NO'}")

    if args.decrypt:
        if not ok:
            _err("Refusing to decrypt because CSHA does not match.")
            return 1
        output_path = Path(args.out or "payload.tar.gz").expanduser()
        try:
            if args.single_pass_prompt:
                decrypt_pass = _prompt_secret("Single passphrase")
            elif args.age_pass_prompt:
                decrypt_pass = _prompt_secret("AGE passphrase")
            else:
                decrypt_pass = args.single_pass or args.age_pass
                if args.single_pass:
                    _warn_literal_secret_arg("--single-pass", "--single-pass-prompt")
                elif args.age_pass:
                    _warn_literal_secret_arg("--age-pass", "--age-pass-prompt")
            if not decrypt_pass:
                _err("--decrypt requires --single-pass-prompt, --age-pass-prompt, --single-pass, or --age-pass.")
                return 1
            _validate_secret(decrypt_pass)
            with _staged_output(output_path, args.force, (payload_path,)) as staged:
                checked_payload = Path(tempfile.mkdtemp(prefix="input-", dir=staged.parent)) / "payload.age"
                shutil.copyfile(payload_path, checked_payload)
                if _sha512_file(checked_payload) != expected:
                    raise RuntimeError("Payload changed after checksum verification. Refusing decryption.")
                _age_decrypt(checked_payload, staged, decrypt_pass)
        except (RuntimeError, OSError) as e:
            _err(str(e))
            return 1
        print(f"Decrypted to: {output_path}")

    return 0 if ok else 1


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="confess",
        description="Local-first terminal protocol for sealed testimony artifacts.",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("doctor", help="Check dependencies")
    sub.add_parser("tui", help="Open the guided terminal menu")

    sub.add_parser("init", help="Initialize local config")

    seal = sub.add_parser("seal", help="Seal a testimony into a locked artifact")
    seal.add_argument("--image", required=True, help="Cover image (jpg/png)")
    seal.add_argument("--text", required=True, help="Testimony file (.md/.txt/etc)")
    seal.add_argument("--out", help="Output artifact (.jpg for JPEG, .png for spatial); payload.age is saved alongside it")
    seal.add_argument("--secrets-file", help="Save generated passphrases to a new private file (never overwritten)")
    seal.add_argument("--force", action="store_true", help="Replace completed outputs only after successful sealing")
    seal.add_argument(
        "--algo",
        default="auto",
        choices=["auto", "j-uniward", "s-uniward"],
        help="HStego algorithm (auto: JPEG->J-UNIWARD, PNG->S-UNIWARD)",
    )
    seal.add_argument(
        "--single-pass",
        dest="single_pass",
        help="Single-mode: one passphrase used for both age encryption and stego embedding",
    )
    seal.add_argument(
        "--single-pass-prompt",
        action="store_true",
        help="Single-mode: prompt securely for one passphrase instead of passing it as an argument",
    )
    seal.add_argument(
        "--gen-single-pass",
        action="store_true",
        help="Single-mode: generate one strong passphrase for both age + stego",
    )
    seal.add_argument(
        "--gen-split-pass",
        action="store_true",
        help="Split-mode: generate separate strong passphrases for age encryption and stego embedding",
    )
    seal.add_argument("--age-pass", help="Split mode: passphrase for age encryption (requires --stego-pass)")
    seal.add_argument("--stego-pass", help="Split mode: password for stego embedding (requires --age-pass)")
    seal.add_argument(
        "--split-pass-prompt",
        action="store_true",
        help="Split-mode: prompt securely for age and stego passphrases instead of passing them as arguments",
    )

    push = sub.add_parser("push", help="Upload locked artifact to Arweave via ArDrive")
    push.add_argument("--file", required=True, help="Locked artifact jpg")
    push.add_argument(
        "--folder-id",
        help="ArDrive parent folder id (the folder `entityId` from `ardrive create-drive` output)",
    )
    push.add_argument("--ack-permanent-upload", action="store_true", help="Acknowledge permanent upload and wallet spending")
    push.add_argument("--dest-name", help="Optional destination filename on ArDrive")

    mint = sub.add_parser("mint", help="Generate Base tx input metadata")
    mint.add_argument("--txid", required=True, help="Arweave TXID")
    mint.add_argument("--csha", required=True, help="CSHA (sha512 of payload.age)")
    mint.add_argument("--title", required=True, help="Title")
    mint.add_argument("--steg", help="Optional: publish stego pass as STEG:<value> in metadata")
    mint.add_argument("--steg-prompt", action="store_true", help="Prompt securely for a STEG value to publish")

    mint.add_argument("--ack-public-steg", action="store_true", help="Acknowledge permanent disclosure; STEG must differ from the AGE password")

    extract = sub.add_parser("extract", help="Extract payload.age from a locked artifact")
    extract.add_argument("--image", required=True, help="Locked artifact jpg")
    extract.add_argument("--out", help="Output payload path (default payload.age)")
    extract.add_argument("--force", action="store_true", help="Overwrite output payload if present")
    extract.add_argument("--legacy-hstego", action="store_true", help="Explicitly read an older HStego v0.5-format record; new seals always use authenticated v2 format")
    extract_group = extract.add_mutually_exclusive_group(required=True)
    extract_group.add_argument("--single-pass", dest="single_pass", help="Single-mode passphrase (same secret used for age + stego)")
    extract_group.add_argument("--stego-pass", help="Split-mode stego password")
    extract_group.add_argument("--single-pass-prompt", action="store_true", help="Prompt securely for single-mode passphrase")
    extract_group.add_argument("--stego-pass-prompt", action="store_true", help="Prompt securely for split-mode stego passphrase")

    verify = sub.add_parser("verify", help="Verify payload hash and optionally decrypt")
    verify.add_argument("--file", help="payload.age path (default payload.age)")
    verify.add_argument("--csha", required=True, help="Expected CSHA (sha512)")
    verify.add_argument("--decrypt", action="store_true", help="Decrypt payload.age -> payload.tar.gz")
    verify.add_argument("--out", help="Decrypted output path (default payload.tar.gz)")
    verify.add_argument("--force", action="store_true", help="Overwrite decrypted output if present")
    verify_pass_group = verify.add_mutually_exclusive_group(required=False)
    verify_pass_group.add_argument("--single-pass", dest="single_pass", help="Single-mode passphrase for decryption")
    verify_pass_group.add_argument("--age-pass", help="Split-mode age passphrase for decryption")
    verify_pass_group.add_argument("--single-pass-prompt", action="store_true", help="Prompt securely for single-mode passphrase")
    verify_pass_group.add_argument("--age-pass-prompt", action="store_true", help="Prompt securely for split-mode age passphrase")

    return parser


def _subparser_action(parser: argparse.ArgumentParser):
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            return action
    return None


def _print_help_all(parser: argparse.ArgumentParser) -> None:
    print(parser.format_help().rstrip())
    sub_action = _subparser_action(parser)
    if sub_action is None:
        return

    print("\nDetailed subcommand flags:\n")
    for name in sorted(sub_action.choices.keys()):
        subparser = sub_action.choices[name]
        print(subparser.format_help().rstrip())
        print("")


def main() -> int:
    try:
        return _main()
    except (KeyboardInterrupt, EOFError):
        _err("Cancelled.")
        return 130
    except (RuntimeError, OSError) as error:
        _err(str(error))
        return 1


def _main() -> int:
    parser = _build_parser()
    argv = sys.argv[1:]

    if argv and any(token in {"-h", "--help"} for token in argv) and all(token in {"-h", "--help"} for token in argv):
        _print_help_all(parser)
        return 0

    if not argv and sys.stdin.isatty() and sys.stdout.isatty():
        args = parser.parse_args(["tui"])
    else:
        args = parser.parse_args()
    return _dispatch(args)


def _dispatch(args: argparse.Namespace) -> int:
    if args.cmd == "tui":
        import tui
        return tui.run(sys.modules[__name__])
    if args.cmd == "doctor":
        return _doctor()
    if args.cmd == "init":
        return _init()
    if args.cmd == "seal":
        return _seal(args)
    if args.cmd == "push":
        return _push(args)
    if args.cmd == "mint":
        return _mint(args)
    if args.cmd == "extract":
        return _extract(args)
    if args.cmd == "verify":
        return _verify(args)

    _err("Unknown command")
    return 1


if __name__ == "__main__":
    sys.exit(main())
