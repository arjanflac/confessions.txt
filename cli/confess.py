#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
from contextlib import contextmanager
import getpass
import hashlib
import json
import os
import platform
import re
import secrets
import shutil
import subprocess
import sys
import tarfile
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


def _err(msg: str) -> None:
    print(msg, file=sys.stderr)


def _run(cmd: list[str], env: Optional[dict] = None) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, env=env)


def _which(name: str) -> Optional[str]:
    return shutil.which(name)


def _load_config() -> dict:
    if CONFIG_PATH.exists():
        try:
            return json.loads(CONFIG_PATH.read_text())
        except json.JSONDecodeError:
            return {}
    return {}


def _save_wallet_path(wallet_path: Path) -> None:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    data = {"wallet_path": str(wallet_path)}
    CONFIG_PATH.write_text(json.dumps(data, indent=2))
    try:
        os.chmod(CONFIG_PATH, 0o600)
    except OSError:
        pass


def _sha512_file(path: Path) -> str:
    h = hashlib.sha512()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _validate_arweave_txid(value: str) -> bool:
    return bool(ARWEAVE_TXID_RE.fullmatch(value.strip()))


def _validate_csha(value: str) -> bool:
    return bool(CSHA_RE.fullmatch(value.strip()))


def _prompt_secret(label: str, confirm: bool = False) -> str:
    secret = getpass.getpass(f"{label}: ")
    if not secret:
        raise RuntimeError(f"{label} cannot be empty.")
    if confirm:
        repeated = getpass.getpass(f"Confirm {label}: ")
        if repeated != secret:
            raise RuntimeError(f"{label} values did not match.")
    return secret


def _remove_existing(path: Path, force: bool, label: str) -> None:
    if not path.exists():
        return
    if not force:
        raise RuntimeError(f"{label} already exists: {path}. Use --force to overwrite.")
    if path.is_dir():
        raise RuntimeError(f"{label} is a directory and cannot be overwritten: {path}")
    path.unlink()


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
    with tarfile.open(payload_tar, "w:gz") as tar:
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
    print("    xcode-select --install")
    print("    brew install python@3.12 age jpeg")
    print("    $(brew --prefix python@3.12)/bin/python3.12 -m venv .venv && source .venv/bin/activate")
    print("    python -m pip install --upgrade pip")
    print("    python -m pip install imageio numpy scipy pycryptodome numba Pillow")
    print("    ./scripts/install_hstego_mac.sh")
    print("    npm install -g ardrive-cli")
    print("  Ubuntu:")
    print("    sudo apt-get update && sudo apt-get install -y age python3-pip build-essential libjpeg-dev python3-tk")
    print("    python3 -m pip install imageio numpy scipy pycryptodome numba Pillow")
    print("    python3 -m pip install git+https://github.com/daniellerch/hstego.git@v0.5")
    print("    npm install -g ardrive-cli")
    print("  Optional Shamir: brew install ssss (or sudo apt-get install -y ssss)")


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
        import hstegolib  # type: ignore
    except SystemExit:
        return False, "native extensions missing"
    except Exception as e:
        return False, str(e)
    version = getattr(hstegolib, "__version__", None)
    return True, version or "import ok"

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
    elif sys.version_info >= (3, 13):
        warnings.append("Python 3.11/3.12 is recommended; 3.13+ can break HStego dependencies.")

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
        warnings.append("ArDrive CLI missing.")

    if platform.system() == "Darwin":
        clt_ok, clt_info = _xcode_clt_status()
        print(
            f"Xcode CLT: {'OK' if clt_ok else 'MISSING'}"
            + (f" ({clt_info})" if clt_info else "")
        )
        if not clt_ok:
            warnings.append("Install Xcode Command Line Tools: xcode-select --install")
        if arch == "arm64":
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
        return isinstance(data, dict)
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
        _err("Wallet file is not valid JSON.")
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


def _resolve_seal_passwords(args: argparse.Namespace) -> Tuple[str, str, str]:
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


def _run_age_with_passphrase(cmd: list[str], passphrase: str, confirm: bool) -> None:
    if _which("age") is None:
        raise RuntimeError("age CLI not found. Install age first.")

    if pty is None:
        raise RuntimeError("pty not available; cannot run age passphrase mode non-interactively.")

    env = os.environ.copy()
    try:
        pid, fd = pty.fork()
    except OSError as e:
        raise RuntimeError(f"Failed to create PTY for age: {e}")

    if pid == 0:
        try:
            os.execvpe(cmd[0], cmd, env)
        except FileNotFoundError:
            os._exit(127)
    else:
        to_send = passphrase + "\n"
        if confirm:
            to_send += passphrase + "\n"
        try:
            os.write(fd, to_send.encode())
        except OSError:
            pass

        output_chunks: list[bytes] = []
        try:
            while True:
                try:
                    chunk = os.read(fd, 1024)
                    if not chunk:
                        break
                    output_chunks.append(chunk)
                except OSError:
                    break
        finally:
            try:
                os.close(fd)
            except OSError:
                pass

        _, status = os.waitpid(pid, 0)
        exit_code = os.waitstatus_to_exitcode(status)
        output = b"".join(output_chunks).decode("utf-8", errors="ignore").strip()
        if exit_code != 0:
            sanitized = _sanitize_age_output(output, passphrase)
            raise RuntimeError("age failed." + (f" {sanitized}" if sanitized else ""))


def _age_encrypt(input_path: Path, output_path: Path, passphrase: str) -> None:
    cmd = ["age", "-p", "-o", str(output_path), str(input_path)]
    _run_age_with_passphrase(cmd, passphrase, confirm=True)


def _age_decrypt(input_path: Path, output_path: Path, passphrase: str) -> None:
    cmd = ["age", "-d", "-o", str(output_path), str(input_path)]
    _run_age_with_passphrase(cmd, passphrase, confirm=False)


def _load_hstegolib():
    try:
        import hstegolib  # type: ignore
    except SystemExit:
        raise RuntimeError("HStego native extensions missing. Reinstall hstego with compiled extensions.")
    except Exception as e:
        raise RuntimeError(f"HStego not available: {e}")
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


def _with_heartbeat(label: str, fn, interval: float = 20.0):
    stop = threading.Event()
    start = time.monotonic()

    def _beat() -> None:
        while not stop.wait(interval):
            elapsed = int(time.monotonic() - start)
            print(f"{label} still working... ({elapsed}s elapsed)", flush=True)

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
    try:
        devnull_fd = os.open(os.devnull, os.O_WRONLY)
        saved_stdout_fd = os.dup(1)
        saved_stderr_fd = os.dup(2)
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
        yield
    finally:
        try:
            os.dup2(saved_stdout_fd, 1)
            os.dup2(saved_stderr_fd, 2)
        finally:
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
            label = "J-UNIWARD (JPEG)"
        else:
            if not (_is_spatial_image(cover, hstegolib) or _is_jpeg_image(cover)):
                raise RuntimeError("Cover image format not supported (use .jpg or .png).")
            stego = hstegolib.S_UNIWARD()
            label = "S-UNIWARD (spatial)"

        print(
            f"HStego embedding {label} started. First run can take several minutes (Numba JIT).",
            flush=True,
        )
        start = time.monotonic()
        _with_heartbeat("HStego", lambda: stego.embed(str(cover), str(payload), password, str(output)))
        elapsed = time.monotonic() - start
        print(f"HStego embedding complete in {elapsed:.1f}s.", flush=True)
    except SystemExit:
        raise RuntimeError("payload too large for cover; use larger image or smaller payload.")
    except Exception as e:
        raise RuntimeError(f"HStego embed failed: {e}")

    if not output.exists():
        raise RuntimeError("payload too large for cover; use larger image or smaller payload.")


def _hstego_extract(stego_image: Path, output: Path, password: str) -> None:
    hstegolib = _load_hstegolib()
    invalid_secret_msg = "HStego extract failed: wrong stego password (or no embedded payload)."

    def _extract(stego_obj) -> None:
        stego_obj.extract(str(stego_image), password, str(output))

    try:
        with _suppress_native_output():
            stego = None
            try:
                if _is_spatial_image(stego_image, hstegolib):
                    stego = hstegolib.S_UNIWARD()
                    _with_heartbeat("HStego extract", lambda: _extract(stego))
                elif _is_jpeg_image(stego_image):
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


def _seal(args: argparse.Namespace) -> int:
    try:
        age_pass, stego_pass, pass_mode = _resolve_seal_passwords(args)
    except RuntimeError as e:
        _err(str(e))
        return 1

    cover = Path(args.image).expanduser()
    text_path = Path(args.text).expanduser()
    if not cover.exists():
        _err(f"Cover image not found: {cover}")
        return 1
    if not text_path.exists():
        _err(f"Testimony file not found: {text_path}")
        return 1
    if not text_path.is_file():
        _err(f"Testimony path is not a regular file: {text_path}")
        return 1

    # Fail fast before encryption so we do not leave a fresh payload.age
    # when HStego is unavailable (e.g., outside the project virtualenv).
    try:
        _load_hstegolib()
    except RuntimeError as e:
        _err(str(e))
        return 1

    payload_tar = Path("payload.tar.gz")
    payload_age = Path("payload.age")
    output_image = Path(args.out or "locked_artifact.jpg")

    try:
        _remove_existing(payload_tar, args.force, "Temporary archive")
        _remove_existing(payload_age, args.force, "Payload file")
        _remove_existing(output_image, args.force, "Locked artifact")
    except RuntimeError as e:
        _err(str(e))
        return 1

    _write_payload_tar(text_path, payload_tar)

    if pass_mode == "single-generated":
        print("Password mode: single (--gen-single-pass).")
        print("Generated passphrase:")
        print(age_pass)
        print("Store this securely. Optional Shamir splitting: ssss-split -t 2 -n 3")
    elif pass_mode == "split-generated":
        print("Password mode: split (--gen-split-pass).")
        print("Generated AGE passphrase:")
        print(age_pass)
        print("Generated STEGO passphrase:")
        print(stego_pass)
        print("Store both securely. Share only stego-pass if delegating extraction-only verification.")
    elif pass_mode == "single":
        print("Password mode: single (--single-pass).")
        print("Warning: passphrase flags can be visible in shell history and process lists. Prefer --single-pass-prompt for manual use.")
    elif pass_mode == "single-prompt":
        print("Password mode: single (--single-pass-prompt).")
    elif pass_mode == "split-prompt":
        print("Password mode: split (--split-pass-prompt).")
        print("Feature: stego-pass can be shared for extraction + CSHA verification without age decryption.")
    else:
        print("Password mode: split (--age-pass + --stego-pass).")
        print("Warning: passphrase flags can be visible in shell history and process lists. Prefer --split-pass-prompt for manual use.")
        print("Feature: stego-pass can be shared for extraction + CSHA verification without age decryption.")

    try:
        _age_encrypt(payload_tar, payload_age, age_pass)
    except RuntimeError as e:
        _err(str(e))
        return 1
    finally:
        if payload_tar.exists():
            try:
                payload_tar.unlink()
            except OSError:
                pass

    csha = _sha512_file(payload_age)

    try:
        _hstego_embed(cover, payload_age, output_image, stego_pass, args.algo)
    except RuntimeError as e:
        _err(str(e))
        return 1

    print(f"Locked artifact: {output_image}")
    print(f"CSHA (sha512 of payload.age): {csha}")
    print(f"Payload file: {payload_age}")
    return 0


def _extract_ardrive_data_tx(output: str) -> Optional[str]:
    match = re.search(r'"dataTxId"\s*:\s*"([^"]+)"', output)
    if match:
        return match.group(1)

    start = output.find("{")
    end = output.rfind("}")
    if start != -1 and end != -1 and end > start:
        try:
            data = json.loads(output[start : end + 1])
            for item in data.get("created", []):
                if item.get("type") == "file" and item.get("dataTxId"):
                    return item.get("dataTxId")
        except Exception:
            pass

    match = re.search(r"[a-zA-Z0-9_-]{43}", output)
    return match.group(0) if match else None


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
        detail = res.stderr.strip() or res.stdout.strip()
        raise RuntimeError("ArDrive upload failed." + (f" Details: {detail}" if detail else ""))

    txid = _extract_ardrive_data_tx(res.stdout + "\n" + res.stderr)
    if not txid:
        raise RuntimeError("ArDrive upload succeeded but no dataTxId was found in output.")
    return txid


def _push(args: argparse.Namespace) -> int:
    file_path = Path(args.file).expanduser()
    if not file_path.exists():
        _err(f"File not found: {file_path}")
        return 1

    cfg = _load_config()
    wallet_path_str = cfg.get("wallet_path")
    if not wallet_path_str:
        _err("Wallet path not configured. Run `confess init`.")
        return 1
    wallet_path = Path(wallet_path_str).expanduser()
    if not wallet_path.exists():
        _err(f"Wallet file not found: {wallet_path}")
        return 1

    folder_id = args.folder_id or os.environ.get("ARDRIVE_PARENT_FOLDER_ID") or os.environ.get("ARDRIVE_FOLDER_ID")
    if not folder_id:
        _err(
            "ArDrive parent folder id is required. Use the `entityId` from the `created` item where "
            "`type` is `folder` in `ardrive create-drive` output, then pass it via --folder-id."
        )
        _err("See ardrive-cli-README.md for the create-drive and upload-file examples.")
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
    title = args.title
    if not title:
        _err("Title is required.")
        return 1
    if "|" in title or "\n" in title:
        _err("Title cannot include '|' or newlines.")
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

    if args.steg and ("|" in args.steg or "\n" in args.steg):
        _err("STEG cannot include '|' or newlines.")
        return 1

    metadata_parts = [title, f"ARTXID:{txid}", f"CSHA:{csha}"]
    if args.steg:
        metadata_parts.append(f"STEG:{args.steg}")
    metadata = " | ".join(metadata_parts)
    data_hex = "0x" + metadata.encode("utf-8").hex()

    print("Metadata string:")
    print(metadata)
    print("\nHex (paste into tx input data):")
    print(data_hex)
    print("\nManual broadcast (Phantom/MetaMask):")
    print("  Network: Base")
    print("  Send: 0 ETH")
    print("  To: null address (0x0000000000000000000000000000000000000000) or self")
    print("  Data field: paste 0x... above")
    if args.steg:
        print("\nNote:")
        print("  STEG is public on-chain when included. Anyone can extract payload.age from the locked artifact.")
    return 0


def _extract(args: argparse.Namespace) -> int:
    stego_image = Path(args.image).expanduser()
    if not stego_image.exists():
        _err(f"Locked artifact not found: {stego_image}")
        return 1

    output_path = Path(args.out or "payload.age").expanduser()
    try:
        if args.single_pass_prompt:
            password = _prompt_secret("Single passphrase")
        elif args.stego_pass_prompt:
            password = _prompt_secret("STEGO passphrase")
        else:
            password = args.single_pass or args.stego_pass
        _remove_existing(output_path, args.force, "Output payload")
    except RuntimeError as e:
        _err(str(e))
        return 1

    try:
        _hstego_extract(stego_image, output_path, password)
    except RuntimeError as e:
        if output_path.exists():
            try:
                output_path.unlink()
            except OSError:
                pass
        _err(str(e))
        return 1

    print(f"Extracted payload: {output_path}")
    return 0


def _verify(args: argparse.Namespace) -> int:
    payload_path = Path(args.file or "payload.age").expanduser()
    if not payload_path.exists():
        _err(f"Payload file not found: {payload_path}")
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
            if not decrypt_pass:
                _err("--decrypt requires --single-pass-prompt, --age-pass-prompt, --single-pass, or --age-pass.")
                return 1
            _remove_existing(output_path, args.force, "Decrypted output")
            _age_decrypt(payload_path, output_path, decrypt_pass)
        except RuntimeError as e:
            if output_path.exists():
                try:
                    output_path.unlink()
                except OSError:
                    pass
            _err(str(e))
            return 1
        print(f"Decrypted to: {output_path}")

    return 0 if ok else 1


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="confess",
        description="Local-first cryptographic archiving tool (R&D).",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("doctor", help="Check dependencies")

    sub.add_parser("init", help="Initialize local config")

    seal = sub.add_parser("seal", help="Seal a testimony into a locked artifact")
    seal.add_argument("--image", required=True, help="Cover image (jpg/png)")
    seal.add_argument("--text", required=True, help="Testimony file (.md/.txt/etc)")
    seal.add_argument("--out", help="Output locked artifact jpg")
    seal.add_argument("--force", action="store_true", help="Overwrite payload.age, payload.tar.gz, or output artifact if present")
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
    push.add_argument("--dest-name", help="Optional destination filename on ArDrive")

    mint = sub.add_parser("mint", help="Generate Base tx input metadata")
    mint.add_argument("--txid", required=True, help="Arweave TXID")
    mint.add_argument("--csha", required=True, help="CSHA (sha512 of payload.age)")
    mint.add_argument("--title", required=True, help="Title")
    mint.add_argument("--steg", help="Optional: publish stego pass as STEG:<value> in metadata")

    extract = sub.add_parser("extract", help="Extract payload.age from a locked artifact")
    extract.add_argument("--image", required=True, help="Locked artifact jpg")
    extract.add_argument("--out", help="Output payload path (default payload.age)")
    extract.add_argument("--force", action="store_true", help="Overwrite output payload if present")
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
    parser = _build_parser()
    argv = sys.argv[1:]

    if argv and any(token in {"-h", "--help"} for token in argv) and all(token in {"-h", "--help"} for token in argv):
        _print_help_all(parser)
        return 0

    args = parser.parse_args()

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
