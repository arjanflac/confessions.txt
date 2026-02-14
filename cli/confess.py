#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
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


def _sha512_file(path: Path) -> str:
    h = hashlib.sha512()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


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
    print("Install hints:")
    print("  macOS (recommended):")
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
    print("confess doctor")
    print(f"Python: {sys.version.split()[0]}")
    if sys.version_info < (3, 9):
        _err("  ! Python 3.9+ recommended")
    if sys.version_info >= (3, 13):
        _err("  ! Python 3.11/3.12 recommended; 3.13+ can break HStego dependencies.")

    venv_ok = _in_venv()
    print(f"venv: {'OK' if venv_ok else 'NO'}")
    if not venv_ok:
        _err("  ! Not in a virtual environment. On macOS, pip installs may fail (PEP 668).")

    arch = platform.machine()
    print(f"arch: {arch}")

    age_path = _which("age")
    age_version = _binary_version(["age", "--version"]) if age_path else None
    print(f"age: {'OK' if age_path else 'MISSING'}" + (f" ({age_version})" if age_version else ""))

    hstego_ok, hstego_info = _check_hstego()
    print(f"hstego (hstegolib): {'OK' if hstego_ok else 'MISSING'}" + (f" ({hstego_info})" if hstego_info else ""))

    ardrive_path = _which("ardrive")
    ardrive_version = _binary_version(["ardrive", "--version"]) if ardrive_path else None
    print(
        f"ardrive: {'OK' if ardrive_path else 'MISSING'}"
        + (f" ({ardrive_version})" if ardrive_version else "")
    )

    if platform.system() == "Darwin":
        clt_ok, clt_info = _xcode_clt_status()
        print(
            f"Xcode CLT: {'OK' if clt_ok else 'MISSING'}"
            + (f" ({clt_info})" if clt_info else "")
        )
        if not clt_ok:
            _err("  ! Install Xcode Command Line Tools: xcode-select --install")
        if arch == "arm64":
            _err("  ! Apple Silicon detected. Use scripts/install_hstego_mac.sh (it patches SSE intrinsics via sse2neon).")
        if _which("python3.12") is None:
            _err("  ! python3.12 not on PATH. Use: $(brew --prefix python@3.12)/bin/python3.12")
        jpeg_header = _find_jpeglib_header()
        print(
            f"libjpeg headers: {'OK' if jpeg_header else 'MISSING'}"
            + (f" ({jpeg_header})" if jpeg_header else "")
        )
        if not jpeg_header:
            _err("  ! Install libjpeg headers: brew install jpeg")

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
        while True:
            try:
                chunk = os.read(fd, 1024)
                if not chunk:
                    break
                output_chunks.append(chunk)
            except OSError:
                break

        _, status = os.waitpid(pid, 0)
        exit_code = os.waitstatus_to_exitcode(status)
        output = b"".join(output_chunks).decode("utf-8", errors="ignore").strip()
        if exit_code != 0:
            raise RuntimeError(f"age failed: {output or 'unknown error'}")


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
    try:
        if _is_spatial_image(stego_image, hstegolib):
            stego = hstegolib.S_UNIWARD()
            _with_heartbeat("HStego extract", lambda: stego.extract(str(stego_image), password, str(output)))
        elif _is_jpeg_image(stego_image):
            stego = hstegolib.J_UNIWARD()
            _with_heartbeat("HStego extract", lambda: stego.extract(str(stego_image), password, str(output)))
        else:
            raise RuntimeError("Stego image format not supported (use .jpg or .png).")
    except SystemExit:
        raise RuntimeError("HStego extract failed.")
    except Exception as e:
        raise RuntimeError(f"HStego extract failed: {e}")

    if not output.exists():
        raise RuntimeError("HStego extract failed: payload not recovered.")


def _seal(args: argparse.Namespace) -> int:
    cover = Path(args.image).expanduser()
    text_path = Path(args.text).expanduser()
    if not cover.exists():
        _err(f"Cover image not found: {cover}")
        return 1
    if not text_path.exists():
        _err(f"Testimony file not found: {text_path}")
        return 1

    payload_tar = Path("payload.tar.gz")
    payload_age = Path("payload.age")
    output_image = Path(args.out or "locked_artifact.jpg")

    if payload_tar.exists():
        payload_tar.unlink()
    if payload_age.exists():
        payload_age.unlink()

    with tarfile.open(payload_tar, "w:gz") as tar:
        tar.add(text_path, arcname="confession.md")

    if args.generate_pass:
        master_pass = _generate_passphrase()
        print("Generated master passphrase (print once):")
        print(master_pass)
        print("Store this securely. Optional Shamir splitting: ssss-split -t 2 -n 3")
    else:
        master_pass = args.master_pass

    try:
        _age_encrypt(payload_tar, payload_age, master_pass)
    except RuntimeError as e:
        _err(str(e))
        return 1

    csha = _sha512_file(payload_age)

    try:
        _hstego_embed(cover, payload_age, output_image, master_pass, args.algo)
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

    cid = _extract_ardrive_data_tx(res.stdout + "\n" + res.stderr)
    if not cid:
        raise RuntimeError("ArDrive upload succeeded but no dataTxId was found in output.")
    return cid


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
        _err("ArDrive parent folder id is required. Create a drive/folder with ArDrive CLI and pass --folder-id.")
        _err("See ardrive-cli-README.md for the create-drive and upload-file examples.")
        return 1

    try:
        cid = _ardrive_upload(file_path, wallet_path, folder_id, args.dest_name)
    except RuntimeError as e:
        _err(str(e))
        return 1

    url = f"{ARWEAVE_URL_PREFIX}{cid}"
    print(f"Arweave TXID: {cid}")
    print(f"URL: {url}")
    print("\nReceipt:")
    print("--------")
    print(f"TXID: {cid}")
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

    file_name = args.file or "payload.age"

    metadata = (
        f"V:2|TITLE:{title}|AR:{args.txid}|CSHA:{args.csha}|ALG:SHA512|FILE:{file_name}|NOTE:R&D"
    )
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
    return 0


def _extract(args: argparse.Namespace) -> int:
    stego_image = Path(args.image).expanduser()
    if not stego_image.exists():
        _err(f"Locked artifact not found: {stego_image}")
        return 1

    output_path = Path(args.out or "payload.age").expanduser()
    password = args.master_pass or args.stego_pass

    try:
        _hstego_extract(stego_image, output_path, password)
    except RuntimeError as e:
        _err(str(e))
        return 1

    print(f"Extracted payload: {output_path}")
    return 0


def _verify(args: argparse.Namespace) -> int:
    payload_path = Path(args.file or "payload.age").expanduser()
    if not payload_path.exists():
        _err(f"Payload file not found: {payload_path}")
        return 1

    actual = _sha512_file(payload_path)
    expected = args.csha.lower()

    print(f"Expected CSHA: {expected}")
    print(f"Actual CSHA:   {actual}")

    ok = actual.lower() == expected
    print(f"CSHA match: {'YES' if ok else 'NO'}")

    if args.decrypt:
        if not args.master_pass:
            _err("--master-pass is required to decrypt.")
            return 1
        output_path = Path(args.out or "payload.tar.gz").expanduser()
        try:
            _age_decrypt(payload_path, output_path, args.master_pass)
        except RuntimeError as e:
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
    seal.add_argument("--text", required=True, help="Testimony text (markdown)")
    seal.add_argument("--out", help="Output locked artifact jpg")
    seal.add_argument(
        "--algo",
        default="auto",
        choices=["auto", "j-uniward", "s-uniward"],
        help="HStego algorithm (auto: JPEG->J-UNIWARD, PNG->S-UNIWARD)",
    )
    group = seal.add_mutually_exclusive_group(required=True)
    group.add_argument("--master-pass", help="Master passphrase for age + stego")
    group.add_argument(
        "--generate-pass",
        action="store_true",
        help="Generate a strong master passphrase",
    )

    push = sub.add_parser("push", help="Upload locked artifact to Arweave via ArDrive")
    push.add_argument("--file", required=True, help="Locked artifact jpg")
    push.add_argument("--folder-id", help="ArDrive parent folder id")
    push.add_argument("--dest-name", help="Optional destination filename on ArDrive")

    mint = sub.add_parser("mint", help="Generate Base tx input metadata")
    mint.add_argument("--txid", required=True, help="Arweave TXID")
    mint.add_argument("--csha", required=True, help="CSHA (sha512 of payload.age)")
    mint.add_argument("--title", required=True, help="Title")
    mint.add_argument("--file", help="Payload filename (default payload.age)")

    extract = sub.add_parser("extract", help="Extract payload.age from a locked artifact")
    extract.add_argument("--image", required=True, help="Locked artifact jpg")
    extract.add_argument("--out", help="Output payload path (default payload.age)")
    extract_group = extract.add_mutually_exclusive_group(required=True)
    extract_group.add_argument("--master-pass", help="Master passphrase")
    extract_group.add_argument("--stego-pass", help="Stego password")

    verify = sub.add_parser("verify", help="Verify payload hash and optionally decrypt")
    verify.add_argument("--file", help="payload.age path (default payload.age)")
    verify.add_argument("--csha", required=True, help="Expected CSHA (sha512)")
    verify.add_argument("--decrypt", action="store_true", help="Decrypt payload.age -> payload.tar.gz")
    verify.add_argument("--out", help="Decrypted output path (default payload.tar.gz)")
    verify.add_argument("--master-pass", help="Master passphrase for decryption")

    return parser


def main() -> int:
    parser = _build_parser()
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
