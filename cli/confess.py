#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import tarfile
from pathlib import Path
from typing import Optional

CONFIG_DIR = Path(".confess")
CONFIG_PATH = CONFIG_DIR / "config.json"

ARWEAVE_URL_PREFIX = "https://arweave.net/"


def _err(msg: str) -> None:
    print(msg, file=sys.stderr)


def _load_config() -> dict:
    if CONFIG_PATH.exists():
        try:
            return json.loads(CONFIG_PATH.read_text())
        except json.JSONDecodeError:
            return {}
    return {}


def _save_config(data: dict) -> None:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    CONFIG_PATH.write_text(json.dumps(data, indent=2))


def _sha512_file(path: Path) -> str:
    h = hashlib.sha512()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _which(name: str) -> Optional[str]:
    return shutil.which(name)


def _run(cmd: list[str], env: Optional[dict] = None) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, env=env)


def _print_install_hints() -> None:
    print("Install hints:")
    print("  macOS: brew install age")
    print("  Ubuntu: sudo apt-get update && sudo apt-get install -y age")
    print("  Python: pip install hstego")
    print("  Node: npm install -g arweave-deploy")
    print("  Optional Shamir: brew install ssss (or sudo apt-get install -y ssss)")


def _doctor() -> int:
    print("confess doctor")
    print(f"Python: {sys.version.split()[0]}")
    if sys.version_info < (3, 9):
        _err("  ! Python 3.9+ recommended")

    age_ok = _which("age") is not None
    print(f"age: {'OK' if age_ok else 'MISSING'}")

    try:
        __import__("hstego")
        hstego_ok = True
    except Exception:
        hstego_ok = False
    print(f"hstego (pip): {'OK' if hstego_ok else 'MISSING'}")

    node_ok = _which("node") is not None
    print(f"node: {'OK' if node_ok else 'MISSING'}")

    arweave_ok = _which("arweave") is not None or _which("arweave-deploy") is not None
    print(f"arweave-deploy: {'OK' if arweave_ok else 'MISSING'}")

    print("")
    _print_install_hints()
    return 0


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


def _maybe_print_wallet_address(wallet_path: Path) -> None:
    address = None
    if _which("arweave"):
        res = _run(["arweave", "wallet-address", str(wallet_path)])
        if res.returncode == 0:
            address = res.stdout.strip().splitlines()[-1]
    if not address:
        address = _wallet_address_from_jwk(wallet_path)
    if address:
        print(f"Wallet address: {address}")
    else:
        _err("Could not derive wallet address. Use `arweave wallet-address <wallet.json>`. ")


def _init() -> int:
    cfg = _load_config()
    wallet = cfg.get("wallet_path")
    if wallet:
        print(f"Existing wallet path: {wallet}")
    else:
        print("Arweave wallet.json path (press Enter to create one):")
    user_input = input("> ").strip()
    if user_input:
        wallet_path = Path(user_input).expanduser()
    else:
        wallet_path = None

    if wallet_path is None or not wallet_path.exists():
        if _which("arweave") is not None:
            print("No wallet found. Create one with arweave-deploy? [y/N]")
            if input("> ").strip().lower() == "y":
                output_path = Path("wallet.json")
                res = _run(["arweave", "key-create", "--output", str(output_path)])
                if res.returncode != 0:
                    _err("Failed to create wallet:")
                    _err(res.stderr.strip() or res.stdout.strip())
                    return 1
                wallet_path = output_path
        if wallet_path is None or not wallet_path.exists():
            _err("Wallet file not found. Provide a valid path or create one.")
            return 1

    cfg["wallet_path"] = str(wallet_path)
    _save_config(cfg)
    print(f"Saved wallet path to {CONFIG_PATH}")
    _maybe_print_wallet_address(wallet_path)
    print("Fund this address with AR before upload.")
    return 0


def _generate_passphrase() -> str:
    raw = secrets.token_bytes(32)
    return base64.urlsafe_b64encode(raw).decode("utf-8").rstrip("=")


def _age_encrypt(input_path: Path, output_path: Path, passphrase: str) -> None:
    env = os.environ.copy()
    env["AGE_PASSWORD"] = passphrase
    attempts = [
        ["age", "--passphrase", "-o", str(output_path), str(input_path)],
        ["age", "-p", "-o", str(output_path), str(input_path)],
    ]
    last_error = None
    for cmd in attempts:
        try:
            res = _run(cmd, env=env)
        except FileNotFoundError:
            raise RuntimeError("age CLI not found. Install age first.")
        if res.returncode == 0:
            return
        last_error = res.stderr.strip() or res.stdout.strip()
    raise RuntimeError(f"age encryption failed. {last_error}")


def _try_hstego_api(cover: Path, payload: Path, output: Path) -> bool:
    try:
        import hstego  # type: ignore
        import inspect
    except Exception:
        return False

    def _attempt_call(func) -> bool:
        try:
            sig = inspect.signature(func)
        except Exception:
            sig = None

        if sig is not None:
            params = sig.parameters
            kwargs = {}
            for name in params:
                lname = name.lower()
                if lname in ("cover", "image", "input", "infile", "input_path", "image_path"):
                    kwargs[name] = str(cover)
                elif lname in ("payload", "data", "secret", "file", "payload_path", "message"):
                    kwargs[name] = str(payload)
                elif lname in ("output", "out", "outfile", "output_path", "result", "dest"):
                    kwargs[name] = str(output)
            if kwargs:
                try:
                    func(**kwargs)
                    return True
                except Exception:
                    pass
        try:
            func(str(cover), str(payload), str(output))
            return True
        except Exception:
            return False

    for func_name in ("embed", "hide", "encode"):
        func = getattr(hstego, func_name, None)
        if callable(func) and _attempt_call(func):
            return True

    for cls_name in ("HStego", "Stego", "Hstego"):
        cls = getattr(hstego, cls_name, None)
        if cls is None:
            continue
        try:
            obj = cls()
        except Exception:
            continue
        for method_name in ("embed", "hide", "encode"):
            method = getattr(obj, method_name, None)
            if callable(method) and _attempt_call(method):
                return True
    return False


def _try_hstego_cli(cover: Path, payload: Path, output: Path) -> bool:
    base_cmds: list[list[str]] = []
    if _which("hstego"):
        base_cmds.append(["hstego"])
    if _which("python3"):
        base_cmds.append(["python3", "-m", "hstego"])

    attempts: list[list[str]] = []
    for base in base_cmds:
        attempts.extend(
            [
                base + ["embed", "-i", str(cover), "-p", str(payload), "-o", str(output)],
                base
                + [
                    "embed",
                    "--input",
                    str(cover),
                    "--payload",
                    str(payload),
                    "--output",
                    str(output),
                ],
                base + ["-e", "-i", str(cover), "-p", str(payload), "-o", str(output)],
                base
                + [
                    "--embed",
                    "--input",
                    str(cover),
                    "--payload",
                    str(payload),
                    "--output",
                    str(output),
                ],
                base + ["hide", "-i", str(cover), "-f", str(payload), "-o", str(output)],
                base
                + [
                    "hide",
                    "--input",
                    str(cover),
                    "--file",
                    str(payload),
                    "--output",
                    str(output),
                ],
            ]
        )

    for cmd in attempts:
        res = _run(cmd)
        if res.returncode == 0:
            return True
    return False


def _embed_with_hstego(cover: Path, payload: Path, output: Path) -> None:
    if _try_hstego_api(cover, payload, output):
        if output.exists():
            return
    if _try_hstego_cli(cover, payload, output):
        if output.exists():
            return
    raise RuntimeError(
        "HStego embed failed. The payload may be too large for the cover image, or hstego is misconfigured."
    )


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

    tar_name = args.name or "confession.md"

    if payload_tar.exists():
        payload_tar.unlink()
    with tarfile.open(payload_tar, "w:gz") as tar:
        tar.add(text_path, arcname=tar_name)

    csha = _sha512_file(payload_tar)

    if args.generate_passphrase:
        passphrase = _generate_passphrase()
        print("Generated passphrase (print once):")
        print(passphrase)
        print("Store this securely. Consider Shamir splitting: ssss-split -t 2 -n 3")
    else:
        passphrase = args.passphrase

    try:
        _age_encrypt(payload_tar, payload_age, passphrase)
    except RuntimeError as e:
        _err(str(e))
        return 1

    try:
        _embed_with_hstego(cover, payload_age, output_image)
    except RuntimeError as e:
        _err(str(e))
        return 1

    print(f"Locked artifact: {output_image}")
    print(f"CSHA (sha512): {csha}")
    print(f"Payload file: {payload_age}")
    return 0


def _extract_cid(output: str) -> Optional[str]:
    match = re.search(r"[a-zA-Z0-9_-]{43}", output)
    return match.group(0) if match else None


def _arweave_deploy(file_path: Path, wallet_path: Path) -> str:
    attempts = [
        ["arweave", "deploy", str(file_path), "--key-file", str(wallet_path)],
        ["arweave", "deploy", str(file_path), "-w", str(wallet_path)],
        ["arweave-deploy", str(file_path), "--key-file", str(wallet_path)],
        ["arweave-deploy", str(file_path), "-w", str(wallet_path)],
    ]
    last_err = None
    for cmd in attempts:
        res = _run(cmd)
        if res.returncode == 0:
            cid = _extract_cid(res.stdout)
            if cid:
                return cid
            cid = _extract_cid(res.stderr)
            if cid:
                return cid
            last_err = res.stdout.strip() or res.stderr.strip()
        else:
            last_err = res.stderr.strip() or res.stdout.strip()
    raise RuntimeError(
        "Arweave deploy failed. Ensure arweave-deploy is installed and try again."
        + (f" Details: {last_err}" if last_err else "")
    )


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

    try:
        cid = _arweave_deploy(file_path, wallet_path)
    except RuntimeError as e:
        _err(str(e))
        return 1

    url = f"{ARWEAVE_URL_PREFIX}{cid}"
    print(f"Arweave CID: {cid}")
    print(f"URL: {url}")
    print("\nReceipt:")
    print("--------")
    print(f"CID: {cid}")
    print(f"URL: {url}")
    print(f"FILE: {file_path.name}")
    return 0


def _mint(args: argparse.Namespace) -> int:
    title = args.title or "Proof of Omerta"
    alg = args.alg or "SHA512"
    file_name = args.file or "payload.age"

    metadata = (
        f"V:2|TITLE:{title}|AR:{args.cid}|CSHA:{args.csha}|ALG:{alg}|FILE:{file_name}|NOTE:R&D"
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


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="confess",
        description="Local-first cryptographic archiving tool (R&D).",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("doctor", help="Check dependencies")

    sub.add_parser("init", help="Initialize local config")

    seal = sub.add_parser("seal", help="Seal a testimony into a locked artifact")
    seal.add_argument("--image", required=True, help="Cover image (jpg)")
    seal.add_argument("--text", required=True, help="Testimony text (markdown)")
    seal.add_argument("--out", help="Output locked artifact jpg")
    seal.add_argument("--name", help="Filename inside tar.gz (default: confession.md)")
    group = seal.add_mutually_exclusive_group(required=True)
    group.add_argument("--passphrase", help="Passphrase for age encryption")
    group.add_argument(
        "--generate-passphrase",
        action="store_true",
        help="Generate a strong passphrase",
    )

    push = sub.add_parser("push", help="Upload locked artifact to Arweave")
    push.add_argument("--file", required=True, help="Locked artifact jpg")

    mint = sub.add_parser("mint", help="Generate Base tx input metadata")
    mint.add_argument("--cid", required=True, help="Arweave CID")
    mint.add_argument("--csha", required=True, help="CSHA (sha512)")
    mint.add_argument("--title", help="Title")
    mint.add_argument("--alg", help="Hash algorithm (default SHA512)")
    mint.add_argument("--file", help="Payload filename (default payload.age)")

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

    _err("Unknown command")
    return 1


if __name__ == "__main__":
    sys.exit(main())
