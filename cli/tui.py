"""The default terminal interface. All operations use the shared command handlers.

Only public paths and checksums are retained between operations. Passwords use
core's hidden prompts or exclusive private files, never shell commands.
"""
from dataclasses import dataclass
from pathlib import Path
import subprocess
import sys


@dataclass
class Session:
    artifact: str = ""
    payload: str = "payload.age"
    csha: str = ""


def _ask(label, default=None):
    value = input(label + (f" [{default}]" if default else "") + ": ").strip()
    if not value and default:
        return default
    if not value:
        raise ValueError(f"{label} is required.")
    return value


def _yes(label):
    return input(label + " [y/N]: ").strip().lower() in {"y", "yes"}


def _option(name, value):
    # A leading dash in a path/title must be data, never another argparse option.
    return f"--{name}={value}"


def _path(label, default=None, *, must_exist=False):
    value = _ask(label, default)
    if len(value) > 1 and value[0] == value[-1] and value[0] in {"'", '"'}:
        value = value[1:-1]
    path = Path(value).expanduser()
    if must_exist and not path.is_file():
        raise ValueError(f"File not found: {path}")
    return str(path)


def _execute(core, argv):
    return core._dispatch(core._build_parser().parse_args(argv))


def _seal(core, state):
    image = _path("Cover image", must_exist=True)
    text = _path("Text to seal", must_exist=True)
    suffix = ".jpg" if core._is_jpeg_image(Path(image)) else ".png"
    out = _path("Save locked image as", "locked_artifact" + suffix)
    core._check_output(Path(out), False, (Path(image), Path(text)))
    core._check_output(Path(out).parent / "payload.age", False, (Path(image), Path(text)))
    argv = ["seal", _option("image", image), _option("text", text), _option("out", out)]
    print("Two passwords keep extraction separate from reading your text.")
    if _yes("Enter your own passwords? Press Enter to generate strong random ones"):
        argv += ["--split-pass-prompt"]
    else:
        secret_path = _path("New private password file", str(Path(out).with_suffix(".secrets.json")))
        core._check_output(Path(secret_path), False, (Path(image), Path(text), Path(out)))
        argv += ["--gen-split-pass", _option("secrets-file", secret_path)]
        print("This file will contain both passwords. Keep it private and save them in your password manager.")
    print(f"\nText: {text}\nLocked image: {out}\nNothing is uploaded during sealing.")
    if not _yes("Seal this record?"):
        return None
    result = _execute(core, argv)
    if result == 0:
        state.artifact = out
        state.payload = str(Path(out).parent / "payload.age")
        state.csha = core._sha512_file(Path(state.payload))
        print("Next: keep your passwords safe. You can check this record locally or choose Upload when ready.")
    return result


def _operation(core, state, choice):
    if choice == "1":
        return _seal(core, state)
    if choice == "2":
        image = _path("Locked image", state.artifact, must_exist=True)
        out = _path("Save encrypted payload as", "extracted_payload.age")
        argv = ["extract", _option("image", image), _option("out", out), "--stego-pass-prompt"]
        if _yes("Was this image made with HStego v0.5 (an older CONFESSIONS.txt setup)?"):
            argv.append("--legacy-hstego")
        result = _execute(core, argv)
        if result == 0:
            state.payload = out
            state.csha = ""  # Never reuse a different record's checksum.
        return result
    if choice == "3":
        payload = _path("Encrypted payload", state.payload, must_exist=True)
        default = state.csha if Path(payload).resolve() == Path(state.payload).resolve() else ""
        csha = _ask("Expected CSHA (public record or your local sealing receipt)", default)
        argv = ["verify", _option("file", payload), _option("csha", csha)]
        if _yes("Also decrypt after the checksum matches?"):
            argv += ["--decrypt", "--age-pass-prompt", _option("out", _path("Save private archive as", "payload.tar.gz"))]
        return _execute(core, argv)
    if choice == "4":
        reference = _ask("Public Base hash, Arweave TXID, or verifier URL")
        script = Path(__file__).resolve().parents[1] / "packages/cli/bin/confessions.mjs"
        return subprocess.run(["node", str(script), "verify", "--", reference], check=False).returncode
    if choice == "5":
        argv = ["mint", _option("title", _ask("Public title")), _option("txid", _ask("Arweave TXID")),
                _option("csha", _ask("Encrypted payload CSHA", state.csha))]
        print("Publishing the extraction password is permanent. Never publish the password that decrypts your text.")
        if _yes("Include a public extraction password that is DIFFERENT from your AGE password?"):
            argv += ["--steg-prompt", "--ack-public-steg"]
        return _execute(core, argv)
    if choice == "6":
        return _execute(core, ["doctor"])
    if choice == "7":
        return _execute(core, ["init"])
    if choice == "8":
        image = _path("Locked artifact", state.artifact, must_exist=True)
        folder = _ask("ArDrive folder entityId")
        print(f"Upload {image!r} to folder {folder!r}. This spends wallet funds and cannot be undone.")
        if input("Type UPLOAD to publish permanently: ") != "UPLOAD":
            return None
        return _execute(core, ["push", _option("file", image), _option("folder-id", folder), "--ack-permanent-upload"])
    print("Choose one of the listed numbers.")
    return None


def run(core):
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        core._err("Open confess in a terminal, or use --help for scriptable commands.")
        return 1
    state = Session()
    while True:
        print("\nCONFESSIONS.txt — keep the record, choose when to reveal it")
        print(f"Workspace: {Path.cwd()}")
        if state.artifact:
            print(f"Current artifact: {state.artifact}")
        print("\nCREATE    1  Seal a text file")
        print("CHECK     2  Extract encrypted payload\n          3  Check checksum / decrypt\n          4  Look up a public record")
        print("PUBLISH   5  Prepare Base transaction data\n          8  Upload to Arweave")
        print("SETUP     6  Check this computer\n          7  Set wallet path\n          0  Exit")
        print("Ctrl-C cancels the current step; at this menu it exits.")
        choice = None
        try:
            choice = input("\nChoose: ").strip()
            if choice in {"0", "q", "quit"}:
                return 0
            code = _operation(core, state, choice)
            if code is not None:
                print("Done." if code == 0 else "Operation did not complete. Review the message above.")
        except KeyboardInterrupt:
            if choice is None:
                print("\nGoodbye.")
                return 130
            print("\nCancelled. Returning to the menu.")
        except EOFError:
            print("\nGoodbye.")
            return 0
        except (OSError, RuntimeError, ValueError) as error:
            core._err(str(error))
