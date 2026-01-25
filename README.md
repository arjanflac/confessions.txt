# CONFESSIONS.TXT / PROOF OF OMERTA (R&D)

Permanently stored + cryptographically sealed testimony artifacts.

This project is R&D: local-first, minimal, auditable. It never asks for private keys and does not broadcast transactions for you.

## What it is
A protocol + toolchain to package a plaintext testimony into a tar.gz, encrypt it with age, embed the encrypted payload in an image via HStego, then upload the locked artifact to Arweave. A Base transaction can optionally anchor a metadata string (CID + integrity hash) by manual signing.

## Threat model (summary)
- Encryption-first: the encrypted payload is the security boundary.
- Stego adds stealth/obfuscation only; it does not replace encryption.
- Trustless broadcasting: the tool generates hex payloads only. You sign and broadcast manually.
- Local-first: plaintext stays on disk and inside the encrypted payload only.

## Prerequisites
- `age` CLI (passphrase mode)
- Python 3.9+
- `pip install hstego`
- `npm install -g arweave-deploy`
- Optional: `ssss-split` for Shamir sharing

## CLI walkthrough
From repo root:

```bash
python3 cli/confess.py doctor
python3 cli/confess.py init
python3 cli/confess.py seal --image cover.jpg --text confession.md --generate-passphrase
python3 cli/confess.py push --file locked_artifact.jpg
python3 cli/confess.py mint --cid <ARWEAVE_CID> --csha <SHA512>
```

Notes:
- `init` stores only the wallet path in `.confess/config.json` (gitignored). Never commit wallet files.
- `seal` prints a passphrase once if generated. Store it securely.

## Verification walkthrough
1. If you have a Base transaction hash, paste it into `/web/verify.html`.
2. The page decodes the tx input and displays:
   - Title
   - Arweave URL
   - CSHA (sha512)
3. Download `locked_artifact.jpg` from Arweave.
4. Extract `payload.age` using HStego.
5. Decrypt and verify:

```bash
age -d -o payload.tar.gz payload.age
sha512sum payload.tar.gz
```

The hash must match CSHA from the metadata.

## Safety notes
- Never commit `wallet.json` or any `*.wallet.json` files.
- Store passphrases offline and consider `ssss-split` for redundancy.
- Stego detection does not imply decryption.
