# CONFESSIONS.txt \ Proof of Omertà
*Research & Development*

Local-first CLI for producing **permanently stored** and **cryptographically sealed** testimony artifacts.

The protocol seals a plaintext testimony file with `age` into `payload.age`, embeds that encrypted payload into a carrier image using **HStego** (adaptive JPEG/bitmap steganography), uploads the locked artifact to **Arweave** (content-addressed, immutable storage), and optionally generates **Base** transaction calldata so the artifact can be publicly *referenced* and its integrity *verified* via an on-chain metadata trail.

Website verifier: **https://confessionstxt.art/verify**

---

## What it produces

A **locked artifact**:

- `locked_artifact.jpg` — a normal-looking image that contains an embedded encrypted payload  
- `payload.age` — the encrypted payload (ciphertext)
- `CSHA` — `sha512(payload.age)` integrity hash used for verification

> Steganography is treated as **obfuscation/transport**. Confidentiality comes from `age` encryption.

---

## Protocol overview

1. **Record**: write testimony as plaintext (`confession.md` / `.txt`)
2. **Pack**: package into an archive boundary (`payload.tar.gz`, preserving original filename + extension)
3. **Seal**: encrypt with `age` → `payload.age`
4. **Conceal**: embed `payload.age` into a cover image using HStego → `locked_artifact.jpg`
5. **Archive**: upload `locked_artifact.jpg` to Arweave via ArDrive CLI → Arweave TXID
6. **Broadcast (optional)**: generate Base calldata containing a catalog-style metadata label (`TITLE | ARTXID | CSHA`).  
   User signs/broadcasts manually (wallet custody remains with the operator).

**Canonical integrity proof:**
- `CSHA = SHA-512(payload.age)` (not the plaintext archive)

---

## Password modes

`seal` supports two security modes:

- **Single-pass mode**
  - custom: `--single-pass "<PASS>"`
  - generated: `--gen-single-pass`
  One secret is used for both `age` encryption and HStego embedding.
- **Split-pass mode**
  - custom: `--age-pass "<AGE_PASS>" --stego-pass "<STEGO_PASS>"`
  - generated: `--gen-split-pass`
  Separate secrets are used for encryption and embedding.

Flag convention:
- `--gen-*` = CLI generates strong secret(s) and prints once.
- Exactly one mode group is allowed per `seal` run.
  Do not mix single-mode flags with split-mode flags.
- Generation method: Python `secrets.token_bytes(32)` (CSPRNG), encoded as URL-safe Base64 without `=` padding.

Curatorial framing:
- **Single-pass mode** preserves total custody: extraction and decryption remain bound to one key, so disclosure is all-or-nothing.
- **Split-pass mode** separates proof from revelation: release `--stego-pass` to allow extraction and `CSHA` verification, while plaintext remains sealed behind `--age-pass`.
- Optional public-proof posture: publish `STEG` in on-chain metadata so third parties can independently extract and hash-check without requesting extraction access.

---

## Repository

- `cli/confess.py` — build, upload, and verify artifacts
- `web/` — static site + verifier (hosted at `confessionstxt.art`)

---

## Security model (high level)

- **Local-first:** plaintext testimony stays local; only encrypted payload is embedded/uploaded.
- **Trustless broadcasting:** the CLI never asks for EVM private keys. It only prints calldata;
  you broadcast it manually using Phantom/MetaMask.
- **Defense in depth:** even if embedding is detected, `payload.age` remains unreadable without the key.
- **Public verifiability (optional):** Base metadata can publish `ARTXID` + `CSHA` so anyone can confirm
  the Arweave artifact matches the sealed payload hash.

No stego method is guaranteed undetectable; embedding is **payload-rate constrained** to reduce
steganalysis reliability.

---

## Prerequisites

- Python **3.11 / 3.12** recommended (3.9+ minimum)
- `age` CLI
- HStego + native JPEG headers (builds a small extension)
- `ardrive` CLI (ArDrive upload)
- Optional: `ssss-split` for passphrase splitting (2-of-3, etc.)

`python3 cli/confess.py doctor` checks availability and prints install hints.

---

## Install

### macOS (Homebrew + venv)
```bash
xcode-select --install
brew install python@3.12 age jpeg

$(brew --prefix python@3.12)/bin/python3.12 -m venv .venv && source .venv/bin/activate
python -m pip install --upgrade pip

python -m pip install imageio numpy scipy pycryptodome numba Pillow
bash scripts/install_hstego_mac.sh

npm install -g ardrive-cli
```

### Ubuntu
```bash
sudo apt-get update
sudo apt-get install -y age python3-pip build-essential libjpeg-dev python3-tk

python3 -m venv .venv && source .venv/bin/activate
python -m pip install --upgrade pip

python -m pip install imageio numpy scipy pycryptodome numba Pillow
python -m pip install git+https://github.com/daniellerch/hstego.git@v0.5

npm install -g ardrive-cli
```

---

## End-to-end quickstart

### 1) Diagnostics
```bash
python3 cli/confess.py doctor
```

### 2) Configure wallet path
```bash
python3 cli/confess.py init
```
Enter your Arweave `wallet.json` path when prompted.  
`init` stores the path in `.confess/config.json` (gitignored).

### 3) Seal (encrypt + embed)
```bash
python3 cli/confess.py seal --image cover.jpg --text confession.md --gen-single-pass
```
Outputs:
- `payload.age`
- `locked_artifact.jpg`
- `CSHA` (sha512 of `payload.age`)
- generated passphrase(s) printed once (if using generated mode)

Split-pass variant (delegated verification mode):
```bash
python3 cli/confess.py seal --image cover.jpg --text confession.md --age-pass "<AGE_PASS>" --stego-pass "<STEGO_PASS>"
```
Use this when you want to share extraction capability (`--stego-pass`) without sharing decryption capability (`--age-pass`).

Split-pass with auto-generated secrets:
```bash
python3 cli/confess.py seal --image cover.jpg --text confession.md --gen-split-pass
```

### 4) Create an ArDrive destination (example)
```bash
ardrive create-drive --wallet-file /path/to/wallet.json --drive-name "CONFESSIONS"
```
ArDrive does not print a field literally named `folder-id`.
For `confess.py push --folder-id`, use:
- `created[].entityId` where `created[].type == "folder"` (UUID)
- Not `metadataTxId`, `bundleTxId`, or the `entityId` where `type == "drive"`

If your `create-drive` output includes:
```json
{
  "type": "folder",
  "entityId": "e77a0859-0d12-43d3-bcf7-03d17930c087"
}
```
Then the folder id to pass is:
`e77a0859-0d12-43d3-bcf7-03d17930c087`

If the drive/folder already exists and you no longer have the folder `entityId` saved:
```bash
# List your drives, then copy the target driveId
ardrive list-all-drives --wallet-file /path/to/wallet.json

# List all folders/files in that drive and copy the folder entityId you want
ardrive list-drive --wallet-file /path/to/wallet.json --drive-id <DRIVE_ID> --all
```
For private drives/folders, add `--private` (or provide `--drive-key`).
Use that folder `entityId` as `--folder-id` in `confess.py push`.

### 5) Upload to Arweave via ArDrive
```bash
python3 cli/confess.py push --file locked_artifact.jpg --folder-id <ARDRIVE_FOLDER_ENTITY_ID>
```
Outputs:
- Arweave TXID
- `https://arweave.net/<TXID>`

### 6) Generate Base calldata (optional)
```bash
python3 cli/confess.py mint --title "Proof of Omertà" --txid <ARWEAVE_TXID> --csha <CSHA_SHA512>
```
This prints a hex string for transaction input data.

Optional public extraction key broadcast:
```bash
python3 cli/confess.py mint --title "Proof of Omertà" --txid <ARWEAVE_TXID> --csha <CSHA_SHA512> --steg "<STEGO_PASS>"
```
Use only if you intentionally want extraction access to be public on-chain.

You broadcast manually:
- Network: Base
- Send: 0 ETH
- To: null address or self
- Data: paste the hex calldata

**Metadata label format (example):**
```
Proof of Omertà | ARTXID:<TXID> | CSHA:<SHA512>
Proof of Omertà | ARTXID:<TXID> | CSHA:<SHA512> | STEG:<STEGO_PASS>
```

Why `|` delimiters:
- This keeps the label human-readable (like catalog metadata) and machine-parsable with stable field boundaries.

---

## Command reference

- `python3 cli/confess.py --help` — prints expanded help for all subcommands and flags
- `doctor` — dependency checks + install hints
- `init` — store wallet path; attempts address/balance lookup when possible
- `seal` — create `payload.age`, embed into image, output `CSHA`  
  Password options: `--single-pass` / `--gen-single-pass` (single mode), or
  `--age-pass` + `--stego-pass` / `--gen-split-pass` (split mode)
- `push` — upload locked artifact through ArDrive (`--folder-id` = `created[].entityId` where `type == "folder"`)
- `mint` — generate Base calldata (manual broadcast). Optional: `--steg` to publish stego extraction password
- `extract` — recover `payload.age` from a locked artifact (requires `--single-pass` or `--stego-pass`)
- `verify` — check `sha512(payload.age)` vs expected `CSHA`

---

## Verification flow

Public readout (metadata + instructions):
- **https://confessionstxt.art/verify**
  - Base tx hash: resolves protocol metadata (`ARTXID`, `CSHA`, optional `STEG`)
  - Arweave TXID: resolves archive location + local verification steps

Local verification (operator):
```bash
python3 cli/confess.py extract --image locked_artifact.jpg --stego-pass "..."
python3 cli/confess.py verify --file payload.age --csha <CSHA_SHA512>
```

Optional local decryption:
```bash
age --decrypt --output payload.tar.gz payload.age
tar -xzf payload.tar.gz
```

---

## Operational notes

- Do not commit `wallet.json` or `.confess/config.json`.
- Store passphrases securely. Consider Shamir splitting (`ssss-split`) for redundancy.
- If using split mode, treat `--age-pass` as strictly higher sensitivity than `--stego-pass`.
- First HStego run may be slow due to native build/JIT overhead.
- Embedding capacity depends on cover image properties; if payload is too large, use a larger cover image or smaller payload.

---

**CripTech**
