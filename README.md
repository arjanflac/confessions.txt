<p align="center">
  <img src="web/logo.png" alt="CONFESSIONS.txt sword logo" width="120" />
</p>

# CONFESSIONS.txt
### Proof of Omertà

CONFESSIONS.txt is a local-first terminal protocol for turning plaintext testimony into a public, verifiable, encrypted artifact.

It is built for records that may need to exist before they can be safely read. The operator writes testimony locally, encrypts it with `age`, embeds the ciphertext inside a carrier image with HStego, archives the locked artifact on Arweave, and generates Base calldata that points to the record.

There is no hosted sealing service. The CLI does not receive files, hold keys, custody wallets, or broadcast transactions. It prepares the artifact; the operator controls disclosure.

Public verifier: **https://confessionstxt.art/verify**

## What It Does

CONFESSIONS.txt turns one local testimony file into a durable public reference.

1. **Record**: write testimony as plaintext (`.md`, `.txt`, or similar).
2. **Pack**: archive the file into `payload.tar.gz` so the original filename survives.
3. **Seal**: encrypt the archive with `age` to produce `payload.age`.
4. **Conceal**: embed `payload.age` into a carrier image with HStego.
5. **Archive**: upload the locked artifact to Arweave through ArDrive.
6. **Broadcast**: generate Base calldata containing the artifact pointer and integrity hash.
7. **Verify**: resolve the public record and compare the extracted payload against the canonical hash.

The CLI is command-oriented rather than an interactive shell. Each subcommand performs one protocol step: `seal`, `push`, `mint`, `extract`, or `verify`. That shape is intentional because each step has different local, public, and operational consequences.

## Artifact Model

A completed record has three layers.

**Local secret material**

- plaintext testimony
- `payload.tar.gz`
- `age` passphrase
- optional stego passphrase, unless published as `STEG`

**Public artifact material**

- `locked_artifact.jpg`
- Arweave transaction ID
- Base transaction metadata
- optional `STEG` value if public extraction is intentional

**Verification material**

- `payload.age`
- `CSHA = sha512(payload.age)`
- browser or local verifier output

`CSHA` is the canonical integrity value. It is calculated over the encrypted payload, not over the plaintext archive.

Steganography is concealment and transport. Confidentiality comes from `age`.

## Public and Private Surfaces

What can become public:

- the locked artifact on Arweave
- the Base metadata label
- the stego extraction secret if `STEG` is published on-chain
- the extracted `payload.age` if the stego secret is public

What remains private by default:

- the plaintext testimony file
- the `age` passphrase
- the stego passphrase
- the decrypted `payload.tar.gz`

Publishing `STEG` makes extraction of `payload.age` public. It does not disclose plaintext unless the `age` passphrase is also disclosed.

## Security Model

- **Local-first**: plaintext remains on the operator's machine unless intentionally disclosed.
- **Encryption boundary**: `age` is the confidentiality layer. If the steganography is detected or removed, the recovered payload is still encrypted.
- **Concealment layer**: HStego hides the encrypted payload inside an image. No steganographic method should be treated as guaranteed undetectable.
- **Public verifiability**: anyone with the artifact and the correct extraction path can verify that `sha512(payload.age)` matches `CSHA`.
- **No wallet custody**: `mint` prints calldata. The operator signs and broadcasts manually from their own wallet.
- **Explicit overwrite behavior**: generated outputs are not overwritten unless `--force` is supplied.

CONFESSIONS.txt is not an anonymity system. It does not protect an operator from device compromise, unsafe operational behavior, exposed passphrases, hostile wallets, malicious dependencies, or legal risk.

This is R&D software. It can support a serious evidence workflow, but it is not a complete safety plan and is not a substitute for legal, medical, security, or crisis support.

## Password Modes

`seal` supports split-pass mode and single-pass mode.

**Split-pass mode**

```bash
python3 cli/confess.py seal --image cover.jpg --text confession.md --gen-split-pass
python3 cli/confess.py seal --image cover.jpg --text confession.md --split-pass-prompt
python3 cli/confess.py seal --image cover.jpg --text confession.md --age-pass "<AGE_PASS>" --stego-pass "<STEGO_PASS>"
```

Split-pass mode separates extraction from decryption.

- `stego-pass` extracts `payload.age` from the locked artifact.
- `age-pass` decrypts `payload.age` back into `payload.tar.gz`.

This allows an operator to publish or share the stego secret for public checksum verification without disclosing the plaintext.

**Single-pass mode**

```bash
python3 cli/confess.py seal --image cover.jpg --text confession.md --gen-single-pass
python3 cli/confess.py seal --image cover.jpg --text confession.md --single-pass-prompt
python3 cli/confess.py seal --image cover.jpg --text confession.md --single-pass "<PASS>"
```

Single-pass mode uses one secret for both extraction and decryption. It is simpler, but it removes the separation between public extraction and private plaintext access.

Prefer prompt flags for manual secrets. Literal passphrase arguments can be visible in shell history and process lists.

## On-Chain Metadata

`mint` builds a human-readable metadata label and prints the corresponding calldata:

```text
TITLE | ARTXID:<ARWEAVE_TXID> | CSHA:<SHA512>
TITLE | ARTXID:<ARWEAVE_TXID> | CSHA:<SHA512> | STEG:<VALUE>
```

- `TITLE` names the record.
- `ARTXID` points to the Arweave artifact.
- `CSHA` is the canonical integrity value.
- `STEG` is optional and makes extraction public if included.

The Base transaction is the pointer layer. The artifact lives on Arweave. The plaintext testimony stays local unless the operator chooses to disclose it.

Manual broadcast settings:

- network: Base
- send: `0 ETH`
- to: null address or self
- data: paste the printed calldata

Recommended wallet for manual calldata broadcast: **Rabby**

Use `--steg-prompt` when publishing `STEG` manually. Literal `--steg` values can be visible in shell history and process lists.

## Repository Layout

- `cli/confess.py` - CLI for sealing, uploading, extracting, and verifying artifacts
- `cli/confess` - small entry wrapper for the CLI
- `web/` - static site and browser verifier deployed at `confessionstxt.art`
- `web/_headers` - Cloudflare Pages security headers for the static verifier
- `web/vendor/pretext/` - vendored Pretext browser layout dependency
- `scripts/bootstrap_mac.sh` - macOS setup helper
- `scripts/install_hstego_mac.sh` - macOS helper for building HStego with JPEG support

## Prerequisites

- Python **3.11 / 3.12** recommended
- `age`
- HStego with native JPEG support
- `ardrive` CLI
- Node/npm if installing `ardrive-cli`
- optional: `ssss-split` for Shamir secret splitting

Check the environment with:

```bash
python3 cli/confess.py doctor
```

## Install

### macOS

```bash
bash scripts/bootstrap_mac.sh
source .venv/bin/activate
```

The bootstrap script installs Homebrew prerequisites, creates `.venv`, installs Python/HStego dependencies, and runs `doctor`. If `ardrive-cli` is missing, it offers to install it with npm.

### Ubuntu

```bash
sudo apt-get update
sudo apt-get install -y age python3-pip build-essential libjpeg-dev python3-tk

python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip

python -m pip install imageio numpy scipy pycryptodome numba Pillow
python -m pip install git+https://github.com/daniellerch/hstego.git@v0.5

npm install -g ardrive-cli
```

## Operator Workflow

### 1. Run diagnostics

```bash
python3 cli/confess.py doctor
```

`doctor` checks local dependencies and prints install hints for missing pieces.

### 2. Store your Arweave wallet path

```bash
python3 cli/confess.py init
```

`init` stores the selected wallet path in `.confess/config.json`. The config is local and should remain out of version control.

### 3. Seal a testimony

Generated split-pass mode:

```bash
python3 cli/confess.py seal --image cover.jpg --text confession.md --gen-split-pass
```

Manual split-pass mode:

```bash
python3 cli/confess.py seal --image cover.jpg --text confession.md --split-pass-prompt
```

Single-pass mode:

```bash
python3 cli/confess.py seal --image cover.jpg --text confession.md --gen-single-pass
```

`seal` creates:

- `payload.tar.gz`
- `payload.age`
- `locked_artifact.jpg`
- `CSHA`

Before embedding, the CLI reports the HStego payload budget for the selected cover image. If payload use is high, the artifact may still be created, but statistical concealment is weaker. Use a larger or more detailed cover image, or reduce the testimony size.

First HStego runs can be slow because of native build and JIT overhead. The CLI prints 15-second progress updates during embedding.

### 4. Create or identify an ArDrive destination

Example:

```bash
ardrive create-drive --wallet-file /path/to/wallet.json --drive-name "CONFESSIONS"
```

For `confess.py push --folder-id`, use the folder `entityId` from the `created[]` item where `type == "folder"`.

Do not use:

- the drive `entityId`
- `metadataTxId`
- `bundleTxId`

If the drive already exists and the folder `entityId` is not saved, list the drive contents and reuse the target folder `entityId`.

### 5. Upload the locked artifact

```bash
python3 cli/confess.py push --file locked_artifact.jpg --folder-id <ARDRIVE_FOLDER_ENTITY_ID>
```

`push` prints:

- Arweave TXID
- `https://arweave.net/<TXID>`

### 6. Generate Base calldata

```bash
python3 cli/confess.py mint --title "Proof of Omertà" --txid <ARWEAVE_TXID> --csha <CSHA_SHA512>
```

Optional public extraction:

```bash
python3 cli/confess.py mint --title "Proof of Omertà" --txid <ARWEAVE_TXID> --csha <CSHA_SHA512> --steg-prompt
```

`mint` prints:

- the metadata string
- the `0x...` calldata to paste into the transaction input field

Keep `STEG` private unless public extraction is intentional.

## Verification

### Browser Verifier

Use the public verifier:

**https://confessionstxt.art/verify**

Direct locator URLs are also supported:

```text
https://confessionstxt.art/verify/<BASE_TX_HASH>
```

It resolves:

- Base transaction metadata
- linked Arweave artifact
- image preview and protocol record

The browser verifier is static and does not require a backend.

### Local Verification

Extract the encrypted payload:

```bash
python3 cli/confess.py extract --image locked_artifact.jpg --stego-pass-prompt
```

For single-pass artifacts, use `--single-pass-prompt` instead.

Verify the checksum:

```bash
python3 cli/confess.py verify --file payload.age --csha <CSHA_SHA512>
```

Decrypt after a successful checksum match:

```bash
python3 cli/confess.py verify --file payload.age --csha <CSHA_SHA512> --decrypt --age-pass-prompt
```

For single-pass artifacts, use `--single-pass-prompt` instead.

## Command Reference

- `python3 cli/confess.py --help` - print expanded help for all subcommands
- `doctor` - check dependencies and print install hints
- `init` - store Arweave wallet path and attempt address/balance lookup
- `seal` - package, encrypt, and embed a testimony file
- `push` - upload a locked artifact through ArDrive
- `mint` - generate Base calldata from title, TXID, and CSHA
- `extract` - recover `payload.age` from a locked artifact
- `verify` - compare `payload.age` against `CSHA` and optionally decrypt

## Operational Notes

- `.confess/config.json` is local configuration and should remain out of version control.
- Prefer `--*-prompt` flags for manual secrets, including `--steg-prompt` when publishing `STEG`.
- Commands refuse to overwrite generated outputs unless `--force` is supplied.
- Embedding capacity is constrained by cover image size, format, and payload rate.
- No stego method is guaranteed undetectable.
- If `STEG` is published, anyone can extract `payload.age` from the public artifact, but plaintext still requires the `age` passphrase.
- Keep plaintext, passphrases, wallet files, and decrypted archives out of screenshots, shell history, cloud sync folders, and public logs.
