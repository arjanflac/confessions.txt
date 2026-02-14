# CONFESSIONS.TXT (R&D)

CONFESSIONS.TXT is a local-first evidence toolchain that packages testimony and encrypts it with `age` into `payload.age`, embeds that encrypted payload into an image carrier with HStego, stores the locked artifact on Arweave for decentralized permanent retrieval by TXID, and publishes titled integrity metadata on Base for verifiable provenance.

The project has two user-facing components:
- `cli/confess.py`: build, upload, and verify artifacts.
- `web/verify.html`: inspect Base tx input data or resolve an Arweave TXID.

## How The Pipeline Works
1. Package plaintext testimony into `payload.tar.gz` so the source content has a deterministic archive boundary.
2. Encrypt `payload.tar.gz` with `age` (passphrase mode) to produce `payload.age`, which becomes the confidential evidence artifact.
3. Embed `payload.age` into a cover image using HStego (J-UNIWARD/S-UNIWARD) so transport appears as a normal media file.
4. Upload the locked artifact image to Arweave via ArDrive for decentralized, durable retrieval by TXID.
5. Generate Base calldata that anchors titled metadata for publication and verification:
`V:2|TITLE:<...>|AR:<ARWEAVE_TXID>|CSHA:<SHA512(payload.age)>|ALG:SHA512|FILE:<...>|NOTE:R&D`

`seal` computes CSHA from `payload.age` (not the plaintext tarball).

## Prerequisites
- Python `3.11` or `3.12` recommended (`3.9+` minimum).
- `age` CLI.
- HStego (`hstegolib`) with native extensions.
- `ardrive` CLI.
- Optional: `ssss-split` for passphrase sharing.

`confess doctor` checks tool availability and prints install hints.

## Install
macOS:
```bash
xcode-select --install
brew install python@3.12 age jpeg
$(brew --prefix python@3.12)/bin/python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install imageio numpy scipy pycryptodome numba Pillow
bash scripts/install_hstego_mac.sh
npm install -g ardrive-cli
```

Ubuntu:
```bash
sudo apt-get update
sudo apt-get install -y age python3-pip build-essential libjpeg-dev python3-tk
python3 -m pip install imageio numpy scipy pycryptodome numba Pillow
python3 -m pip install git+https://github.com/daniellerch/hstego.git@v0.5
npm install -g ardrive-cli
```

## End-To-End Quickstart
1. Run environment checks:
```bash
python3 cli/confess.py doctor
```
2. Configure wallet path:
```bash
python3 cli/confess.py init
```
Then enter your Arweave `wallet.json` path when prompted. `init` stores the path in `.confess/config.json` and attempts a live balance check.

3. Seal testimony into a locked artifact:
```bash
python3 cli/confess.py seal --image cover.jpg --text confession.md --generate-pass
```
This writes `payload.age`, emits `CSHA (sha512 of payload.age)`, and produces `locked_artifact.jpg` by default.

4. Create an ArDrive destination and capture the folder ID:
```bash
ardrive create-drive --wallet-file /path/to/wallet.json --drive-name "CONFESSIONS"
```

5. Upload artifact:
```bash
python3 cli/confess.py push --file locked_artifact.jpg --folder-id <ARDRIVE_FOLDER_ID>
```
`push` outputs an Arweave TXID and URL.

6. Generate Base calldata that references the Arweave TXID + CSHA:
```bash
python3 cli/confess.py mint --title "Proof of Omerta" --txid <ARWEAVE_TXID> --csha <CSHA_SHA512>
```
Broadcast this calldata manually from your wallet on Base.

## Command Reference
- `doctor`: check runtime/toolchain dependencies.
- `init`: store wallet path and derive wallet address; also attempts an on-chain AR balance check.
- `seal`: create encrypted payload + stego artifact. Required: `--image`, `--text`, and one of `--master-pass` or `--generate-pass`.
- `push`: upload locked artifact to Arweave through ArDrive. Required: `--file` and `--folder-id` (or `ARDRIVE_PARENT_FOLDER_ID` / `ARDRIVE_FOLDER_ID` env var).
- `mint`: generate Base tx input metadata. Required: `--title`, `--txid`, and `--csha`.
- `extract`: recover `payload.age` from locked artifact. Required: `--image` and one of `--master-pass` or `--stego-pass`.
- `verify`: compare `sha512(payload.age)` to expected CSHA and optionally decrypt.

## Verification Flow
1. Open `web/verify.html`.
2. Input either a Base transaction hash (`0x...`) containing CONFESSIONS metadata, or an Arweave TXID directly.
3. Confirm the resolved `AR` value (Arweave TXID) and `CSHA`.
4. Download the artifact from Arweave, extract `payload.age`, and verify locally:
```bash
python3 cli/confess.py verify --file payload.age --csha <CSHA_SHA512>
python3 cli/confess.py verify --file payload.age --csha <CSHA_SHA512> --decrypt --master-pass "<MASTER_PASS>"
```

## Notes For Operators
- Steganography is obfuscation; confidentiality comes from `age` encryption.
- HStego uses adaptive algorithms to reduce detectability, but no stego method is guaranteed undetectable.
- First HStego run can be slow due to JIT/native compile overhead.
- If `init` reports balance-check unavailable, network/API access may be blocked; uploads can still be attempted.
