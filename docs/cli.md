# Terminal reference

Start with `./confess` for the guided menu. Its operations use the same handlers as the commands below. The commands remain available for scripts and the instructions produced by the public verifier.

Run `./confess --help` for all options, or `./confess seal --help` for one operation. From a separate private workspace, use the launcher's absolute path instead. Paths are relative to your current working directory; the launcher still finds the repository's `.venv`.

## Setup

On macOS, run `bash scripts/bootstrap_mac.sh`. This installs Python 3.12, age, JPEG libraries, pinned Python dependencies, and HStego. The installer verifies the HStego v0.6.1 source commit before building it. Apple Silicon needs compatibility patches applied by `scripts/install_hstego_mac.sh`.

Homebrew and Xcode Command Line Tools must already be installed. An existing `.venv` must use Python 3.12. Move an incompatible environment aside before rerunning setup.

ArDrive is optional and used only for paid uploads. The bootstrap script offers to install it with npm. Node.js 22 or newer is needed for public lookups; install the package dependencies for MCP development:

```bash
npm --prefix packages/cli ci --ignore-scripts
./confess doctor
```

Linux requires Python 3.12 and its venv support, age, a C/C++ toolchain, libjpeg headers, and Python Tk support. Create a Python 3.12 virtual environment, install `requirements.txt`, then build HStego from commit `bf71f6e0d7faaa632ad8a988c0393e94bfd13b2a`. The native Linux build has not been validated for this release; the macOS script is not portable to Linux. Windows is not supported by the POSIX age password bridge.

## Seal

Prefer separate generated passwords saved directly to a private file:

```bash
./confess seal --image cover.jpg --text confession.txt \
  --gen-split-pass --secrets-file record.secrets.json
```

Or enter two passwords using hidden prompts:

```bash
./confess seal --image cover.png --text confession.txt --split-pass-prompt
```

New manual AGE passwords must be at least 20 characters. Length is a minimum, not a strength guarantee. Split passwords must differ. Passwords cannot contain terminal controls and are limited to 1,024 UTF-8 bytes. Existing short-password records can still be decrypted.

`seal` packs the text, encrypts it with age, embeds the ciphertext, and verifies extraction before saving `payload.age` and the image. Both outputs are private files with mode 0600. Plaintext intermediate archives live in a mode-0700 temporary directory and are removed after encryption. Deletion is not secure erasure of snapshots or backups.

JPEG covers default to `locked_artifact.jpg`; spatial covers default to `locked_artifact.png`. Spatial embedding requires lossless PNG output. Use `--out PATH` to choose the image name. `payload.age` is saved in the same directory, which must already exist. Keep separate records in separate folders.

The preflight reports the image's payload capacity. A larger, more detailed image or a shorter text gives the embedding more room. The first native run can take several minutes for compilation; embedding prints progress every 15 seconds.

The secret file is created before encryption so generated passwords survive a later failure. A failed seal may therefore leave that private file; inspect it before retrying with a new filename. Without `--secrets-file`, generated passwords can be shown only in an interactive terminal. Avoid recording that terminal.

Legacy single-password creation remains available with `--gen-single-pass` or `--single-pass-prompt`. Publishing STEG for such a record also publishes its decryption password. The menu always creates split-password records.

Literal `--age-pass`, `--stego-pass`, and `--single-pass` arguments exist for compatibility. Prefer hidden prompts: literal arguments can appear in shell history and process listings.

## Extract, check, and decrypt

```bash
./confess extract --image locked_artifact.jpg --stego-pass-prompt \
  --out extracted_payload.age
./confess verify --file extracted_payload.age --csha <EXPECTED_CSHA>
./confess verify --file extracted_payload.age --csha <EXPECTED_CSHA> \
  --decrypt --age-pass-prompt --out decrypted_payload.tar.gz
```

Older records made with HStego v0.5 need `--legacy-hstego` on the extraction command, or the legacy choice in the menu. The bootstrap installs a checksum-pinned compatibility reader with its license; on another supported environment, install it using `.venv/bin/python scripts/install_legacy_hstego.py`. The legacy reader uses the current decoder’s length checks and is never selected automatically or used for new seals. Always compare the recovered payload against the original CSHA.

For a legacy single-password record, use `--single-pass-prompt` at both password steps. Extraction recognizes JPEG/PNG content even if the downloaded extension is wrong.

The expected CSHA must come from the public record or your original local sealing output. Calculating it from an untrusted download and comparing it to itself establishes nothing. Decryption proceeds only after a match, using a private copy that is checked again before age runs. The resulting archive contains the original text filename; extraction of that archive is left to you.

Commands refuse existing outputs unless you add `--force`. Even with `--force`, an output cannot alias an input, and existing files survive encryption/extraction/decryption failures. Each file is published atomically; the set of image, payload, and secret files is not a single filesystem transaction. An interruption during final publication can leave only some outputs.

## Upload to Arweave

A wallet is needed only here. `./confess init` validates a local Arweave JWK and stores its absolute path in `.confess/config.json` in the current workspace. It derives the public address locally and requests its balance from Arweave. It does not copy or upload the private key.

Create or select your ArDrive folder using ArDrive's own tools. Supply the folder's `entityId`, not a drive ID, metadata transaction ID, or bundle ID.

```bash
./confess push --file locked_artifact.jpg --folder-id <FOLDER_ENTITY_ID> \
  --ack-permanent-upload
```

This passes the wallet path to ArDrive, which signs and sends a paid upload. The file must have JPEG/PNG content and a matching supported extension. The program cannot prove that an arbitrary image is safe to publish; choose the sealed artifact carefully. It reports a TXID only from a typed file upload receipt's `dataTxId`. If a tool fails after submitting, inspect ArDrive before retrying; a missing receipt does not prove nothing was uploaded.

## Prepare a Base transaction

```bash
./confess mint --title "Proof of Omertà" --txid <ARWEAVE_TXID> --csha <CSHA>
```

To deliberately make extraction public for a split-password record:

```bash
./confess mint --title "Proof of Omertà" --txid <ARWEAVE_TXID> --csha <CSHA> \
  --steg-prompt --ack-public-steg
```

The label is UTF-8 text:

```text
TITLE | ARTXID:<ARWEAVE_TXID> | CSHA:<SHA512> | STEG:<OPTIONAL_PUBLIC_PASSWORD>
```

`mint` prints the label and its hex calldata. Review it before signing. On Base, send 0 ETH to yourself or the null address and put the calldata in the transaction's data field. Gas still costs money. The application never broadcasts this transaction.

Whitespace at the edges of a published STEG value, control characters, and the `|` delimiter are rejected. Internal spaces are preserved. An AGE password must never be included. The program cannot infer whether manually supplied STEG was reused as the AGE password; that check is your responsibility.

## Public lookup and MCP

```bash
node packages/cli/bin/confessions.mjs verify <PUBLIC_REFERENCE>
node packages/cli/bin/confessions.mjs verify <PUBLIC_REFERENCE> --json
node packages/cli/bin/confessions.mjs mcp
```

The reference can be a Base hash, Arweave TXID, verifier URL, or public metadata label. Use `--no-artifact-check` to skip the Arweave HEAD request. A Base hash still needs an RPC lookup. Use `--` before a reference beginning with a dash. See the [package documentation](../packages/cli/README.md) for client configuration and its read-only boundary.
