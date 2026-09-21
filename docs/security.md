# Security model

CONFESSIONS.txt encrypts locally with age, embeds that ciphertext using HStego, and optionally publishes an image on Arweave with a reference on Base. This document describes what those layers establish and what they do not.

## Confidentiality and passwords

AGE is the encryption boundary. HStego is a concealment and transport layer. An attacker who detects the hidden data, knows the STEG password, or downloads `payload.age` still needs the AGE password to decrypt it.

The generator uses Python's `secrets.token_bytes(32)` independently for each password and encodes it as 43 URL-safe characters. This supplies 256 bits of randomness before encoding. Exhaustively guessing an independently generated secret at that size is not a realistic attack. That assessment assumes a working OS random source, correct dependencies, and no disclosure of the secret.

A public ciphertext allows unlimited offline password guesses. Short or reused human passwords are at risk regardless of hiding. A failed dictionary test is not proof of strength. Public STEG is appropriate only when the AGE password is independent and strong. Single-password records lose confidentiality if STEG is published.

There is no recovery key or reset service. Generated password files are plaintext, written with mode 0600. Copy the passwords into a password manager and keep backups deliberately. Losing a password can make the record unreadable.

## Local handling

- Plaintext intermediate archives are created in private temporary directories and removed after encryption, including normal error and cancellation paths.
- Hidden password prompts fail closed if a private terminal is unavailable. The age subprocess receives passwords over a private pipe and a non-echoing terminal, not arguments or environment variables.
- Secret control characters are rejected. Native-tool diagnostics that might contain sensitive material are withheld.
- Completed outputs use mode 0600. Output preflight rejects symlinks and input aliases; per-file atomic publication protects existing files from failed operations. The related output files are not committed as a single transaction.
- Sealing checks a full embed/extract round trip before publishing local outputs. Decryption rechecks a private copy of the ciphertext after the password prompt.
- The menu requires a deliberate upload confirmation. The command interface requires `--ack-permanent-upload` and `--ack-public-steg` for the corresponding permanent actions.

These measures do not defend against malware, a hostile local user with access to the same account, modified executables on PATH, live memory inspection, or an attacker concurrently controlling the workspace. Use a private directory on a trusted computer. Cleanup cannot securely erase SSD remnants, swap, filesystem snapshots, backups, or terminal recordings. The original text file remains where you put it.

## Public verification

`CSHA = sha512(payload.age)`. A matching checksum establishes that the extracted encrypted bytes match the referenced checksum. It does not establish author identity, truth, consent, or the date the plaintext was first written.

The browser and npm verifier resolve public metadata using third-party RPCs and gateways. They check transaction hash, Base chain ID, and reported block inclusion. They do not independently validate consensus or finality. Metadata is untrusted data, including for an MCP client.

The browser does not extract or decrypt the hidden payload. “Metadata Resolved” is separate from the local checksum comparison. The npm/MCP package never asks for plaintext, private passphrases, or wallets and does not execute the commands it generates.

The shared metadata parser rejects malformed UTF-8, duplicate/ambiguous fields, terminal controls, and incomplete current-format labels. Generated shell commands validate identifiers and quote values. Terminal output escapes control and bidirectional formatting characters.

## Network and browser limits

RPC requests time out after 15 seconds and cap responses at 256 KiB while streaming. Arweave HEAD requests permit at most four redirects within HTTPS Arweave gateway hosts. The browser caps previews at 25 MiB, checks JPEG/PNG signatures and dimensions before decoding, and allows at most 16 megapixels and 8,192 pixels per side. Preview pixels still pass through the browser's image decoder.

The static Pages site uses a script CSP without `unsafe-inline` or `unsafe-eval`. Two JSON-LD blocks are allowed by exact hashes. Styles still require `unsafe-inline`. Fonts and scripts are served locally. Framing is denied, referrers are suppressed, and HTTPS is enforced. Opening a public reference makes requests to Base and Arweave that can reveal the visitor's IP and interest in that record.

## Remaining trust and limitations

- HStego includes native C/C++ code and has not received a complete native memory-safety review here. Its JPEG/image dependencies process attacker-controlled files. Run extraction of unfamiliar artifacts in a disposable environment when appropriate. No claim of undetectable steganography is made.
- Package vulnerability scanners cover known advisories, not all implementation flaws. HStego's source installation is not covered by the PyPI advisory lookup.
- Permanent storage and chain records cannot reliably be revoked. Deleting a social post does not remove the uploaded ciphertext. Wallet activity can identify the publisher.
- Recompression, resizing, or editing can destroy the hidden data. Preserve and verify the original uploaded bytes.
- The app does not prove an arbitrary selected image is an encrypted artifact. Review the file before upload.
- macOS Apple Silicon is the native environment tested for this release. Other platforms and funded ArDrive uploads need separate validation.

For a suspected vulnerability, avoid posting private testimony, keys, passwords, or decrypted material in a public issue. A minimal reproduction using synthetic data is sufficient for ordinary bugs; share exploitable vulnerabilities privately with the maintainer first.
