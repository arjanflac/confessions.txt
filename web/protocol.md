# CONFESSIONS.txt Protocol Overview

CONFESSIONS.txt is a local-first terminal protocol for sealed testimony
artifacts. It creates a public, durable reference to a record without requiring
the record's plaintext to be public.

The protocol is severe by design: every step has a custody boundary.

## Artifact Flow

1. Record plaintext testimony locally.
2. Pack the testimony into `payload.tar.gz` so the original filename survives.
3. Encrypt the archive with `age` to create `payload.age`.
4. Embed `payload.age` into a carrier image with HStego.
5. Archive the locked carrier artifact on Arweave.
6. Publish a Base metadata label that points to the artifact and names its
   checksum.
7. Verify by extracting `payload.age` and comparing its SHA-512 hash with the
   published `CSHA`.

## Current Public Label

```text
TITLE | ARTXID:<ARWEAVE_TXID> | CSHA:<SHA512>
TITLE | ARTXID:<ARWEAVE_TXID> | CSHA:<SHA512> | STEG:<VALUE>
```

Fields:

- `TITLE`: human-readable record title.
- `ARTXID`: Arweave transaction id for the locked carrier artifact.
- `CSHA`: `sha512(payload.age)`, encoded as 128 hexadecimal characters.
- `STEG`: optional public extraction secret for recovering `payload.age` from
  the carrier image.

`STEG` makes extraction public. It does not disclose plaintext unless the `age`
passphrase is also disclosed.

## Public Material

The following may be public:

- Base transaction hash and transaction input metadata.
- Arweave transaction id.
- Locked carrier image, usually `locked_artifact.jpg`.
- `CSHA`.
- Optional `STEG`.
- Extracted `payload.age`, if the stego extraction path is public.

## Private Material

The following should remain local unless the operator intentionally discloses
it:

- Plaintext testimony.
- `payload.tar.gz`.
- `age` passphrase.
- Stego passphrase, unless published as `STEG`.
- Wallet files and private keys.
- Decrypted archives.

## CLI Surface

Run `./confess` to open the guided menu. The same operations are available as individual commands; see the [terminal reference](https://github.com/arjanflac/confessions.txt/blob/main/docs/cli.md) for all options.

```bash
./confess doctor
./confess init
./confess seal --image cover.jpg --text testimony.md --gen-split-pass --secrets-file record.secrets.json
./confess push --file locked_artifact.jpg --folder-id <ARDRIVE_FOLDER_ENTITY_ID> --ack-permanent-upload
./confess mint --title "Proof of Omerta" --txid <ARWEAVE_TXID> --csha <CSHA_SHA512>
./confess extract --image locked_artifact.jpg --stego-pass-prompt --out extracted_payload.age
./confess verify --file extracted_payload.age --csha <CSHA_SHA512>
```

Split-pass mode separates extraction from decryption. The stego passphrase can
extract `payload.age`; the `age` passphrase decrypts `payload.age` back into
`payload.tar.gz`.

## Security Boundary

CONFESSIONS.txt is not an anonymity system and not a complete safety plan.
Encryption comes from `age`. Steganography is concealment and transport, not a
guarantee of invisibility. Public verifiability comes from comparing
`sha512(payload.age)` to `CSHA`.

Sealing and decryption happen locally. Arweave publication uses ArDrive and
your wallet file to sign and send a paid upload. For Base, the application
only prepares transaction data; you sign and send it from your own wallet.

## Password disclosure

Public STEG permits extraction and offline password guesses against the encrypted
AGE payload. Use a strong, independently generated AGE password. A single-pass
artifact becomes decryptable if its STEG password is published. Local file
cleanup does not guarantee secure erasure from disks, backups, or snapshots.
