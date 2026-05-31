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

The CLI is command-oriented:

```bash
python3 cli/confess.py doctor
python3 cli/confess.py init
python3 cli/confess.py seal --image cover.jpg --text testimony.md --gen-split-pass
python3 cli/confess.py push --file locked_artifact.jpg --folder-id <ARDRIVE_FOLDER_ENTITY_ID>
python3 cli/confess.py mint --title "Proof of Omerta" --txid <ARWEAVE_TXID> --csha <CSHA_SHA512>
python3 cli/confess.py extract --image locked_artifact.jpg --stego-pass-prompt
python3 cli/confess.py verify --file payload.age --csha <CSHA_SHA512>
```

Split-pass mode separates extraction from decryption. The stego passphrase can
extract `payload.age`; the `age` passphrase decrypts `payload.age` back into
`payload.tar.gz`.

## Security Boundary

CONFESSIONS.txt is not an anonymity system and not a complete safety plan.
Encryption comes from `age`. Steganography is concealment and transport, not a
guarantee of invisibility. Public verifiability comes from comparing
`sha512(payload.age)` to `CSHA`.

There is no hosted sealing service in the current protocol. The CLI does not
receive files, hold keys, custody wallets, or broadcast transactions. The
operator controls disclosure.
