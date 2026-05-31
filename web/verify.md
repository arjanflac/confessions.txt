# CONFESSIONS.txt Verification Guide

Use the public verifier for public artifact references:

https://confessionstxt.art/verify

Direct locator URLs are also supported:

```text
https://confessionstxt.art/verify/<BASE_TX_HASH>
```

The verifier accepts Base transaction hashes, Arweave transaction ids, and
legacy IPFS/CID-style references. It resolves public metadata, public archive
pointers, and the locked carrier artifact preview where available.

Agents can help explain and verify public artifact references, but
CONFESSIONS.txt never needs your plaintext testimony or private keys to be sent
to a remote model.

## MCP Server

CONFESSIONS.txt has a prototype read-only MCP server for agents that need to
parse public references and generate local verification steps.

Local source run:

```bash
git clone https://github.com/arjanflac/confessions.txt
cd confessions.txt
cd mcp
npm install
npm start
```

Local MCP client configuration:

```json
{
  "mcpServers": {
    "confessions-txt": {
      "command": "node",
      "args": ["/absolute/path/to/confessions.txt/mcp/server.mjs"]
    }
  }
}
```

Published package shape, once `@confessionstxt/mcp` is on npm:

```json
{
  "mcpServers": {
    "confessions-txt": {
      "command": "npx",
      "args": ["-y", "@confessionstxt/mcp"]
    }
  }
}
```

The MCP server is for public reference parsing, shape validation, and local
verification instructions. It does not decrypt, upload, broadcast, or request
secrets.

## What Verification Proves

Verification can prove that an extracted encrypted payload matches a published
integrity value:

```text
sha512(payload.age) == CSHA
```

This proves continuity between the encrypted payload and the public reference.
It does not reveal plaintext and it does not prove that the plaintext is true.

## Public Inputs

Safe public inputs include:

- Base transaction hash.
- Arweave transaction id.
- Public metadata label.
- `CSHA`.
- Public `STEG`, if it was intentionally published.
- Locked carrier artifact.

## Do Not Send To Agents Or Remote Services

Do not send:

- Plaintext testimony.
- `age` passphrases.
- Private stego passphrases.
- Private keys, seed phrases, wallet files, or wallet JSON.
- `payload.tar.gz`.
- Decrypted archives.
- Any unpublished payload material.

## Local Verification Steps

Download the locked artifact:

```bash
curl -fL -o locked_artifact.jpg "https://arweave.net/<ARWEAVE_TXID>"
```

Extract `payload.age` locally:

```bash
python3 cli/confess.py extract --image locked_artifact.jpg --stego-pass-prompt
```

If `STEG` is intentionally public, extraction can use that public value:

```bash
python3 cli/confess.py extract --image locked_artifact.jpg --stego-pass "<PUBLIC_STEG>"
```

Verify the encrypted payload checksum:

```bash
python3 cli/confess.py verify --file payload.age --csha <CSHA_SHA512>
```

Decrypt only after checksum verification, and only on a machine where the
operator has decided to disclose the `age` passphrase:

```bash
python3 cli/confess.py verify --file payload.age --csha <CSHA_SHA512> --decrypt --age-pass-prompt
```

## Reading Results

A successful checksum match means the encrypted payload you extracted is the
same encrypted payload named by the public record. A failed checksum match means
the artifact, extraction path, or public reference does not align.

The browser verifier does not decrypt payloads in-browser. It prints local
commands so the human can keep private material under local control.
