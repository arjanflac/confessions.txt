# CONFESSIONS.txt CLI + MCP

CONFESSIONS.txt publishes one npm package for public verification:

```text
@confessionstxt/cli
```

It has two surfaces:

- Human terminal verification via `npx`.
- Agent verification context via a read-only MCP stdio server.

It is not a remote confession intake surface. It does not seal testimony,
decrypt testimony, upload files, custody wallets, broadcast transactions, or
request secrets.

## Terminal Verify

```bash
npx -y @confessionstxt/cli@latest verify 0x...
```

The short form also works:

```bash
npx -y @confessionstxt/cli@latest 0x...
```

Useful flags:

```bash
npx -y @confessionstxt/cli@latest verify 0x... --json
npx -y @confessionstxt/cli@latest verify 0x... --commands
```

The command resolves public Base calldata, parses the CONFESSIONS.txt metadata
label, prints public provenance, and emits local audit commands. It does not
decrypt payloads.

## MCP Install

```json
{
  "mcpServers": {
    "confessions-txt": {
      "command": "npx",
      "args": ["-y", "@confessionstxt/cli@latest", "mcp"]
    }
  }
}
```

This starts a local stdio MCP process. It is still local process execution, not
a hosted verifier.

## Local Source Run

From a local checkout:

```bash
git clone https://github.com/arjanflac/confessions.txt
cd confessions.txt
npm --prefix packages/cli install
npm --prefix packages/cli run confessions -- verify 0x...
npm --prefix packages/cli run confessions -- mcp
```

For an MCP client during unpublished local development, use an absolute path:

```json
{
  "mcpServers": {
    "confessions-txt": {
      "command": "node",
      "args": ["/absolute/path/to/confessions.txt/packages/cli/server.mjs"]
    }
  }
}
```

## Resources

### `confessions://protocol`

Protocol overview: artifact flow, public/private layers, metadata label format,
and security boundary.

### `confessions://verification`

Verification guide: accepted public references, checksum model, public inputs,
and remote-model privacy boundary.

### `confessions://cli`

CLI usage guide: local extraction and checksum commands:

```bash
python3 cli/confess.py extract --image locked_artifact.jpg --stego-pass-prompt
python3 cli/confess.py verify --file payload.age --csha <CSHA_SHA512>
```

### `confessions://mcp-boundary`

Allowed and forbidden MCP behavior.

## Tools

### `explain_artifact_reference`

Classifies and explains a public reference.

Accepted public shapes:

- Base transaction hash
- BaseScan transaction URL
- `confessionstxt.art/verify/...` URL
- Arweave transaction id
- Arweave URL
- legacy CID-like value
- public metadata label

### `resolve_public_artifact_reference`

Resolves a public Base transaction hash, verifier URL, Arweave TXID, or metadata
label into public provenance and local audit commands. It may make public Base
RPC and Arweave header requests. It does not download private material or
decrypt anything.

### `validate_confession_manifest_shape`

Validates a public manifest object:

```json
{
  "title": "Proof of Omerta",
  "artxid": "43-character Arweave transaction id",
  "csha": "128-character SHA-512 hex",
  "steg": "optional public STEG"
}
```

It rejects control characters, pipe-delimited title breaks, malformed ARTXID,
malformed CSHA, and malformed public `STEG`.

### `verify_csha_format`

Checks that a CSHA value is exactly 128 hexadecimal characters and normalizes
case for display.

This is syntax only. It is not artifact verification.

### `generate_local_verification_steps`

Generates local shell commands for the human operator.

Input may include:

```json
{
  "base_tx_hash": "0x...",
  "artxid": "<ARWEAVE_TXID>",
  "csha": "<CSHA_SHA512>",
  "public_steg": "<PUBLIC_STEG>"
}
```

Output may include:

```bash
curl -fL -o locked_artifact.jpg "https://arweave.net/<ARWEAVE_TXID>"
python3 cli/confess.py extract --image locked_artifact.jpg --stego-pass-prompt
python3 cli/confess.py verify --file payload.age --csha <CSHA_SHA512>
```

If `public_steg` is explicitly provided, the extraction command may include the
public value. The server must never ask for a private stego passphrase.

### `parse_public_metadata_label`

Parses:

```text
TITLE | ARTXID:<ARWEAVE_TXID> | CSHA:<SHA512>
TITLE | ARTXID:<ARWEAVE_TXID> | CSHA:<SHA512> | STEG:<VALUE>
```

Parsing is not proof. Local verification still requires extracting
`payload.age` and comparing `sha512(payload.age)` to `CSHA`.

## Prompts

### `explain_confession_to_human`

Explains CONFESSIONS.txt in severe, precise, art-aware language. It must avoid
claims of anonymity, guaranteed safety, hosted decryption, or generic SaaS
positioning.

### `should_this_person_contact_arjan`

Routes project-specific collaborators toward Arjan when the request concerns
curation, net art, public records, protocol critique, cryptography, local-first
tooling, verification, experimental publishing, agent/MCP integration, or
criptech-adjacent research.

It should reject wedding, portrait, broad photography booking, generic
marketing, and remote-decryption interpretations.

## Hard Boundary

The CLI and MCP server may handle public reference material only.

Allowed:

- Base transaction hashes
- Arweave transaction ids
- public metadata labels
- `CSHA`
- optional public `STEG`
- local command generation
- protocol explanation

Forbidden:

- plaintext testimony
- `age` passphrases
- private stego passphrases
- private keys, seed phrases, wallet files, or wallet JSON
- `payload.tar.gz`
- decrypted archives
- unpublished payload material
- remote decryption
- server-side access claims

`CSHA` is `sha512(payload.age)`, not a hash of the plaintext. A checksum match
proves continuity between the encrypted payload and the public reference. It
does not prove that the testimony is true.
