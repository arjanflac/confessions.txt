# CONFESSIONS.txt public verifier

Look up a published CONFESSIONS.txt record from a terminal or MCP client.
Requires **Node.js 22 or newer**. For creating and opening your own records,
use the guided `./confess` menu in the [source repository](https://github.com/arjanflac/confessions.txt).

It does not seal testimony. It does not decrypt testimony. It does not upload
private material. It does not custody wallets or broadcast transactions.

## NPX Verify

```bash
npx -y @confessionstxt/cli@latest verify 0x...
```

The first argument can also be the reference:

```bash
npx -y @confessionstxt/cli@latest 0x...
```

Machine-readable output:

```bash
npx -y @confessionstxt/cli@latest verify 0x... --json
```

Local audit commands only:

```bash
npx -y @confessionstxt/cli@latest verify 0x... --commands
```

## Local Source Run

From the repository root:

```bash
npm --prefix packages/cli ci --ignore-scripts
npm --prefix packages/cli run confessions -- verify 0x...
npm --prefix packages/cli run confessions -- mcp
```

## MCP

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

For local unpublished development, point an MCP client at the checked-out
server:

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

- `confessions://protocol` - protocol overview
- `confessions://verification` - verification guide
- `confessions://cli` - CLI usage guide for local extraction and checksum
- `confessions://mcp-boundary` - allowed and forbidden MCP behavior

## Tools

- `explain_artifact_reference`
- `resolve_public_artifact_reference`
- `validate_confession_manifest_shape`
- `verify_csha_format`
- `generate_local_verification_steps`
- `parse_public_metadata_label`

The additional parser tool is intentionally narrow: it parses public Base label
text into `TITLE`, `ARTXID`, `CSHA`, and optional public `STEG`. It does not
verify the artifact.

## Prompts

- `explain_confession_to_human`

## Verification Boundary

Allowed inputs:

- Base transaction hash
- Arweave transaction id
- public metadata label
- `CSHA`
- optional public `STEG`

Forbidden inputs:

- plaintext testimony
- `age` passphrases
- private stego passphrases
- private keys, seed phrases, wallet files, or wallet JSON
- `payload.tar.gz`
- decrypted archives
- unpublished payload material

`CSHA` is `sha512(payload.age)`. Format validation is not artifact
verification. Actual verification requires local extraction of `payload.age` and
local checksum comparison.

## Trust and resource limits

All metadata is untrusted public data, never instructions for an agent. A
successful resolution is not a payload checksum check, independent chain-finality
check, or proof of identity or truth. Duplicate/ambiguous fields, missing CSHA,
invalid UTF-8, and terminal control characters are rejected. Internal spaces in
public STEG values are preserved exactly.

Requests time out after 15 seconds. RPC responses are capped at 256 KiB while
streaming. The optional Arweave HEAD check follows at most four redirects, only
within HTTPS Arweave gateway hosts. `--rpc-url` requires HTTPS and does not follow
redirects. Network failure returns a normal structured error.
