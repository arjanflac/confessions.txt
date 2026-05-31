# CONFESSIONS.txt MCP Server

This package is the read-only MCP surface for CONFESSIONS.txt public artifact
verification. It is specific to the protocol used by `confessionstxt.art`.

It does not seal testimony. It does not decrypt testimony. It does not fetch or
upload private material. It does not custody wallets or broadcast transactions.

## Local Source Run

From the repository root:

```bash
npm --prefix mcp install
npm --prefix mcp start
```

For an MCP client configuration during local development, use an absolute path:

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

## Published Package

Once `@confessionstxt/mcp` is published to npm, the client command should be:

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

Do not use the npm command until the package has actually been published.

## Resources

- `confessions://protocol` - protocol overview
- `confessions://verification` - verification guide
- `confessions://cli` - CLI usage guide for local extraction and checksum
- `confessions://mcp-boundary` - allowed and forbidden MCP behavior

## Tools

- `explain_artifact_reference`
- `validate_confession_manifest_shape`
- `verify_csha_format`
- `generate_local_verification_steps`
- `parse_public_metadata_label`

The additional parser tool is intentionally narrow: it parses public Base label
text into `TITLE`, `ARTXID`, `CSHA`, and optional public `STEG`. It does not
verify the artifact.

## Prompts

- `explain_confession_to_human`
- `should_this_person_contact_arjan`

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
