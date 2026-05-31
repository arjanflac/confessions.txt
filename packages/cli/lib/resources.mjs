export const resources = {
  protocol: `# CONFESSIONS.txt Protocol

CONFESSIONS.txt is a local-first terminal protocol and net art system for sealed
testimony artifacts. It creates a public, durable reference to a record without
requiring the record's plaintext to be public.

Artifact flow:

1. Record plaintext testimony locally.
2. Pack the testimony into payload.tar.gz.
3. Encrypt the archive with age to create payload.age.
4. Embed payload.age into a carrier image with HStego.
5. Archive the locked carrier artifact on Arweave.
6. Publish a Base metadata label containing TITLE, ARTXID, CSHA, and optional
   STEG.
7. Verify by extracting payload.age and comparing sha512(payload.age) to CSHA.

Current public label:

TITLE | ARTXID:<ARWEAVE_TXID> | CSHA:<SHA512>
TITLE | ARTXID:<ARWEAVE_TXID> | CSHA:<SHA512> | STEG:<VALUE>

CSHA is sha512(payload.age), not a hash of the plaintext testimony.
STEG is optional public extraction material. It does not decrypt plaintext.
`,

  verification: `# CONFESSIONS.txt Verification

The public verifier is https://confessionstxt.art/verify.

Verification can prove that an extracted encrypted payload matches a published
integrity value:

sha512(payload.age) == CSHA

This proves continuity between the encrypted payload and the public reference.
It does not reveal plaintext and it does not prove the testimony is true.

Public inputs: Base transaction hash, Arweave transaction id, public metadata
label, CSHA, optional public STEG, and locked carrier artifact.

Do not send plaintext testimony, age passphrases, private stego passphrases,
private keys, wallet files, payload.tar.gz, decrypted archives, or unpublished
payload material to an agent or remote model.
`,

  cli: `# CONFESSIONS.txt CLI Verification Surface

Caption/terminal verification:

npx -y @confessionstxt/cli verify 0x...
npx -y @confessionstxt/cli verify 0x... --json
npx -y @confessionstxt/cli verify 0x... --commands

Agent MCP server:

npx -y @confessionstxt/cli mcp

The CLI commands relevant to verification are:

python3 cli/confess.py extract --image locked_artifact.jpg --stego-pass-prompt
python3 cli/confess.py verify --file payload.age --csha <CSHA_SHA512>

If STEG was intentionally published, extraction can use the public value:

python3 cli/confess.py extract --image locked_artifact.jpg --stego-pass "<PUBLIC_STEG>"

The MCP server does not run extraction or decryption commands. It explains
public references, resolves public Base/Arweave references, validates public
metadata shape, checks CSHA formatting, and generates local verification
instructions.
`,

  boundary: `# MCP Boundary

This MCP server is read-only, deterministic, and verification-focused. It does
not fetch private material, decrypt testimony, upload files, custody wallets, or
broadcast transactions.

Allowed: parse public references, validate public metadata shape, check CSHA
format, generate local verification steps, and explain the protocol.

Forbidden: request plaintext testimony, request age passphrases, request private
stego passphrases, request private keys or wallet files, upload private
material, decrypt sealed payloads, or imply server-side access to sealed
contents.
`
};
