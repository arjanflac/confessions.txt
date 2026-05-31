#!/usr/bin/env node
import { createRequire } from "node:module";

import { formatVerificationJson, formatVerificationText } from "../lib/output.mjs";
import { resolveVerificationReference } from "../lib/verify.mjs";

const require = createRequire(import.meta.url);
const pkg = require("../package.json");

function printHelp() {
  process.stdout.write(`CONFESSIONS.txt CLI

Usage:
  confessions verify <reference> [--json] [--commands] [--no-artifact-check]
  confessions <reference> [--json] [--commands] [--no-artifact-check]
  confessions mcp

References:
  Base transaction hash, verifier URL, Arweave TXID, Arweave URL, or public metadata label.

Options:
  --json                 Print machine-readable JSON.
  --commands             Print only local audit commands.
  --no-artifact-check    Do not make an Arweave HEAD request.
  --rpc-url <url>        Base JSON-RPC endpoint. Defaults to https://mainnet.base.org.
  -h, --help             Show help.
  -v, --version          Show version.

Examples:
  npx -y @confessionstxt/cli verify 0x1fc1...
  npx -y @confessionstxt/cli 0x1fc1... --json
  npx -y @confessionstxt/cli mcp
`);
}

function parseArgs(argv) {
  const flags = {
    json: false,
    commandsOnly: false,
    checkArtifact: true,
    rpcUrl: null
  };
  const positional = [];

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--json") flags.json = true;
    else if (arg === "--commands") flags.commandsOnly = true;
    else if (arg === "--no-artifact-check") flags.checkArtifact = false;
    else if (arg === "--rpc-url") {
      i += 1;
      flags.rpcUrl = argv[i] || null;
    } else if (arg.startsWith("--rpc-url=")) {
      flags.rpcUrl = arg.slice("--rpc-url=".length);
    } else if (arg === "-h" || arg === "--help") {
      flags.help = true;
    } else if (arg === "-v" || arg === "--version") {
      flags.version = true;
    } else {
      positional.push(arg);
    }
  }

  return { flags, positional };
}

async function runVerify(reference, flags) {
  const record = await resolveVerificationReference(reference, {
    rpcUrl: flags.rpcUrl,
    checkArtifact: flags.checkArtifact
  });
  const output = flags.json ? formatVerificationJson(record) : formatVerificationText(record, flags);
  process.stdout.write(output);
  return record.valid ? 0 : 1;
}

async function main() {
  const { flags, positional } = parseArgs(process.argv.slice(2));
  const command = positional[0] || null;

  if (flags.version) {
    process.stdout.write(`${pkg.version}\n`);
    return 0;
  }

  if (flags.help || !command) {
    printHelp();
    return flags.help ? 0 : 1;
  }

  if (command === "mcp") {
    const { runMcpServer } = await import("../server.mjs");
    await runMcpServer();
    return 0;
  }

  if (command === "verify") {
    const reference = positional.slice(1).join(" ").trim();
    if (!reference) {
      process.stderr.write("Missing reference. Run `confessions verify <hash>`.\n");
      return 1;
    }
    return runVerify(reference, flags);
  }

  const reference = positional.join(" ").trim();
  return runVerify(reference, flags);
}

main()
  .then((code) => {
    process.exitCode = code;
  })
  .catch((error) => {
    process.stderr.write(`${error.stack || error.message || String(error)}\n`);
    process.exitCode = 1;
  });
