#!/usr/bin/env node
// Exercise the real npm tarball in a clean directory. Never publishes anything.
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const root = fileURLToPath(new URL('..', import.meta.url));
const source = join(root, 'packages/cli');
const pkg = JSON.parse(await readFile(join(source, 'package.json'), 'utf8'));
const require = createRequire(join(source, 'package.json'));
const { Client } = await import(pathToFileURL(require.resolve('@modelcontextprotocol/sdk/client/index.js')));
const { StdioClientTransport } = await import(pathToFileURL(require.resolve('@modelcontextprotocol/sdk/client/stdio.js')));
const workspace = await mkdtemp(join(tmpdir(), 'confessions-package-check-'));
const run = (command, args, cwd = workspace) => execFileSync(command, args, {
  cwd, encoding: 'utf8', timeout: 120000, stdio: ['ignore', 'pipe', 'pipe']
});
try {
  const packed = JSON.parse(run('npm', ['pack', '--ignore-scripts', '--json', '--pack-destination', workspace], source));
  // npm 12 keys its JSON by package name; earlier npm versions return an array.
  const pack = Array.isArray(packed) ? packed[0] : packed[pkg.name];
  const files = pack.files.map(file => file.path).sort();
  for (const file of files) {
    assert.match(file, /^(?:package\.json|README\.md|LICENSE|server\.mjs|bin\/confessions\.mjs|lib\/[a-z-]+\.mjs)$/,
      `Unexpected public package file: ${file}`);
  }
  for (const required of ['LICENSE', 'package.json', 'server.mjs', 'lib/network.mjs', 'bin/confessions.mjs']) {
    assert.ok(files.includes(required), `Package missing ${required}`);
  }
  run('npm', ['install', '--ignore-scripts', '--no-audit', '--no-fund', '--no-package-lock', resolve(workspace, pack.filename)]);
  const installed = join(workspace, 'node_modules/@confessionstxt/cli');
  const bin = join(installed, 'bin/confessions.mjs');
  assert.equal(run(process.execPath, [bin, '--version']).trim(), pkg.version);
  assert.match(run(process.execPath, [bin, '--help']), /confessions verify/);
  const label = `Synthetic package check | ARTXID:${'a'.repeat(43)} | CSHA:${'b'.repeat(128)}`;
  const result = JSON.parse(run(process.execPath, [bin, 'verify', '--json', '--no-artifact-check', '--', label]));
  assert.equal(result.valid, true);
  assert.equal(result.title, 'Synthetic package check');
  const transport = new StdioClientTransport({command: process.execPath, args: [bin, 'mcp'], cwd: workspace});
  const client = new Client({name: 'package-release-check', version: '0.0.0'});
  try {
    await client.connect(transport);
    assert.equal(client.getServerVersion().version, pkg.version);
    assert.equal((await client.listTools()).tools.length, 6);
    assert.equal((await client.listResources()).resources.length, 4);
    const response = await client.callTool({name: 'resolve_public_artifact_reference',
      arguments: {reference: label, check_artifact: false}});
    assert.equal(response.structuredContent.valid, true);
  } finally {
    await client.close();
  }
  console.log(`Package ${pkg.name}@${pkg.version}: ${files.length} public files; installed CLI and MCP checks passed.`);
} finally {
  await rm(workspace, {recursive: true, force: true});
}
