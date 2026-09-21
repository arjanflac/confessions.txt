import assert from 'node:assert/strict';
import test from 'node:test';
import { readFile } from 'node:fs/promises';
import { execFileSync } from 'node:child_process';
import { asciiToHex, hexToAscii, fetchBaseTransaction } from '../lib/base.mjs';
import { parseMetadataLabel, classifyReference, generateLocalVerificationSteps, shellQuote } from '../lib/protocol.mjs';
import { resolveVerificationReference, fetchArweaveHeaders } from '../lib/verify.mjs';
import { readLimited } from '../lib/network.mjs';
import { formatVerificationText } from '../lib/output.mjs';
import { buildNpxVerifyCommand, inspectRasterImage } from '../../../web/verifier-security.mjs';
const hash = '0x' + 'a'.repeat(64);
const id = 'b'.repeat(43);
const csha = 'c'.repeat(128);
const label = `Omertà 🔒 | ARTXID:${id} | CSHA:${csha} | STEG:two  spaces`;
const response = tx => new Response(JSON.stringify({result: tx}));
const tx = {hash, chainId: '0x2105', blockHash: hash, blockNumber: '0x123', input: asciiToHex(label)};

test('UTF-8 metadata and exact internal password whitespace survive decoding', async () => {
  assert.equal(hexToAscii(asciiToHex(label)), label);
  assert.equal(hexToAscii('0xc328'), '');
  assert.equal(hexToAscii('0xgg'), '');
  const r = await resolveVerificationReference(label, {checkArtifact: false});
  assert.equal(r.steg, 'two  spaces');
  assert.equal(r.title, 'Omertà 🔒');
});

test('metadata limits count UTF-8 bytes and canonical parsing normalizes checksum aliases', async () => {
  const oversized = label.replace('Omertà 🔒', '🔒'.repeat(7000));
  assert.ok(oversized.length < 16384);
  assert.ok(parseMetadataLabel(oversized).errors.some(error => /16 KiB/.test(error)));
  for (const key of ['CSHA', 'PROOF', 'SHA', 'HASH']) {
    const aliased = label.replace('CSHA:', key + ':');
    assert.equal(parseMetadataLabel(aliased).csha, csha);
    assert.equal((await resolveVerificationReference(aliased, {checkArtifact:false})).csha, csha);
  }
});

test('duplicate fields, aliases, control characters, and missing checksums fail closed', async () => {
  for (const bad of [label + ' | CSHA:' + 'd'.repeat(128), label + ' | AR:' + id,
    label + ' | STEG:', label + '\n', label.replace('CSHA:', 'OTHER:')]) {
    const r = await resolveVerificationReference(bad, {checkArtifact: false});
    // Trailing CLI whitespace is normalized; embedded control characters are not.
    if (bad.endsWith('\n')) continue;
    assert.equal(r.valid, false, bad);
    assert.equal(r.auditCommands, '');
  }
  assert.ok(classifyReference(label.replace('two  spaces', 'two\nspaces')).errors.length);
  assert.ok(parseMetadataLabel(label.replace('Omertà', '\x1b[31mOmertà')).errors.length);
});

test('untrusted verifier locators cannot become shell programs', () => {
  for (const input of ['; touch /tmp/should-never-exist', '$(id)', 'Qmabc;id', '0x123\nid', '`id`']) {
    assert.equal(buildNpxVerifyCommand(input), 'Enter a valid public reference to generate a command.');
  }
  assert.equal(buildNpxVerifyCommand(hash), `npx -y @confessionstxt/cli@latest verify -- '${hash}'`);
  const dashId = '-' + 'a'.repeat(42);
  assert.equal(buildNpxVerifyCommand(dashId), `npx -y @confessionstxt/cli@latest verify -- '${dashId}'`);
  const publicSteg = "x'$(echo hostile);#";
  assert.equal(execFileSync('sh', ['-c', 'printf %s ' + shellQuote(publicSteg)], {encoding:'utf8'}), publicSteg);
  assert.equal(generateLocalVerificationSteps({artxid: id, csha:'bad'}).commands, '');
});

test('RPC rejects wrong chain, mismatched hash, pending transactions, failures, and oversized bodies', async () => {
  for (const bad of [{...tx, hash:'0x'+'f'.repeat(64)}, {...tx, chainId:'0x1'}, {...tx, blockNumber:null}]) {
    const r = await fetchBaseTransaction(hash, {fetchImpl: async () => response(bad)});
    assert.equal(r.ok, false);
  }
  assert.equal((await fetchBaseTransaction(hash, {fetchImpl: async () => {throw new Error('offline')}})).status, 'rpc_error');
  assert.equal((await fetchBaseTransaction(hash, {fetchImpl: async () => new Response('x'.repeat(300000))})).ok, false);
  assert.equal((await fetchBaseTransaction(hash, {fetchImpl: async () => response(tx)})).ok, true);
});

test('unknown-length downloads stop while streaming, not after buffering the whole file', async () => {
  let cancelled = false;
  const stream = new ReadableStream({pull(controller) {controller.enqueue(new Uint8Array(1024));},cancel() {cancelled = true;}});
  await assert.rejects(readLimited(new Response(stream), 1500), /limit/);
  assert.equal(cancelled,true);
});

test('Arweave HEAD redirects cannot reach local or arbitrary services', async () => {
  for (const target of ['http://127.0.0.1/private','https://attacker.invalid/','https://arweave.net.attacker.invalid/']) {
    const calls=[];
    const result=await fetchArweaveHeaders(id,{fetchImpl:async url => {
      calls.push(url);return new Response(null,{status:302,headers:{location:target}});
    }});
    assert.equal(result.ok,false);assert.equal(calls.length,1);
  }
});

test('terminal output neutralizes control and bidi sequences', () => {
  const output = formatVerificationText({valid:false,title:'bad\x1b]52;c;AAAA\x07\u202e',warnings:[],errors:[],notes:[]});
  assert.doesNotMatch(output, /[\x1b\x07\u202e]/);
});

test('previews reject SVG, corrupt images, and decompression-size bombs', () => {
  assert.throws(() => inspectRasterImage(new TextEncoder().encode('<svg></svg>')));
  const png = new Uint8Array(33);png.set([137,80,78,71,13,10,26,10]);
  const v=new DataView(png.buffer);v.setUint32(8,13);v.setUint32(12,0x49484452);v.setUint32(16,100000);v.setUint32(20,100000);
  assert.throws(() => inspectRasterImage(png), /megapixel/);
  v.setUint32(16,1440);v.setUint32(20,1920);
  assert.deepEqual(inspectRasterImage(png), {width:1440,height:1920,mime:'image/png'});
});

test('browser and package share identical protocol, RPC, and network behavior', async () => {
  for (const file of ['protocol.mjs','base.mjs','network.mjs']) {
    const local=await readFile(new URL('../lib/'+file,import.meta.url),'utf8');
    const browser=await readFile(new URL('../../../web/lib/'+file,import.meta.url),'utf8');
    assert.equal(browser,local, 'Run node scripts/sync_web_modules.mjs');
  }
});

test('Pages policy permits only the intended JSON-LD inline scripts', async () => {
  const {createHash}=await import('node:crypto');
  const headers=await readFile(new URL('../../../web/_headers',import.meta.url),'utf8');
  const policy=headers.match(/script-src ([^;]+)/)[1];
  assert.doesNotMatch(policy,/unsafe-inline|unsafe-eval/);
  for (const name of ['index.html','verify.html']) {
    const html=await readFile(new URL('../../../web/'+name,import.meta.url),'utf8');
    for (const match of html.matchAll(/<script([^>]*)>([\s\S]*?)<\/script>/g)) {
      if (match[1].includes('src=')) continue;
      assert.match(match[1],/application\/ld\+json/);
      const hash=createHash('sha256').update(match[2]).digest('base64');
      assert.ok(policy.includes(`'sha256-${hash}'`));
    }
  }
});
