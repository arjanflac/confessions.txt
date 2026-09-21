import { readFile, writeFile, mkdir } from 'node:fs/promises';
const root = new URL('../', import.meta.url);
const check = process.argv.includes('--check');
await mkdir(new URL('web/lib/', root), { recursive: true });
for (const name of ['protocol.mjs', 'base.mjs', 'network.mjs']) {
  const source = await readFile(new URL('packages/cli/lib/' + name, root), 'utf8');
  const target = new URL('web/lib/' + name, root);
  if (check) {
    if (await readFile(target, 'utf8') !== source) throw new Error('Run node scripts/sync_web_modules.mjs: ' + name);
  } else await writeFile(target, source);
}
