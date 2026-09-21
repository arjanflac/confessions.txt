// Shared by the local verifier and static browser. Bound both time and bytes.
export const REQUEST_TIMEOUT_MS = 15000;
export const MAX_RPC_BYTES = 256 * 1024;

export async function readLimited(response, maxBytes) {
  const length = response.headers?.get('content-length');
  if (length !== null && Number(length) > maxBytes) {
    await response.body?.cancel();
    throw new Error('Response exceeds the download limit.');
  }
  if (!response.body?.getReader) throw new Error('Streaming response unavailable.');
  const reader = response.body.getReader();
  const chunks = [];
  let size = 0;
  try {
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > maxBytes) throw new Error('Response exceeds the download limit.');
      chunks.push(value);
    }
  } finally {
    await reader.cancel();
    reader.releaseLock();
  }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
  return bytes;
}

export async function fetchRpcJson(url, payload, options = {}) {
  const endpoint = new URL(url);
  if (endpoint.protocol !== 'https:' || endpoint.username || endpoint.password) {
    throw new Error('RPC endpoint must be an HTTPS URL without credentials.');
  }
  const response = await (options.fetchImpl || globalThis.fetch)(endpoint.href, {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify(payload), redirect: 'error',
    signal: AbortSignal.timeout(options.timeoutMs ?? REQUEST_TIMEOUT_MS)
  });
  if (!response.ok) throw new Error(`Base RPC returned HTTP ${response.status}.`);
  return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(await readLimited(response, MAX_RPC_BYTES)));
}

export function isArweaveUrl(value) {
  const url = new URL(value);
  return url.protocol === 'https:' && !url.username && !url.password && !url.port &&
    (url.hostname === 'arweave.net' || url.hostname.endsWith('.arweave.net'));
}

export async function fetchArweaveHead(url, options = {}) {
  const fetchImpl = options.fetchImpl || globalThis.fetch;
  const signal = AbortSignal.timeout(options.timeoutMs ?? REQUEST_TIMEOUT_MS);
  for (let redirects = 0; redirects <= 4; redirects++) {
    if (!isArweaveUrl(url)) throw new Error('Archive redirect left the trusted Arweave gateway.');
    const response = await fetchImpl(url, { method: 'HEAD', redirect: 'manual', signal });
    if (![301, 302, 303, 307, 308].includes(response.status)) return response;
    const location = response.headers.get('location');
    if (!location) throw new Error('Archive redirect has no destination.');
    url = new URL(location, url).href;
  }
  throw new Error('Too many archive redirects.');
}
