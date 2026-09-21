import { parseMetadataLabel, validateBaseTxHash } from './protocol.mjs';
import { fetchRpcJson } from './network.mjs';

export const DEFAULT_BASE_RPC_URL = 'https://mainnet.base.org';

// Historical export names retained for callers; metadata is UTF-8, not ASCII.
export function hexToAscii(hex) {
  const clean = String(hex ?? '').replace(/^0x/, '');
  if (!clean || clean.length > 32768 || clean.length % 2 || !/^[0-9a-fA-F]+$/.test(clean)) return '';
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(Uint8Array.from(clean.match(/../g), b => parseInt(b, 16)));
  } catch { return ''; }
}

export function asciiToHex(value) {
  return '0x' + Array.from(new TextEncoder().encode(String(value ?? '')), b => b.toString(16).padStart(2, '0')).join('');
}

export async function fetchBaseTransaction(txHash, options = {}) {
  const checked = validateBaseTxHash(txHash);
  const failure = (status, message) => ({ ok: false, status, txHash: checked.normalized, errors: [message] });
  if (!checked.valid) return failure('invalid_hash', checked.message);
  try {
    const data = await fetchRpcJson(options.rpcUrl || DEFAULT_BASE_RPC_URL, {
      jsonrpc: '2.0', id: 1, method: 'eth_getTransactionByHash', params: [checked.normalized]
    }, options);
    if (data.error) return failure('rpc_error', 'Base RPC returned an error. Try again later.');
    const tx = data.result;
    if (!tx) return failure('not_found', 'Base mainnet returned no transaction for that hash.');
    if (String(tx.hash).toLowerCase() !== checked.normalized || tx.chainId !== '0x2105') {
      return failure('rpc_error', 'RPC response does not match the requested Base mainnet transaction.');
    }
    if (!/^0x[0-9a-fA-F]+$/.test(tx.blockNumber || '') || !validateBaseTxHash(tx.blockHash).valid) {
      return failure('pending', 'Transaction is not yet included in a block. Retry after confirmation.');
    }
    const ascii = hexToAscii(tx.input);
    return { ok: true, status: 'found', txHash: checked.normalized, transaction: tx,
      inputHex: tx.input, ascii, rawMetadata: ascii, parsed: parseMetadataLabel(ascii) };
  } catch (error) {
    return failure('rpc_error', error.name === 'TimeoutError' ? 'Base RPC request timed out.' : 'Base RPC request failed or returned an invalid response.');
  }
}
