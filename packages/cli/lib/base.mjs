import { parseMetadataLabel, validateBaseTxHash } from "./protocol.mjs";

export const DEFAULT_BASE_RPC_URL = "https://mainnet.base.org";

export function hexToAscii(hex) {
  const clean = String(hex ?? "").startsWith("0x") ? String(hex).slice(2) : String(hex ?? "");
  if (!clean || clean.length % 2 !== 0 || !/^[0-9a-fA-F]+$/.test(clean)) return "";

  let output = "";
  for (let i = 0; i < clean.length; i += 2) {
    const code = Number.parseInt(clean.slice(i, i + 2), 16);
    if (Number.isNaN(code) || code === 0) continue;
    output += String.fromCharCode(code);
  }
  return output;
}

export function asciiToHex(value) {
  return (
    "0x" +
    Array.from(String(value ?? ""))
      .map((char) => char.charCodeAt(0).toString(16).padStart(2, "0"))
      .join("")
  );
}

export async function fetchBaseTransaction(txHash, options = {}) {
  const checked = validateBaseTxHash(txHash);
  if (!checked.valid) {
    return {
      ok: false,
      status: "invalid_hash",
      txHash: String(txHash ?? "").trim(),
      errors: [checked.message]
    };
  }

  const fetchImpl = options.fetchImpl || globalThis.fetch;
  if (typeof fetchImpl !== "function") {
    return {
      ok: false,
      status: "fetch_unavailable",
      txHash: checked.normalized,
      errors: ["This Node runtime does not provide fetch. Use Node 18 or newer."]
    };
  }

  const payload = {
    jsonrpc: "2.0",
    id: 1,
    method: "eth_getTransactionByHash",
    params: [checked.normalized]
  };

  const response = await fetchImpl(options.rpcUrl || DEFAULT_BASE_RPC_URL, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(payload)
  });

  if (!response.ok) {
    return {
      ok: false,
      status: "rpc_error",
      txHash: checked.normalized,
      errors: [`Base RPC returned HTTP ${response.status}.`]
    };
  }

  const data = await response.json();
  if (data.error) {
    return {
      ok: false,
      status: "rpc_error",
      txHash: checked.normalized,
      errors: [data.error.message || "Base RPC returned an error."]
    };
  }
  if (!data.result) {
    return {
      ok: false,
      status: "not_found",
      txHash: checked.normalized,
      errors: ["Base mainnet returned no transaction for that hash."]
    };
  }

  const inputHex = data.result.input || "";
  const ascii = hexToAscii(inputHex);
  const rawMetadata = String(ascii || "").replace(/\u0000/g, " ").trim();
  const parsed = parseMetadataLabel(ascii);

  return {
    ok: true,
    status: "found",
    txHash: checked.normalized,
    transaction: data.result,
    inputHex,
    ascii,
    rawMetadata,
    parsed
  };
}

