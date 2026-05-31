import { fetchBaseTransaction } from "./base.mjs";
import {
  ARWEAVE_TXID_RE,
  BASE_TX_RE,
  LEGACY_CID_RE,
  classifyReference,
  generateLocalVerificationSteps,
  normalizeWhitespace,
  parseMetadataLabel,
  validateArweaveTxid,
  validateCsha
} from "./protocol.mjs";

export function formatBytes(bytes) {
  const value = Number(bytes);
  if (!Number.isFinite(value) || value < 0) return null;
  const units = ["B", "KB", "MB", "GB"];
  let size = value;
  let unit = 0;
  while (size >= 1024 && unit < units.length - 1) {
    size /= 1024;
    unit += 1;
  }
  return `${size.toFixed(size >= 100 ? 0 : size >= 10 ? 1 : 2)} ${units[unit]}`;
}

function normalizeFieldMap(parsed) {
  return {
    title: parsed?.title || null,
    artxid: parsed?.artxid || null,
    csha: parsed?.csha || null,
    steg: parsed?.steg || null
  };
}

function buildAudit(record) {
  const steps = generateLocalVerificationSteps({
    base_tx_hash: record.artxid ? null : record.baseTxHash,
    artxid: record.artxid,
    csha: record.csha,
    public_steg: record.steg
  });
  return {
    commands: steps.commands,
    warnings: steps.warnings,
    notes: steps.notes,
    errors: steps.errors
  };
}

function parseLegacyMetadata(text, parsedFields = {}) {
  const normalized = String(text || "").replace(/\u0000/g, " ");
  const compact = normalized.replace(/\s+/g, " ").trim();
  const fields = parsedFields.fields || parsedFields || {};
  let seededTitle = fields.TITLE || null;
  if (seededTitle && /\b(?:cid|ipfs|proof|sha|hash|csha)\s*:/i.test(seededTitle)) seededTitle = null;

  const legacy = {
    title: seededTitle,
    cid: fields.IPFS || fields.CID || null,
    checksum: fields.CSHA || fields.PROOF || fields.SHA || fields.HASH || null
  };

  const cidMatch = normalized.match(/\b(?:ipfs|cid)\s*:\s*([a-zA-Z0-9_-]+)/i);
  if (!legacy.cid && cidMatch) legacy.cid = cidMatch[1];

  const checksumMatch = normalized.match(/\b(?:csha|proof|sha512|sha|hash)\s*:\s*((?:0x)?[a-fA-F0-9]{32,128})/i);
  if (!legacy.checksum && checksumMatch) legacy.checksum = checksumMatch[1];

  const titleMatch = normalized.match(/\btitle\s*:\s*(.+?)(?=\s+\b(?:ipfs|cid|csha|proof|sha512|sha|hash)\s*:|$)/i);
  if (!legacy.title && titleMatch) legacy.title = titleMatch[1].trim();
  if (!legacy.title) {
    const firstField = compact.match(/\b(?:artxid|ar|ipfs|cid|csha|proof|sha512|sha|hash|steg)\s*:/i);
    if (firstField && typeof firstField.index === "number" && firstField.index > 0) {
      legacy.title = compact.slice(0, firstField.index).replace(/[|,;:-]+$/g, "").trim() || null;
    }
  }

  return legacy;
}

export async function fetchArweaveHeaders(txid, options = {}) {
  const checked = validateArweaveTxid(txid);
  if (!checked.valid) {
    return { checked: false, ok: false, errors: [checked.message] };
  }

  const fetchImpl = options.fetchImpl || globalThis.fetch;
  if (typeof fetchImpl !== "function") {
    return {
      checked: false,
      ok: false,
      errors: ["This Node runtime does not provide fetch. Use Node 18 or newer."]
    };
  }

  const url = `https://arweave.net/${checked.normalized}`;
  try {
    const response = await fetchImpl(url, { method: "HEAD", redirect: "follow" });
    const contentLength = response.headers.get("content-length");
    return {
      checked: true,
      ok: response.ok,
      status: response.status,
      url: response.url || url,
      contentType: response.headers.get("content-type") || null,
      contentLength,
      sizeLabel: contentLength === null ? null : formatBytes(Number(contentLength)),
      errors: response.ok ? [] : [`Arweave returned HTTP ${response.status}.`]
    };
  } catch (error) {
    return {
      checked: true,
      ok: false,
      status: null,
      url,
      contentType: null,
      contentLength: null,
      sizeLabel: null,
      errors: [error.message || String(error)]
    };
  }
}

function createRecord(base) {
  const record = {
    valid: true,
    status: "resolved",
    type: null,
    input: null,
    title: null,
    baseTxHash: null,
    artxid: null,
    arweaveUrl: null,
    csha: null,
    steg: null,
    verifierUrl: null,
    rawMetadata: null,
    artifact: null,
    auditCommands: "",
    warnings: [],
    errors: [],
    notes: [],
    ...base
  };

  if (record.artxid) record.arweaveUrl = `https://arweave.net/${record.artxid}`;
  const audit = buildAudit(record);
  record.auditCommands = audit.commands;
  record.warnings.push(...audit.warnings);
  record.notes.push(...audit.notes);
  record.errors.push(...audit.errors);
  record.valid = record.errors.length === 0;
  return record;
}

async function withArtifactCheck(record, options) {
  if (!record.artxid || options.checkArtifact === false) return record;
  const artifact = await fetchArweaveHeaders(record.artxid, options);
  record.artifact = artifact;
  if (artifact.errors?.length) {
    record.warnings.push(`Artifact header check did not confirm availability: ${artifact.errors.join(" ")}`);
  }
  return record;
}

function recordFromParsedLabel(input, parsed, baseTxHash = null) {
  const fields = normalizeFieldMap(parsed);
  const warnings = [...(parsed.warnings || [])];
  const errors = [...(parsed.errors || [])];
  const csha = fields.csha && validateCsha(fields.csha).valid ? validateCsha(fields.csha).normalized : fields.csha;

  if (!fields.artxid) errors.push("Public metadata label does not include ARTXID.");

  return createRecord({
    status: errors.length ? "invalid_label" : "resolved",
    type: "metadata_label",
    input,
    title: fields.title,
    baseTxHash,
    artxid: fields.artxid,
    csha,
    steg: fields.steg,
    verifierUrl: baseTxHash
      ? `https://confessionstxt.art/verify/${baseTxHash}`
      : fields.artxid
        ? `https://confessionstxt.art/verify?txid=${encodeURIComponent(fields.artxid)}`
        : "https://confessionstxt.art/verify",
    rawMetadata: input,
    warnings,
    errors
  });
}

export async function resolveVerificationReference(reference, options = {}) {
  const input = String(reference ?? "").trim();
  const classified = classifyReference(input);

  if (classified.type === "empty" || classified.type === "unknown") {
    return createRecord({
      valid: false,
      status: classified.type,
      type: classified.type,
      input,
      verifierUrl: classified.verifierUrl,
      warnings: classified.warnings || [],
      errors: classified.errors || ["Unknown reference shape."]
    });
  }

  if (classified.type === "base_transaction_hash") {
    const fetched = await fetchBaseTransaction(classified.normalized, options);
    if (!fetched.ok) {
      return createRecord({
        valid: false,
        status: fetched.status,
        type: "base_transaction_hash",
        input,
        baseTxHash: fetched.txHash,
        verifierUrl: `https://confessionstxt.art/verify/${fetched.txHash || classified.normalized}`,
        errors: fetched.errors
      });
    }

    if (!fetched.ascii) {
      return createRecord({
        valid: false,
        status: "unreadable",
        type: "base_transaction_hash",
        input,
        baseTxHash: fetched.txHash,
        verifierUrl: `https://confessionstxt.art/verify/${fetched.txHash}`,
        errors: ["No readable artifact metadata was found in the transaction input."]
      });
    }

    const fields = fetched.parsed.fields || {};
    const arField = fields.ARTXID || fields.AR;
    if (!arField) {
      const legacy = parseLegacyMetadata(fetched.ascii, fetched.parsed);
      if (legacy.cid) {
        return createRecord({
          status: "legacy",
          type: "legacy_cid",
          input,
          title: legacy.title,
          baseTxHash: fetched.txHash,
          csha: legacy.checksum,
          verifierUrl: `https://confessionstxt.art/verify/${fetched.txHash}`,
          rawMetadata: fetched.rawMetadata,
          warnings: ["Legacy IPFS metadata detected. Current labels use ARTXID and CSHA."],
          errors: []
        });
      }

      return createRecord({
        valid: false,
        status: "unparsed",
        type: "base_transaction_hash",
        input,
        baseTxHash: fetched.txHash,
        verifierUrl: `https://confessionstxt.art/verify/${fetched.txHash}`,
        rawMetadata: fetched.rawMetadata,
        errors: ["Readable transaction input found, but it does not conform to a known artifact label."]
      });
    }

    const record = recordFromParsedLabel(fetched.rawMetadata, fetched.parsed, fetched.txHash);
    record.type = "base_transaction_hash";
    record.input = input;
    record.rawMetadata = fetched.rawMetadata;
    return withArtifactCheck(record, options);
  }

  if (classified.type === "metadata_label") {
    const parsed = parseMetadataLabel(normalizeWhitespace(classified.normalized));
    const record = recordFromParsedLabel(classified.normalized, parsed, null);
    return withArtifactCheck(record, options);
  }

  if (classified.type === "arweave_transaction_id") {
    const record = createRecord({
      status: "artifact_located",
      type: "arweave_transaction_id",
      input,
      artxid: classified.normalized,
      verifierUrl: classified.verifierUrl,
      warnings: ["Arweave TXID alone is an archive pointer. Resolve a Base transaction hash or metadata label for CSHA proof material."]
    });
    return withArtifactCheck(record, options);
  }

  if (classified.type === "legacy_cid" || LEGACY_CID_RE.test(classified.normalized)) {
    return createRecord({
      status: "legacy",
      type: "legacy_cid",
      input,
      verifierUrl: classified.verifierUrl,
      warnings: ["Legacy CID-like reference detected. Current labels use ARTXID and CSHA."]
    });
  }

  if (BASE_TX_RE.test(input) || ARWEAVE_TXID_RE.test(input)) {
    return resolveVerificationReference(input, options);
  }

  return createRecord({
    valid: false,
    status: "unknown",
    type: "unknown",
    input,
    verifierUrl: "https://confessionstxt.art/verify",
    errors: ["Unknown reference shape."]
  });
}
