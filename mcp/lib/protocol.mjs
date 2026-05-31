export const BASE_TX_RE = /^0x[a-fA-F0-9]{64}$/;
export const ARWEAVE_TXID_RE = /^[a-zA-Z0-9_-]{43}$/;
export const CSHA_RE = /^[0-9a-fA-F]{128}$/;
export const LEGACY_CID_RE = /^(bafy|bafk|Qm)[a-zA-Z0-9_-]+$/i;
export const CONTROL_CHARS_RE = /[\x00-\x1f\x7f]/;

const KNOWN_FIELDS = new Set([
  "TITLE",
  "ARTXID",
  "AR",
  "CSHA",
  "STEG",
  "CID",
  "IPFS",
  "PROOF",
  "SHA",
  "HASH"
]);

export function normalizeWhitespace(value) {
  return String(value ?? "").replace(/\u0000/g, " ").replace(/\s+/g, " ").trim();
}

export function hasControlChars(value) {
  return CONTROL_CHARS_RE.test(String(value ?? ""));
}

export function validateCsha(value) {
  const raw = String(value ?? "").trim();
  return {
    valid: CSHA_RE.test(raw),
    normalized: CSHA_RE.test(raw) ? raw.toLowerCase() : raw,
    length: raw.length,
    message: CSHA_RE.test(raw)
      ? "CSHA format is valid: 128 hexadecimal characters."
      : "CSHA must be exactly 128 hexadecimal characters. This is only a format check, not checksum verification."
  };
}

export function validateArweaveTxid(value) {
  const raw = String(value ?? "").trim();
  return {
    valid: ARWEAVE_TXID_RE.test(raw),
    normalized: raw,
    length: raw.length,
    message: ARWEAVE_TXID_RE.test(raw)
      ? "Arweave transaction id format is valid."
      : "ARTXID must be a 43-character Arweave transaction id."
  };
}

export function validateBaseTxHash(value) {
  const raw = String(value ?? "").trim();
  return {
    valid: BASE_TX_RE.test(raw),
    normalized: BASE_TX_RE.test(raw) ? raw.toLowerCase() : raw,
    length: raw.length,
    message: BASE_TX_RE.test(raw)
      ? "Base transaction hash format is valid."
      : "Base transaction hash must be 0x followed by 64 hexadecimal characters."
  };
}

export function parseMetadataLabel(label) {
  const text = String(label ?? "");
  const normalized = normalizeWhitespace(text);
  const fields = {};
  const unknownFields = {};
  const warnings = [];
  const errors = [];

  if (!normalized) {
    return { title: null, artxid: null, csha: null, steg: null, fields, unknownFields, warnings, errors: ["Metadata label is empty."] };
  }

  if (hasControlChars(text)) {
    errors.push("Metadata label contains control characters.");
  }

  const parts = text.split("|");
  const hasPipeDelimitedLabel = parts.length > 1;

  for (let i = 0; i < parts.length; i += 1) {
    const part = parts[i];
    const trimmed = part.trim();
    if (!trimmed) continue;

    if (i === 0) {
      const firstColon = trimmed.indexOf(":");
      const firstKey = firstColon === -1 ? "" : trimmed.slice(0, firstColon).trim().toUpperCase();
      const explicitTitle = firstKey === "TITLE";
      const knownFirstField = KNOWN_FIELDS.has(firstKey);
      const freeTitle = firstColon === -1;

      if ((hasPipeDelimitedLabel && !knownFirstField) || explicitTitle || freeTitle) {
        const value = explicitTitle ? trimmed.slice(firstColon + 1).trim() : trimmed;
        if (fields.TITLE) warnings.push("Duplicate TITLE field encountered; first value kept.");
        else fields.TITLE = value;
        continue;
      }
    }

    const idx = trimmed.indexOf(":");
    if (idx === -1) {
      warnings.push(`Ignored unkeyed metadata segment: ${trimmed}`);
      continue;
    }

    const key = trimmed.slice(0, idx).trim().toUpperCase();
    const value = trimmed.slice(idx + 1).trim();
    if (!key) {
      warnings.push("Ignored metadata segment with empty key.");
      continue;
    }
    if (!KNOWN_FIELDS.has(key)) {
      unknownFields[key] = value;
      warnings.push(`Unknown metadata field retained for display: ${key}`);
      continue;
    }
    if (fields[key]) {
      warnings.push(`Duplicate ${key} field encountered; first value kept.`);
      continue;
    }
    fields[key] = value;
  }

  const title = fields.TITLE || null;
  const artxid = fields.ARTXID || fields.AR || null;
  const csha = fields.CSHA || fields.PROOF || fields.SHA || fields.HASH || null;
  const steg = fields.STEG || null;

  if (title && (title.includes("|") || title.includes("\n") || hasControlChars(title))) {
    errors.push("TITLE cannot contain pipe, newline, or control characters.");
  }
  if (artxid && !validateArweaveTxid(artxid).valid) {
    errors.push("ARTXID field is present but does not have the current Arweave transaction id shape.");
  }
  if (csha && !validateCsha(csha).valid) {
    errors.push("CSHA field is present but does not have the current CSHA shape.");
  }
  if (steg && (steg.includes("|") || steg.includes("\n") || hasControlChars(steg))) {
    errors.push("STEG cannot contain pipe, newline, or control characters.");
  }
  if (steg) {
    warnings.push("STEG is public extraction material when published in a metadata label. It must not be treated as private after publication.");
  }

  return {
    title,
    artxid,
    csha,
    steg,
    fields,
    unknownFields,
    warnings,
    errors
  };
}

export function extractLocatorFromUrl(input) {
  const raw = String(input ?? "").trim();
  try {
    const url = new URL(raw);
    const host = url.hostname.toLowerCase();
    if (host === "confessionstxt.art" || host === "www.confessionstxt.art") {
      const tx = url.searchParams.get("tx") || url.searchParams.get("txid");
      if (tx) return tx.trim();
      const match = url.pathname.replace(/\/+$/, "").match(/^\/verify\/(.+)$/);
      if (match) return decodeURIComponent(match[1]).trim();
    }
    if (host === "arweave.net" || host.endsWith(".arweave.net")) {
      const firstPathSegment = url.pathname.split("/").filter(Boolean)[0];
      if (firstPathSegment) return firstPathSegment.trim();
    }
    if (host === "basescan.org" || host.endsWith(".basescan.org")) {
      const match = url.pathname.match(/\/tx\/(0x[a-fA-F0-9]{64})/);
      if (match) return match[1].trim();
    }
  } catch {
    return raw;
  }
  return raw;
}

export function classifyReference(reference) {
  const raw = String(reference ?? "").trim();
  const locator = extractLocatorFromUrl(raw);
  const normalized = normalizeWhitespace(locator);
  const looksLikeLabel = /\b(?:ARTXID|AR|CSHA|STEG|TITLE|PROOF|SHA|HASH)\s*:/i.test(normalized) || normalized.includes("|");

  if (!normalized) {
    return {
      type: "empty",
      normalized: "",
      public: false,
      verifierUrl: null,
      summary: "No reference was provided.",
      fields: null,
      warnings: [],
      errors: ["Reference is empty."]
    };
  }

  if (BASE_TX_RE.test(normalized)) {
    return {
      type: "base_transaction_hash",
      normalized: normalized.toLowerCase(),
      public: true,
      verifierUrl: `https://confessionstxt.art/verify/${normalized.toLowerCase()}`,
      summary: "Base transaction hash. Resolve it through the public verifier to read the on-chain metadata label.",
      fields: null,
      warnings: [],
      errors: []
    };
  }

  if (ARWEAVE_TXID_RE.test(normalized)) {
    return {
      type: "arweave_transaction_id",
      normalized,
      public: true,
      verifierUrl: `https://confessionstxt.art/verify?txid=${encodeURIComponent(normalized)}`,
      summary: "Arweave transaction id for a public locked carrier artifact. It is an archive pointer, not a complete proof record by itself.",
      fields: { artxid: normalized },
      warnings: [],
      errors: []
    };
  }

  if (LEGACY_CID_RE.test(normalized)) {
    return {
      type: "legacy_cid",
      normalized,
      public: true,
      verifierUrl: `https://confessionstxt.art/verify/${encodeURIComponent(normalized)}`,
      summary: "Legacy CID-like reference. Current CONFESSIONS.txt labels prefer ARTXID and CSHA.",
      fields: null,
      warnings: ["Legacy reference shape detected."],
      errors: []
    };
  }

  if (looksLikeLabel) {
    const parsed = parseMetadataLabel(normalized);
    return {
      type: "metadata_label",
      normalized,
      public: true,
      verifierUrl: parsed.artxid ? `https://confessionstxt.art/verify?txid=${encodeURIComponent(parsed.artxid)}` : "https://confessionstxt.art/verify",
      summary: "Public CONFESSIONS.txt metadata label. It can identify the title, archive pointer, checksum, and optional public extraction material.",
      fields: {
        title: parsed.title,
        artxid: parsed.artxid,
        csha: parsed.csha ? validateCsha(parsed.csha).normalized : null,
        steg: parsed.steg
      },
      warnings: parsed.warnings,
      errors: parsed.errors
    };
  }

  return {
    type: "unknown",
    normalized,
    public: false,
    verifierUrl: "https://confessionstxt.art/verify",
    summary: "Unknown reference shape. Expected a Base transaction hash, Arweave transaction id, legacy CID-like value, or public metadata label.",
    fields: null,
    warnings: [],
    errors: ["Unknown reference shape."]
  };
}

export function validateManifestShape(manifest) {
  const errors = [];
  const warnings = [];
  const normalized = {};

  if (!manifest || typeof manifest !== "object" || Array.isArray(manifest)) {
    return {
      valid: false,
      normalized,
      warnings,
      errors: ["Manifest must be an object with title, artxid, csha, and optional steg."]
    };
  }

  const title = String(manifest.title ?? "").trim();
  if (!title) errors.push("title is required.");
  if (title && (title.includes("|") || title.includes("\n") || hasControlChars(title))) {
    errors.push("title cannot contain pipe, newline, or control characters.");
  }
  if (title) normalized.title = title;

  const artxid = validateArweaveTxid(manifest.artxid ?? "");
  if (!artxid.valid) errors.push(artxid.message);
  else normalized.artxid = artxid.normalized;

  const csha = validateCsha(manifest.csha ?? "");
  if (!csha.valid) errors.push(csha.message);
  else normalized.csha = csha.normalized;

  const steg = manifest.steg ?? manifest.STEG ?? null;
  if (steg !== null && steg !== undefined) {
    const value = String(steg).trim();
    if (!value) errors.push("steg cannot be empty when present.");
    if (value.includes("|") || value.includes("\n") || hasControlChars(value)) {
      errors.push("steg cannot contain pipe, newline, or control characters.");
    }
    if (value) {
      normalized.steg = value;
      warnings.push("steg is public extraction material if published. Do not ask for private stego passphrases through MCP.");
    }
  }

  return {
    valid: errors.length === 0,
    normalized,
    warnings,
    errors
  };
}

export function shellQuote(value) {
  return "'" + String(value ?? "").replace(/'/g, "'\"'\"'") + "'";
}

export function generateLocalVerificationSteps(input) {
  const warnings = [
    "Do not send plaintext testimony, private keys, wallet files, age passphrases, private stego passphrases, payload.tar.gz, or decrypted archives to a remote model.",
    "These commands are local verification instructions. The MCP server does not run extraction, checksum verification, decryption, uploads, or broadcasts."
  ];
  const errors = [];
  const commands = [];

  const baseTxHash = input?.base_tx_hash || input?.baseTxHash || null;
  const artxid = input?.artxid || null;
  const csha = input?.csha || null;
  const publicSteg = input?.public_steg || input?.publicSteg || null;

  if (baseTxHash) {
    const base = validateBaseTxHash(baseTxHash);
    if (!base.valid) errors.push(base.message);
    else {
      commands.push(`# Resolve the public record first\nopen "https://confessionstxt.art/verify/${base.normalized}"`);
      warnings.push("A Base transaction hash must be resolved to ARTXID and CSHA before artifact-level local verification.");
    }
  }

  if (artxid) {
    const ar = validateArweaveTxid(artxid);
    if (!ar.valid) errors.push(ar.message);
    else {
      commands.push(`# Download locked carrier artifact\ncurl -fL -o locked_artifact.jpg "https://arweave.net/${ar.normalized}"`);
      if (publicSteg) {
        const stegValue = String(publicSteg).trim();
        if (!stegValue || stegValue.includes("|") || stegValue.includes("\n") || hasControlChars(stegValue)) {
          errors.push("public_steg cannot be empty and cannot contain pipe, newline, or control characters.");
        } else {
          commands.push(`# Extract encrypted payload with intentionally public STEG\npython3 cli/confess.py extract --image locked_artifact.jpg --stego-pass ${shellQuote(stegValue)}`);
          warnings.push("public_steg is included only because the caller marked it public. Do not use this field for private stego passphrases.");
        }
      } else {
        commands.push(`# Extract encrypted payload locally\npython3 cli/confess.py extract --image locked_artifact.jpg --stego-pass-prompt`);
      }
    }
  }

  if (csha) {
    const proof = validateCsha(csha);
    if (!proof.valid) errors.push(proof.message);
    else {
      commands.push(`# Verify encrypted payload checksum\npython3 cli/confess.py verify --file payload.age --csha ${proof.normalized}`);
    }
  } else if (artxid) {
    commands.push(`# Verify encrypted payload checksum after resolving CSHA\npython3 cli/confess.py verify --file payload.age --csha <CSHA_SHA512>`);
  }

  if (!baseTxHash && !artxid) {
    errors.push("Provide base_tx_hash for public resolution or artxid for local artifact verification steps.");
  }

  return {
    valid: errors.length === 0,
    commands: commands.join("\n\n"),
    warnings,
    errors,
    notes: [
      "CSHA is sha512(payload.age), not a hash of plaintext testimony.",
      "A checksum match verifies continuity between the encrypted payload and the public reference. It does not disclose plaintext and does not prove the testimony is true."
    ]
  };
}

export function explainReference(reference) {
  const classified = classifyReference(reference);
  const nextSteps = [];

  if (classified.type === "base_transaction_hash") {
    nextSteps.push("Open the public verifier URL to resolve the Base transaction input into ARTXID, CSHA, and optional STEG.");
  }
  if (classified.type === "arweave_transaction_id") {
    nextSteps.push("Use the Arweave transaction id to download the locked carrier artifact, then verify only after obtaining CSHA from the public record.");
  }
  if (classified.type === "metadata_label" && classified.fields?.artxid) {
    nextSteps.push("Download the Arweave artifact, extract payload.age locally, and compare sha512(payload.age) to CSHA.");
  }
  if (classified.type === "metadata_label" && classified.fields?.steg) {
    nextSteps.push("STEG is public in this label; extraction of payload.age can be public. Plaintext still requires the age passphrase.");
  }
  if (classified.type === "unknown" || classified.type === "empty") {
    nextSteps.push("Ask for a public Base transaction hash, Arweave transaction id, or metadata label. Do not ask for secrets.");
  }

  return {
    ...classified,
    nextSteps,
    privacyBoundary: "Public references are safe to discuss. Plaintext testimony, private keys, wallet files, age passphrases, private stego passphrases, payload.tar.gz, and decrypted archives must stay out of the MCP/model boundary."
  };
}
