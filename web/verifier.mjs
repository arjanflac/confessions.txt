import { fetchBaseTransaction } from './lib/base.mjs';
import { classifyReference, parseMetadataLabel, shellQuote, hasControlChars } from './lib/protocol.mjs';
import { readLimited, REQUEST_TIMEOUT_MS } from './lib/network.mjs';
import { inspectRasterImage, buildNpxVerifyCommand } from './verifier-security.mjs';

const consoleEl = document.getElementById("console");
const inputEl = document.getElementById("input");
const verifyBtn = document.getElementById("verify");
const npxCommandEl = document.getElementById("npx-command");
const npxCopyBtn = document.getElementById("npx-copy");
const ARWEAVE_TXID_PATTERN = /^[a-zA-Z0-9_-]{43}$/;
const MAX_PREVIEW_BYTES = 25 * 1024 * 1024;

let activePreviewObjectUrl = null;
window.addEventListener("pagehide", releasePreviewUrl);

function updateNpxCommand() {
  const command = buildNpxVerifyCommand(inputEl.value.trim());
  if (npxCommandEl) npxCommandEl.textContent = command;
  if (npxCopyBtn) {
    npxCopyBtn.disabled = !command.startsWith("npx ");
    npxCopyBtn.setAttribute("data-copy", npxCopyBtn.disabled ? "" : command);
  }
}

function releasePreviewUrl() {
  if (activePreviewObjectUrl) {
    URL.revokeObjectURL(activePreviewObjectUrl);
    activePreviewObjectUrl = null;
  }
}

function revealResults() {
  const results = document.querySelector(".verify-results");
  if (!results) return;
  const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  requestAnimationFrame(function () {
    results.scrollIntoView({ block: "start", behavior: reducedMotion ? "auto" : "smooth" });
  });
}

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function isArweaveTxid(value) {
  return ARWEAVE_TXID_PATTERN.test(String(value || "").trim());
}

function normalizeArweaveTxid(value) {
  const normalized = String(value || "").trim();
  return isArweaveTxid(normalized) ? normalized : null;
}

function quoteTitle(title) {
  const clean = String(title || "").trim();
  if (!clean) return clean;
  const hasDoubleQuotes = clean.charAt(0) === '"' && clean.charAt(clean.length - 1) === '"';
  const hasSingleQuotes = clean.charAt(0) === "'" && clean.charAt(clean.length - 1) === "'";
  if (hasDoubleQuotes || hasSingleQuotes) return clean;
  return '"' + clean + '"';
}

function formatBytes(bytes) {
  if (!Number.isFinite(bytes) || bytes < 0) return null;
  if (bytes < 1024) return bytes + " B";
  const units = ["KB", "MB", "GB"];
  let value = bytes / 1024;
  let unitIndex = 0;
  while (value >= 1024 && unitIndex < units.length - 1) {
    value /= 1024;
    unitIndex += 1;
  }
  return value.toFixed(value >= 100 ? 0 : value >= 10 ? 1 : 2) + " " + units[unitIndex];
}

function copyToClipboard(text, btn) {
  return (async function () {
    try {
      if (navigator.clipboard && navigator.clipboard.writeText) {
        await navigator.clipboard.writeText(text);
      } else {
        const textarea = document.createElement("textarea");
        textarea.value = text;
        textarea.style.position = "fixed";
        textarea.style.opacity = "0";
        document.body.appendChild(textarea);
        textarea.select();
        document.execCommand("copy");
        document.body.removeChild(textarea);
      }
      const originalText = btn.textContent;
      btn.textContent = "Copied";
      btn.classList.add("copied");
      setTimeout(function () {
        btn.textContent = originalText;
        btn.classList.remove("copied");
      }, 2000);
    } catch (err) {
      console.error("Copy failed:", err);
    }
  })();
}

function renderStatus(text, type, tooltip) {
  const icons = {
    verified: "&#10003;",
    error: "&#10007;",
    warning: "&#9888;",
    loading: "&#8230;"
  };
  const hasTooltip = Boolean(tooltip);
  const tooltipHtml = hasTooltip ? '<span class="status-tooltip" role="tooltip">' + escapeHtml(tooltip) + "</span>" : "";
  const attrs = hasTooltip ? ' tabindex="0" role="button" aria-expanded="false"' : "";
  const classes = "status " + type + (hasTooltip ? " has-tip" : "");
  return '<div class="' + classes + '"' + attrs + '><span class="status-icon">' + (icons[type] || icons.loading) + "</span>" + escapeHtml(text) + tooltipHtml + "</div>";
}

function renderStatusPanel(text, type, tooltip) {
  return '<div class="status-panel">' + renderStatus(text, type, tooltip) + "</div>";
}

function renderDataBlock(label, value, options) {
  options = options || {};
  const copyValue = options.copyValue;
  const isLink = options.isLink;
  const mono = options.mono;
  const extra = options.extra;
  const copyBtn = copyValue
    ? '<button class="copy-btn" data-copy="' + escapeHtml(copyValue) + '" aria-label="Copy ' + escapeHtml(label) + '">Copy</button>'
    : "";
  const valueHtml = isLink
    ? '<a href="' + escapeHtml(value) + '" target="_blank" rel="noopener noreferrer">' + escapeHtml(value) + "</a>"
    : escapeHtml(value);
  const monoClass = mono ? " mono" : "";
  const extraHtml = extra ? '<div class="data-value subtle">' + escapeHtml(extra) + "</div>" : "";
  return '<div class="data-block"><div class="data-header"><span class="data-label">' + escapeHtml(label) + '</span><div class="data-actions">' + copyBtn + "</div></div><div class=\"data-value" + monoClass + '">' + valueHtml + "</div>" + extraHtml + "</div>";
}

function renderArtifactRecordBlock(txid, canonicalUrl) {
  const items = [];
  if (canonicalUrl) {
    items.push(renderDataBlock("Permanent Archive (AR)", canonicalUrl, {
      isLink: true,
      copyValue: canonicalUrl,
      mono: true,
      extra: txid ? "TXID: " + txid : null
    }));
  } else if (txid) {
    items.push(renderDataBlock("Arweave TXID", txid, { copyValue: txid, mono: true }));
  }
  return items.join("");
}

function renderArtifactPanel(preview, title, statusHtml) {
  const artifactTitle = title ? quoteTitle(title) : "Artifact";
  const metaParts = [];
  if (preview && preview.dimensionsLabel) metaParts.push(preview.dimensionsLabel);
  if (preview && preview.sizeLabel) metaParts.push(preview.sizeLabel);
  if (preview && preview.contentType) metaParts.push(preview.contentType);
  const artifactMeta = metaParts.length ? metaParts.join(" • ") : "Preview unavailable";
  const imageHtml = preview && preview.objectUrl
    ? '<img class="artifact-image" src="' + escapeHtml(preview.objectUrl) + '" alt="' + escapeHtml("Resolved artifact preview for " + artifactTitle) + '" loading="eager" decoding="async" />'
    : '<div class="artifact-placeholder">Preview unavailable</div>';
  return '' +
    '<section class="artifact-panel">' +
      '<div class="artifact-stage">' +
        '<div class="artifact-frame">' +
          '<div class="artifact-header">' +
            (statusHtml || "") +
            '<span class="panel-label">Preview</span>' +
          "</div>" +
          '<div class="artifact-image-wrap">' + imageHtml + "</div>" +
          '<div class="artifact-caption">' +
            '<div class="artifact-title" data-pretext="left">' + escapeHtml(artifactTitle) + "</div>" +
            '<div class="artifact-meta">' + escapeHtml(artifactMeta) + "</div>" +
          "</div>" +
        "</div>" +
      "</div>" +
    "</section>";
}

function renderAudit(commands) {
  if (!commands) return "";
  const escapedCommands = escapeHtml(commands).replace(/^(# .+)$/gm, '<span class="comment">$1</span>');
  return '' +
    '<section class="steps-section">' +
      '<div class="commands">' +
        '<div class="commands-header">' +
          '<span class="commands-label">Audit Commands</span>' +
          '<button class="copy-btn" data-copy="' + escapeHtml(commands) + '" aria-label="Copy commands">Copy</button>' +
        "</div>" +
        "<pre><code>" + escapedCommands + "</code></pre>" +
      "</div>" +
    "</section>";
}

function renderNpxCommand(reference) {
  if (!reference) return "";
  const command = buildNpxVerifyCommand(reference);
  return '' +
    '<section class="steps-section">' +
      '<div class="commands">' +
        '<div class="commands-header">' +
          '<span class="commands-label">NPX Verify</span>' +
          '<button class="copy-btn" data-copy="' + escapeHtml(command) + '" aria-label="Copy npx verify command">Copy</button>' +
        "</div>" +
        "<pre><code>" + escapeHtml(command) + "</code></pre>" +
      "</div>" +
    "</section>";
}

function renderResolvedRecord(options) {
  const title = options.title;
  const txHash = options.txHash;
  const arTxid = options.arTxid;
  const canonicalUrl = options.canonicalUrl;
  const proofValue = options.proofValue;
  const stegValue = options.stegValue;
  const commands = options.commands;
  const statusText = options.statusText;
  const statusType = options.statusType || "verified";
  const statusTooltip = options.statusTooltip;
  const preview = options.preview;
  const previewError = options.previewError;
  let html = '<div class="console-content"><div class="record-shell">';
  html += '<div class="record-layout">';
  html += renderArtifactPanel(preview, title, renderStatusPanel(statusText, statusType, statusTooltip));
  html += '<aside class="record-panel">';
  html += '<section class="record-card"><div class="record-topline"><span class="panel-label">Provenance Record</span></div><div class="record-body">';
  html += '<div class="data-grid">';
  if (title) {
    html += renderDataBlock("Title", quoteTitle(title));
  }
  if (txHash) {
    html += renderDataBlock("Base TX Hash", txHash, { copyValue: txHash, mono: true });
  }
  html += renderArtifactRecordBlock(arTxid, canonicalUrl);
  if (proofValue) {
    html += renderDataBlock("Proof (CSHA)", proofValue, { copyValue: proofValue, mono: true });
  }
  if (stegValue) {
    html += renderDataBlock("STEGO-PASS", stegValue, { copyValue: stegValue, mono: true });
  }
  html += "</div>";
  if (previewError) {
    html += '<div class="notes"><p class="notes-text">' + escapeHtml(previewError) + "</p></div>";
  }
  html += '<div class="notes"><p class="notes-text">Payload checksum not checked. Download the original archive file and run the local verification commands. Metadata is untrusted public content.</p></div>';
  if (stegValue) {
    html += '<div class="notes"><p class="notes-text" data-pretext="left">Public STEG makes extraction public. Plaintext stays private only if the age password is strong and different from STEG.</p></div>';
  }
  html += "</div></section></aside></div>";
  html += renderNpxCommand(txHash || arTxid || canonicalUrl);
  html += renderAudit(commands);
  html += "</div></div>";
  consoleEl.innerHTML = html;
  attachCopyHandlers();
}

function renderLegacy(cid, options) {
  releasePreviewUrl();
  options = options || {};
  const title = options.title;
  const checksum = options.checksum;
  const txHash = options.txHash;
  const rawMetadata = options.rawMetadata;
  const statusText = txHash ? "Legacy Protocol" : "Legacy Archive";
  const tooltip = "Legacy IPFS metadata detected. Current labels use ARTXID + CSHA.";
  let html = '<div class="console-content"><div class="record-shell">';
  html += renderStatusPanel(statusText, "warning", tooltip);
  html += '<div class="record-layout">';
  html += '<section class="artifact-panel"><div class="artifact-stage"><div class="artifact-frame"><div class="artifact-image-wrap"><div class="artifact-placeholder">IPFS metadata only</div></div><div class="artifact-caption"><div class="artifact-title" data-pretext="left">' + escapeHtml(title ? quoteTitle(title) : "Legacy record") + '</div><div class="artifact-meta">Pre-Arweave format</div></div></div></div></section>';
  html += '<aside class="record-panel"><section class="record-card"><div class="record-topline"><span class="panel-label">Legacy Provenance</span></div><div class="record-body"><div class="data-grid">';
  if (rawMetadata) {
    html += renderDataBlock("Decoded Label", rawMetadata, { copyValue: rawMetadata, mono: true });
  }
  if (title) {
    html += renderDataBlock("Title", quoteTitle(title));
  }
  if (txHash) {
    html += renderDataBlock("Base TX Hash", txHash, { copyValue: txHash, mono: true });
  }
  html += renderDataBlock("IPFS CID", cid, { copyValue: cid, mono: true });
  if (checksum) {
    html += renderDataBlock("Proof Hash", checksum, { copyValue: checksum, mono: true });
  }
  html += "</div></div></section></aside></div></div></div>";
  consoleEl.innerHTML = html;
  attachCopyHandlers();
}

function parseLegacyMetadata(text, parsedFields) {
  parsedFields = parsedFields || {};
  const normalized = String(text || "").replace(/\u0000/g, " ");
  const compact = normalized.replace(/\s+/g, " ").trim();
  let seededTitle = parsedFields.TITLE || null;
  if (seededTitle && /\b(?:cid|ipfs|proof|sha|hash|csha)\s*:/i.test(seededTitle)) {
    seededTitle = null;
  }
  const legacy = {
    title: seededTitle,
    cid: parsedFields.IPFS || parsedFields.CID || null,
    checksum: parsedFields.CSHA || parsedFields.PROOF || parsedFields.SHA || parsedFields.HASH || null
  };
  if (legacy.cid && /\s+\b(?:title|ipfs|cid|csha|proof|sha512|sha|hash)\s*:/i.test(legacy.cid)) {
    legacy.cid = null;
  }
  if (legacy.checksum && /\s+\b(?:title|ipfs|cid|csha|proof|sha512|sha|hash)\s*:/i.test(legacy.checksum)) {
    legacy.checksum = null;
  }

  const cidMatch = normalized.match(/\b(?:ipfs|cid)\s*:\s*([a-zA-Z0-9_-]+)/i);
  if (!legacy.cid && cidMatch) {
    legacy.cid = cidMatch[1];
  }

  const checksumMatch = normalized.match(/\b(?:csha|proof|sha512|sha|hash)\s*:\s*((?:0x)?[a-fA-F0-9]{32,128})/i);
  if (!legacy.checksum && checksumMatch) {
    legacy.checksum = checksumMatch[1];
  }

  const titleMatch = normalized.match(/\btitle\s*:\s*(.+?)(?=\s+\b(?:ipfs|cid|csha|proof|sha512|sha|hash)\s*:|$)/i);
  if (!legacy.title && titleMatch) {
    legacy.title = titleMatch[1].trim();
  }
  if (!legacy.title) {
    const firstField = compact.match(/\b(?:artxid|ar|ipfs|cid|csha|proof|sha512|sha|hash|steg)\s*:/i);
    if (firstField && typeof firstField.index === "number" && firstField.index > 0) {
      const prefix = compact.slice(0, firstField.index).replace(/[|,;:\-]+$/g, "").trim();
      if (prefix) {
        legacy.title = prefix;
      }
    }
  }

  return legacy;
}

function attachCopyHandlers(root) {
  const scope = root || consoleEl;
  const buttons = scope.querySelectorAll("[data-copy]");
  buttons.forEach(function (btn) {
    if (btn.dataset.copyBound === "1") return;
    btn.dataset.copyBound = "1";
    btn.addEventListener("click", function () {
      const text = btn.getAttribute("data-copy");
      copyToClipboard(text, btn);
    });
  });
  if (!root || scope === consoleEl) {
    attachStatusTooltipHandlers();
  }
}

function useTapTooltipMode() {
  return window.matchMedia("(hover: none), (pointer: coarse)").matches;
}

function closeStatusTooltips(exceptEl) {
  const badges = consoleEl.querySelectorAll(".status.has-tip.is-open");
  badges.forEach(function (badge) {
    if (badge !== exceptEl) {
      badge.classList.remove("is-open");
      badge.setAttribute("aria-expanded", "false");
    }
  });
}

function attachStatusTooltipHandlers() {
  const badges = consoleEl.querySelectorAll(".status.has-tip");
  badges.forEach(function (badge) {
    badge.addEventListener("click", function (event) {
      if (!useTapTooltipMode()) return;
      event.stopPropagation();
      const isOpen = badge.classList.contains("is-open");
      closeStatusTooltips(badge);
      if (isOpen) {
        badge.classList.remove("is-open");
        badge.setAttribute("aria-expanded", "false");
      } else {
        badge.classList.add("is-open");
        badge.setAttribute("aria-expanded", "true");
      }
    });
    badge.addEventListener("keydown", function (event) {
      if (event.key === "Enter" || event.key === " ") {
        event.preventDefault();
        const isOpen = badge.classList.contains("is-open");
        closeStatusTooltips(badge);
        if (isOpen) {
          badge.classList.remove("is-open");
          badge.setAttribute("aria-expanded", "false");
        } else {
          badge.classList.add("is-open");
          badge.setAttribute("aria-expanded", "true");
        }
      } else if (event.key === "Escape") {
        badge.classList.remove("is-open");
        badge.setAttribute("aria-expanded", "false");
        badge.blur();
      }
    });
    badge.addEventListener("blur", function () {
      if (!useTapTooltipMode()) {
        badge.classList.remove("is-open");
        badge.setAttribute("aria-expanded", "false");
      }
    });
  });
  if (!document.body.dataset.statusTooltipBound) {
    document.addEventListener("click", function () {
      if (!useTapTooltipMode()) return;
      closeStatusTooltips(null);
    });
    document.body.dataset.statusTooltipBound = "1";
  }
}

function readImageDimensions(objectUrl) {
  return new Promise(function (resolve, reject) {
    const img = new Image();
    const timer = setTimeout(() => { img.src = ""; reject(new Error("Image preview timed out.")); }, REQUEST_TIMEOUT_MS);
    img.onload = function () {
      clearTimeout(timer);
      resolve({ width: img.naturalWidth, height: img.naturalHeight });
    };
    img.onerror = function () {
      clearTimeout(timer);
      reject(new Error("Image preview could not be decoded."));
    };
    img.src = objectUrl;
  });
}

async function fetchArtifactPreview(txid) {
  const safeTxidValue = normalizeArweaveTxid(txid);
  if (!safeTxidValue) {
    throw new Error("Invalid Arweave transaction id.");
  }
  const canonicalUrl = "https://arweave.net/" + safeTxidValue;
  const response = await fetch(canonicalUrl, { mode: "cors", cache: "default", signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS) });
  if (!response.ok) {
    throw new Error("Arweave artifact request failed with status " + response.status + ".");
  }

  const contentLength = Number(response.headers.get("content-length"));
  if (Number.isFinite(contentLength) && contentLength > MAX_PREVIEW_BYTES) {
    throw new Error("Artifact is larger than the browser preview limit (" + formatBytes(MAX_PREVIEW_BYTES) + ").");
  }

  const bytes = await readLimited(response, MAX_PREVIEW_BYTES);
  const dimensions = inspectRasterImage(bytes);
  const blob = new Blob([bytes], { type: dimensions.mime });
  if (blob.size > MAX_PREVIEW_BYTES) {
    throw new Error("Artifact is larger than the browser preview limit (" + formatBytes(MAX_PREVIEW_BYTES) + ").");
  }

  const contentType = blob.type || response.headers.get("content-type") || "";
  const preview = {
    canonicalUrl: canonicalUrl,
    resolvedUrl: response.url || canonicalUrl,
    contentType: contentType,
    size: blob.size,
    sizeLabel: formatBytes(blob.size),
    dimensionsLabel: null,
    objectUrl: null
  };

  if (!/^image\//i.test(contentType)) {
    return preview;
  }

  const originalUrl = URL.createObjectURL(blob);
  try {
    await readImageDimensions(originalUrl);
    preview.objectUrl = originalUrl;
  } catch (error) {
    URL.revokeObjectURL(originalUrl);
    throw error;
  }
  preview.dimensionsLabel = dimensions.width + " × " + dimensions.height + " px";
  return preview;
}

function renderLoading(message, detail) {
  releasePreviewUrl();
  consoleEl.innerHTML = '' +
    '<div class="console-content">' +
      renderStatusPanel(message, "loading", detail || "Resolving record.") +
      '<div class="record-shell">' +
        '<div class="record-layout">' +
          '<section class="artifact-panel">' +
            '<div class="record-topline"><span class="panel-label">Artifact</span><span class="panel-label">Loading</span></div>' +
            '<div class="artifact-stage"><div class="artifact-frame"><div class="artifact-image-wrap"><div class="artifact-placeholder">Preparing artifact view</div></div><div class="artifact-caption"><div class="artifact-title">Resolution in progress</div><div class="artifact-meta">Awaiting artifact data</div><p class="artifact-note">The artifact will appear here once retrieval completes.</p></div></div></div>' +
          "</section>" +
          '<aside class="record-panel"><section class="record-card"><div class="record-topline"><span class="panel-label">Catalog Record</span><span class="panel-label">Loading</span></div><div class="record-body"><div class="data-grid">' +
            renderDataBlock("Status", detail || "Resolving...") +
          "</div></div></section></aside>" +
        "</div>" +
      "</div>" +
    "</div>";
}

async function renderArweave(txid) {
  const safeTxidValue = normalizeArweaveTxid(txid);
  if (!safeTxidValue) {
    releasePreviewUrl();
    consoleEl.innerHTML = '<div class="console-content">' + renderStatusPanel("Invalid Input", "error", "Enter a valid 43-character Arweave TXID.") + "</div>";
    attachCopyHandlers();
    return;
  }
  const canonicalUrl = "https://arweave.net/" + safeTxidValue;
  renderLoading("Fetching Artifact", "Loading the artifact from Arweave.");

  let preview = null;
  let previewError = null;
  try {
    preview = await fetchArtifactPreview(safeTxidValue);
  } catch (err) {
    previewError = err.message || String(err);
  }

  releasePreviewUrl();
  if (preview && preview.objectUrl) {
    activePreviewObjectUrl = preview.objectUrl;
  }

  const commands = "# Download artifact\ncurl -fL -o locked_artifact.jpg \"" + canonicalUrl + "\"\n\n# Extract payload (requires HStego or confess CLI)\n./confess extract --image locked_artifact.jpg --stego-pass-prompt\n\n# Verify checksum (if known)\n./confess verify --file payload.age --csha <CSHA_SHA512>";
  renderResolvedRecord({
    statusText: previewError ? "Preview Unavailable" : "Artifact Located",
    statusType: "warning",
    statusTooltip: "Archive pointer resolved. Public carrier located in permanent storage, without accompanying on-chain label or proof material.",
    title: null,
    txHash: null,
    arTxid: safeTxidValue,
    canonicalUrl: canonicalUrl,
    proofValue: null,
    stegValue: null,
    commands: commands,
    preview: preview,
    previewError: previewError
  });
}

async function verifyTx(txHash) {
  renderLoading("Querying Ledger", "Decoding the published label.");

  try {
    const fetched = await fetchBaseTransaction(txHash);
    if (!fetched.ok) throw new Error(fetched.errors.join(" "));
    const ascii = fetched.ascii;
    const rawMetadata = fetched.rawMetadata;

    if (!ascii) {
      releasePreviewUrl();
      consoleEl.innerHTML = '<div class="console-content">' + renderStatusPanel("Unreadable", "error", "No readable artifact metadata was found in the transaction input.") + "</div>";
      attachCopyHandlers();
      return;
    }

    const parsed = parseMetadataLabel(ascii);
    if (parsed.errors.length) throw new Error(parsed.errors.join(" "));
    const fields = parsed.fields;
    const arField = parsed.artxid;
    const legacy = parseLegacyMetadata(ascii, fields);

    if (!arField && legacy.cid) {
      renderLegacy(legacy.cid, {
        title: legacy.title,
        checksum: legacy.checksum,
        txHash: txHash,
        rawMetadata: rawMetadata
      });
      return;
    }

    if (!arField) {
      releasePreviewUrl();
      consoleEl.innerHTML = '<div class="console-content">' + renderStatusPanel("Unparsed", "warning", "Readable transaction input found, but it does not conform to a known artifact label.") + '<div class="data-grid">' + renderDataBlock("Raw Data", ascii, { mono: true, copyValue: ascii }) + "</div></div>";
      attachCopyHandlers();
      return;
    }

    const arId = normalizeArweaveTxid(arField);
    if (!arId) {
      releasePreviewUrl();
      consoleEl.innerHTML = '<div class="console-content">' + renderStatusPanel("Invalid Archive Pointer", "error", "The on-chain ARTXID field is not a valid Arweave transaction id.") + '<div class="data-grid">' + renderDataBlock("Raw ARTXID", arField, { mono: true, copyValue: arField }) + "</div></div>";
      attachCopyHandlers();
      return;
    }
    const canonicalUrl = "https://arweave.net/" + arId;
    const proofValue = String(parsed.csha || "").trim();
    if (!/^[a-fA-F0-9]{128}$/.test(proofValue)) throw new Error("Missing or invalid CSHA. This label cannot support payload verification.");
    const cshaValue = proofValue.toLowerCase();
    const extractCommand = fields.STEG
      ? "./confess extract --image locked_artifact.jpg --stego-pass=" + shellQuote(fields.STEG)
      : "./confess extract --image locked_artifact.jpg --stego-pass-prompt";
    const commands = "# Download artifact\ncurl -fL -o locked_artifact.jpg \"" + canonicalUrl + "\"\n\n# Extract payload\n" + extractCommand + "\n\n# Verify checksum\n./confess verify --file payload.age --csha " + cshaValue;

    renderLoading("Fetching Artifact", "Loading the artifact from Arweave.");

    let preview = null;
    let previewError = null;
    try {
      preview = await fetchArtifactPreview(arId);
    } catch (err) {
      previewError = err.message || String(err);
    }

    releasePreviewUrl();
    if (preview && preview.objectUrl) {
      activePreviewObjectUrl = preview.objectUrl;
    }

    const resolvedTip = "Public RPC reports transaction inclusion. The encrypted payload checksum, finality, author identity, and testimony have not been independently verified.";

    renderResolvedRecord({
      statusText: "Metadata Resolved",
      statusType: "warning",
      statusTooltip: resolvedTip,
      title: fields.TITLE || null,
      txHash: txHash,
      arTxid: arId,
      canonicalUrl: canonicalUrl,
      proofValue: proofValue || null,
      stegValue: fields.STEG || null,
      commands: commands,
      preview: preview,
      previewError: previewError
    });
  } catch (err) {
    releasePreviewUrl();
    consoleEl.innerHTML = '<div class="console-content">' + renderStatusPanel("Error", "error", "Verification request failed. Network or resolver error.") + '<div class="data-grid">' + renderDataBlock("Details", err.message || String(err)) + "</div></div>";
  }
}

let verifying = false;
async function handleVerify() {
  if (verifying) return;
  const classified = classifyReference(inputEl.value);
  const value = classified.normalized;
  if (!value) return;
  verifying = true;
  verifyBtn.disabled = true;
  inputEl.readOnly = true;
  consoleEl.setAttribute("aria-busy", "true");
  try {
  revealResults();

  const isTx = /^0x[a-fA-F0-9]{64}$/.test(value);
  const isIpfs = /^(bafy|bafk|Qm)[a-zA-Z0-9_-]+$/i.test(value);
  const isArTxid = isArweaveTxid(value);

  if (isTx) {
    await verifyTx(value.toLowerCase());
  } else if (isIpfs) {
    renderLegacy(value);
  } else if (isArTxid) {
    await renderArweave(value);
  } else {
    releasePreviewUrl();
    consoleEl.innerHTML = '<div class="console-content">' + renderStatusPanel("Invalid Input", "error", "Enter a Base transaction hash, Arweave TXID, supported public URL, or legacy CID.") + "</div>";
  }
  } finally {
    verifying = false;
    verifyBtn.disabled = false;
    inputEl.readOnly = false;
    consoleEl.setAttribute("aria-busy", "false");
  }
}

verifyBtn.addEventListener("click", function () {
  handleVerify();
});

inputEl.addEventListener("keydown", function (event) {
  if (event.key === "Enter") handleVerify();
});

inputEl.addEventListener("input", updateNpxCommand);
updateNpxCommand();

const mcpPanel = document.querySelector(".mcp-panel");
if (mcpPanel) {
  attachCopyHandlers(mcpPanel);
}

function getPathLocator() {
  const path = window.location.pathname.replace(/\/+$/, "");
  const match = path.match(/^\/verify\/(.+)$/);
  if (!match) return null;
  try {
    return decodeURIComponent(match[1]).trim();
  } catch (error) {
    return match[1].trim();
  }
}

const urlParams = new URLSearchParams(window.location.search);
const txParam = urlParams.get("tx");
const txidParam = urlParams.get("txid");
const pathParam = getPathLocator();
const initialLocator = txParam || txidParam || pathParam;
if (initialLocator) {
  inputEl.value = initialLocator;
  updateNpxCommand();
  handleVerify();
}
