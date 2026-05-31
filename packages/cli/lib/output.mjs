import { formatBytes } from "./verify.mjs";

function quoteTitle(title) {
  if (!title) return null;
  return `"${String(title).replace(/^"+|"+$/g, "")}"`;
}

function section(label, value) {
  if (value === null || value === undefined || value === "") return "";
  return `${label}\n${value}\n\n`;
}

function artifactLine(artifact) {
  if (!artifact) return null;
  if (!artifact.checked) return "not checked";
  if (!artifact.ok) return artifact.status ? `not confirmed (HTTP ${artifact.status})` : "not confirmed";
  const parts = ["confirmed"];
  if (artifact.contentType) parts.push(artifact.contentType);
  const size = artifact.sizeLabel || formatBytes(Number(artifact.contentLength));
  if (size) parts.push(size);
  return parts.join(" / ");
}

export function formatVerificationText(record, options = {}) {
  if (options.commandsOnly) {
    return record.auditCommands ? `${record.auditCommands}\n` : "";
  }

  let output = "";
  const status = record.valid ? record.status || "resolved" : record.status || "error";
  output += `CONFESSIONS.txt / ${status.toUpperCase().replace(/_/g, " ")}\n\n`;
  output += section("TITLE", quoteTitle(record.title));
  output += section("BASE", record.baseTxHash);
  output += section("ARWEAVE", record.arweaveUrl);
  output += section("CSHA", record.csha);
  output += section("PUBLIC STEG", record.steg);
  output += section("VERIFIER", record.verifierUrl);
  output += section("ARTIFACT", artifactLine(record.artifact));

  if (record.auditCommands) {
    output += `AUDIT COMMANDS\n${record.auditCommands}\n\n`;
  }

  const warnings = Array.from(new Set(record.warnings || []));
  if (warnings.length) {
    output += `WARNINGS\n${warnings.map((warning) => `- ${warning}`).join("\n")}\n\n`;
  }

  const errors = Array.from(new Set(record.errors || []));
  if (errors.length) {
    output += `ERRORS\n${errors.map((error) => `- ${error}`).join("\n")}\n\n`;
  }

  const notes = Array.from(new Set(record.notes || []));
  if (notes.length) {
    output += `NOTES\n${notes.map((note) => `- ${note}`).join("\n")}\n`;
  }

  return output.endsWith("\n") ? output : `${output}\n`;
}

export function formatVerificationJson(record) {
  return `${JSON.stringify(record, null, 2)}\n`;
}

