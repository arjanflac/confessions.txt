import assert from "node:assert/strict";
import test from "node:test";

import {
  classifyReference,
  generateLocalVerificationSteps,
  parseMetadataLabel,
  validateCsha,
  validateManifestShape
} from "../lib/protocol.mjs";

const ARTXID = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const CSHA = "a".repeat(128);
const BASE_TX = "0x" + "b".repeat(64);

test("parseMetadataLabel extracts current public fields", () => {
  const parsed = parseMetadataLabel(`Proof | ARTXID:${ARTXID} | CSHA:${CSHA} | STEG:public-open`);

  assert.equal(parsed.title, "Proof");
  assert.equal(parsed.artxid, ARTXID);
  assert.equal(parsed.csha, CSHA);
  assert.equal(parsed.steg, "public-open");
  assert.deepEqual(parsed.errors, []);
  assert.ok(parsed.warnings.some((warning) => warning.includes("STEG is public")));
});

test("classifyReference recognizes verifier, Base, Arweave, and metadata references", () => {
  assert.equal(classifyReference(BASE_TX).type, "base_transaction_hash");
  assert.equal(classifyReference(`https://confessionstxt.art/verify/${BASE_TX}`).type, "base_transaction_hash");
  assert.equal(classifyReference(`https://arweave.net/${ARTXID}`).type, "arweave_transaction_id");
  assert.equal(classifyReference(`Proof | ARTXID:${ARTXID} | CSHA:${CSHA}`).type, "metadata_label");
});

test("validateCsha is syntax-only and normalizes case", () => {
  const valid = validateCsha("A".repeat(128));
  assert.equal(valid.valid, true);
  assert.equal(valid.normalized, "a".repeat(128));

  const invalid = validateCsha("a".repeat(127));
  assert.equal(invalid.valid, false);
  assert.match(invalid.message, /format check/);
});

test("validateManifestShape refuses malformed public metadata", () => {
  const invalid = validateManifestShape({
    title: "Bad | Title",
    artxid: "too-short",
    csha: "not-a-csha"
  });

  assert.equal(invalid.valid, false);
  assert.ok(invalid.errors.length >= 3);

  const valid = validateManifestShape({
    title: "Proof",
    artxid: ARTXID,
    csha: CSHA
  });

  assert.equal(valid.valid, true);
  assert.deepEqual(valid.errors, []);
});

test("generateLocalVerificationSteps creates local-only commands and warnings", () => {
  const steps = generateLocalVerificationSteps({
    artxid: ARTXID,
    csha: CSHA
  });

  assert.equal(steps.valid, true);
  assert.match(steps.commands, /curl -fL -o locked_artifact\.jpg/);
  assert.match(steps.commands, /stego-pass-prompt/);
  assert.match(steps.commands, new RegExp(`--csha ${CSHA}`));
  assert.ok(steps.warnings.some((warning) => warning.includes("Do not send plaintext")));
});

test("generateLocalVerificationSteps treats public_steg as explicit public material", () => {
  const steps = generateLocalVerificationSteps({
    artxid: ARTXID,
    csha: CSHA,
    public_steg: "public-pass"
  });

  assert.equal(steps.valid, true);
  assert.match(steps.commands, /--stego-pass 'public-pass'/);
  assert.ok(steps.warnings.some((warning) => warning.includes("public_steg")));
});
