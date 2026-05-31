import assert from "node:assert/strict";
import test from "node:test";

import { asciiToHex } from "../lib/base.mjs";
import { resolveVerificationReference } from "../lib/verify.mjs";

const ARTXID = "a".repeat(43);
const CSHA = "b".repeat(128);
const BASE_TX = "0x" + "c".repeat(64);
const LABEL = `WHISTLEBLOWING | ARTXID:${ARTXID} | CSHA:${CSHA} | STEG:public-steg`;

test("resolveVerificationReference resolves a Base transaction through public calldata", async () => {
  const fetchImpl = async () => ({
    ok: true,
    json: async () => ({
      result: {
        hash: BASE_TX,
        input: asciiToHex(LABEL)
      }
    })
  });

  const record = await resolveVerificationReference(BASE_TX, {
    fetchImpl,
    checkArtifact: false
  });

  assert.equal(record.valid, true);
  assert.equal(record.type, "base_transaction_hash");
  assert.equal(record.title, "WHISTLEBLOWING");
  assert.equal(record.artxid, ARTXID);
  assert.equal(record.csha, CSHA);
  assert.equal(record.steg, "public-steg");
  assert.match(record.auditCommands, /curl -fL -o locked_artifact\.jpg/);
  assert.doesNotMatch(record.auditCommands, /^open /m);
});

test("resolveVerificationReference parses a public metadata label without network", async () => {
  const record = await resolveVerificationReference(LABEL, {
    checkArtifact: false
  });

  assert.equal(record.valid, true);
  assert.equal(record.type, "metadata_label");
  assert.equal(record.arweaveUrl, `https://arweave.net/${ARTXID}`);
});

