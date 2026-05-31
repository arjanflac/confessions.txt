import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import test from "node:test";

const ARTXID = "a".repeat(43);
const CSHA = "b".repeat(128);
const LABEL = `Proof | ARTXID:${ARTXID} | CSHA:${CSHA}`;

function runCli(args) {
  return spawnSync(process.execPath, ["bin/confessions.mjs", ...args], {
    cwd: new URL("..", import.meta.url),
    encoding: "utf8"
  });
}

test("CLI verifies a metadata label as JSON", () => {
  const result = runCli(["verify", LABEL, "--json", "--no-artifact-check"]);

  assert.equal(result.status, 0, result.stderr);
  const payload = JSON.parse(result.stdout);
  assert.equal(payload.valid, true);
  assert.equal(payload.title, "Proof");
  assert.equal(payload.artxid, ARTXID);
});

test("CLI accepts the reference as the first argument and prints commands only", () => {
  const result = runCli([LABEL, "--commands", "--no-artifact-check"]);

  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /curl -fL -o locked_artifact\.jpg/);
  assert.match(result.stdout, /python3 cli\/confess\.py verify/);
  assert.doesNotMatch(result.stdout, /CONFESSIONS\.txt/);
});

test("CLI exposes help and version", () => {
  const help = runCli(["--help"]);
  assert.equal(help.status, 0);
  assert.match(help.stdout, /confessions verify <reference>/);

  const version = runCli(["--version"]);
  assert.equal(version.status, 0);
  assert.match(version.stdout, /^\d+\.\d+\.\d+/);
});

