import assert from "node:assert/strict";
import test from "node:test";

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

test("stdio MCP server exposes verification resources and tools", async () => {
  const transport = new StdioClientTransport({
    command: "node",
    args: ["server.mjs"]
  });
  const client = new Client({ name: "confessions-test-client", version: "0.0.0" });

  await client.connect(transport);
  try {
    const tools = await client.listTools();
    const toolNames = tools.tools.map((tool) => tool.name).sort();

    assert.deepEqual(toolNames, [
      "explain_artifact_reference",
      "generate_local_verification_steps",
      "parse_public_metadata_label",
      "resolve_public_artifact_reference",
      "validate_confession_manifest_shape",
      "verify_csha_format"
    ]);

    const resources = await client.listResources();
    const resourceUris = resources.resources.map((resource) => resource.uri).sort();

    assert.deepEqual(resourceUris, [
      "confessions://cli",
      "confessions://mcp-boundary",
      "confessions://protocol",
      "confessions://verification"
    ]);

    const prompts = await client.listPrompts();
    const promptNames = prompts.prompts.map((prompt) => prompt.name).sort();

    assert.deepEqual(promptNames, [
      "explain_confession_to_human",
      "should_this_person_contact_arjan"
    ]);

    const prompt = await client.getPrompt({
      name: "should_this_person_contact_arjan",
      arguments: { person_context: "curator researching sealed public records" }
    });

    assert.equal(prompt.messages.length, 1);
    assert.equal(prompt.messages[0].role, "user");

    const result = await client.callTool({
      name: "verify_csha_format",
      arguments: { csha: "a".repeat(128) }
    });

    assert.equal(result.content[0].type, "text");
    assert.equal(result.structuredContent.valid, true);

    const resolved = await client.callTool({
      name: "resolve_public_artifact_reference",
      arguments: {
        reference: `Proof | ARTXID:${"a".repeat(43)} | CSHA:${"a".repeat(128)}`,
        check_artifact: false
      }
    });

    assert.equal(resolved.structuredContent.type, "metadata_label");
    assert.equal(resolved.structuredContent.valid, true);
  } finally {
    await client.close();
  }
});
