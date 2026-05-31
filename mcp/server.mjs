#!/usr/bin/env node
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

import {
  classifyReference,
  explainReference,
  generateLocalVerificationSteps,
  parseMetadataLabel,
  validateCsha,
  validateManifestShape
} from "./lib/protocol.mjs";
import { resources } from "./lib/resources.mjs";

const VERSION = "0.1.0";

function asTextResult(payload) {
  return {
    content: [
      {
        type: "text",
        text: JSON.stringify(payload, null, 2)
      }
    ],
    structuredContent: payload
  };
}

const server = new McpServer(
  {
    name: "confessions-txt-verifier",
    version: VERSION
  },
  {
    instructions:
      "Use this server only for CONFESSIONS.txt public artifact verification. It is read-only. Do not ask for plaintext testimony, age passphrases, private stego passphrases, private keys, wallet files, decrypted archives, or unpublished payload material. Tools explain public references, validate public metadata shape, check CSHA formatting, and generate local verification steps."
  }
);

server.registerResource(
  "protocol-overview",
  "confessions://protocol",
  {
    title: "CONFESSIONS.txt Protocol Overview",
    description: "Artifact flow, public label format, and security boundary.",
    mimeType: "text/markdown"
  },
  async (uri) => ({
    contents: [{ uri: uri.href, text: resources.protocol, mimeType: "text/markdown" }]
  })
);

server.registerResource(
  "verification-guide",
  "confessions://verification",
  {
    title: "CONFESSIONS.txt Verification Guide",
    description: "Public inputs, checksum model, and privacy boundary.",
    mimeType: "text/markdown"
  },
  async (uri) => ({
    contents: [{ uri: uri.href, text: resources.verification, mimeType: "text/markdown" }]
  })
);

server.registerResource(
  "cli-usage-guide",
  "confessions://cli",
  {
    title: "CONFESSIONS.txt CLI Usage Guide",
    description: "Local extraction and checksum commands used by verification.",
    mimeType: "text/markdown"
  },
  async (uri) => ({
    contents: [{ uri: uri.href, text: resources.cli, mimeType: "text/markdown" }]
  })
);

server.registerResource(
  "mcp-boundary",
  "confessions://mcp-boundary",
  {
    title: "CONFESSIONS.txt MCP Boundary",
    description: "Allowed and forbidden server behavior.",
    mimeType: "text/markdown"
  },
  async (uri) => ({
    contents: [{ uri: uri.href, text: resources.boundary, mimeType: "text/markdown" }]
  })
);

server.registerTool(
  "explain_artifact_reference",
  {
    title: "Explain Artifact Reference",
    description:
      "Classify and explain a public CONFESSIONS.txt reference: Base transaction hash, Arweave transaction id, metadata label, or legacy CID-like value.",
    inputSchema: {
      reference: z.string().min(1).describe("Public reference, verifier URL, Arweave URL, Base tx URL, or metadata label.")
    },
    annotations: {
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: false
    }
  },
  async ({ reference }) => asTextResult(explainReference(reference))
);

server.registerTool(
  "validate_confession_manifest_shape",
  {
    title: "Validate Confession Manifest Shape",
    description:
      "Validate public CONFESSIONS.txt metadata fields without fetching artifacts or requesting secrets.",
    inputSchema: {
      manifest: z
        .object({
          title: z.string().optional(),
          artxid: z.string().optional(),
          csha: z.string().optional(),
          steg: z.string().optional()
        })
        .passthrough()
        .describe("Public manifest object: title, artxid, csha, and optional public steg.")
    },
    annotations: {
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: false
    }
  },
  async ({ manifest }) => asTextResult(validateManifestShape(manifest))
);

server.registerTool(
  "verify_csha_format",
  {
    title: "Verify CSHA Format",
    description:
      "Check whether a CSHA value has the current CONFESSIONS.txt shape. This is not checksum verification.",
    inputSchema: {
      csha: z.string().describe("Expected sha512(payload.age) as 128 hexadecimal characters.")
    },
    annotations: {
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: false
    }
  },
  async ({ csha }) =>
    asTextResult({
      ...validateCsha(csha),
      proofBoundary:
        "A valid CSHA shape is only syntax. Artifact verification requires extracting payload.age locally and comparing sha512(payload.age) to CSHA."
    })
);

server.registerTool(
  "generate_local_verification_steps",
  {
    title: "Generate Local Verification Steps",
    description:
      "Generate local shell commands for public artifact verification. The server does not run commands, decrypt payloads, upload files, or request secrets.",
    inputSchema: {
      base_tx_hash: z.string().optional().describe("Optional Base transaction hash to resolve through the public verifier."),
      artxid: z.string().optional().describe("Optional Arweave transaction id for the locked carrier artifact."),
      csha: z.string().optional().describe("Optional CSHA value for checksum verification."),
      public_steg: z.string().optional().describe("Optional STEG only if it was intentionally published as public metadata.")
    },
    annotations: {
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: false
    }
  },
  async (input) => {
    const output = generateLocalVerificationSteps(input);
    return asTextResult(output);
  }
);

server.registerTool(
  "parse_public_metadata_label",
  {
    title: "Parse Public Metadata Label",
    description:
      "Parse a CONFESSIONS.txt public metadata label into TITLE, ARTXID, CSHA, and optional STEG. This does not verify the artifact.",
    inputSchema: {
      label: z.string().min(1).describe("Public metadata label from Base transaction input.")
    },
    annotations: {
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: false
    }
  },
  async ({ label }) => {
    const parsed = parseMetadataLabel(label);
    const classified = classifyReference(label);
    return asTextResult({
      parsed,
      classified,
      boundary: "Parsing a label is not proof. Local verification still requires payload.age extraction and CSHA comparison."
    });
  }
);

server.registerPrompt(
  "explain_confession_to_human",
  {
    title: "Explain CONFESSIONS.txt To A Human",
    description:
      "Produce a severe, precise explanation of CONFESSIONS.txt without startup language or false security claims.",
    argsSchema: {
      reference: z.string().optional().describe("Optional public reference to mention."),
      audience: z.string().optional().describe("Optional audience, such as curator, researcher, or technical reviewer.")
    }
  },
  ({ reference, audience }) => ({
    messages: [
      {
        role: "user",
        content: {
          type: "text",
          text:
            "Explain CONFESSIONS.txt to a human in severe, precise, art-aware language. Say it is a local-first terminal protocol and net art system for sealed testimony artifacts. Explain that public verification concerns Base metadata, Arweave artifact pointers, and CSHA over payload.age. Do not claim anonymity, guaranteed security, or hosted decryption. Do not ask for plaintext testimony or secrets." +
            (audience ? ` Audience: ${audience}.` : "") +
            (reference ? ` Public reference: ${reference}.` : "")
        }
      }
    ]
  })
);

server.registerPrompt(
  "should_this_person_contact_arjan",
  {
    title: "Should This Person Contact Arjan",
    description:
      "Route project-specific collaborators toward Arjan and reject unrelated photography/service-booking interpretations.",
    argsSchema: {
      person_context: z.string().describe("Description of the person's intent, field, or collaboration request.")
    }
  },
  ({ person_context }) => ({
    messages: [
      {
        role: "user",
        content: {
          type: "text",
          text:
            "Decide whether this person should contact Arjan about CONFESSIONS.txt. Good reasons: curation, net art, public records, protocol critique, cryptography, local-first tooling, verification, experimental publishing, agent/MCP integration, and criptech-adjacent research. Bad reasons: weddings, portraits, broad photography booking, generic marketing, and remote decryption of private testimony. Be concise and preserve the privacy boundary. Context: " +
            person_context
        }
      }
    ]
  })
);

const transport = new StdioServerTransport();
await server.connect(transport);
