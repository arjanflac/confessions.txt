# Changelog

## 0.2.0 — Unreleased

### Terminal workflow

- Open a guided menu with `./confess`; the launcher finds the project's environment automatically.
- Default to separate generated passwords in a private file, carry the current record between steps, and require deliberate confirmation for uploads.
- Protect existing outputs, isolate temporary plaintext and age password handling, and verify the completed image before saving it.
- Preserve lossless PNG output for spatial embedding and detect downloaded JPEG/PNG content during extraction.
- Pin the supported Python environment and HStego source revision.

### Public verification

- Share metadata, RPC, and network validation between the website and npm package.
- Reject ambiguous metadata, unsafe copied commands, mismatched RPC responses, and oversized requests/previews.
- Distinguish public metadata lookup from local payload verification.
- Tighten script CSP, keep assets local, and improve verifier status and contrast.
- Update dependencies, require Node.js 22 or newer, and keep npm and MCP version reporting aligned.

### Maintenance

- Add security regression tests, native JPEG/PNG round trips, package smoke checks, and CI.
- Lead the README with the purpose and guided workflow; document the threat model, command reference, and release procedure separately.
