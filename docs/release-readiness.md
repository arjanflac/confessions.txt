# Release readiness — 0.2.0 candidate

**Verdict: ready with caveats for a deliberately scoped release.** The candidate is prepared locally. It is not a certification that all vulnerabilities have been found. No push, npm publication, wallet upload, or deployment was part of this review.

## Evidence from the local review

Validated on macOS Apple Silicon on 2026-09-21:

- 32 Python tests passed with native integration enabled. These include real JPEG and PNG seal → extract → checksum → decrypt round trips using synthetic text, wrong-password rejection, file preservation, private permissions, and terminal-menu transitions.
- 24 JavaScript tests passed on Node.js 22 and 24. Coverage includes malformed/ambiguous metadata, UTF-8, shell and terminal injection, RPC identity and block checks, streaming byte limits, redirects, browser/package consistency, and CSP hashes.
- An actual npm tarball contained only 11 intended public files, including its license. A clean installation passed offline CLI verification and MCP initialization, resource/tool discovery, and metadata resolution. CLI and MCP report version 0.2.0 from the same package manifest.
- A real terminal session sealed synthetic text using generated split passwords, then checked its checksum through the menu. The launcher was also tested from a different working directory and without a terminal.
- An independent code-review pass identified four metadata/command consistency defects, now fixed with regression coverage. It found no additional release-blocking encryption or command-injection flaw.
- Browser checks exercised the local Pages headers, desktop/mobile layouts, untrusted title rendering, copied commands, invalid input, and unavailable previews. The earlier audit also exercised the live public lookup and original-image preview. Browser verification does not decrypt a payload.
- npm and PyPI advisory scans reported no known vulnerabilities in scanned dependencies. HStego is a source install and is not covered by the PyPI advisory lookup.
- Source/history secret scans found no detected credentials. Personal artifact tests and generated records remain outside public commits in ignored local audit storage.

Run the reproducible checks in the [README](../README.md#details-and-development) and `scripts/check_package.mjs` before a later release. Native tests are opt-in; the CI matrix runs the portable tests on Node 22/24 with Python 3.12. The GitHub-hosted workflow itself has not run for these unpublished commits.

## Production configuration checked read-only

Cloudflare Pages serves `web/` from this GitHub repository, with no build command or environment variables configured. `main` is the production branch and automatic production deployments are enabled. Preview deployments are enabled for all branches. **Pushing a branch can therefore create a publicly accessible preview even before merging.**

At review time the successful production deployment and remote `main` both referenced `dd803d10d90817ef424bd49416289f3af8f2e8d6`. No platform settings were changed. Shared verifier modules are committed into `web/lib/`, so the current static deployment configuration needs no new build step.

The existing live site injected a Cloudflare Insights beacon blocked by its CSP. This is an analytics/configuration issue rather than a verifier failure. Resolve the unwanted injection in platform settings when deploying; do not loosen the script policy just to silence it.

## Caveats and unchecked paths

- **Funded ArDrive upload has not been tested.** Receipt parsing, input checks, and confirmation paths are tested locally. Do not describe the paid upload path as end-to-end certified; validate it with a disposable artifact and a deliberately funded test wallet before relying on it.
- **Native HStego is not comprehensively audited.** The pinned source and local integration work, but its C/C++ image processing remains a trust boundary. Linux/Intel builds were not validated for this candidate.
- **No npm authentication or publication was attempted.** The registry version at review time was 0.1.0. It remains separate from the local 0.2.0 candidate and from the website.
- There is no new independent assessment of chain finality, gateway uptime, anonymity, or an arbitrary human-chosen password's strength. See [the security model](security.md).

## Release procedure when publication is authorized

1. Review the local commits, rerun the checks, confirm the package version is still unused, and replace the changelog's “Unreleased” with the release date.
2. Confirm the intended npm account and its publishing rights using a local authenticated npm session. Complete browser login/2FA locally if needed; never put credentials in a chat, repo, README, or shell argument.
3. Publish the reviewed `@confessionstxt/cli` package separately. Verify the registry tarball, version, command entry point, and MCP startup. Publishing GitHub commits alone does not update npm.
4. Push the reviewed Git history and complete the CI checks before advancing `main`. Remember that branch pushes create Pages previews. Advancing `main` deploys the website automatically.
5. Smoke-test the deployed homepage, `/verify`, direct `/verify/<hash>` links, original-image download, CSP headers, and both mobile and desktop results. Confirm `npx ...@latest` resolves the intended package release.

The package and site use the same existing metadata format, so temporary version skew during these separate releases is expected. The changed generated audit commands use the root `./confess` launcher; users need the updated checkout to run those commands.

For a website regression, roll Pages back to the previously successful deployment and fix the source before the next automatic deployment. For an npm regression, publish a corrected higher version and, where appropriate, deprecate the faulty version; published version numbers cannot be reused. Avoid presenting the older verifier as an equivalent security fallback.
