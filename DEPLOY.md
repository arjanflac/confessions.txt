# Cloudflare Pages Deployment

Target: static site in `/web`.

1. Create a new Pages project and connect the repository.
2. Set the build configuration:
   - Framework preset: None
   - Build command: (leave empty)
   - Build output directory: `web`
3. Deploy. Cloudflare will publish `/web/index.html` as the site root.

Notes:
- No backend required.
- The verify page uses `https://mainnet.base.org` for Base RPC calls.
