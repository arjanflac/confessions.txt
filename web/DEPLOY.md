# Cloudflare Pages Deployment

Target: static site in `/web`.

## Deployment Steps

1. Create a new Pages project in Cloudflare Dashboard and connect the repository.
2. Set the build configuration:
   - **Framework preset:** None
   - **Build command:** (leave empty)
   - **Build output directory:** `web`
3. Deploy. Cloudflare will publish `/web/index.html` as the site root.

## Architecture Notes

- **Static only:** No backend, no server functions, no API routes.
- **Client-side verification:** The verify page uses `https://mainnet.base.org` for Base RPC calls directly from the browser.
- **SEO:** Real HTML text, proper `<title>` and meta descriptions, indexable.
- **Mobile-first:** Responsive layout optimized for mobile and desktop.

## File Structure

```
web/
├── index.html      # Main page — Forensic Noir aesthetic
├── verify.html     # Verification console — resolves Base tx or Arweave TXID
├── logo.png        # Logo asset (pixel art sword)
└── logo.svg        # SVG version (if available)
```

## Design System

- **Palette:** Deep obsidian backgrounds (#050505 to #0b0b0c), off-white typography, cold steel blue accent (#5a7a8c)
- **Typography:** Crimson Pro (serif) for headlines, JetBrains Mono for technical content
- **Motion:** Subtle fade-in on load, respects `prefers-reduced-motion`
