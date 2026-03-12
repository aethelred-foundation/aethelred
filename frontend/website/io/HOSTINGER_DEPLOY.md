# Hostinger Deployment

This folder now includes a Hostinger-ready static deployment build for the `io` site.

## Output

- Build script: [build-hostinger.cjs](/Users/rameshtamilselvan/Downloads/aethelred/frontend/website/io/build-hostinger.cjs)
- Generated upload folder: `hostinger-public_html`
- Recommended upload archive: `aethelred-io-hostinger-public_html.zip`

## What the build does

1. Creates a self-contained `public_html` bundle from the live `io` site.
2. Copies local fonts into `assets/fonts` so the site does not depend on the parent workspace structure.
3. Rewrites internal page links to direct `.html` URLs like `developers.html` and keeps the bundle flat.
4. Adds Apache `.htaccess` support for:
   - optional clean URL fallback to `.html`
   - asset caching
   - gzip compression
   - custom `404` page
5. Rewrites `../org/...` links to the live absolute `https://www.aethelred.org/...` URLs.
6. Rewrites hosted metadata and sitemap URLs to the `.html` versions used in the bundle.
7. Adds a manifest link and font preloads to the hosted HTML output.

## Hostinger upload steps

1. Run the build script:

```bash
node build-hostinger.cjs
```

2. Upload the contents of `hostinger-public_html` to Hostinger `public_html`.

3. Or upload the generated zip and extract it directly inside `public_html`.

4. After upload, verify:
   - `https://www.aethelred.io/`
   - `https://www.aethelred.io/developers.html`
   - `https://www.aethelred.io/tools.html`
   - `https://www.aethelred.io/testnet.html`
   - `https://www.aethelred.io/community.html`
   - `https://www.aethelred.io/smart-contracts.html`
   - `https://www.aethelred.io/404.html`

## Notes

- The generated bundle is the hosting artifact. It is intentionally more production-oriented than the local source tree.
- The foundation links on the `io` site point to `https://www.aethelred.org/...` in the hosted bundle.
- Do not upload the legacy root HTML files from `../website`; upload only the generated `hostinger-public_html` contents.
- This Hostinger package is intentionally flattened. You should not see route folders like `developers/index.html` inside it.
