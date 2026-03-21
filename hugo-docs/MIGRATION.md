# MkDocs to Hugo Migration

This directory contains the Hugo + Docsy replacement for the older MkDocs site.

## What changed

- Replaced MkDocs Material with Hugo using the Docsy theme
- Kept the same major routes:
  - `/docs/`
  - `/docs/multi-provider/`
  - `/docs/monitoring/`
  - `/docs/rotation/`
  - `/docs/debugging/`
  - `/docs/contributing/`
- Preserved provider-specific documentation under `/docs/providers/`
- Added custom styling to keep the UI close to the previous Material docs look

## Local development

```bash
cd hugo-docs
npm install
hugo server
```

Default local URL:

```text
http://localhost:1313/swarm-external-secrets/
```

If the default port is already in use:

```bash
cd hugo-docs
hugo server --port 1314
```

## Build

```bash
cd hugo-docs
hugo --minify
```

## Notes

- Generated directories such as `node_modules/`, `public/`, and `resources/` are ignored.
- The site is configured for GitHub Pages under `https://sugar-org.github.io/swarm-external-secrets/`.
- See `README.md` in this folder for the shortest local setup and commit guide.
