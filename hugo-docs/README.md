# Hugo Docs

This directory contains the Hugo + Docsy documentation site for `swarm-external-secrets`.

## Prerequisites

- [Hugo Extended](https://gohugo.io/installation/) `>= 0.158.0`
- `npm`
- `go`

## Install dependencies

```bash
cd hugo-docs
npm install
```

## Run locally

```bash
cd hugo-docs
hugo server --buildDrafts --buildFuture
```

Open:

```text
http://localhost:1313/swarm-external-secrets/
```

If port `1313` is busy:

```bash
hugo server --port 1314 --buildDrafts --buildFuture
```

## Production build

```bash
cd hugo-docs
hugo --minify
```

Generated output is written to `hugo-docs/public/`.

## What to commit

Commit the Hugo source files only:

- `content/`
- `assets/`
- `layouts/`
- `hugo.yaml`
- `go.mod`
- `go.sum`
- `postcss.config.js`
- `README.md`
- `MIGRATION.md`

Do not commit generated files from:

- `node_modules/`
- `public/`
- `resources/`
