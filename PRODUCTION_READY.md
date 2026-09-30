# Hawkeye status (v0.2.0, beta)

This file replaces an earlier checklist that claimed things nobody had verified. Everything below
was checked on 2026-09-29.

## Verified

| Area | How it was checked |
|------|--------------------|
| Advisory data from OSV.dev for installed versions | Ran on a sample app; package list matches `npm audit` exactly |
| Lockfiles: npm v1/v3, pnpm v9, yarn v1, yarn berry | Unit tests with real generated lockfiles (`tests/fixtures/lockfiles`) |
| Reachability (imports, usage, type-only, test-only, transitive) | Unit tests plus runs on `nestjs/nest` (2,047 files, 5s) and `excalidraw/excalidraw` (689 files, 8s) |
| EPSS and CISA KEV enrichment | Live APIs; failures produce warnings and never invented values |
| HTML escaping, SARIF physical locations | Unit tests |
| API auth, path allow-list, body limit | Manual HTTP tests against the running server |
| Production build (`npm ci`, build, prune) | Run in a clean directory |

## Not verified yet

- `docker build`: no Docker access where this was written. The CI `docker` job builds the image and
  checks `/api/health` on every push.
- Hosting: nothing is deployed. Run the CLI locally or the container yourself.
- Python and other ecosystems: not supported.

See the "Limitações atuais" section in [README.md](./README.md) for the known gaps.
