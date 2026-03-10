# Contributing to Lethe

Thanks for your interest in contributing. This guide covers everything you need to get started.

## Prerequisites

- **Node.js 18+** (20+ recommended)
- **npm** (ships with Node)
- **Git**

## Setup

```bash
git clone https://github.com/sibyllai/lethe.git
cd lethe
npm install
```

Verify everything works:

```bash
npx tsc --noEmit          # type check
npx vitest run            # full test suite
npm run build             # compile to dist/
```

## Project structure

```
src/
  cli.ts              CLI commands (scan, audit, init)
  scanner.ts          Orchestrator: walk files, apply pipeline, produce output
  redactor.ts         Apply findings to produce redacted content
  config.ts           Config file loading and validation (Zod)
  models.ts           Types: Finding, ScanResult, Severity, FileAction
  utils.ts            Encoding detection, entropy math, file helpers
  layers/
    ignore.ts         Layer 0: .gitignore / .letheignore / binary detection
    fileRules.ts      Layer 1: file-level exclude/passthrough
    patterns.ts       Layer 2: built-in regex catalog (~53 patterns)
    entropy.ts        Layer 3: Shannon entropy analysis
    custom.ts         Layer 4: user-defined rules from config
  catalog/
    patterns.yaml     The built-in regex pattern catalog
tests/                Mirrors src/ structure
  fixtures/           Fake repos with planted secrets for testing
```

**Stack:** TypeScript (strict, ESM), Node.js, Commander.js, Zod, js-yaml, fast-glob, ignore, Vitest.

## Development workflow

1. **Fork and branch.** Branch from `main`. Use a descriptive name: `feat/thing`, `fix/thing`, `chore/thing`.

2. **Make your changes.** Follow the conventions below.

3. **Test.**

   ```bash
   npx tsc --noEmit            # must pass — no type errors
   npm run lint                 # must pass — no lint errors
   npx vitest run              # must pass — no regressions
   npx vitest run tests/path   # run a specific test file
   ```

4. **Commit.** See commit message format below.

5. **Open a PR** against `main`. CI runs type check, lint, and tests across Node 18, 20, and 22.

## Conventions

### Code

- **TypeScript strict mode.** No `any` unless absolutely necessary.
- **ESM only.** All imports use `.js` extensions (TypeScript ESM convention).
- **Node built-in prefix.** Use `node:fs`, `node:path`, etc.
- **Path safety.** All file paths via `path.join` / `path.resolve`, never string concatenation.
- **Pure functions where possible.** Keep functions small and testable.
- **No global mutable state.**
- **This is a security tool.** False negatives (missed secrets) are worse than false positives. When in doubt, redact.

### Commit messages

```
type(scope): one-liner

- list changes (optional if human, mandatory if AI agent)
- list changes (optional if human, mandatory if AI agent)

sibylline quote that pertains to the topic of the commit, poetic, no quotes
```

**Types:** `feat`, `fix`, `docs`, `chore`, `refactor`, `test`

**Scopes:** the feature area — e.g. `scanner`, `patterns`, `entropy`, `config`, `cli`, `redactor`, `ci`, `security`

The closing line is a short poetic quote (no quotation marks) loosely related to the commit's theme. This is a project tradition — have fun with it.

### Pull requests

- Keep PRs focused. One feature or fix per PR.
- Include a short description of what changed and why.
- If your change adds a new pattern to the catalog, include at least 3 positive and 2 negative test cases.
- If your change adds a new feature, add tests.

## Adding patterns

The built-in pattern catalog lives in `src/catalog/patterns.yaml`. Each pattern needs:

```yaml
- id: short-kebab-id
  name: Human Readable Name
  pattern: 'regex-here'
  severity: critical|high|medium|low
  replacement: "[REDACTED:type]"
  description: >-
    What this pattern detects and why.
```

Use capture groups `(...)` around the secret value when the pattern includes assignment context (variable name + operator). This ensures only the secret is replaced, preserving code structure.

## Reporting issues

Use [GitHub Issues](https://github.com/sibyllai/lethe/issues). Include:

- What you expected vs. what happened
- Steps to reproduce
- `lethe --version` output
- Node.js version

## License

By contributing, you agree that your contributions will be licensed under the [MIT License](LICENSE).
