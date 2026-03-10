# Lethe (λήθη)

**Pre-ingestion code sanitization for AI agents.**

Lethe (`lethe`, pronounced "LEE-thee") scans source code repositories for secrets, credentials, PII, and sensitive patterns, then produces a clean copy with all sensitive content replaced by typed redaction placeholders. The AI sees the structure, the logic, the intent — but never the secrets.

```
Your repo  →  Lethe  →  Clean copy  →  AI agent
```

In Greek mythology, Lethe is the river of oblivion in the underworld. Souls drink from it and forget. When your code crosses through Lethe, the secrets stay behind.

## The problem

AI coding agents read everything — secrets, credentials, API keys, internal URLs, PII. Most organizations either accept the risk or block AI tooling entirely.

Lethe provides a third option: **sanitize before the AI reads it.**

```typescript
// Before
const AWS_SECRET_KEY = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';
const DATABASE_URL = 'postgres://admin:s3cret@prod-db.internal.corp:5432/main';

// After
const AWS_SECRET_KEY = '[REDACTED:aws_secret_key]';
const DATABASE_URL = '[REDACTED:postgres_uri]';
```

Code structure, logic, imports, and comments are preserved. The AI still gets useful context; your organization keeps its secrets.

## Quick start

```bash
npm install -g @sibyllai/lethe
```

**Sanitize a repo:**

```bash
lethe scan ./my-repo --output ./my-repo-clean
```

**Dry run — see what would be redacted:**

```bash
lethe scan ./my-repo --dry-run
```

**CI gate — exit code 0 means clean:**

```bash
lethe audit ./my-repo
```

**Generate a config file:**

```bash
lethe init
lethe init --preset strict
```

## What it detects

Lethe runs a layered detection pipeline. Each layer is independent and configurable.

| Layer | What it does | How |
|-------|-------------|-----|
| **0 — Ignore** | Skip files that shouldn't be scanned | `.gitignore`, `.letheignore`, binary detection |
| **1 — File rules** | Exclude or passthrough entire files | Glob patterns (`.env`, `*.pem`, `*.key`, `credentials.json`, etc.) |
| **2 — Patterns** | Match known secret formats line-by-line | 53 regex patterns curated from gitleaks/detect-secrets |
| **3 — Entropy** | Flag high-entropy strings that evade patterns | Shannon entropy with charset-specific thresholds |
| **4 — Custom rules** | Match org-specific sensitive content | User-defined patterns in `.lethe.yaml` |

The built-in pattern catalog covers: AWS, GCP, Azure, GitHub, GitLab, Slack, Stripe, JWT, private keys, database connection strings, bearer tokens, basic auth URLs, generic API keys, and more.

## Commands

**Lethe never modifies your source files.** `scan` writes a separate clean copy to the output directory. `audit` is read-only — it reports findings and sets an exit code, nothing more. Your original repo is never touched.

### `lethe scan`

```
lethe scan <paths...> [OPTIONS]

  -o, --output PATH       Output directory for sanitized copy (required unless --dry-run)
  -c, --config PATH       Path to config file
  --dry-run               Show findings without producing output
  --format [text|json]    Output format (default: text)
  --no-entropy            Disable entropy analysis
  --severity <level>      Minimum severity to redact: low|medium|high|critical
  -v, --verbose           Show each file as it's processed
  -q, --quiet             Suppress all output except errors
```

### `lethe audit`

Non-destructive validation for CI/CD pipelines. Exit code `0` = clean, `1` = findings, `2` = error.

```
lethe audit <paths...> [OPTIONS]

  -c, --config PATH       Path to config file
  --format [text|json]    Output format (default: text)
  --no-entropy            Disable entropy analysis
  --severity <level>      Minimum severity to report
```

### `lethe init`

```
lethe init [OPTIONS]

  -p, --preset <preset>   Config preset: default|strict|minimal
  -f, --force             Overwrite existing .lethe.yaml
```

## Configuration

`.lethe.yaml` — looked up in the scanned directory, then `~/.config/lethe/config.yaml`, then `~/.lethe.yaml`.

```yaml
files:
  exclude:
    - "**/.env"
    - "**/.env.*"
    - "**/*.pem"
    - "**/*.key"
    - "**/credentials.json"
  passthrough:
    - "**/node_modules/**"
    - "**/vendor/**"
    - "**/*.min.js"
  max_size: 5242880  # 5MB

patterns:
  enabled: true
  disable: []
    # - aws_secret_key  # disable specific patterns

entropy:
  enabled: true
  hex_threshold: 4.5
  base64_threshold: 5.0
  min_length: 12
  allowlist:
    - "**/*test*"
    - "**/*fixture*"

custom_rules:
  - name: "internal_host"
    pattern: '[a-zA-Z0-9-]+\.internal\.example\.org'
    replacement: "[REDACTED:internal_host]"
    severity: "high"

  - name: "org_email"
    pattern: '[a-zA-Z0-9._%+-]+@example\.org'
    replacement: "[REDACTED:org_email]"
    severity: "medium"
```

## Findings report

```
src/config/aws.ts
  [CRITICAL] src/config/aws.ts:12 — aws-secret-access-key
    wJa...EKEY
    Matches AWS secret access keys assigned to common variable names.
  [HIGH    ] src/db/connection.ts:8 — postgres-connection-string
    pos...5432
    Matches PostgreSQL connection URIs containing embedded credentials.

Summary
────────────────────────────────────────
  Files scanned:     342
  Files excluded:    4
  Files clean:       326
  Files redacted:    12

  Total findings:    17
    CRITICAL: 3
    HIGH    : 6
    MEDIUM  : 5
    LOW     : 3
```

## Design principles

- **Zero network calls.** Everything runs locally. No telemetry, no external services.
- **False negatives are worse than false positives.** This is a security tool. When in doubt, redact.
- **Preserve code structure.** Redacted output should be syntactically valid and semantically useful to the AI.
- **Six dependencies.** commander, chalk, js-yaml, zod, ignore, fast-glob. All pure JavaScript, no native compilation.

## Part of Sibyllai

Lethe is part of the **Sibyllai** ecosystem of AI security and governance tools:

- [**Khoregos**](https://github.com/sibyllai/khoregos) — enterprise governance layer for AI coding agent teams
- **Lethe** — pre-ingestion repo sanitization CLI _(this project)_
- **Stegano** — prompt injection detection API _(planned)_
- **Adyton** — autonomous OSINT agent _(planned)_

## License

MIT

---

Built by [Sibyllai](https://github.com/sibyllai).
