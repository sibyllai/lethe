import { describe, test, expect, beforeAll } from 'vitest';
import { loadPatternCatalog, scanPatterns } from '../../src/layers/patterns.js';
import type { PatternDefinition } from '../../src/models.js';
import type { LetheConfig } from '../../src/config.js';
import { Severity } from '../../src/models.js';

// Minimal config with patterns enabled and no disabled patterns
const baseConfig: LetheConfig = {
  files: { exclude: [], passthrough: [], max_size: 5242880 },
  patterns: { enabled: true, disable: [] },
  entropy: { enabled: false, hex_threshold: 4.5, base64_threshold: 5.0, min_length: 12, allowlist: [] },
  custom_rules: [],
  reporting: { summary: true, group_by: 'file' },
};

let catalog: PatternDefinition[];

beforeAll(async () => {
  catalog = await loadPatternCatalog();
});

function scan(content: string) {
  return scanPatterns('test-file.ts', content, baseConfig, catalog);
}

describe('Pattern catalog loading', () => {
  test('catalog loads with patterns', () => {
    expect(catalog.length).toBeGreaterThan(0);
  });

  test('each pattern has required fields', () => {
    for (const p of catalog) {
      expect(p.id).toBeTruthy();
      expect(p.name).toBeTruthy();
      expect(p.pattern).toBeTruthy();
      expect(p.replacement).toBeTruthy();
      expect(Object.values(Severity)).toContain(p.severity);
    }
  });
});

describe('Known secrets are detected', () => {
  test('AWS access key ID', () => {
    const findings = scan('const key = "AKIAIOSFODNN7EXAMPLE";');
    expect(findings.some((f) => f.type === 'aws-access-key-id')).toBe(true);
  });

  test('GitHub personal access token (classic)', () => {
    const findings = scan('const token = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef1234";');
    expect(findings.some((f) => f.type === 'github-pat-classic')).toBe(true);
  });

  test('Slack bot token', () => {
    const prefix = 'xoxb';
    const findings = scan(`const slack = "${prefix}-0000000000-0000000000000-FAKEFAKEFAKEFAKEFAKEFAKE";`);
    expect(findings.some((f) => f.type === 'slack-bot-token')).toBe(true);
  });

  test('RSA private key header', () => {
    const findings = scan('-----BEGIN RSA PRIVATE KEY-----');
    expect(findings.some((f) => f.type === 'private-key-rsa')).toBe(true);
  });

  test('PostgreSQL connection string with credentials', () => {
    const findings = scan('const db = "postgresql://admin:secretpass@db.example.com:5432/mydb";');
    expect(findings.some((f) => f.type === 'postgres-connection-string')).toBe(true);
  });

  test('generic API key assignment', () => {
    const findings = scan('api_key = "abcdefghij1234567890klmnop"');
    expect(findings.some((f) => f.type === 'generic-api-key')).toBe(true);
  });

  test('Bearer token', () => {
    const findings = scan('authorization = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.signature"');
    expect(findings.some((f) => f.type === 'bearer-token')).toBe(true);
  });

  test('Stripe secret key', () => {
    const findings = scan('const key = "sk_test_FAKEFAKEFAKEFAKE1234567890";');
    expect(findings.some((f) => f.type === 'stripe-secret-key')).toBe(true);
  });

  test('Generic private key header', () => {
    const findings = scan('-----BEGIN PRIVATE KEY-----');
    expect(findings.some((f) => f.type === 'private-key-generic')).toBe(true);
  });

  test('MongoDB connection string with credentials', () => {
    const findings = scan('const uri = "mongodb+srv://user:p4ssw0rd@cluster0.mongodb.net/mydb";');
    expect(findings.some((f) => f.type === 'mongodb-connection-string')).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Bug fix: JSON config file format (quoted keys like "Password": "value")
// Prior to the fix, patterns only matched bare keys (password=) but not
// JSON-style quoted keys ("Password":).
// ---------------------------------------------------------------------------
describe('JSON config file format (quoted keys)', () => {
  // --- Core JSON detection ---
  test('detects "Password" in JSON config', () => {
    const findings = scan('"Password": "AA"');
    expect(findings.some((f) => f.type === 'generic-password')).toBe(true);
  });

  test('detects "Secret" in JSON config', () => {
    const findings = scan('"Secret": "BB"');
    expect(findings.some((f) => f.type === 'generic-secret')).toBe(true);
  });

  test('detects "Password" with longer value in JSON config', () => {
    const findings = scan('"Password": "MyS3cr3tP@ss"');
    const match = findings.find((f) => f.type === 'generic-password');
    expect(match).toBeDefined();
    expect(match!.match).toBe('MyS3cr3tP@ss');
  });

  test('detects "Secret" with longer value in JSON config', () => {
    const findings = scan('"Secret": "long-secret-value-123"');
    const match = findings.find((f) => f.type === 'generic-secret');
    expect(match).toBeDefined();
    expect(match!.match).toBe('long-secret-value-123');
  });

  // --- Indentation / trailing commas (realistic JSON) ---
  test('detects password in indented JSON with trailing comma', () => {
    const findings = scan('    "Password": "supersecretpassword123",');
    expect(findings.some((f) => f.type === 'generic-password')).toBe(true);
  });

  test('detects secret in indented JSON with trailing comma', () => {
    const findings = scan('    "Secret": "hmac-key-abc123xyz",');
    expect(findings.some((f) => f.type === 'generic-secret')).toBe(true);
  });

  // --- Case insensitivity ---
  test('detects "password" (lowercase) in JSON', () => {
    const findings = scan('"password": "hunter2"');
    expect(findings.some((f) => f.type === 'generic-password')).toBe(true);
  });

  test('detects "PASSWORD" (uppercase) in JSON', () => {
    const findings = scan('"PASSWORD": "hunter2"');
    expect(findings.some((f) => f.type === 'generic-password')).toBe(true);
  });

  test('detects "secret_key" in JSON', () => {
    const findings = scan('"secret_key": "my-signing-key"');
    expect(findings.some((f) => f.type === 'generic-secret')).toBe(true);
  });

  // --- JSON with single quotes (e.g. JS object literals, YAML-ish configs) ---
  test("detects 'Password' with single-quoted key", () => {
    const findings = scan("'Password': 'hunter2'");
    expect(findings.some((f) => f.type === 'generic-password')).toBe(true);
  });

  test("detects 'Secret' with single-quoted key", () => {
    const findings = scan("'Secret': 'abc123'");
    expect(findings.some((f) => f.type === 'generic-secret')).toBe(true);
  });

  // --- Variant key names ---
  test('detects "pwd" in JSON', () => {
    const findings = scan('"pwd": "shortpw"');
    expect(findings.some((f) => f.type === 'generic-password')).toBe(true);
  });

  test('detects "passwd" in JSON', () => {
    const findings = scan('"passwd": "unix-style-field"');
    expect(findings.some((f) => f.type === 'generic-password')).toBe(true);
  });

  // --- Other patterns that also needed JSON key fix ---
  test('detects "api_key" in JSON', () => {
    const findings = scan('"api_key": "abcdefghij1234567890klmnop"');
    expect(findings.some((f) => f.type === 'generic-api-key')).toBe(true);
  });

  test('detects "ApiKey" in JSON', () => {
    const findings = scan('"ApiKey": "abcdefghij1234567890klmnop"');
    expect(findings.some((f) => f.type === 'generic-api-key')).toBe(true);
  });

  test('detects "client_secret" in JSON (oauth pattern)', () => {
    const findings = scan('"client_secret": "abcdefghijklmnop1234"');
    expect(findings.some((f) => f.type === 'oauth-client-secret')).toBe(true);
  });

  test('detects "db_password" in JSON (password-in-variable pattern)', () => {
    const findings = scan('"db_password": "pg-pass-123"');
    expect(findings.some((f) => f.type === 'password-in-variable')).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Bug fix: Single-quote matching via \u0027
// Prior to the fix, \u0027 was literal text in YAML single-quoted strings,
// so patterns could not match values wrapped in single quotes.
// ---------------------------------------------------------------------------
describe('Single-quote value matching (\\u0027 fix)', () => {
  test('detects AWS secret key in single-quoted assignment', () => {
    const findings = scan("aws_secret_access_key = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'");
    expect(findings.some((f) => f.type === 'aws-secret-access-key')).toBe(true);
  });

  test('detects AWS secret key in double-quoted assignment', () => {
    const findings = scan('aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"');
    expect(findings.some((f) => f.type === 'aws-secret-access-key')).toBe(true);
  });

  test('detects generic API key in single-quoted assignment', () => {
    const findings = scan("api_key = 'abcdefghij1234567890klmnop'");
    expect(findings.some((f) => f.type === 'generic-api-key')).toBe(true);
  });

  test('detects generic secret in single-quoted assignment', () => {
    const findings = scan("secret = 'my-secret-value'");
    expect(findings.some((f) => f.type === 'generic-secret')).toBe(true);
  });

  test('detects generic password in single-quoted assignment', () => {
    const findings = scan("password = 'hunter2'");
    expect(findings.some((f) => f.type === 'generic-password')).toBe(true);
  });

  test('detects bearer token with single-quoted value', () => {
    const findings = scan("authorization = 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.signature'");
    expect(findings.some((f) => f.type === 'bearer-token')).toBe(true);
  });

  test('detects oauth client_secret in single-quoted assignment', () => {
    const findings = scan("client_secret = 'abcdefghijklmnop1234'");
    expect(findings.some((f) => f.type === 'oauth-client-secret')).toBe(true);
  });

  test('detects password-in-variable with single quotes', () => {
    const findings = scan("db_password = 'pg-pass-123'");
    expect(findings.some((f) => f.type === 'password-in-variable')).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Bug fix: Minimum capture length for password/secret patterns
// Prior to the fix, generic-password and generic-secret required {8,} chars,
// missing short but real passwords. When the key is explicitly "Password" or
// "Secret", even short values should be flagged.
// ---------------------------------------------------------------------------
describe('Short password/secret values (minimum length fix)', () => {
  test('detects single-character password', () => {
    const findings = scan('"Password": "x"');
    expect(findings.some((f) => f.type === 'generic-password')).toBe(true);
  });

  test('detects two-character password', () => {
    const findings = scan('"Password": "AA"');
    expect(findings.some((f) => f.type === 'generic-password')).toBe(true);
  });

  test('detects short secret', () => {
    const findings = scan('"Secret": "BB"');
    expect(findings.some((f) => f.type === 'generic-secret')).toBe(true);
  });

  test('detects 3-char password in bare assignment', () => {
    const findings = scan('password = "abc"');
    expect(findings.some((f) => f.type === 'generic-password')).toBe(true);
  });

  test('detects 5-char secret in YAML-style assignment', () => {
    const findings = scan('secret: "12345"');
    expect(findings.some((f) => f.type === 'generic-secret')).toBe(true);
  });

  test('captures the correct short value', () => {
    const findings = scan('"Password": "pw"');
    const match = findings.find((f) => f.type === 'generic-password');
    expect(match).toBeDefined();
    expect(match!.match).toBe('pw');
  });

  test('short db_password is detected', () => {
    const findings = scan('"db_password": "root"');
    expect(findings.some((f) => f.type === 'password-in-variable')).toBe(true);
  });
});

describe('Safe strings are NOT detected', () => {
  test('normal variable names', () => {
    const findings = scan('const apiKeyName = "description";');
    expect(findings.length).toBe(0);
  });

  test('short strings', () => {
    const findings = scan('const x = "hello";');
    expect(findings.length).toBe(0);
  });

  test('comments about keys without actual keys', () => {
    const findings = scan('// The API key should be rotated every 90 days');
    expect(findings.length).toBe(0);
  });

  test('normal TypeScript code', () => {
    const findings = scan('export function getUser(id: number): Promise<User> { return db.find(id); }');
    expect(findings.length).toBe(0);
  });

  test('import statements', () => {
    const findings = scan('import { createHash } from "node:crypto";');
    expect(findings.length).toBe(0);
  });
});

describe('Pattern disable config', () => {
  test('disabled patterns are skipped', () => {
    const configDisabled: LetheConfig = {
      ...baseConfig,
      patterns: { enabled: true, disable: ['aws-access-key-id'] },
    };
    const findings = scanPatterns(
      'test.ts',
      'const key = "AKIAIOSFODNN7EXAMPLE";',
      configDisabled,
      catalog,
    );
    expect(findings.some((f) => f.type === 'aws-access-key-id')).toBe(false);
  });

  test('patterns disabled entirely returns empty', () => {
    const configOff: LetheConfig = {
      ...baseConfig,
      patterns: { enabled: false, disable: [] },
    };
    const findings = scanPatterns(
      'test.ts',
      '-----BEGIN RSA PRIVATE KEY-----',
      configOff,
      catalog,
    );
    expect(findings.length).toBe(0);
  });
});

describe('Finding structure', () => {
  test('findings have correct fields', () => {
    const findings = scan('const key = "AKIAIOSFODNN7EXAMPLE";');
    expect(findings.length).toBeGreaterThan(0);
    const f = findings[0]!;
    expect(f.file).toBe('test-file.ts');
    expect(f.line).toBe(1);
    expect(f.column).toBeGreaterThan(0);
    expect(f.type).toBeTruthy();
    expect(f.severity).toBeTruthy();
    expect(f.layer).toBe('pattern');
    expect(f.replacement).toBeTruthy();
    expect(f.match).toBeTruthy();
  });
});
