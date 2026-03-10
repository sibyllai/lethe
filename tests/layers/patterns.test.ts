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
