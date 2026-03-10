import { describe, test, expect } from 'vitest';
import * as fs from 'node:fs/promises';
import * as path from 'node:path';
import * as os from 'node:os';
import { loadConfig, generateDefaultConfig } from '../src/config.js';

describe('Default config', () => {
  test('default config is valid and has expected structure', async () => {
    // loadConfig with a non-existent config file returns defaults
    const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'lethe-test-'));
    try {
      const config = await loadConfig(tmpDir);

      expect(config.files).toBeDefined();
      expect(config.files.exclude).toBeInstanceOf(Array);
      expect(config.files.exclude.length).toBeGreaterThan(0);
      expect(config.files.passthrough).toBeInstanceOf(Array);
      expect(config.files.max_size).toBeGreaterThan(0);

      expect(config.patterns).toBeDefined();
      expect(config.patterns.enabled).toBe(true);
      expect(config.patterns.disable).toBeInstanceOf(Array);

      expect(config.entropy).toBeDefined();
      expect(config.entropy.enabled).toBe(true);
      expect(config.entropy.hex_threshold).toBeGreaterThan(0);
      expect(config.entropy.base64_threshold).toBeGreaterThan(0);
      expect(config.entropy.min_length).toBeGreaterThan(0);

      expect(config.custom_rules).toBeInstanceOf(Array);
      expect(config.custom_rules.length).toBe(0);

      expect(config.reporting).toBeDefined();
      expect(config.reporting.summary).toBe(true);
      expect(config.reporting.group_by).toBe('file');
    } finally {
      await fs.rm(tmpDir, { recursive: true });
    }
  });
});

describe('Loading config from YAML', () => {
  test('loads config from a .lethe.yaml file', async () => {
    const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'lethe-test-'));
    try {
      const yamlContent = `
files:
  exclude:
    - "**/.env"
  passthrough:
    - "**/vendor/**"
  max_size: 1048576

patterns:
  enabled: true
  disable:
    - "generic-password"

entropy:
  enabled: false

custom_rules:
  - name: "internal_host"
    pattern: "[a-z]+\\\\.internal\\\\.example\\\\.com"
    replacement: "[REDACTED:host]"
    severity: "high"

reporting:
  summary: false
  group_by: type
`;
      await fs.writeFile(path.join(tmpDir, '.lethe.yaml'), yamlContent, 'utf-8');

      const config = await loadConfig(tmpDir);

      expect(config.files.exclude).toEqual(['**/.env']);
      expect(config.files.passthrough).toEqual(['**/vendor/**']);
      expect(config.files.max_size).toBe(1048576);
      expect(config.patterns.enabled).toBe(true);
      expect(config.patterns.disable).toEqual(['generic-password']);
      expect(config.entropy.enabled).toBe(false);
      expect(config.custom_rules.length).toBe(1);
      expect(config.custom_rules[0]!.name).toBe('internal_host');
      expect(config.reporting.summary).toBe(false);
      expect(config.reporting.group_by).toBe('type');
    } finally {
      await fs.rm(tmpDir, { recursive: true });
    }
  });
});

describe('Config validation with Zod', () => {
  test('invalid severity value is rejected', async () => {
    const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'lethe-test-'));
    try {
      const yamlContent = `
custom_rules:
  - name: "bad_rule"
    pattern: "test"
    replacement: "[REDACTED]"
    severity: "super_high"
`;
      await fs.writeFile(path.join(tmpDir, '.lethe.yaml'), yamlContent, 'utf-8');

      await expect(loadConfig(tmpDir)).rejects.toThrow();
    } finally {
      await fs.rm(tmpDir, { recursive: true });
    }
  });

  test('invalid group_by value is rejected', async () => {
    const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'lethe-test-'));
    try {
      const yamlContent = `
reporting:
  group_by: "severity"
`;
      await fs.writeFile(path.join(tmpDir, '.lethe.yaml'), yamlContent, 'utf-8');

      await expect(loadConfig(tmpDir)).rejects.toThrow();
    } finally {
      await fs.rm(tmpDir, { recursive: true });
    }
  });

  test('invalid max_size type is rejected', async () => {
    const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'lethe-test-'));
    try {
      const yamlContent = `
files:
  max_size: "not_a_number"
`;
      await fs.writeFile(path.join(tmpDir, '.lethe.yaml'), yamlContent, 'utf-8');

      await expect(loadConfig(tmpDir)).rejects.toThrow();
    } finally {
      await fs.rm(tmpDir, { recursive: true });
    }
  });
});

describe('generateDefaultConfig', () => {
  test('default preset generates valid YAML string', () => {
    const yaml = generateDefaultConfig('default');
    expect(yaml).toContain('files:');
    expect(yaml).toContain('patterns:');
    expect(yaml).toContain('entropy:');
    expect(yaml).toContain('.env');
  });

  test('strict preset generates valid YAML string', () => {
    const yaml = generateDefaultConfig('strict');
    expect(yaml).toContain('strict');
    expect(yaml).toContain('max_size: 10485760');
  });

  test('minimal preset generates valid YAML string', () => {
    const yaml = generateDefaultConfig('minimal');
    expect(yaml).toContain('minimal');
    expect(yaml).toContain('enabled: false');
  });
});
