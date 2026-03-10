import * as fs from 'node:fs/promises';
import * as path from 'node:path';
import yaml from 'js-yaml';
import { z } from 'zod';
import { Severity } from './models.js';

const CustomRuleSchema = z.object({
  name: z.string(),
  pattern: z.string(),
  replacement: z.string(),
  severity: z.nativeEnum(Severity).default(Severity.MEDIUM),
  description: z.string().optional(),
});

const LetheConfigSchema = z.object({
  files: z.object({
    exclude: z.array(z.string()).default([
      '**/.env',
      '**/.env.*',
      '**/*.pem',
      '**/*.key',
      '**/*.p12',
      '**/*.pfx',
      '**/*.jks',
      '**/credentials.json',
      '**/service-account*.json',
      '**/*secret*',
      '**/id_rsa*',
      '**/id_ed25519*',
    ]),
    passthrough: z.array(z.string()).default([
      '**/node_modules/**',
      '**/vendor/**',
      '**/*.min.js',
      '**/*.min.css',
      '**/package-lock.json',
      '**/yarn.lock',
      '**/pnpm-lock.yaml',
      '**/*.woff*',
      '**/*.ttf',
      '**/*.ico',
      '**/*.png',
      '**/*.jpg',
      '**/*.jpeg',
      '**/*.gif',
      '**/*.svg',
    ]),
    max_size: z.number().default(5242880),
  }).default({}),
  patterns: z.object({
    enabled: z.boolean().default(true),
    disable: z.array(z.string()).default([]),
  }).default({}),
  entropy: z.object({
    enabled: z.boolean().default(true),
    hex_threshold: z.number().default(4.5),
    base64_threshold: z.number().default(5.0),
    min_length: z.number().default(12),
    allowlist: z.array(z.string()).default([
      '**/package-lock.json',
      '**/yarn.lock',
      '**/pnpm-lock.yaml',
      '**/*.lock',
      '**/*test*',
      '**/*fixture*',
      '**/*mock*',
    ]),
  }).default({}),
  custom_rules: z.array(CustomRuleSchema).default([]),
  reporting: z.object({
    summary: z.boolean().default(true),
    group_by: z.enum(['file', 'type']).default('file'),
  }).default({}),
});

export type LetheConfig = z.infer<typeof LetheConfigSchema>;

/**
 * Resolve config file path using the lookup chain:
 * 1. Explicit --config path
 * 2. .lethe.yaml in scanned directory
 * 3. ~/.config/lethe/config.yaml
 * 4. ~/.lethe.yaml
 */
export async function resolveConfigPath(
  scanRoot: string,
  explicitPath?: string,
): Promise<string | null> {
  if (explicitPath) {
    try {
      await fs.access(explicitPath);
      return explicitPath;
    } catch {
      throw new Error(`Config file not found: ${explicitPath}`);
    }
  }

  const candidates = [
    path.join(scanRoot, '.lethe.yaml'),
    path.join(scanRoot, '.lethe.yml'),
    path.join(process.env['HOME'] || '~', '.config', 'lethe', 'config.yaml'),
    path.join(process.env['HOME'] || '~', '.lethe.yaml'),
  ];

  for (const candidate of candidates) {
    try {
      await fs.access(candidate);
      return candidate;
    } catch {
      continue;
    }
  }

  return null;
}

/**
 * Load and validate config from a file path. Returns defaults if no config file.
 */
export async function loadConfig(
  scanRoot: string,
  explicitPath?: string,
): Promise<LetheConfig> {
  const configPath = await resolveConfigPath(scanRoot, explicitPath);

  if (!configPath) {
    return LetheConfigSchema.parse({});
  }

  const raw = await fs.readFile(configPath, 'utf-8');
  const parsed = yaml.load(raw);

  if (parsed === null || parsed === undefined) {
    return LetheConfigSchema.parse({});
  }

  return LetheConfigSchema.parse(parsed);
}

/**
 * Generate a starter config YAML string.
 */
export function generateDefaultConfig(preset: 'default' | 'strict' | 'minimal'): string {
  if (preset === 'minimal') {
    return `# Lethe configuration (minimal preset)
# See: https://github.com/sibyllai/lethe

files:
  exclude:
    - "**/.env"
    - "**/.env.*"
    - "**/*.pem"
    - "**/*.key"

patterns:
  enabled: true

entropy:
  enabled: false
`;
  }

  if (preset === 'strict') {
    return `# Lethe configuration (strict preset)
# See: https://github.com/sibyllai/lethe

files:
  exclude:
    - "**/.env"
    - "**/.env.*"
    - "**/*.pem"
    - "**/*.key"
    - "**/*.p12"
    - "**/*.pfx"
    - "**/*.jks"
    - "**/credentials.json"
    - "**/service-account*.json"
    - "**/*secret*"
    - "**/id_rsa*"
    - "**/id_ed25519*"
    - "**/*.keystore"
    - "**/*.cert"
    - "**/*.crt"
    - "**/token*"
  passthrough:
    - "**/node_modules/**"
    - "**/vendor/**"
  max_size: 10485760  # 10MB

patterns:
  enabled: true

entropy:
  enabled: true
  hex_threshold: 4.0
  base64_threshold: 4.5
  min_length: 10
  allowlist:
    - "**/package-lock.json"
    - "**/yarn.lock"
    - "**/pnpm-lock.yaml"
    - "**/*.lock"

custom_rules: []

reporting:
  summary: true
  group_by: file
`;
  }

  // default preset
  return `# Lethe configuration
# See: https://github.com/sibyllai/lethe

files:
  exclude:
    - "**/.env"
    - "**/.env.*"
    - "**/*.pem"
    - "**/*.key"
    - "**/*.p12"
    - "**/*.pfx"
    - "**/*.jks"
    - "**/credentials.json"
    - "**/service-account*.json"
    - "**/*secret*"
    - "**/id_rsa*"
    - "**/id_ed25519*"
  passthrough:
    - "**/node_modules/**"
    - "**/vendor/**"
    - "**/*.min.js"
    - "**/*.min.css"
    - "**/package-lock.json"
    - "**/yarn.lock"
    - "**/pnpm-lock.yaml"
    - "**/*.woff*"
    - "**/*.ttf"
    - "**/*.ico"
    - "**/*.png"
    - "**/*.jpg"
    - "**/*.jpeg"
    - "**/*.gif"
    - "**/*.svg"
  max_size: 5242880  # 5MB

patterns:
  enabled: true

entropy:
  enabled: true
  hex_threshold: 4.5
  base64_threshold: 5.0
  min_length: 12
  allowlist:
    - "**/package-lock.json"
    - "**/yarn.lock"
    - "**/pnpm-lock.yaml"
    - "**/*.lock"
    - "**/*test*"
    - "**/*fixture*"
    - "**/*mock*"

custom_rules: []
# Example:
# - name: "internal_host"
#   pattern: "[a-zA-Z0-9-]+\\\\.internal\\\\.example\\\\.org"
#   replacement: "[REDACTED:internal_host]"
#   severity: "high"
#   description: "Internal hostnames"

reporting:
  summary: true
  group_by: file
`;
}
