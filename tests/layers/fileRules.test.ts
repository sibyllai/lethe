import { describe, test, expect } from 'vitest';
import { checkFileRules } from '../../src/layers/fileRules.js';
import { FileAction } from '../../src/models.js';
import type { LetheConfig } from '../../src/config.js';

const defaultConfig: LetheConfig = {
  files: {
    exclude: [
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
    ],
    passthrough: [
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
    ],
    max_size: 5242880,
  },
  patterns: { enabled: true, disable: [] },
  entropy: { enabled: true, hex_threshold: 4.5, base64_threshold: 5.0, min_length: 12, allowlist: [] },
  custom_rules: [],
  reporting: { summary: true, group_by: 'file' },
};

describe('File exclusion rules', () => {
  test('.env files are excluded', () => {
    expect(checkFileRules('.env', defaultConfig)).toBe(FileAction.EXCLUDE);
  });

  test('.env.local files are excluded', () => {
    expect(checkFileRules('.env.local', defaultConfig)).toBe(FileAction.EXCLUDE);
  });

  test('.pem files are excluded', () => {
    expect(checkFileRules('certs/server.pem', defaultConfig)).toBe(FileAction.EXCLUDE);
  });

  test('.key files are excluded', () => {
    expect(checkFileRules('ssl/private.key', defaultConfig)).toBe(FileAction.EXCLUDE);
  });

  test('credentials.json is excluded', () => {
    expect(checkFileRules('credentials.json', defaultConfig)).toBe(FileAction.EXCLUDE);
  });

  test('files with "secret" in name are excluded', () => {
    expect(checkFileRules('my-secret-config.yaml', defaultConfig)).toBe(FileAction.EXCLUDE);
  });
});

describe('File passthrough rules', () => {
  test('node_modules files are passthrough', () => {
    expect(checkFileRules('node_modules/express/index.js', defaultConfig)).toBe(FileAction.PASSTHROUGH);
  });

  test('.png files are passthrough', () => {
    expect(checkFileRules('assets/logo.png', defaultConfig)).toBe(FileAction.PASSTHROUGH);
  });

  test('.min.js files are passthrough', () => {
    expect(checkFileRules('dist/bundle.min.js', defaultConfig)).toBe(FileAction.PASSTHROUGH);
  });

  test('package-lock.json is passthrough', () => {
    expect(checkFileRules('package-lock.json', defaultConfig)).toBe(FileAction.PASSTHROUGH);
  });

  test('.svg files are passthrough', () => {
    expect(checkFileRules('icons/icon.svg', defaultConfig)).toBe(FileAction.PASSTHROUGH);
  });
});

describe('Files that should be scanned', () => {
  test('normal .ts files are scanned', () => {
    expect(checkFileRules('src/index.ts', defaultConfig)).toBe(FileAction.SCAN);
  });

  test('normal .js files are scanned', () => {
    expect(checkFileRules('src/app.js', defaultConfig)).toBe(FileAction.SCAN);
  });

  test('README.md is scanned', () => {
    expect(checkFileRules('README.md', defaultConfig)).toBe(FileAction.SCAN);
  });

  test('package.json is scanned', () => {
    expect(checkFileRules('package.json', defaultConfig)).toBe(FileAction.SCAN);
  });

  test('.yaml config files are scanned', () => {
    expect(checkFileRules('config/app.yaml', defaultConfig)).toBe(FileAction.SCAN);
  });
});

describe('Edge cases', () => {
  test('empty path is excluded', () => {
    expect(checkFileRules('', defaultConfig)).toBe(FileAction.EXCLUDE);
  });

  test('exclude takes priority over passthrough', () => {
    // A file that could match both exclude and passthrough patterns
    const config: LetheConfig = {
      ...defaultConfig,
      files: {
        ...defaultConfig.files,
        exclude: ['**/*.json'],
        passthrough: ['**/*.json'],
      },
    };
    expect(checkFileRules('data.json', config)).toBe(FileAction.EXCLUDE);
  });
});
