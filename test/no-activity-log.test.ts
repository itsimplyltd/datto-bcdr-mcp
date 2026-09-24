import { describe, it, expect } from 'vitest';
import { readFileSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __dirname = dirname(fileURLToPath(import.meta.url));

describe('Guard: activity-log removal', () => {
  it('datto-api.ts source does not contain "activity-log"', () => {
    const apiFilePath = join(__dirname, '..', 'src', 'datto-api.ts');
    const source = readFileSync(apiFilePath, 'utf-8');
    // Strip all comments
    const withoutComments = source
      .replace(/\/\*[\s\S]*?\*\//g, '') // Remove /* */ comments
      .replace(/\/\/.*/g, '');          // Remove // comments

    expect(withoutComments).not.toContain('activity-log');
  });

  it('mcp-server.ts source does not contain "datto_bcdr_list_activity"', () => {
    const serverFilePath = join(__dirname, '..', 'src', 'mcp-server.ts');
    const source = readFileSync(serverFilePath, 'utf-8');

    expect(source).not.toContain('datto_bcdr_list_activity');
  });
});
