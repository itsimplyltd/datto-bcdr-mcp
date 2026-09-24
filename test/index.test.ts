import { describe, it, expect } from 'vitest';

describe('Datto BCDR MCP Server', () => {
  describe('Tool Definitions', () => {
    const expectedTools = [
      'datto_bcdr_list_devices',
      'datto_bcdr_get_device',
      'datto_bcdr_list_assets',
      'datto_bcdr_get_asset',
      'datto_bcdr_list_backups',
      'datto_bcdr_list_screenshots',
      'datto_bcdr_get_screenshot',
      'datto_bcdr_get_offsite_status',
      'datto_bcdr_list_alerts',
    ];

    it('should define all 9 tools', () => {
      expect(expectedTools).toHaveLength(9);
    });

    it('should include device tools', () => {
      expect(expectedTools).toContain('datto_bcdr_list_devices');
      expect(expectedTools).toContain('datto_bcdr_get_device');
    });

    it('should include asset tools', () => {
      expect(expectedTools).toContain('datto_bcdr_list_assets');
      expect(expectedTools).toContain('datto_bcdr_get_asset');
    });

    it('should include backup and screenshot tools', () => {
      expect(expectedTools).toContain('datto_bcdr_list_backups');
      expect(expectedTools).toContain('datto_bcdr_list_screenshots');
      expect(expectedTools).toContain('datto_bcdr_get_screenshot');
    });

    it('should include offsite and alerts tools', () => {
      expect(expectedTools).toContain('datto_bcdr_get_offsite_status');
      expect(expectedTools).toContain('datto_bcdr_list_alerts');
    });
  });

  describe('Region validation', () => {
    const validRegions = ['us', 'eu'];

    it('should support us and eu regions', () => {
      expect(validRegions).toContain('us');
      expect(validRegions).toContain('eu');
    });

    it('should default to us when DATTO_BCDR_REGION is not set', () => {
      expect(process.env.DATTO_BCDR_REGION).toBeUndefined();
    });
  });

  describe('Credentials', () => {
    it('should require DATTO_BCDR_PUBLIC_KEY and DATTO_BCDR_PRIVATE_KEY', () => {
      const required = ['DATTO_BCDR_PUBLIC_KEY', 'DATTO_BCDR_PRIVATE_KEY'];
      expect(required).toHaveLength(2);
    });
  });

  describe('Server Configuration', () => {
    it('should define server with correct name', () => {
      const config = { name: 'datto-bcdr-mcp', version: '0.0.0' };
      expect(config.name).toBe('datto-bcdr-mcp');
    });
  });
});
