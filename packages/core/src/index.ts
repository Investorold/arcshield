/**
 * ArcShield Core
 * Multi-Agent AI Security Scanner for Arc Ecosystem
 */

// Export types
export * from './types/index.js';

// Export constants
export * from './constants.js';

// Export utilities
export * from './utils/index.js';

// Version
export const VERSION = '0.1.0';

// Main Scanner class (to be implemented)
export class Scanner {
  private config: import('./types/index.js').ScanConfig;

  constructor(config: Partial<import('./types/index.js').ScanConfig> = {}) {
    this.config = {
      target: config.target || '.',
      targetType: config.targetType || 'local',
      includeSmartContracts: config.includeSmartContracts ?? true,
      includeWebApp: config.includeWebApp ?? true,
      includeGenLayer: config.includeGenLayer ?? false,
      model: config.model || 'sonnet',
      outputFormat: config.outputFormat || 'json',
      outputPath: config.outputPath,
    };
  }

  /**
   * Run a full security scan
   */
  async scan(): Promise<import('./types/index.js').ScanReport> {
    // TODO: Implement multi-agent scanning pipeline
    throw new Error('Scanner not yet implemented. Coming in Phase 1.');
  }

  /**
   * Get current configuration
   */
  getConfig(): import('./types/index.js').ScanConfig {
    return { ...this.config };
  }
}
