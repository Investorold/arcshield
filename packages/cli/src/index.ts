#!/usr/bin/env node

/**
 * ArcShield CLI
 * Command-line interface for the ArcShield security scanner
 */

import { Command } from 'commander';
import { Scanner, VERSION } from '@arcshield/core';

const program = new Command();

program
  .name('arcshield')
  .description('Multi-Agent AI Security Scanner for Arc Ecosystem')
  .version(VERSION);

program
  .command('scan')
  .description('Scan a codebase for security vulnerabilities')
  .argument('[path]', 'Path to scan (default: current directory)', '.')
  .option('-t, --type <type>', 'Target type: local, github, contract_address', 'local')
  .option('-m, --model <model>', 'AI model: haiku, sonnet, opus', 'sonnet')
  .option('-o, --output <path>', 'Output file path')
  .option('-f, --format <format>', 'Output format: json, markdown, html', 'json')
  .option('--no-contracts', 'Skip smart contract scanning')
  .option('--no-webapp', 'Skip web app scanning')
  .option('--genlayer', 'Include GenLayer intelligent contract scanning')
  .action(async (targetPath, options) => {
    console.log('\n🛡️  ArcShield Security Scanner v' + VERSION);
    console.log('━'.repeat(50));
    console.log(`\n📂 Target: ${targetPath}`);
    console.log(`🤖 Model: ${options.model}`);
    console.log(`📄 Format: ${options.format}\n`);

    try {
      const scanner = new Scanner({
        target: targetPath,
        targetType: options.type,
        model: options.model,
        outputFormat: options.format,
        outputPath: options.output,
        includeSmartContracts: options.contracts !== false,
        includeWebApp: options.webapp !== false,
        includeGenLayer: options.genlayer || false,
      });

      console.log('🔍 Starting scan...\n');

      // TODO: Implement actual scanning
      const report = await scanner.scan();

      console.log('\n✅ Scan complete!');
      console.log(`📊 Security Score: ${report.score}/100`);
      console.log(`🔴 Critical: ${report.summary.critical}`);
      console.log(`🟠 High: ${report.summary.high}`);
      console.log(`🟡 Medium: ${report.summary.medium}`);
      console.log(`🟢 Low: ${report.summary.low}`);

    } catch (error) {
      if (error instanceof Error && error.message.includes('not yet implemented')) {
        console.log('⚠️  Scanner is not yet implemented.');
        console.log('📝 This is the initial project setup.');
        console.log('🚀 Implementation coming in Phase 1!\n');
      } else {
        console.error('❌ Error:', error);
        process.exit(1);
      }
    }
  });

program
  .command('report')
  .description('Generate a report from a previous scan')
  .argument('<scan-id>', 'Scan ID to generate report for')
  .option('-f, --format <format>', 'Output format: json, markdown, html', 'markdown')
  .action((scanId, options) => {
    console.log(`Generating ${options.format} report for scan: ${scanId}`);
    // TODO: Implement report generation
  });

program
  .command('verify')
  .description('Verify a smart contract on Arc')
  .argument('<address>', 'Contract address to verify')
  .action((address) => {
    console.log(`Verifying contract: ${address}`);
    // TODO: Implement contract verification
  });

program.parse();
