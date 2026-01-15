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
  .option('-p, --provider <provider>', 'AI provider: anthropic, ollama', 'anthropic')
  .option('-m, --model <model>', 'AI model (anthropic: haiku/sonnet/opus, ollama: llama3/mistral/etc)', 'sonnet')
  .option('--ollama-url <url>', 'Ollama server URL', 'http://localhost:11434')
  .option('-o, --output <path>', 'Output file path')
  .option('-f, --format <format>', 'Output format: json, markdown, html', 'json')
  .option('--no-contracts', 'Skip smart contract scanning')
  .option('--no-webapp', 'Skip web app scanning')
  .option('--genlayer', 'Include GenLayer intelligent contract scanning')
  .action(async (targetPath, options) => {
    try {
      const scanner = new Scanner({
        target: targetPath,
        targetType: options.type,
        provider: options.provider,
        model: options.model,
        ollamaUrl: options.ollamaUrl,
        outputFormat: options.format,
        outputPath: options.output,
        includeSmartContracts: options.contracts !== false,
        includeWebApp: options.webapp !== false,
        includeGenLayer: options.genlayer || false,
      });

      const report = await scanner.scan();

      // Output summary
      console.log('\n📊 Scan Summary');
      console.log('━'.repeat(50));
      console.log(`Security Score: ${report.score}/100`);
      console.log(`Total Issues: ${report.summary.totalIssues}`);
      console.log(`  🔴 Critical: ${report.summary.critical}`);
      console.log(`  🟠 High: ${report.summary.high}`);
      console.log(`  🟡 Medium: ${report.summary.medium}`);
      console.log(`  🟢 Low: ${report.summary.low}`);
      console.log(`  ℹ️  Info: ${report.summary.info}`);

      if (report.badge.eligible) {
        console.log('\n🏆 Eligible for ArcShield Verified badge!');
      } else {
        console.log(`\n⚠️  Badge: ${report.badge.reason}`);
      }

    } catch (error) {
      console.error('\n❌ Error:', error instanceof Error ? error.message : error);
      process.exit(1);
    }
  });

program
  .command('assess')
  .description('Run only the assessment phase (generates SECURITY.md)')
  .argument('[path]', 'Path to assess (default: current directory)', '.')
  .option('-p, --provider <provider>', 'AI provider: anthropic, ollama', 'anthropic')
  .option('-m, --model <model>', 'AI model (anthropic: haiku/sonnet/opus, ollama: llama3/mistral/etc)', 'sonnet')
  .option('--ollama-url <url>', 'Ollama server URL', 'http://localhost:11434')
  .action(async (targetPath, options) => {
    try {
      console.log('\n🛡️  ArcShield Assessment');
      console.log('━'.repeat(50));

      const scanner = new Scanner({
        target: targetPath,
        provider: options.provider,
        model: options.model,
        ollamaUrl: options.ollamaUrl,
      });

      const assessment = await scanner.assess();

      console.log('\n📋 Assessment Results');
      console.log('━'.repeat(50));

      // Handle both AssessmentResult (full AI) and QuickAssessment (rules-only)
      if ('architecture' in assessment) {
        // Full AI assessment
        console.log(`Application Type: ${assessment.architecture.type}`);
        console.log(`Frameworks: ${assessment.architecture.frameworks.join(', ')}`);
        console.log(`Entry Points: ${assessment.architecture.entryPoints.length}`);
        console.log(`Data Flows: ${assessment.dataFlows.length}`);
        console.log(`Auth Mechanisms: ${assessment.authMechanisms.length}`);
        console.log(`External Dependencies: ${assessment.externalDependencies.length}`);
      } else {
        // Quick assessment (rules-only)
        console.log(`Application Type: ${assessment.applicationType}`);
        console.log(`Frameworks: ${assessment.frameworks.join(', ')}`);
        console.log(`Entry Points: ${assessment.entryPoints.length}`);
        console.log(`Data Flows: ${assessment.dataFlows.length}`);
        console.log(`Files Analyzed: ${assessment.filesAnalyzed}`);
        console.log(`Lines of Code: ${assessment.linesOfCode}`);
      }
      console.log('\n✅ SECURITY.md generated successfully!');

    } catch (error) {
      console.error('\n❌ Error:', error instanceof Error ? error.message : error);
      process.exit(1);
    }
  });

program
  .command('report')
  .description('Generate a report from a previous scan')
  .argument('<scan-id>', 'Scan ID to generate report for')
  .option('-f, --format <format>', 'Output format: json, markdown, html', 'markdown')
  .action((scanId, options) => {
    console.log(`Generating ${options.format} report for scan: ${scanId}`);
    console.log('⚠️  Report generation not yet implemented.');
  });

program
  .command('verify')
  .description('Verify a smart contract on Arc')
  .argument('<address>', 'Contract address to verify')
  .action((address) => {
    console.log(`Verifying contract: ${address}`);
    console.log('⚠️  Contract verification not yet implemented.');
  });

program.parse();
