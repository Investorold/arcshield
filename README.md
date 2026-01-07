# ArcShield

> Multi-Agent AI Security Scanner for Arc Ecosystem

ArcShield is a comprehensive security scanning tool that uses multiple AI agents working together to identify vulnerabilities in web applications and smart contracts, with special focus on the Arc blockchain ecosystem.

## Features

- **Multi-Agent AI Analysis**: 5+ specialized AI agents that work like a human security team
- **Smart Contract Scanning**: Integration with Slither and Mythril for Solidity analysis
- **Arc-Specific Rules**: Security checks tailored for Arc blockchain (USDC gas, finality, decimals)
- **GenLayer Support**: Security analysis for intelligent contracts
- **Web App Scanning**: Full STRIDE threat modeling for web applications
- **AI Fix Prompts**: Copy-paste prompts for Claude/Cursor to fix issues
- **Verified Badge**: "ArcShield Verified" badge for projects scoring 80+

## Installation

```bash
npm install -g @arcshield/cli
```

## Usage

```bash
# Scan current directory
arcshield scan

# Scan a specific path
arcshield scan ./my-project

# Scan with specific options
arcshield scan --model sonnet --format markdown --output report.md

# Scan a GitHub repository
arcshield scan https://github.com/user/repo --type github

# Scan a deployed contract
arcshield scan 0x1234... --type contract_address
```

## How It Works

ArcShield uses a multi-agent pipeline inspired by how human security teams work:

```
┌─────────────────────────────────────────────────────────┐
│  Agent 1: Assessment                                     │
│  Maps codebase architecture and data flows              │
└─────────────────────┬───────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────┐
│  Agent 2: Threat Modeling                                │
│  Applies STRIDE framework to identify threats           │
└─────────────────────┬───────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────┐
│  Agent 3: Code Review                                    │
│  Validates threats against actual code                  │
└─────────────────────┬───────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────┐
│  Agent 4: Report Generator                               │
│  Compiles findings into actionable report               │
└─────────────────────────────────────────────────────────┘
```

For smart contracts, additional agents handle:
- Slither static analysis (99 detectors)
- Mythril symbolic execution
- Arc-specific security rules
- GenLayer prompt injection detection

## Arc-Specific Checks

| Rule | Description |
|------|-------------|
| ARC001 | Using block.prevrandao (always 0 on Arc) |
| ARC002 | Hardcoded 6 decimal assumption (Arc native = 18) |
| ARC003 | Strict timestamp comparison (blocks can share timestamps) |
| ARC004 | Unnecessary confirmation waits (Arc has instant finality) |
| ARC005 | SELFDESTRUCT in constructor (reverts on Arc) |
| ARC006 | Missing USDC blocklist handling |
| ARC007 | Mixed decimal interface usage |

## Development

```bash
# Clone the repository
git clone https://github.com/yourusername/arcshield.git
cd arcshield

# Install dependencies
npm install

# Build all packages
npm run build

# Run development mode
npm run dev

# Run tests
npm test
```

## Project Structure

```
arcshield/
├── packages/
│   ├── core/           # Core scanning logic
│   │   ├── agents/     # AI agents
│   │   ├── scanners/   # Web, contract, GenLayer scanners
│   │   ├── rules/      # Security rules
│   │   └── types/      # TypeScript types
│   ├── cli/            # Command-line interface
│   └── web/            # Web interface (coming soon)
├── docs/               # Documentation
└── docker/             # Docker configuration
```

## Roadmap

- [x] Phase 1: Foundation (multi-agent framework)
- [ ] Phase 2: Smart Contract Integration
- [ ] Phase 3: Arc Specialization
- [ ] Phase 4: Web Interface
- [ ] Phase 5: Production Launch

## License

MIT

## Credits

Inspired by:
- [SecureVibes](https://github.com/anshumanbh/securevibes) - Multi-agent architecture
- [Slither](https://github.com/crytic/slither) - Smart contract analysis
- [Mythril](https://github.com/ConsenSys/mythril) - Symbolic execution
