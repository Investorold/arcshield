/**
 * Rule Engine Tests
 */

import { RuleEngine, initializeRuleEngine } from './engine';
import type { Rule, RuleSet, RuleMatch } from './types';
import type { FileContext } from '../types/index';

// Helper to create file context with required fields
function createFile(path: string, content: string): FileContext {
  const ext = path.split('.').pop() || '';
  const langMap: Record<string, string> = {
    js: 'javascript',
    ts: 'typescript',
    py: 'python',
    sol: 'solidity',
    java: 'java',
    go: 'go',
    rs: 'rust',
  };
  return {
    path,
    content,
    language: langMap[ext] || 'unknown',
    lines: content.split('\n').length,
  };
}

describe('RuleEngine', () => {
  let engine: RuleEngine;

  beforeEach(async () => {
    engine = new RuleEngine();
    await engine.loadRules();
  });

  describe('loadRules', () => {
    it('should load built-in rules from JSON files', async () => {
      const rules = engine.getRules();
      expect(rules.length).toBeGreaterThan(0);
    });

    it('should load multiple rule sets', async () => {
      const ruleSets = engine.getRuleSets();
      expect(ruleSets.length).toBeGreaterThan(0);

      // Should have JavaScript, Python, Solidity, GenLayer, Java, Go, Rust
      const names = ruleSets.map(rs => rs.name.toLowerCase());
      expect(names.some(n => n.includes('javascript'))).toBe(true);
      expect(names.some(n => n.includes('python'))).toBe(true);
    });

    it('should track rule statistics', async () => {
      const stats = engine.getStats();
      expect(stats.total).toBeGreaterThan(0);
      expect(Object.keys(stats.byCategory).length).toBeGreaterThan(0);
      expect(Object.keys(stats.bySeverity).length).toBeGreaterThan(0);
      expect(Object.keys(stats.byLanguage).length).toBeGreaterThan(0);
    });
  });

  describe('filtering', () => {
    it('should filter rules by severity', async () => {
      const filteredEngine = new RuleEngine({
        severityFilter: ['critical'],
      });
      await filteredEngine.loadRules();

      const rules = filteredEngine.getRules();
      expect(rules.every(r => r.severity === 'critical')).toBe(true);
    });

    it('should filter rules by category', async () => {
      const filteredEngine = new RuleEngine({
        categoryFilter: ['injection'],
      });
      await filteredEngine.loadRules();

      const rules = filteredEngine.getRules();
      expect(rules.every(r => r.category === 'injection')).toBe(true);
    });

    it('should filter rules by language', async () => {
      const filteredEngine = new RuleEngine({
        languageFilter: ['javascript'],
      });
      await filteredEngine.loadRules();

      const rules = filteredEngine.getRules();
      expect(rules.every(r =>
        r.languages.includes('javascript') || r.languages.includes('any')
      )).toBe(true);
    });

    it('should disable specific rules', async () => {
      const allRules = engine.getRules();
      const firstRuleId = allRules[0]?.id;

      if (firstRuleId) {
        const filteredEngine = new RuleEngine({
          disableRules: [firstRuleId],
        });
        await filteredEngine.loadRules();

        const rules = filteredEngine.getRules();
        expect(rules.find(r => r.id === firstRuleId)).toBeUndefined();
      }
    });
  });

  describe('scan', () => {
    it('should detect XSS vulnerabilities in JavaScript', () => {
      const files: FileContext[] = [createFile('/test/app.js', `
          function renderUser(user) {
            document.getElementById('name').innerHTML = user.name;
          }
        `)];

      const matches = engine.scan(files);
      const xssMatch = matches.find(m => m.rule.id === 'JS001');

      expect(xssMatch).toBeDefined();
      expect(xssMatch?.filePath).toBe('/test/app.js');
    });

    it('should detect SQL injection in JavaScript', () => {
      const files: FileContext[] = [createFile('/test/db.js', `
          async function getUser(userId) {
            return db.query(\`SELECT * FROM users WHERE id = \${userId}\`);
          }
        `)];

      const matches = engine.scan(files);
      const sqlMatch = matches.find(m => m.rule.id === 'JS003');

      expect(sqlMatch).toBeDefined();
    });

    it('should detect eval injection', () => {
      const files: FileContext[] = [createFile('/test/eval.js', `
          function calculate(expression) {
            return eval(expression);
          }
        `)];

      const matches = engine.scan(files);
      const evalMatch = matches.find(m => m.rule.id === 'JS002');

      expect(evalMatch).toBeDefined();
      expect(evalMatch?.rule.severity).toBe('critical');
    });

    it('should detect hardcoded secrets', () => {
      const files: FileContext[] = [createFile('/test/config.js', `
          const apiKey = "sk-1234567890abcdefghijklmnop";
          const password = "supersecretpassword123";
        `)];

      const matches = engine.scan(files);
      const secretMatch = matches.find(m => m.rule.id === 'JS004');

      expect(secretMatch).toBeDefined();
    });

    it('should respect exclude patterns', () => {
      const files: FileContext[] = [createFile('/test/safe.js', `
          import DOMPurify from 'dompurify';
          element.innerHTML = DOMPurify.sanitize(userInput);
        `)];

      const matches = engine.scan(files);
      const xssMatch = matches.find(m =>
        m.rule.id === 'JS001' &&
        m.codeSnippet.includes('innerHTML')
      );

      // Should not match because DOMPurify is in exclude patterns
      expect(xssMatch).toBeUndefined();
    });

    it('should detect Python SQL injection', () => {
      const files: FileContext[] = [createFile('/test/app.py', `
          def get_user(user_id):
              cursor.execute("SELECT * FROM users WHERE id = " + user_id)
        `)];

      const matches = engine.scan(files);
      const sqlMatch = matches.find(m =>
        m.rule.category === 'injection' &&
        m.filePath.endsWith('.py')
      );

      expect(sqlMatch).toBeDefined();
    });

    it('should detect Solidity reentrancy patterns', () => {
      const files: FileContext[] = [createFile('/test/Contract.sol', `
          pragma solidity ^0.8.0;
          contract Vulnerable {
            function withdraw() public {
              (bool success, ) = msg.sender.call{value: balance}("");
              balance = 0;
            }
          }
        `)];

      const matches = engine.scan(files);
      // Should detect call before state change
      expect(matches.length).toBeGreaterThan(0);
    });

    it('should return correct line numbers', () => {
      const files: FileContext[] = [createFile('/test/lines.js', `line1
line2
line3
const password = "secret123456";
line5`)];

      const matches = engine.scan(files);
      const secretMatch = matches.find(m => m.rule.id === 'JS004');

      expect(secretMatch?.lineNumber).toBe(4);
    });

    it('should handle empty files', () => {
      const files: FileContext[] = [createFile('/test/empty.js', '')];

      const matches = engine.scan(files);
      expect(matches).toEqual([]);
    });

    it('should handle files with no vulnerabilities', () => {
      const files: FileContext[] = [createFile('/test/clean.js', `
          function greet(name) {
            return 'Hello, ' + name;
          }
        `)];

      const matches = engine.scan(files);
      expect(matches.length).toBe(0);
    });
  });

  describe('toVulnerabilities', () => {
    it('should convert matches to vulnerability format', () => {
      const mockRule: Rule = {
        id: 'TEST001',
        name: 'Test Rule',
        description: 'A test rule',
        severity: 'high',
        category: 'injection',
        languages: ['javascript'],
        patterns: [{ pattern: 'test', flags: 'gi' }],
        remediation: 'Fix the issue',
        enabled: true,
        confidence: 'high',
      };

      const matches: RuleMatch[] = [{
        rule: mockRule,
        filePath: '/test/file.js',
        lineNumber: 10,
        codeSnippet: 'test code',
        matchedPattern: 'test',
      }];

      const vulns = engine.toVulnerabilities(matches);

      expect(vulns.length).toBe(1);
      expect(vulns[0].title).toBe('Test Rule');
      expect(vulns[0].severity).toBe('high');
      expect(vulns[0].filePath).toBe('/test/file.js');
      expect(vulns[0].lineNumber).toBe(10);
      expect(vulns[0].remediation).toBe('Fix the issue');
    });

    it('should deduplicate matches by file+line+rule', () => {
      const mockRule: Rule = {
        id: 'TEST001',
        name: 'Test Rule',
        description: 'A test rule',
        severity: 'high',
        category: 'injection',
        languages: ['javascript'],
        patterns: [{ pattern: 'test', flags: 'gi' }],
        remediation: 'Fix it',
        enabled: true,
      };

      const matches: RuleMatch[] = [
        {
          rule: mockRule,
          filePath: '/test/file.js',
          lineNumber: 10,
          codeSnippet: 'test code',
          matchedPattern: 'test',
        },
        {
          rule: mockRule,
          filePath: '/test/file.js',
          lineNumber: 10,
          codeSnippet: 'test code again',
          matchedPattern: 'test',
        },
      ];

      const vulns = engine.toVulnerabilities(matches);
      expect(vulns.length).toBe(1);
    });
  });

  describe('rule management', () => {
    it('should get rule by ID', () => {
      const rules = engine.getRules();
      if (rules.length > 0) {
        const rule = engine.getRule(rules[0].id);
        expect(rule).toBeDefined();
        expect(rule?.id).toBe(rules[0].id);
      }
    });

    it('should return undefined for non-existent rule ID', () => {
      const rule = engine.getRule('NON_EXISTENT_RULE_ID');
      expect(rule).toBeUndefined();
    });

    it('should get rules by category', () => {
      const injectionRules = engine.getRulesByCategory('injection');
      expect(injectionRules.every(r => r.category === 'injection')).toBe(true);
    });

    it('should get rules by severity', () => {
      const criticalRules = engine.getRulesBySeverity('critical');
      expect(criticalRules.every(r => r.severity === 'critical')).toBe(true);
    });

    it('should enable/disable rules at runtime', () => {
      const rules = engine.getRules();
      if (rules.length > 0) {
        const ruleId = rules[0].id;

        engine.disableRule(ruleId);
        expect(engine.getRule(ruleId)?.enabled).toBe(false);

        engine.enableRule(ruleId);
        expect(engine.getRule(ruleId)?.enabled).toBe(true);
      }
    });

    it('should add custom rules at runtime', () => {
      const initialCount = engine.getRules().length;

      const customRule: Rule = {
        id: 'CUSTOM001',
        name: 'Custom Test Rule',
        description: 'A custom rule added at runtime',
        severity: 'medium',
        category: 'other',
        languages: ['javascript'],
        patterns: [{ pattern: 'customPattern', flags: 'gi' }],
        remediation: 'Custom fix',
        enabled: true,
      };

      engine.addRule(customRule);

      expect(engine.getRules().length).toBe(initialCount + 1);
      expect(engine.getRule('CUSTOM001')).toBeDefined();
    });

    it('should remove rules at runtime', () => {
      const customRule: Rule = {
        id: 'REMOVE_ME',
        name: 'Rule to Remove',
        description: 'Will be removed',
        severity: 'low',
        category: 'other',
        languages: ['javascript'],
        patterns: [{ pattern: 'remove', flags: 'gi' }],
        remediation: 'N/A',
        enabled: true,
      };

      engine.addRule(customRule);
      expect(engine.getRule('REMOVE_ME')).toBeDefined();

      const removed = engine.removeRule('REMOVE_ME');
      expect(removed).toBe(true);
      expect(engine.getRule('REMOVE_ME')).toBeUndefined();
    });
  });

  describe('Java rules', () => {
    it('should detect SQL injection in Java', () => {
      const files: FileContext[] = [createFile('/test/UserDao.java', `
          public User getUser(String id) {
            Statement stmt = conn.createStatement();
            return stmt.executeQuery("SELECT * FROM users WHERE id = " + id);
          }
        `)];

      const matches = engine.scan(files);
      const sqlMatch = matches.find(m => m.rule.id === 'JAVA001');

      expect(sqlMatch).toBeDefined();
      expect(sqlMatch?.rule.severity).toBe('critical');
    });

    it('should detect insecure deserialization in Java', () => {
      const files: FileContext[] = [createFile('/test/Deserialize.java', `
          public Object deserialize(InputStream is) {
            ObjectInputStream ois = new ObjectInputStream(is);
            return ois.readObject();
          }
        `)];

      const matches = engine.scan(files);
      const deserMatch = matches.find(m => m.rule.id === 'JAVA003');

      expect(deserMatch).toBeDefined();
    });

    it('should detect weak cryptography in Java', () => {
      const files: FileContext[] = [createFile('/test/Crypto.java', `
          public byte[] encrypt(byte[] data) {
            Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
            return cipher.doFinal(data);
          }
        `)];

      const matches = engine.scan(files);
      const cryptoMatch = matches.find(m => m.rule.id === 'JAVA006');

      expect(cryptoMatch).toBeDefined();
    });
  });

  describe('Go rules', () => {
    it('should detect SQL injection in Go', () => {
      const files: FileContext[] = [createFile('/test/db.go', `
          func getUser(id string) User {
            query := fmt.Sprintf("SELECT * FROM users WHERE id = %s", id)
            db.Query(query)
          }
        `)];

      const matches = engine.scan(files);
      const sqlMatch = matches.find(m => m.rule.id === 'GO001');

      expect(sqlMatch).toBeDefined();
    });

    it('should detect insecure TLS in Go', () => {
      const files: FileContext[] = [createFile('/test/client.go', `
          client := &http.Client{
            Transport: &http.Transport{
              TLSClientConfig: &tls.Config{
                InsecureSkipVerify: true,
              },
            },
          }
        `)];

      const matches = engine.scan(files);
      const tlsMatch = matches.find(m => m.rule.id === 'GO005');

      expect(tlsMatch).toBeDefined();
    });

    it('should detect command injection in Go', () => {
      const files: FileContext[] = [createFile('/test/exec.go', `
          func runCommand(input string) {
            exec.Command("sh", "-c", "echo " + input).Run()
          }
        `)];

      const matches = engine.scan(files);
      const cmdMatch = matches.find(m => m.rule.id === 'GO002');

      expect(cmdMatch).toBeDefined();
    });
  });

  describe('Rust rules', () => {
    it('should detect SQL injection in Rust', () => {
      const files: FileContext[] = [createFile('/test/db.rs', `
          fn get_user(id: &str) -> Result<User> {
            let query = format!("SELECT * FROM users WHERE id = {}", id);
            conn.execute(&query)?
          }
        `)];

      const matches = engine.scan(files);
      const sqlMatch = matches.find(m => m.rule.id === 'RS001');

      expect(sqlMatch).toBeDefined();
    });

    it('should detect unsafe blocks in Rust', () => {
      const files: FileContext[] = [createFile('/test/unsafe.rs', `
          fn dangerous() {
            unsafe {
              let ptr = &mut data as *mut i32;
              *ptr = 42;
            }
          }
        `)];

      const matches = engine.scan(files);
      const unsafeMatch = matches.find(m => m.rule.id === 'RS003');

      expect(unsafeMatch).toBeDefined();
    });

    it('should detect weak crypto in Rust', () => {
      const files: FileContext[] = [createFile('/test/crypto.rs', `
          use md5::Md5;

          fn hash_password(password: &str) -> String {
            let digest = Md5::digest(password.as_bytes());
          }
        `)];

      const matches = engine.scan(files);
      const cryptoMatch = matches.find(m => m.rule.id === 'RS006');

      expect(cryptoMatch).toBeDefined();
    });
  });

  describe('initializeRuleEngine', () => {
    it('should create and initialize a new engine', async () => {
      const newEngine = await initializeRuleEngine();
      expect(newEngine.getRules().length).toBeGreaterThan(0);
    });

    it('should accept custom configuration', async () => {
      const newEngine = await initializeRuleEngine({
        severityFilter: ['critical'],
      });

      const rules = newEngine.getRules();
      expect(rules.every(r => r.severity === 'critical')).toBe(true);
    });
  });
});
