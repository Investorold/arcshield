/**
 * Base Agent Class
 *
 * All agents inherit from this base class which provides:
 * - Claude API integration (Anthropic)
 * - Ollama integration (free local models)
 * - File context handling
 * - Cost tracking
 * - Error handling
 */

import Anthropic from '@anthropic-ai/sdk';
import type { Agent, AgentContext, AgentResult, AIProvider } from '../types/index.js';
import { MODEL_COSTS } from '../constants.js';

export type ModelType = string; // Now accepts any model name

// Anthropic model IDs
const ANTHROPIC_MODEL_IDS: Record<string, string> = {
  haiku: 'claude-3-haiku-20240307',
  sonnet: 'claude-3-sonnet-20240229',
  opus: 'claude-3-opus-20240229',
};

// Default Ollama URL
const DEFAULT_OLLAMA_URL = 'http://localhost:11434';

export interface AgentMessage {
  role: 'user' | 'assistant';
  content: string;
}

export abstract class BaseAgent implements Agent {
  abstract name: string;
  abstract description: string;

  protected client: Anthropic | null = null;
  protected provider: AIProvider;
  protected model: string;
  protected ollamaUrl: string;
  protected maxTokens: number;
  protected totalInputTokens: number = 0;
  protected totalOutputTokens: number = 0;

  constructor(
    model: string = 'sonnet',
    maxTokens: number = 4096,
    provider: AIProvider = 'anthropic',
    ollamaUrl?: string
  ) {
    this.provider = provider;
    this.model = model;
    // Haiku has lower token limit
    this.maxTokens = model === 'haiku' ? Math.min(maxTokens, 4096) : maxTokens;
    this.ollamaUrl = ollamaUrl || DEFAULT_OLLAMA_URL;

    // Only initialize Anthropic client if using that provider
    if (provider === 'anthropic') {
      this.client = new Anthropic();
    }
  }

  /**
   * Run the agent - implemented by subclasses
   */
  abstract run(context: AgentContext): Promise<AgentResult>;

  /**
   * Send a message and get a response (routes to correct provider)
   */
  protected async chat(
    systemPrompt: string,
    messages: AgentMessage[],
  ): Promise<string> {
    if (this.provider === 'ollama') {
      return this.chatOllama(systemPrompt, messages);
    }
    return this.chatAnthropic(systemPrompt, messages);
  }

  /**
   * Chat with Anthropic (Claude)
   */
  private async chatAnthropic(
    systemPrompt: string,
    messages: AgentMessage[],
  ): Promise<string> {
    if (!this.client) {
      throw new Error('Anthropic client not initialized');
    }

    const modelId = ANTHROPIC_MODEL_IDS[this.model] || this.model;

    const response = await this.client.messages.create({
      model: modelId,
      max_tokens: this.maxTokens,
      system: systemPrompt,
      messages: messages.map(m => ({
        role: m.role,
        content: m.content,
      })),
    });

    // Track token usage
    this.totalInputTokens += response.usage.input_tokens;
    this.totalOutputTokens += response.usage.output_tokens;

    // Extract text content
    const textContent = response.content.find(c => c.type === 'text');
    return textContent?.text || '';
  }

  /**
   * Chat with Ollama (local models)
   */
  private async chatOllama(
    systemPrompt: string,
    messages: AgentMessage[],
  ): Promise<string> {
    // Build messages array with system prompt
    const ollamaMessages = [
      { role: 'system', content: systemPrompt },
      ...messages.map(m => ({ role: m.role, content: m.content })),
    ];

    const response = await fetch(`${this.ollamaUrl}/api/chat`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model: this.model,
        messages: ollamaMessages,
        stream: false,
        options: {
          num_predict: this.maxTokens,
        },
      }),
    });

    if (!response.ok) {
      const error = await response.text();
      throw new Error(`Ollama error: ${error}`);
    }

    const data = await response.json() as {
      message: { content: string };
      prompt_eval_count?: number;
      eval_count?: number;
    };

    // Track token usage (approximate for Ollama)
    this.totalInputTokens += data.prompt_eval_count || 0;
    this.totalOutputTokens += data.eval_count || 0;

    return data.message?.content || '';
  }

  /**
   * Calculate cost based on token usage
   */
  protected calculateCost(): number {
    // Ollama is free (local)
    if (this.provider === 'ollama') {
      return 0;
    }

    // Anthropic pricing
    const costs = MODEL_COSTS[this.model as keyof typeof MODEL_COSTS];
    if (!costs) {
      return 0; // Unknown model
    }

    const inputCost = (this.totalInputTokens / 1_000_000) * costs.input;
    const outputCost = (this.totalOutputTokens / 1_000_000) * costs.output;
    return inputCost + outputCost;
  }

  /**
   * Reset token counters
   */
  protected resetTokens(): void {
    this.totalInputTokens = 0;
    this.totalOutputTokens = 0;
  }

  /**
   * Format file contents for context
   */
  protected formatFilesForContext(
    files: { path: string; content: string }[],
    maxChars: number = 100000,
  ): string {
    let result = '';
    let currentChars = 0;

    for (const file of files) {
      const fileContent = `\n### ${file.path}\n\`\`\`\n${file.content}\n\`\`\`\n`;

      if (currentChars + fileContent.length > maxChars) {
        result += `\n... (${files.length - files.indexOf(file)} more files truncated)`;
        break;
      }

      result += fileContent;
      currentChars += fileContent.length;
    }

    return result;
  }

  /**
   * Parse JSON from response - with multiple fallback strategies
   */
  protected parseJSON<T>(response: string): T | null {
    // Strategy 1: Try to find JSON in markdown code block
    const jsonMatch = response.match(/```json\n?([\s\S]*?)\n?```/);
    if (jsonMatch) {
      try {
        return JSON.parse(jsonMatch[1].trim()) as T;
      } catch {
        // Continue to next strategy
      }
    }

    // Strategy 2: Try to find any code block
    const codeMatch = response.match(/```\n?([\s\S]*?)\n?```/);
    if (codeMatch) {
      try {
        return JSON.parse(codeMatch[1].trim()) as T;
      } catch {
        // Continue to next strategy
      }
    }

    // Strategy 3: Try to find raw JSON object (greedy)
    const objectMatch = response.match(/\{[\s\S]*\}/);
    if (objectMatch) {
      try {
        return JSON.parse(objectMatch[0]) as T;
      } catch {
        // Try to fix common JSON issues
        let fixed = objectMatch[0]
          .replace(/,\s*}/g, '}')  // Remove trailing commas
          .replace(/,\s*]/g, ']')  // Remove trailing commas in arrays
          .replace(/'/g, '"');     // Replace single quotes with double quotes
        try {
          return JSON.parse(fixed) as T;
        } catch {
          // Continue to next strategy
        }
      }
    }

    // Strategy 4: Try parsing the whole response
    try {
      return JSON.parse(response.trim()) as T;
    } catch {
      return null;
    }
  }

  /**
   * Log agent activity
   */
  protected log(message: string): void {
    console.log(`[${this.name}] ${message}`);
  }

  /**
   * Get provider name for display
   */
  protected getProviderName(): string {
    if (this.provider === 'ollama') {
      return `Ollama (${this.model})`;
    }
    return `Claude ${this.model}`;
  }
}
