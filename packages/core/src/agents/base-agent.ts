/**
 * Base Agent Class
 *
 * All agents inherit from this base class which provides:
 * - Claude API integration
 * - File context handling
 * - Cost tracking
 * - Error handling
 */

import Anthropic from '@anthropic-ai/sdk';
import type { Agent, AgentContext, AgentResult } from '../types/index.js';
import { MODEL_COSTS } from '../constants.js';

export type ModelType = 'haiku' | 'sonnet' | 'opus';

const MODEL_IDS: Record<ModelType, string> = {
  haiku: 'claude-3-5-haiku-20241022',
  sonnet: 'claude-sonnet-4-20250514',
  opus: 'claude-opus-4-20250514',
};

export interface AgentMessage {
  role: 'user' | 'assistant';
  content: string;
}

export abstract class BaseAgent implements Agent {
  abstract name: string;
  abstract description: string;

  protected client: Anthropic;
  protected model: ModelType;
  protected maxTokens: number;
  protected totalInputTokens: number = 0;
  protected totalOutputTokens: number = 0;

  constructor(model: ModelType = 'sonnet', maxTokens: number = 8192) {
    this.client = new Anthropic();
    this.model = model;
    this.maxTokens = maxTokens;
  }

  /**
   * Run the agent - implemented by subclasses
   */
  abstract run(context: AgentContext): Promise<AgentResult>;

  /**
   * Send a message to Claude and get a response
   */
  protected async chat(
    systemPrompt: string,
    messages: AgentMessage[],
  ): Promise<string> {
    const response = await this.client.messages.create({
      model: MODEL_IDS[this.model],
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
   * Calculate cost based on token usage
   */
  protected calculateCost(): number {
    const costs = MODEL_COSTS[this.model];
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
   * Parse JSON from Claude's response
   */
  protected parseJSON<T>(response: string): T | null {
    // Try to find JSON in the response
    const jsonMatch = response.match(/```json\n?([\s\S]*?)\n?```/);
    const jsonStr = jsonMatch ? jsonMatch[1] : response;

    try {
      return JSON.parse(jsonStr.trim()) as T;
    } catch {
      // Try to find raw JSON object
      const objectMatch = response.match(/\{[\s\S]*\}/);
      if (objectMatch) {
        try {
          return JSON.parse(objectMatch[0]) as T;
        } catch {
          return null;
        }
      }
      return null;
    }
  }

  /**
   * Log agent activity
   */
  protected log(message: string): void {
    console.log(`[${this.name}] ${message}`);
  }
}
