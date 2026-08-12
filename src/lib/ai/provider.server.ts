/**
 * AI provider abstraction.
 *
 * The deterministic analysis engine is always the source of truth. Providers
 * here only rewrite already-computed, sanitized findings into prose.
 *
 *   AIProvider
 *    ├── GatewayProvider  (Lovable AI Gateway, used when a key is present)
 *    └── LocalProvider    (deterministic template fallback, always available)
 */

import { streamText } from "ai";
import { createLovableAiGatewayProvider } from "@/lib/ai-gateway.server";

export interface AiRequest {
  system: string;
  prompt: string;
  /** Deterministic text used when no model is reachable. */
  fallback: string;
  maxOutputChars?: number;
}

export interface AiResponse {
  text: string;
  provider: "gateway" | "local";
  model: string | null;
  degraded: boolean;
  notice: string | null;
}

export interface AIProvider {
  readonly id: "gateway" | "local";
  generate(request: AiRequest): Promise<AiResponse>;
}

export const AI_MODEL = "google/gemini-3.6-flash";

export class LocalProvider implements AIProvider {
  readonly id = "local" as const;

  async generate(request: AiRequest): Promise<AiResponse> {
    return {
      text: request.fallback,
      provider: "local",
      model: null,
      degraded: true,
      notice:
        "AI narration is unavailable, so this text was generated deterministically from the analysis output. All figures are identical to the engine result.",
    };
  }
}

export class GatewayProvider implements AIProvider {
  readonly id = "gateway" as const;

  constructor(private readonly apiKey: string) {}

  async generate(request: AiRequest): Promise<AiResponse> {
    const gateway = createLovableAiGatewayProvider(this.apiKey);
    // Streamed on the wire and consumed here: long analyses must not sit on a
    // silent buffered request.
    const result = streamText({
      model: gateway(AI_MODEL),
      system: request.system,
      prompt: request.prompt,
    });

    const text = (await result.text).trim();
    if (!text) throw new Error("The model returned an empty response.");

    const limit = request.maxOutputChars ?? 6000;
    return {
      text: text.length > limit ? `${text.slice(0, limit)}…` : text,
      provider: "gateway",
      model: AI_MODEL,
      degraded: false,
      notice: null,
    };
  }
}

export function resolveProvider(): AIProvider {
  const apiKey = process.env["LOVABLE_API_KEY"];
  return apiKey ? new GatewayProvider(apiKey) : new LocalProvider();
}

/** Runs the configured provider and degrades to the local one on any failure. */
export async function generateWithFallback(request: AiRequest): Promise<AiResponse> {
  const provider = resolveProvider();
  if (provider.id === "local") return provider.generate(request);

  try {
    return await provider.generate(request);
  } catch (cause) {
    const message = cause instanceof Error ? cause.message : "Unknown AI gateway error";
    const local = await new LocalProvider().generate(request);
    const rateLimited = /429|rate limit/i.test(message);
    const outOfCredits = /402|credit/i.test(message);
    return {
      ...local,
      notice: rateLimited
        ? "The AI service is rate limited right now, so a deterministic summary is shown instead. Try again shortly."
        : outOfCredits
          ? "The AI workspace credits are exhausted, so a deterministic summary is shown instead."
          : `AI narration failed (${message}). A deterministic summary is shown instead.`,
    };
  }
}