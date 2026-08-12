/**
 * Server functions for the AI narration layer.
 *
 * Only sanitized, already-computed analysis output is sent to the model.
 * The APK itself, its bytes and its full string pool never leave the app.
 */

import { createServerFn } from "@tanstack/react-start";
import { z } from "zod";

const evidenceSchema = z.object({
  source: z.string().max(120),
  detail: z.string().max(400),
});

const findingSchema = z.object({
  ruleId: z.string().max(80),
  title: z.string().max(200),
  severity: z.enum(["INFO", "LOW", "MEDIUM", "HIGH"]),
  description: z.string().max(1200),
  recommendation: z.string().max(1200),
  evidence: z.array(evidenceSchema).max(12).default([]),
});

const summaryInputSchema = z.object({
  packageName: z.string().max(200).nullable(),
  versionName: z.string().max(80).nullable(),
  minSdk: z.number().int().nullable(),
  targetSdk: z.number().int().nullable(),
  sizeBytes: z.number().int().nonnegative(),
  scores: z.array(z.object({ label: z.string().max(60), value: z.number().int() })).max(8),
  findings: z.array(findingSchema).max(40),
  capabilities: z
    .array(z.object({ label: z.string().max(60), state: z.string().max(20), confidence: z.string().max(20) }))
    .max(30),
  permissions: z.array(z.string().max(120)).max(80),
  libraries: z.array(z.string().max(80)).max(60),
  coverageNotes: z.array(z.string().max(300)).max(10),
});

export type AiSummaryInput = z.infer<typeof summaryInputSchema>;

const SYSTEM_PROMPT = [
  "You are a senior Android application security and quality reviewer writing for AppGuard, a static analysis platform.",
  "The deterministic analysis engine is the only source of truth: never invent findings, permissions, capabilities, versions or numbers that are absent from the input.",
  "Never state that an application is safe, unsafe, malicious or certified. Use careful language such as 'review recommended' or 'configuration requires attention'.",
  "Be concise, concrete and technical. Plain prose and short lists only; no markdown headings.",
].join(" ");

export const explainFinding = createServerFn({ method: "POST" })
  .inputValidator((input: unknown) => findingSchema.parse(input))
  .handler(async ({ data }) => {
    const { generateWithFallback } = await import("@/lib/ai/provider.server");
    return generateWithFallback({
      system: SYSTEM_PROMPT,
      maxOutputChars: 2500,
      prompt: [
        `Explain this static-analysis finding to a developer who is unfamiliar with the rule.`,
        `Rule: ${data.ruleId}`,
        `Severity: ${data.severity}`,
        `Title: ${data.title}`,
        `Engine description: ${data.description}`,
        `Engine recommendation: ${data.recommendation}`,
        `Evidence: ${data.evidence.map((item) => `${item.source} → ${item.detail}`).join("; ") || "none recorded"}`,
        "",
        "Write three short paragraphs: (1) what the configuration actually means, (2) the realistic impact and when it is acceptable, (3) concrete remediation steps.",
      ].join("\n"),
      fallback: [
        `${data.title} (${data.severity}, rule ${data.ruleId}).`,
        data.description,
        `Recommended action: ${data.recommendation}`,
        data.evidence.length > 0
          ? `Evidence recorded by the engine: ${data.evidence.map((item) => `${item.source} → ${item.detail}`).join("; ")}.`
          : "No additional evidence was recorded for this finding.",
      ].join("\n\n"),
    });
  });

export const summarizeAnalysis = createServerFn({ method: "POST" })
  .inputValidator((input: unknown) => summaryInputSchema.parse(input))
  .handler(async ({ data }) => {
    const { generateWithFallback } = await import("@/lib/ai/provider.server");
    const detected = data.capabilities.filter((capability) => capability.state === "DETECTED").map((c) => c.label);
    const uncertain = data.capabilities.filter((capability) => capability.state === "UNCERTAIN").map((c) => c.label);
    const high = data.findings.filter((finding) => finding.severity === "HIGH");
    const medium = data.findings.filter((finding) => finding.severity === "MEDIUM");

    return generateWithFallback({
      system: SYSTEM_PROMPT,
      maxOutputChars: 3500,
      prompt: [
        "Write an executive summary of this APK static analysis for an engineering manager.",
        `Package: ${data.packageName ?? "unknown"} version ${data.versionName ?? "unknown"}`,
        `SDK: min ${data.minSdk ?? "?"}, target ${data.targetSdk ?? "?"}; package size ${data.sizeBytes} bytes.`,
        `Scores: ${data.scores.map((score) => `${score.label} ${score.value}/100`).join(", ")}`,
        `Detected capabilities: ${detected.join(", ") || "none"}`,
        `Uncertain capabilities: ${uncertain.join(", ") || "none"}`,
        `Libraries: ${data.libraries.join(", ") || "none detected"}`,
        `Permissions: ${data.permissions.join(", ") || "none"}`,
        `Findings: ${data.findings.map((finding) => `[${finding.severity}] ${finding.title}`).join("; ") || "none"}`,
        `Coverage notes: ${data.coverageNotes.join(" ") || "none"}`,
        "",
        "Structure: one paragraph describing what the app appears to do based on capabilities and libraries; one paragraph on the most important configuration observations and why they matter; one short list of the top three actions. End with one sentence restating that these scores are analytical indicators, not a certification.",
      ].join("\n"),
      fallback: [
        `${data.packageName ?? "This package"} (version ${data.versionName ?? "unknown"}) targets SDK ${data.targetSdk ?? "unknown"} with a minimum of ${data.minSdk ?? "unknown"}.`,
        `Detected capabilities: ${detected.join(", ") || "none"}. Uncertain: ${uncertain.join(", ") || "none"}.`,
        `The rule engine produced ${data.findings.length} findings (${high.length} high, ${medium.length} medium). ${
          high[0] ? `The highest-severity item is "${high[0].title}".` : "No high-severity rules fired."
        }`,
        `Scores — ${data.scores.map((score) => `${score.label}: ${score.value}/100`).join(", ")}.`,
        "These scores are analytical indicators derived from documented rule weights, not a security certification.",
      ].join("\n\n"),
    });
  });

const comparisonInputSchema = z.object({
  basePackage: z.string().max(200).nullable(),
  headPackage: z.string().max(200).nullable(),
  baseVersion: z.string().max(80).nullable(),
  headVersion: z.string().max(80).nullable(),
  lines: z.array(z.string().max(300)).max(200),
  overallFrom: z.number().int(),
  overallTo: z.number().int(),
});

export const summarizeComparison = createServerFn({ method: "POST" })
  .inputValidator((input: unknown) => comparisonInputSchema.parse(input))
  .handler(async ({ data }) => {
    const { generateWithFallback } = await import("@/lib/ai/provider.server");
    return generateWithFallback({
      system: SYSTEM_PROMPT,
      maxOutputChars: 2500,
      prompt: [
        "Summarize the difference between two versions of an Android package for a release review.",
        `Base: ${data.basePackage ?? "unknown"} ${data.baseVersion ?? ""}`,
        `Head: ${data.headPackage ?? "unknown"} ${data.headVersion ?? ""}`,
        `Overall indicator moved ${data.overallFrom} → ${data.overallTo}.`,
        "Machine-generated diff lines:",
        ...data.lines,
        "",
        "Explain in two short paragraphs what changed and which changes deserve reviewer attention before release.",
      ].join("\n"),
      fallback: [
        `Comparing ${data.basePackage ?? "base"} ${data.baseVersion ?? ""} with ${data.headPackage ?? "head"} ${data.headVersion ?? ""}.`,
        `Overall indicator moved from ${data.overallFrom} to ${data.overallTo}.`,
        data.lines.length > 0 ? `Recorded differences:\n${data.lines.map((line) => `• ${line}`).join("\n")}` : "No structural differences were recorded.",
      ].join("\n\n"),
    });
  });

export const aiHealth = createServerFn({ method: "GET" }).handler(async () => {
  const configured = Boolean(process.env["LOVABLE_API_KEY"]);
  return {
    provider: configured ? "gateway" : "local",
    configured,
    model: configured ? "google/gemini-3.6-flash" : null,
    message: configured
      ? "AI narration is available. Only sanitized findings are sent to the model."
      : "No AI key configured. Deterministic summaries are used; all analysis features remain fully functional.",
  };
});