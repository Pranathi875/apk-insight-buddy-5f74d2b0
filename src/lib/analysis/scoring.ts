/**
 * Transparent scoring: every score starts at a configured baseline and is
 * reduced only by the weights of findings that actually fired.
 */

import { SCORE_DEFINITIONS } from "./config/rules";
import type { Finding, Score, ScoreKey } from "./types";

const SCORE_ORDER: ScoreKey[] = ["security", "privacy", "quality", "coverage"];

export function computeScores(findings: Finding[]): Score[] {
  return SCORE_ORDER.map((key) => {
    const definition = SCORE_DEFINITIONS[key];
    const relevant = findings.filter((finding) => finding.scoreTarget === key);
    const contributions = relevant.map((finding) => ({
      ruleId: finding.ruleId,
      title: finding.title,
      severity: finding.severity,
      deduction: finding.weight,
    }));
    const total = contributions.reduce((sum, contribution) => sum + contribution.deduction, 0);
    return {
      key,
      label: definition.label,
      start: definition.start,
      value: clamp(definition.start - total),
      contributions: contributions.sort((a, b) => b.deduction - a.deduction),
      methodology: definition.methodology,
    } satisfies Score;
  });
}

export function overallScore(scores: Score[]): number {
  // Coverage is reported but excluded from the headline: it measures how much
  // evidence we had, not the quality of the application.
  const weighted = scores.filter((score) => score.key !== "coverage");
  if (weighted.length === 0) return 0;
  return Math.round(weighted.reduce((sum, score) => sum + score.value, 0) / weighted.length);
}

export function scoreBand(value: number): "strong" | "fair" | "weak" {
  if (value >= 80) return "strong";
  if (value >= 55) return "fair";
  return "weak";
}

function clamp(value: number): number {
  return Math.max(0, Math.min(100, Math.round(value)));
}