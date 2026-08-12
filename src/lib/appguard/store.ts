/**
 * Persistence layer for analysis runs and comparisons.
 *
 * The APK itself is never uploaded: parsing happens in the browser and only
 * the derived, sanitized JSON result is stored.
 */

import { supabase } from "@/integrations/supabase/client";
import type { ComparisonResult } from "@/lib/analysis/compare";
import { overallScore } from "@/lib/analysis/scoring";
import type { AnalysisResult, Severity } from "@/lib/analysis/types";

export interface AnalysisSummaryRow {
  id: string;
  created_at: string;
  file_name: string;
  file_size: number;
  sha256: string;
  package_name: string | null;
  version_name: string | null;
  version_code: number | null;
  min_sdk: number | null;
  target_sdk: number | null;
  rules_version: string;
  overall_score: number;
  score_security: number;
  score_privacy: number;
  score_quality: number;
  score_coverage: number;
  findings_high: number;
  findings_medium: number;
  findings_low: number;
  findings_info: number;
}

const SUMMARY_COLUMNS =
  "id, created_at, file_name, file_size, sha256, package_name, version_name, version_code, min_sdk, target_sdk, rules_version, overall_score, score_security, score_privacy, score_quality, score_coverage, findings_high, findings_medium, findings_low, findings_info";

function severityCount(result: AnalysisResult, severity: Severity): number {
  return result.findings.filter((finding) => finding.severity === severity).length;
}

function scoreOf(result: AnalysisResult, key: string): number {
  return result.scores.find((score) => score.key === key)?.value ?? 0;
}

export async function saveAnalysis(result: AnalysisResult): Promise<string> {
  const { data, error } = await supabase
    .from("analyses")
    .insert({
      file_name: result.file.fileName,
      file_size: result.file.fileSize,
      sha256: result.file.sha256,
      package_name: result.manifest.packageName,
      version_name: result.manifest.versionName,
      version_code: result.manifest.versionCode,
      min_sdk: result.manifest.minSdkVersion,
      target_sdk: result.manifest.targetSdkVersion,
      rules_version: result.rulesVersion,
      schema_version: result.schemaVersion,
      overall_score: overallScore(result.scores),
      score_security: scoreOf(result, "security"),
      score_privacy: scoreOf(result, "privacy"),
      score_quality: scoreOf(result, "quality"),
      score_coverage: scoreOf(result, "coverage"),
      findings_high: severityCount(result, "HIGH"),
      findings_medium: severityCount(result, "MEDIUM"),
      findings_low: severityCount(result, "LOW"),
      findings_info: severityCount(result, "INFO"),
      result: JSON.parse(JSON.stringify(result)),
    })
    .select("id")
    .single();

  if (error) throw new Error(`Could not save analysis: ${error.message}`);
  return data.id;
}

export async function listAnalyses(limit = 50): Promise<AnalysisSummaryRow[]> {
  const { data, error } = await supabase
    .from("analyses")
    .select(SUMMARY_COLUMNS)
    .order("created_at", { ascending: false })
    .limit(limit);
  if (error) throw new Error(error.message);
  return (data ?? []) as AnalysisSummaryRow[];
}

export interface AnalysisRecord {
  id: string;
  createdAt: string;
  aiSummary: string | null;
  result: AnalysisResult;
}

export async function getAnalysis(id: string): Promise<AnalysisRecord | null> {
  const { data, error } = await supabase
    .from("analyses")
    .select("id, created_at, ai_summary, result")
    .eq("id", id)
    .maybeSingle();
  if (error) throw new Error(error.message);
  if (!data) return null;
  return {
    id: data.id,
    createdAt: data.created_at,
    aiSummary: data.ai_summary,
    result: data.result as unknown as AnalysisResult,
  };
}

export async function saveAiSummary(id: string, summary: string): Promise<void> {
  const { error } = await supabase.from("analyses").update({ ai_summary: summary }).eq("id", id);
  // Anonymous sessions cannot update rows; the summary is still shown in the
  // current session, so a failure here is non-fatal.
  if (error) console.warn("AI summary was not persisted:", error.message);
}

export async function saveComparison(
  baseId: string,
  headId: string,
  diff: ComparisonResult,
  rulesVersion: string,
): Promise<string> {
  const { data, error } = await supabase
    .from("comparisons")
    .insert({
      base_analysis_id: baseId,
      head_analysis_id: headId,
      rules_version: rulesVersion,
      diff: JSON.parse(JSON.stringify(diff)),
    })
    .select("id")
    .single();
  if (error) throw new Error(`Could not save comparison: ${error.message}`);
  return data.id;
}