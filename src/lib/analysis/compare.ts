/**
 * Structural diff between two analysis runs.
 */

import { overallScore } from "./scoring";
import type { AnalysisResult, ScoreKey, Severity } from "./types";

export interface ListDiff {
  added: string[];
  removed: string[];
  unchanged: number;
}

export interface ComparisonResult {
  base: ComparisonSide;
  head: ComparisonSide;
  samePackage: boolean;
  permissions: ListDiff;
  capabilities: ListDiff;
  libraries: ListDiff;
  components: { added: string[]; removed: string[]; countDelta: number; exportedDelta: number };
  sizeDelta: number;
  sdk: { minFrom: number | null; minTo: number | null; targetFrom: number | null; targetTo: number | null };
  findings: {
    added: { ruleId: string; title: string; severity: Severity }[];
    resolved: { ruleId: string; title: string; severity: Severity }[];
  };
  scores: { key: ScoreKey; label: string; from: number; to: number; delta: number }[];
  overall: { from: number; to: number; delta: number };
  summaryLines: string[];
}

interface ComparisonSide {
  id: string | null;
  label: string;
  packageName: string | null;
  versionName: string | null;
  versionCode: number | null;
  size: number;
  sha256: string;
}

export function compareAnalyses(
  base: AnalysisResult,
  head: AnalysisResult,
  ids: { baseId?: string; headId?: string } = {},
): ComparisonResult {
  const permissions = diffLists(
    base.permissions.map((permission) => permission.name),
    head.permissions.map((permission) => permission.name),
  );
  const capabilities = diffLists(
    base.capabilities.filter((capability) => capability.state === "DETECTED").map((capability) => capability.label),
    head.capabilities.filter((capability) => capability.state === "DETECTED").map((capability) => capability.label),
  );
  const libraries = diffLists(
    base.libraries.map((library) => library.name),
    head.libraries.map((library) => library.name),
  );
  const componentDiff = diffLists(
    base.manifest.components.map((component) => `${component.type}:${component.name}`),
    head.manifest.components.map((component) => `${component.type}:${component.name}`),
  );

  const baseFindings = new Map(base.findings.map((finding) => [finding.ruleId, finding]));
  const headFindings = new Map(head.findings.map((finding) => [finding.ruleId, finding]));

  const addedFindings = [...headFindings.values()]
    .filter((finding) => !baseFindings.has(finding.ruleId))
    .map((finding) => ({ ruleId: finding.ruleId, title: finding.title, severity: finding.severity }));
  const resolvedFindings = [...baseFindings.values()]
    .filter((finding) => !headFindings.has(finding.ruleId))
    .map((finding) => ({ ruleId: finding.ruleId, title: finding.title, severity: finding.severity }));

  const scores = head.scores.map((score) => {
    const previous = base.scores.find((candidate) => candidate.key === score.key);
    const from = previous?.value ?? 0;
    return { key: score.key, label: score.label, from, to: score.value, delta: score.value - from };
  });

  const overallFrom = overallScore(base.scores);
  const overallTo = overallScore(head.scores);

  const result: ComparisonResult = {
    base: sideOf(base, ids.baseId ?? null),
    head: sideOf(head, ids.headId ?? null),
    samePackage: base.manifest.packageName === head.manifest.packageName,
    permissions,
    capabilities,
    libraries,
    components: {
      added: componentDiff.added,
      removed: componentDiff.removed,
      countDelta: head.manifest.components.length - base.manifest.components.length,
      exportedDelta:
        head.manifest.components.filter((component) => component.exported).length -
        base.manifest.components.filter((component) => component.exported).length,
    },
    sizeDelta: head.file.fileSize - base.file.fileSize,
    sdk: {
      minFrom: base.manifest.minSdkVersion,
      minTo: head.manifest.minSdkVersion,
      targetFrom: base.manifest.targetSdkVersion,
      targetTo: head.manifest.targetSdkVersion,
    },
    findings: { added: addedFindings, resolved: resolvedFindings },
    scores,
    overall: { from: overallFrom, to: overallTo, delta: overallTo - overallFrom },
    summaryLines: [],
  };

  result.summaryLines = buildSummaryLines(result);
  return result;
}

function sideOf(result: AnalysisResult, id: string | null): ComparisonSide {
  return {
    id,
    label: result.file.fileName,
    packageName: result.manifest.packageName,
    versionName: result.manifest.versionName,
    versionCode: result.manifest.versionCode,
    size: result.file.fileSize,
    sha256: result.file.sha256,
  };
}

export function diffLists(base: string[], head: string[]): ListDiff {
  const baseSet = new Set(base);
  const headSet = new Set(head);
  return {
    added: [...headSet].filter((value) => !baseSet.has(value)).sort(),
    removed: [...baseSet].filter((value) => !headSet.has(value)).sort(),
    unchanged: [...headSet].filter((value) => baseSet.has(value)).length,
  };
}

function buildSummaryLines(result: ComparisonResult): string[] {
  const lines: string[] = [];
  if (!result.samePackage) {
    lines.push(`Different packages compared: ${result.base.packageName ?? "unknown"} → ${result.head.packageName ?? "unknown"}`);
  }
  lines.push(
    `Version ${result.base.versionName ?? "?"} (${result.base.versionCode ?? "?"}) → ${result.head.versionName ?? "?"} (${result.head.versionCode ?? "?"})`,
  );
  result.permissions.added.forEach((name) => lines.push(`+ permission ${name}`));
  result.permissions.removed.forEach((name) => lines.push(`- permission ${name}`));
  result.capabilities.added.forEach((name) => lines.push(`+ capability ${name}`));
  result.capabilities.removed.forEach((name) => lines.push(`- capability ${name}`));
  result.libraries.added.forEach((name) => lines.push(`+ library ${name}`));
  result.libraries.removed.forEach((name) => lines.push(`- library ${name}`));
  if (result.components.countDelta !== 0) {
    lines.push(`${result.components.countDelta > 0 ? "+" : ""}${result.components.countDelta} components`);
  }
  if (result.components.exportedDelta !== 0) {
    lines.push(`${result.components.exportedDelta > 0 ? "+" : ""}${result.components.exportedDelta} exported components`);
  }
  if (result.sizeDelta !== 0) lines.push(`APK size delta ${result.sizeDelta > 0 ? "+" : ""}${result.sizeDelta} bytes`);
  result.findings.added.forEach((finding) => lines.push(`+ finding [${finding.severity}] ${finding.title}`));
  result.findings.resolved.forEach((finding) => lines.push(`- finding [${finding.severity}] ${finding.title}`));
  return lines;
}