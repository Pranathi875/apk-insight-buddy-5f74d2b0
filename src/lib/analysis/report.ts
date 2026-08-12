/**
 * Self-contained HTML report generator. The output has no external assets,
 * so it can be archived, emailed, or printed to PDF from the browser.
 */

import { formatBytes } from "./rules-engine";
import { overallScore } from "./scoring";
import type { AnalysisResult } from "./types";

export interface ReportOptions {
  executiveSummary?: string | null;
  generatedBy?: string;
}

export function buildHtmlReport(result: AnalysisResult, options: ReportOptions = {}): string {
  const overall = overallScore(result.scores);
  const title = `AppGuard report — ${escapeHtml(result.manifest.packageName ?? result.file.fileName)}`;

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>${title}</title>
<style>
  :root { color-scheme: light; }
  * { box-sizing: border-box; }
  body { margin: 0; padding: 40px; font: 14px/1.55 ui-sans-serif, system-ui, -apple-system, "Segoe UI", sans-serif; color: #10161d; background: #fff; }
  h1 { font-size: 26px; margin: 0 0 4px; }
  h2 { font-size: 18px; margin: 36px 0 10px; border-bottom: 2px solid #10161d; padding-bottom: 6px; }
  h3 { font-size: 14px; margin: 18px 0 6px; text-transform: uppercase; letter-spacing: .08em; color: #4b5b6b; }
  .sub { color: #5b6b7b; margin: 0 0 18px; }
  table { width: 100%; border-collapse: collapse; margin: 8px 0 16px; font-size: 13px; }
  th, td { text-align: left; padding: 7px 9px; border-bottom: 1px solid #e2e8ee; vertical-align: top; }
  th { background: #f4f7fa; font-weight: 600; }
  code, .mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px; }
  .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 12px; }
  .card { border: 1px solid #dbe3ea; border-radius: 10px; padding: 14px; }
  .score { font-size: 30px; font-weight: 700; }
  .badge { display: inline-block; padding: 2px 8px; border-radius: 999px; font-size: 11px; font-weight: 700; letter-spacing: .04em; }
  .HIGH { background: #fde2e1; color: #8d1b16; }
  .MEDIUM { background: #fdeccd; color: #8a5a04; }
  .LOW { background: #dff0f7; color: #145b74; }
  .INFO { background: #eceff3; color: #4b5b6b; }
  .DETECTED { background: #d9f2e3; color: #14603a; }
  .UNCERTAIN { background: #fdeccd; color: #8a5a04; }
  .NOT_DETECTED { background: #eceff3; color: #4b5b6b; }
  .note { background: #f6f8fa; border-left: 3px solid #94a4b4; padding: 10px 14px; margin: 12px 0; }
  ul { margin: 6px 0 6px 18px; padding: 0; }
  footer { margin-top: 40px; border-top: 1px solid #dbe3ea; padding-top: 12px; color: #6b7b8b; font-size: 12px; }
  @media print { body { padding: 12mm; } h2 { page-break-after: avoid; } table { page-break-inside: avoid; } }
</style>
</head>
<body>
<h1>AppGuard analysis report</h1>
<p class="sub">${escapeHtml(result.manifest.packageName ?? "Unknown package")} · version ${escapeHtml(
    result.manifest.versionName ?? "?",
  )} (${result.manifest.versionCode ?? "?"}) · generated ${new Date(result.analyzedAt).toUTCString()}</p>

${options.executiveSummary ? `<div class="note"><strong>Executive summary</strong><br />${escapeHtml(options.executiveSummary).replace(/\n/g, "<br />")}</div>` : ""}

<h2>Scores</h2>
<div class="grid">
  <div class="card"><div>Overall indicator</div><div class="score">${overall}</div></div>
  ${result.scores
    .map((score) => `<div class="card"><div>${escapeHtml(score.label)}</div><div class="score">${score.value}</div><div class="mono">start ${score.start} · ${score.contributions.length} deductions</div></div>`)
    .join("")}
</div>
<div class="note">This score is an analytical indicator, not a security certification.</div>

<h2>Application summary</h2>
<table>
  <tr><th>File</th><td class="mono">${escapeHtml(result.file.fileName)}</td></tr>
  <tr><th>SHA-256</th><td class="mono">${escapeHtml(result.file.sha256)}</td></tr>
  <tr><th>Size</th><td>${formatBytes(result.file.fileSize)} (${result.file.entryCount} entries, ${result.file.dexCount} DEX files)</td></tr>
  <tr><th>Package</th><td class="mono">${escapeHtml(result.manifest.packageName ?? "—")}</td></tr>
  <tr><th>Version</th><td>${escapeHtml(result.manifest.versionName ?? "—")} (code ${result.manifest.versionCode ?? "—"})</td></tr>
  <tr><th>SDK</th><td>min ${result.manifest.minSdkVersion ?? "—"} · target ${result.manifest.targetSdkVersion ?? "—"} · compile ${result.manifest.compileSdkVersion ?? "—"}</td></tr>
  <tr><th>Native ABIs</th><td>${result.file.nativeAbis.join(", ") || "none"}</td></tr>
  <tr><th>Signing</th><td>${result.file.signatureBlockPresent ? "APK Signing Block present" : "No APK Signing Block detected"}${result.file.hasSignatureV1 ? " · v1 JAR signature files present" : ""}</td></tr>
  <tr><th>Rules version</th><td class="mono">${escapeHtml(result.rulesVersion)}</td></tr>
</table>

<h2>Findings (${result.findings.length})</h2>
${
  result.findings.length === 0
    ? "<p>No configured rule fired for this package. This does not mean the application is free of defects.</p>"
    : `<table><thead><tr><th>Severity</th><th>Rule</th><th>Finding</th><th>Evidence</th></tr></thead><tbody>${result.findings
        .map(
          (finding) => `<tr>
  <td><span class="badge ${finding.severity}">${finding.severity}</span></td>
  <td class="mono">${escapeHtml(finding.ruleId)}<br />−${finding.weight} ${finding.scoreTarget}</td>
  <td><strong>${escapeHtml(finding.title)}</strong><br />${escapeHtml(finding.description)}<br /><em>${escapeHtml(finding.recommendation)}</em></td>
  <td><ul>${finding.evidence.map((evidence) => `<li class="mono">${escapeHtml(evidence.source)}: ${escapeHtml(evidence.detail)}</li>`).join("")}</ul></td>
</tr>`,
        )
        .join("")}</tbody></table>`
}

<h2>Permissions (${result.permissions.length})</h2>
<table><thead><tr><th>Permission</th><th>Category</th><th>Group</th><th>Why it matters</th></tr></thead><tbody>
${result.permissions
  .map(
    (permission) => `<tr><td class="mono">${escapeHtml(permission.name)}</td><td><span class="badge ${permission.severityHint}">${permission.category}</span></td><td>${escapeHtml(permission.group)}</td><td>${escapeHtml(permission.whyItMatters)}</td></tr>`,
  )
  .join("")}
</tbody></table>

<h2>Components (${result.manifest.components.length})</h2>
<table><thead><tr><th>Type</th><th>Name</th><th>Exported</th><th>Permission</th><th>Intent filters</th></tr></thead><tbody>
${result.manifest.components
  .map(
    (component) => `<tr><td>${component.type}</td><td class="mono">${escapeHtml(component.name)}</td><td>${component.exported ? "yes" : "no"}${component.exportedExplicit ? "" : " (implied)"}</td><td class="mono">${escapeHtml(component.permission ?? "—")}</td><td>${component.intentFilters
      .map((filter) => escapeHtml(filter.actions.join(", ")))
      .join("<br />")}</td></tr>`,
  )
  .join("")}
</tbody></table>

<h2>Capabilities</h2>
<table><thead><tr><th>Capability</th><th>State</th><th>Confidence</th><th>Evidence</th></tr></thead><tbody>
${result.capabilities
  .map(
    (capability) => `<tr><td>${escapeHtml(capability.label)}</td><td><span class="badge ${capability.state}">${capability.state}</span></td><td>${capability.confidence}</td><td><ul>${
      capability.evidence.map((evidence) => `<li class="mono">${escapeHtml(evidence.source)}: ${escapeHtml(evidence.detail)}</li>`).join("") ||
      `<li>${escapeHtml(capability.explanation)}</li>`
    }</ul></td></tr>`,
  )
  .join("")}
</tbody></table>

<h2>Third-party libraries (${result.libraries.length})</h2>
<table><thead><tr><th>Library</th><th>Category</th><th>Version</th><th>Confidence</th></tr></thead><tbody>
${result.libraries
  .map(
    (library) => `<tr><td>${escapeHtml(library.name)}</td><td>${escapeHtml(library.category)}</td><td class="mono">${escapeHtml(library.version ?? "not resolvable")}</td><td>${library.confidence}</td></tr>`,
  )
  .join("")}
</tbody></table>

<h2>Scoring methodology</h2>
${result.scores
  .map(
    (score) => `<h3>${escapeHtml(score.label)} — ${score.value}/100</h3><p>${escapeHtml(score.methodology)}</p>
<table><thead><tr><th>Rule</th><th>Severity</th><th>Deduction</th></tr></thead><tbody>
${
  score.contributions
    .map((contribution) => `<tr><td class="mono">${escapeHtml(contribution.ruleId)}</td><td>${contribution.severity}</td><td>−${contribution.deduction}</td></tr>`)
    .join("") || '<tr><td colspan="3">No deductions.</td></tr>'
}
<tr><th>Final</th><th></th><th>${score.start} − ${score.start - score.value} = ${score.value}</th></tr>
</tbody></table>`,
  )
  .join("")}

<h2>Analysis coverage</h2>
<ul>${result.coverage.notes.map((note) => `<li>${escapeHtml(note)}</li>`).join("")}</ul>

<h2>Limitations</h2>
<ul>${result.limitations.map((limitation) => `<li>${escapeHtml(limitation)}</li>`).join("")}</ul>

<footer>Generated by ${escapeHtml(options.generatedBy ?? "AppGuard")} · rules ${escapeHtml(result.rulesVersion)} · schema v${result.schemaVersion} · analysis took ${result.durationMs} ms.</footer>
</body>
</html>`;
}

export function escapeHtml(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}