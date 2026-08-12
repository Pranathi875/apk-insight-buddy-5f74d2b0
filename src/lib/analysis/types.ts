/**
 * Shared domain model for the AppGuard static analysis pipeline.
 *
 * Everything the analyzers produce is plain JSON so it can be persisted,
 * diffed, rendered and (in sanitized form) handed to an LLM.
 */

export type Severity = "INFO" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

export type Confidence = "LOW" | "MEDIUM" | "HIGH";

/**
 * NOT_ANALYZED is deliberately distinct from NOT_DETECTED: the first means the
 * evidence source never ran, the second means it ran and found nothing.
 */
export type DetectionState = "DETECTED" | "NOT_DETECTED" | "UNCERTAIN" | "NOT_ANALYZED";


export type FindingCategory =
  | "MANIFEST"
  | "PERMISSION"
  | "COMPONENT"
  | "QUALITY"
  | "PRIVACY"
  | "COVERAGE";

export interface Evidence {
  /** Where the evidence came from, e.g. "AndroidManifest", "dex:strings". */
  source: string;
  /** Human readable detail. Never contains raw APK bytes. */
  detail: string;
}

export interface Finding {
  id: string;
  ruleId: string;
  category: FindingCategory;
  severity: Severity;
  confidence: Confidence;
  title: string;
  description: string;
  /** What the configuration realistically means for the app or its users. */
  impact: string;
  recommendation: string;
  evidence: Evidence[];
  /** Distinct evidence sources this finding was derived from. */
  analysisSources: string[];
  /** Score deduction applied by the scoring engine, per target score. */
  weight: number;
  scoreTarget: ScoreKey;
}

export type ScoreKey = "quality" | "security" | "privacy" | "coverage";

export interface ScoreContribution {
  ruleId: string;
  title: string;
  severity: Severity;
  deduction: number;
}

/**
 * COMPLETE  — every evidence source this score depends on was analyzed.
 * PARTIAL   — some evidence was missing; the value is a lower bound.
 * UNAVAILABLE — required evidence was absent; no numeric score is reported.
 */
export type ScoreStatus = "COMPLETE" | "PARTIAL" | "UNAVAILABLE";

export interface Score {
  key: ScoreKey;
  label: string;
  /** null when status is UNAVAILABLE — rendered as "N/A", never as 100. */
  value: number | null;
  start: number;
  status: ScoreStatus;
  /** Why the score is partial or unavailable. */
  statusReason: string | null;
  contributions: ScoreContribution[];
  methodology: string;
}


export interface PermissionInfo {
  name: string;
  shortName: string;
  category: "NORMAL" | "DANGEROUS" | "SPECIAL" | "SIGNATURE" | "UNKNOWN";
  group: string;
  whyItMatters: string;
  commonlyExpected: boolean;
  severityHint: Severity;
  /** Non-judgemental note on whether the request looks routine or wide. */
  assessment: string;
  maxSdkVersion: number | null;
  declaredOnly: boolean;
}


export interface ComponentInfo {
  type: "activity" | "activity-alias" | "service" | "receiver" | "provider";
  name: string;
  exported: boolean;
  exportedExplicit: boolean;
  permission: string | null;
  intentFilters: IntentFilterInfo[];
  enabled: boolean;
  extra: Record<string, string>;
  notes: string[];
}

export interface IntentFilterInfo {
  actions: string[];
  categories: string[];
  dataSchemes: string[];
  dataHosts: string[];
  autoVerify: boolean;
}

export interface CapabilityResult {
  id: string;
  label: string;
  description: string;
  state: DetectionState;
  confidence: Confidence;
  strength: number;
  evidence: Evidence[];
  explanation: string;
}

export interface LibraryResult {
  id: string;
  name: string;
  category: string;
  version: string | null;
  confidence: Confidence;
  evidence: Evidence[];
}

export interface ManifestModel {
  packageName: string | null;
  versionName: string | null;
  versionCode: number | null;
  compileSdkVersion: number | null;
  minSdkVersion: number | null;
  targetSdkVersion: number | null;
  maxSdkVersion: number | null;
  applicationLabel: string | null;
  debuggable: boolean;
  allowBackup: boolean | null;
  usesCleartextTraffic: boolean | null;
  networkSecurityConfig: string | null;
  hasBackupRules: boolean;
  permissions: { name: string; maxSdkVersion: number | null }[];
  declaredPermissions: string[];
  features: { name: string; required: boolean }[];
  components: ComponentInfo[];
  metaData: { name: string; value: string }[];
  usesLibraries: string[];
  supportsRtl: boolean | null;
  parsed: boolean;
  parseError: string | null;
}

export interface ApkFileFacts {
  fileName: string;
  fileSize: number;
  sha256: string;
  entryCount: number;
  dexCount: number;
  nativeAbis: string[];
  nativeLibCount: number;
  hasSignatureV1: boolean;
  signatureBlockPresent: boolean;
  signingCertFiles: string[];
  largestEntries: { name: string; size: number }[];
  totalUncompressedSize: number;
  assetCount: number;
  resourceCount: number;
  hasResourcesArsc: boolean;
}

export interface DexFacts {
  parsed: boolean;
  dexFiles: number;
  classCount: number;
  /** Distinct package prefixes observed in class descriptors. */
  packagePrefixes: string[];
  /** Only strings that matched a configured signature token are retained. */
  matchedStrings: string[];
  /** Class descriptors that matched a configured signature token. */
  matchedClasses: string[];
  truncated: boolean;
  error: string | null;
}

export interface AnalysisResult {
  schemaVersion: number;
  rulesVersion: string;
  analyzedAt: string;
  durationMs: number;
  file: ApkFileFacts;
  manifest: ManifestModel;
  dex: DexFacts;
  permissions: PermissionInfo[];
  capabilities: CapabilityResult[];
  libraries: LibraryResult[];
  findings: Finding[];
  scores: Score[];
  coverage: {
    manifestParsed: boolean;
    dexParsed: boolean;
    resourcesParsed: boolean;
    signatureInspected: boolean;
    notes: string[];
  };
  limitations: string[];
}

export const SCHEMA_VERSION = 1;