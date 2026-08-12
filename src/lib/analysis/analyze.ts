/**
 * Analysis orchestrator.
 *
 * Runs entirely on parsed bytes: the APK is never executed, never written to
 * disk and (in the default configuration) never leaves the machine that
 * uploaded it.
 */

import { capabilityTokens } from "./config/capabilities";
import { libraryTokens } from "./config/libraries";
import { RULES_VERSION } from "./config/rules";
import { detectCapabilities } from "./capabilities";
import { scanDex } from "./dex";
import { detectLibraries } from "./libraries";
import { buildManifestModel } from "./manifest";
import { analyzePermissions } from "./permissions";
import { evaluateRules } from "./rules-engine";
import { computeScores } from "./scoring";
import { ApkZip, ZipError } from "./zip";
import { SCHEMA_VERSION, type AnalysisResult, type ApkFileFacts, type ManifestModel } from "./types";

export const MAX_APK_BYTES = 300 * 1024 * 1024;

export class ApkValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ApkValidationError";
  }
}

export type ProgressStage =
  | "hashing"
  | "container"
  | "manifest"
  | "dex"
  | "capabilities"
  | "rules"
  | "done";

export interface AnalyzeOptions {
  fileName: string;
  onProgress?: (stage: ProgressStage, percent: number) => void;
}

const EXTRA_DEX_TOKENS = ["addjavascriptinterface", "okhttp/", "setjavascriptenabled"];

export async function analyzeApk(bytes: Uint8Array, options: AnalyzeOptions): Promise<AnalysisResult> {
  const startedAt = Date.now();
  const report = (stage: ProgressStage, percent: number) => options.onProgress?.(stage, percent);

  validateContainer(bytes, options.fileName);

  report("hashing", 5);
  const sha256 = await sha256Hex(bytes);

  report("container", 15);
  let zip: ApkZip;
  try {
    zip = ApkZip.open(bytes);
  } catch (cause) {
    throw new ApkValidationError(
      cause instanceof ZipError
        ? `This file is not a readable APK archive: ${cause.message}`
        : "This file could not be opened as an APK archive.",
    );
  }

  const entryNames = zip.entries.map((entry) => entry.name);
  if (!entryNames.includes("AndroidManifest.xml")) {
    throw new ApkValidationError(
      "The archive does not contain AndroidManifest.xml, so it is a ZIP file but not an Android application package.",
    );
  }

  const file = buildFileFacts(zip, bytes, options.fileName, sha256);

  report("manifest", 30);
  let manifest: ManifestModel;
  try {
    manifest = buildManifestModel(await zip.read("AndroidManifest.xml"));
  } catch (cause) {
    manifest = buildManifestModel(new Uint8Array(0));
    manifest.parseError = cause instanceof Error ? cause.message : "Manifest entry could not be read";
  }

  report("dex", 50);
  const dexEntries = zip.find((entry) => /^classes\d*\.dex$/.test(entry.name));
  const dexBuffers: Uint8Array[] = [];
  let dexReadError: string | null = null;
  for (const entry of dexEntries) {
    try {
      dexBuffers.push(await zip.read(entry));
    } catch (cause) {
      dexReadError = cause instanceof Error ? cause.message : "DEX entry unreadable";
    }
  }

  const tokens = [...new Set([...capabilityTokens(), ...libraryTokens(), ...EXTRA_DEX_TOKENS])];
  const dex = scanDex(dexBuffers, { tokens });
  if (dexReadError && !dex.error) dex.error = dexReadError;

  report("capabilities", 70);
  const nativeLibs = entryNames.filter((name) => name.startsWith("lib/") && name.endsWith(".so"));
  const permissions = analyzePermissions(manifest);
  const capabilities = detectCapabilities({ manifest, dex, entryNames, nativeLibs });
  const libraries = detectLibraries({ dex, entryNames });

  report("rules", 85);
  const findings = evaluateRules({ file, manifest, dex, permissions, capabilities });
  const scores = computeScores(findings);

  report("done", 100);

  return {
    schemaVersion: SCHEMA_VERSION,
    rulesVersion: RULES_VERSION,
    analyzedAt: new Date().toISOString(),
    durationMs: Date.now() - startedAt,
    file,
    manifest,
    dex,
    permissions,
    capabilities,
    libraries,
    findings,
    scores,
    coverage: {
      manifestParsed: manifest.parsed,
      dexParsed: dex.parsed,
      resourcesParsed: file.hasResourcesArsc,
      signatureInspected: file.signatureBlockPresent || file.hasSignatureV1,
      notes: buildCoverageNotes(manifest, dex, file),
    },
    limitations: LIMITATIONS,
  };
}

export const LIMITATIONS = [
  "This is static analysis only. Runtime behaviour, server-side logic and network payloads are not observed.",
  "Scores are analytical indicators derived from documented rule weights. They are not a security certification.",
  "Detection is signature-based. Obfuscated, packed or dynamically loaded code can hide capabilities and libraries.",
  "Absence of evidence is reported as NOT_DETECTED, which is not the same as proof that a capability is absent.",
  "Signing information is inferred from container structure only; certificate chains are not cryptographically verified.",
  "Resource values that resolve through resources.arsc are reported as raw resource identifiers.",
];

function validateContainer(bytes: Uint8Array, fileName: string): void {
  if (bytes.length === 0) throw new ApkValidationError("The uploaded file is empty.");
  if (bytes.length > MAX_APK_BYTES) {
    throw new ApkValidationError(`The uploaded file exceeds the ${Math.round(MAX_APK_BYTES / 1024 / 1024)} MB limit.`);
  }
  if (!/\.(apk|zip)$/i.test(fileName)) {
    throw new ApkValidationError("Only .apk files are accepted.");
  }
  const isZipMagic = bytes[0] === 0x50 && bytes[1] === 0x4b && (bytes[2] === 0x03 || bytes[2] === 0x05 || bytes[2] === 0x07);
  if (!isZipMagic) {
    throw new ApkValidationError("The file does not start with a ZIP local-file header, so it is not a valid APK.");
  }
}

function buildFileFacts(zip: ApkZip, bytes: Uint8Array, fileName: string, sha256: string): ApkFileFacts {
  const entries = zip.entries;
  const nativeAbis = [
    ...new Set(
      entries
        .filter((entry) => entry.name.startsWith("lib/") && entry.name.endsWith(".so"))
        .map((entry) => entry.name.split("/")[1] ?? "")
        .filter(Boolean),
    ),
  ].sort();

  const signingCertFiles = entries
    .filter((entry) => /^META-INF\/.*\.(RSA|DSA|EC|SF|MF)$/i.test(entry.name))
    .map((entry) => entry.name);

  return {
    fileName,
    fileSize: bytes.length,
    sha256,
    entryCount: entries.length,
    dexCount: entries.filter((entry) => /^classes\d*\.dex$/.test(entry.name)).length,
    nativeAbis,
    nativeLibCount: entries.filter((entry) => entry.name.startsWith("lib/") && entry.name.endsWith(".so")).length,
    hasSignatureV1: signingCertFiles.some((name) => /\.(RSA|DSA|EC)$/i.test(name)),
    signatureBlockPresent: hasApkSigningBlock(bytes),
    signingCertFiles,
    largestEntries: entries
      .map((entry) => ({ name: entry.name, size: entry.uncompressedSize }))
      .sort((a, b) => b.size - a.size)
      .slice(0, 15),
    totalUncompressedSize: entries.reduce((sum, entry) => sum + entry.uncompressedSize, 0),
    assetCount: entries.filter((entry) => entry.name.startsWith("assets/")).length,
    resourceCount: entries.filter((entry) => entry.name.startsWith("res/")).length,
    hasResourcesArsc: entries.some((entry) => entry.name === "resources.arsc"),
  };
}

/** The APK Signing Block ends with the magic "APK Sig Block 42". */
function hasApkSigningBlock(bytes: Uint8Array): boolean {
  const magic = "APK Sig Block 42";
  const magicBytes = new TextEncoder().encode(magic);
  const searchWindow = Math.min(bytes.length, 4 * 1024 * 1024);
  const start = bytes.length - searchWindow;
  outer: for (let i = bytes.length - magicBytes.length; i >= start; i -= 1) {
    for (let j = 0; j < magicBytes.length; j += 1) {
      if (bytes[i + j] !== magicBytes[j]) continue outer;
    }
    return true;
  }
  return false;
}

function buildCoverageNotes(manifest: ManifestModel, dex: AnalysisResult["dex"], file: ApkFileFacts): string[] {
  const notes: string[] = [];
  if (!manifest.parsed) notes.push(`Manifest not decoded: ${manifest.parseError ?? "unknown reason"}.`);
  if (!dex.parsed) notes.push("No DEX bytecode was decoded; class-level evidence is unavailable.");
  if (dex.truncated) notes.push("DEX string scanning hit the configured limit; some evidence may be missing.");
  if (!file.hasResourcesArsc) notes.push("No resources.arsc; resource references are not resolved to literals.");
  if (notes.length === 0) notes.push("All configured analysis stages completed on this package.");
  return notes;
}

export async function sha256Hex(bytes: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", bytes as unknown as ArrayBuffer);
  return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}