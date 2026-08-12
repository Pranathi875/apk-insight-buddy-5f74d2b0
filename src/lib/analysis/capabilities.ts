/**
 * Generic, evidence-weighted capability detection.
 *
 * The engine has no per-capability branches: every capability is described
 * by the signature configuration and scored identically.
 */

import { CAPABILITY_SIGNATURES, type CapabilitySignature } from "./config/capabilities";
import type { CapabilityResult, Confidence, DetectionState, DexFacts, Evidence, ManifestModel } from "./types";

export interface CapabilityInput {
  manifest: ManifestModel;
  dex: DexFacts;
  entryNames: string[];
  nativeLibs: string[];
}

export function detectCapabilities(input: CapabilityInput): CapabilityResult[] {
  return CAPABILITY_SIGNATURES.map((signature) => evaluateCapability(signature, input));
}

function evaluateCapability(signature: CapabilitySignature, input: CapabilityInput): CapabilityResult {
  const evidence: Evidence[] = [];
  let strength = 0;
  let sourceKinds = 0;

  const permissionNames = new Set(input.manifest.permissions.map((permission) => permission.name));
  const matchedPermissions = (signature.permissions ?? []).filter((entry) => permissionNames.has(entry.name));
  if (matchedPermissions.length > 0) {
    sourceKinds += 1;
    strength += Math.max(...matchedPermissions.map((entry) => entry.weight));
    matchedPermissions.forEach((entry) =>
      evidence.push({ source: "AndroidManifest / uses-permission", detail: entry.name }),
    );
  }

  const featureNames = new Set(input.manifest.features.map((feature) => feature.name));
  const matchedFeatures = (signature.features ?? []).filter((entry) => featureNames.has(entry.name));
  if (matchedFeatures.length > 0) {
    sourceKinds += 1;
    strength += Math.max(...matchedFeatures.map((entry) => entry.weight));
    matchedFeatures.forEach((entry) =>
      evidence.push({ source: "AndroidManifest / uses-feature", detail: entry.name }),
    );
  }

  const lowerClasses = input.dex.matchedClasses.map((value) => value.toLowerCase());
  const matchedClasses = (signature.classIndicators ?? []).filter((indicator) =>
    lowerClasses.some((value) => value.includes(indicator.token.toLowerCase())),
  );
  if (matchedClasses.length > 0) {
    sourceKinds += 1;
    strength += Math.max(...matchedClasses.map((indicator) => indicator.weight));
    matchedClasses.forEach((indicator) =>
      evidence.push({
        source: "dex:classes",
        detail: `${indicator.note ?? "Class reference"} — matched "${indicator.token}"`,
      }),
    );
  }

  const lowerStrings = input.dex.matchedStrings.map((value) => value.toLowerCase());
  const matchedStrings = (signature.stringIndicators ?? []).filter((indicator) =>
    lowerStrings.some((value) => value.includes(indicator.token.toLowerCase())),
  );
  if (matchedStrings.length > 0) {
    sourceKinds += 1;
    strength += Math.max(...matchedStrings.map((indicator) => indicator.weight));
    matchedStrings.forEach((indicator) =>
      evidence.push({ source: "dex:strings", detail: `String indicator "${indicator.token}"` }),
    );
  }

  const lowerNative = input.nativeLibs.map((value) => value.toLowerCase());
  const matchedNative = (signature.nativeIndicators ?? []).filter((indicator) =>
    lowerNative.some((value) => value.includes(indicator.token.toLowerCase())),
  );
  if (matchedNative.length > 0) {
    sourceKinds += 1;
    strength += Math.max(...matchedNative.map((indicator) => indicator.weight));
    matchedNative.forEach((indicator) =>
      evidence.push({ source: "native libraries", detail: `Library name contains "${indicator.token}"` }),
    );
  }

  const lowerEntries = input.entryNames.map((value) => value.toLowerCase());
  const matchedEntries = (signature.entryIndicators ?? []).filter((indicator) =>
    lowerEntries.some((value) => value.includes(indicator.token.toLowerCase())),
  );
  if (matchedEntries.length > 0) {
    sourceKinds += 1;
    strength += Math.max(...matchedEntries.map((indicator) => indicator.weight));
    matchedEntries.forEach((indicator) =>
      evidence.push({ source: "apk:entries", detail: `Packaged entry matching "${indicator.token}"` }),
    );
  }

  const lowerMeta = input.manifest.metaData.map((entry) => entry.name.toLowerCase());
  const matchedMeta = (signature.metaDataIndicators ?? []).filter((indicator) =>
    lowerMeta.some((value) => value.includes(indicator.token.toLowerCase())),
  );
  if (matchedMeta.length > 0) {
    sourceKinds += 1;
    strength += Math.max(...matchedMeta.map((indicator) => indicator.weight));
    matchedMeta.forEach((indicator) =>
      evidence.push({ source: "AndroidManifest / meta-data", detail: `meta-data matching "${indicator.token}"` }),
    );
  }

  let state: DetectionState;
  if (strength >= signature.detectedAt) state = "DETECTED";
  else if (strength >= signature.uncertainAt) state = "UNCERTAIN";
  else state = "NOT_DETECTED";

  // Evidence read from a partially parsed package can never be conclusive.
  const degraded = !input.dex.parsed || input.dex.truncated || !input.manifest.parsed;
  if (state === "DETECTED" && degraded && sourceKinds < 2) state = "UNCERTAIN";

  const confidence: Confidence =
    state === "NOT_DETECTED"
      ? degraded
        ? "LOW"
        : "MEDIUM"
      : sourceKinds >= 2 && !degraded
        ? "HIGH"
        : sourceKinds >= 2
          ? "MEDIUM"
          : "LOW";

  return {
    id: signature.id,
    label: signature.label,
    description: signature.description,
    state,
    confidence,
    strength,
    evidence,
    explanation: buildExplanation(signature, state, strength, sourceKinds, degraded),
  };
}

function buildExplanation(
  signature: CapabilitySignature,
  state: DetectionState,
  strength: number,
  sourceKinds: number,
  degraded: boolean,
): string {
  if (state === "NOT_DETECTED") {
    return degraded
      ? `No evidence found, but analysis coverage was incomplete for this package, so absence is not conclusive.`
      : `No configured indicator for ${signature.label} matched (threshold ${signature.uncertainAt}, observed ${strength}).`;
  }
  const base = `Evidence strength ${strength} from ${sourceKinds} independent source${sourceKinds === 1 ? "" : "s"} (detection threshold ${signature.detectedAt}).`;
  if (state === "UNCERTAIN") {
    return `${base} This is below the confident-detection threshold or rests on a single source, so it is reported as uncertain rather than detected.`;
  }
  return base;
}