/**
 * Deterministic rule evaluation.
 *
 * Each predicate returns zero or more evidence sets; the engine turns them
 * into findings using the weights and copy from the rule configuration.
 */

import { RULE_INDEX, THRESHOLDS } from "./config/rules";
import type {
  ApkFileFacts,
  CapabilityResult,
  DexFacts,
  Evidence,
  Finding,
  ManifestModel,
  PermissionInfo,
} from "./types";

export interface RuleContext {
  file: ApkFileFacts;
  manifest: ManifestModel;
  dex: DexFacts;
  permissions: PermissionInfo[];
  capabilities: CapabilityResult[];
}

interface RuleHit {
  ruleId: string;
  evidence: Evidence[];
  /** Multiplies the configured weight (capped by maxDeduction). */
  occurrences?: number;
  confidenceOverride?: Finding["confidence"];
  titleSuffix?: string;
}

type Predicate = (context: RuleContext) => RuleHit[];

const predicates: Predicate[] = [
  // --- Manifest configuration -------------------------------------------
  ({ manifest }) =>
    manifest.debuggable
      ? [{ ruleId: "MANIFEST_DEBUGGABLE", evidence: [{ source: "AndroidManifest", detail: 'application android:debuggable="true"' }] }]
      : [],

  ({ manifest }) =>
    manifest.usesCleartextTraffic === true
      ? [
          {
            ruleId: "MANIFEST_CLEARTEXT_TRAFFIC",
            evidence: [{ source: "AndroidManifest", detail: 'application android:usesCleartextTraffic="true"' }],
          },
        ]
      : [],

  ({ manifest }) =>
    manifest.parsed && !manifest.networkSecurityConfig
      ? [
          {
            ruleId: "MANIFEST_NO_NETWORK_SECURITY_CONFIG",
            evidence: [{ source: "AndroidManifest", detail: "No android:networkSecurityConfig attribute on <application>" }],
          },
        ]
      : [],

  ({ manifest }) =>
    manifest.allowBackup !== false && manifest.parsed && !manifest.hasBackupRules
      ? [
          {
            ruleId: "MANIFEST_BACKUP_ALLOWED",
            evidence: [
              {
                source: "AndroidManifest",
                detail: `allowBackup=${manifest.allowBackup === null ? "unset (platform default true)" : "true"}, no fullBackupContent/dataExtractionRules`,
              },
            ],
          },
        ]
      : [],

  // --- Components --------------------------------------------------------
  ({ manifest }) => {
    const unguarded = manifest.components.filter(
      (component) => component.exported && !component.permission && component.type !== "provider",
    );
    if (unguarded.length === 0) return [];
    return [
      {
        ruleId: "COMPONENT_EXPORTED_UNPROTECTED",
        occurrences: unguarded.length,
        evidence: unguarded.slice(0, 12).map((component) => ({
          source: `AndroidManifest / ${component.type}`,
          detail: `${component.name}${component.exportedExplicit ? "" : " (exported implied by intent filter)"}`,
        })),
      },
    ];
  },

  ({ manifest }) => {
    const providers = manifest.components.filter((component) => component.type === "provider" && component.exported);
    if (providers.length === 0) return [];
    return [
      {
        ruleId: "COMPONENT_EXPORTED_PROVIDER",
        occurrences: providers.length,
        evidence: providers.map((component) => ({
          source: "AndroidManifest / provider",
          detail: `${component.name}${component.permission ? ` (permission: ${component.permission})` : " (no permission attribute)"}`,
        })),
      },
    ];
  },

  ({ manifest }) => {
    const exported = manifest.components.filter((component) => component.exported).length;
    if (exported < THRESHOLDS.exportedComponentWarnCount) return [];
    return [
      {
        ruleId: "COMPONENT_EXPORTED_COUNT_HIGH",
        evidence: [{ source: "AndroidManifest", detail: `${exported} exported components (warn threshold ${THRESHOLDS.exportedComponentWarnCount})` }],
        confidenceOverride: exported >= THRESHOLDS.exportedComponentHighCount ? "HIGH" : "MEDIUM",
      },
    ];
  },

  ({ manifest }) => {
    const browsable = manifest.components.filter((component) =>
      component.intentFilters.some((filter) => filter.categories.includes("android.intent.category.BROWSABLE")),
    );
    if (browsable.length === 0) return [];
    return [
      {
        ruleId: "COMPONENT_BROWSABLE_DEEP_LINK",
        occurrences: browsable.length,
        evidence: browsable.slice(0, 10).map((component) => ({
          source: "AndroidManifest / intent-filter",
          detail: `${component.name} — schemes: ${
            component.intentFilters.flatMap((filter) => filter.dataSchemes).join(", ") || "(none declared)"
          }`,
        })),
      },
    ];
  },

  // --- Permissions & privacy --------------------------------------------
  ({ permissions }) => {
    const dangerous = permissions.filter((permission) => permission.category === "DANGEROUS");
    if (dangerous.length < THRESHOLDS.dangerousPermissionWarnCount) return [];
    return [
      {
        ruleId: "PERMISSION_DANGEROUS_MANY",
        evidence: [
          {
            source: "AndroidManifest",
            detail: `${dangerous.length} runtime-protected permissions: ${dangerous.map((permission) => permission.shortName).join(", ")}`,
          },
        ],
        confidenceOverride: dangerous.length >= THRESHOLDS.dangerousPermissionHighCount ? "HIGH" : "MEDIUM",
      },
    ];
  },

  ({ permissions }) => {
    const special = permissions.filter((permission) => permission.category === "SPECIAL");
    if (special.length === 0) return [];
    return [
      {
        ruleId: "PERMISSION_SPECIAL",
        occurrences: special.length,
        evidence: special.map((permission) => ({ source: "AndroidManifest", detail: `${permission.name} — ${permission.whyItMatters}` })),
      },
    ];
  },

  ({ permissions }) =>
    permissions.some((permission) => permission.name === "android.permission.QUERY_ALL_PACKAGES")
      ? [
          {
            ruleId: "PERMISSION_QUERY_ALL_PACKAGES",
            evidence: [{ source: "AndroidManifest", detail: "android.permission.QUERY_ALL_PACKAGES" }],
          },
        ]
      : [],

  ({ permissions }) => {
    const unknown = permissions.filter((permission) => permission.category === "UNKNOWN");
    if (unknown.length === 0) return [];
    return [
      {
        ruleId: "PERMISSION_CUSTOM_UNDOCUMENTED",
        occurrences: unknown.length,
        evidence: unknown.slice(0, 15).map((permission) => ({ source: "AndroidManifest", detail: permission.name })),
        confidenceOverride: "LOW",
      },
    ];
  },

  // --- Quality -----------------------------------------------------------
  ({ manifest }) => {
    const target = manifest.targetSdkVersion;
    if (target === null || target >= THRESHOLDS.targetSdkWarnBelow) return [];
    return [
      {
        ruleId: "QUALITY_TARGET_SDK_OLD",
        occurrences: target < THRESHOLDS.targetSdkHighBelow ? 2 : 1,
        evidence: [
          {
            source: "AndroidManifest / uses-sdk",
            detail: `targetSdkVersion=${target}; current platform baseline in rules configuration is ${THRESHOLDS.currentTargetSdk}`,
          },
        ],
      },
    ];
  },

  ({ manifest }) =>
    manifest.minSdkVersion !== null && manifest.minSdkVersion < THRESHOLDS.minSdkVeryOldBelow
      ? [
          {
            ruleId: "QUALITY_MIN_SDK_VERY_OLD",
            evidence: [{ source: "AndroidManifest / uses-sdk", detail: `minSdkVersion=${manifest.minSdkVersion}` }],
          },
        ]
      : [],

  ({ file }) => {
    if (file.fileSize < THRESHOLDS.apkSizeWarnBytes) return [];
    return [
      {
        ruleId: "QUALITY_APK_SIZE",
        occurrences: file.fileSize >= THRESHOLDS.apkSizeHighBytes ? 2 : 1,
        evidence: [{ source: "apk:container", detail: `Package size ${formatBytes(file.fileSize)}` }],
      },
    ];
  },

  ({ file }) => {
    const large = file.largestEntries.filter((entry) => entry.size >= THRESHOLDS.largeAssetBytes);
    if (large.length === 0) return [];
    return [
      {
        ruleId: "QUALITY_LARGE_ASSETS",
        occurrences: large.length,
        evidence: large.slice(0, 5).map((entry) => ({ source: "apk:entries", detail: `${entry.name} — ${formatBytes(entry.size)}` })),
      },
    ];
  },

  ({ file }) =>
    file.nativeAbis.length > 1
      ? [
          {
            ruleId: "QUALITY_MULTIPLE_ABIS",
            evidence: [{ source: "apk:entries", detail: `ABIs present: ${file.nativeAbis.join(", ")}` }],
          },
        ]
      : [],

  ({ file }) =>
    !file.signatureBlockPresent
      ? [
          {
            ruleId: "QUALITY_NO_V2_SIGNATURE_BLOCK",
            evidence: [
              {
                source: "apk:container",
                detail: file.hasSignatureV1
                  ? "Legacy META-INF JAR signature files present, but no APK Signing Block magic found"
                  : "No APK Signing Block and no META-INF signature files found",
              },
            ],
            confidenceOverride: "MEDIUM",
          },
        ]
      : [],

  ({ file }) => {
    const debugCert = file.signingCertFiles.some((name) => /debug/i.test(name));
    if (!debugCert) return [];
    return [
      {
        ruleId: "QUALITY_DEBUG_CERT",
        evidence: file.signingCertFiles
          .filter((name) => /debug/i.test(name))
          .map((name) => ({ source: "apk:entries", detail: name })),
        confidenceOverride: "LOW",
      },
    ];
  },

  // --- Capability-derived ------------------------------------------------
  ({ capabilities, dex }) => {
    const webview = capabilities.find((capability) => capability.id === "webview");
    const bridge = dex.matchedStrings.some((value) => value.toLowerCase().includes("addjavascriptinterface"));
    if (!webview || webview.state === "NOT_DETECTED" || !bridge) return [];
    return [
      {
        ruleId: "CAPABILITY_WEBVIEW_JS_BRIDGE",
        evidence: [
          { source: "dex:strings", detail: "addJavascriptInterface reference" },
          { source: "capability:webview", detail: `WebView capability state ${webview.state}` },
        ],
        confidenceOverride: webview.state === "DETECTED" ? "MEDIUM" : "LOW",
      },
    ];
  },

  ({ capabilities }) => {
    const sensitive = ["camera", "microphone", "location"].filter((id) =>
      capabilities.some((capability) => capability.id === id && capability.state === "DETECTED"),
    );
    if (sensitive.length < 2) return [];
    return [
      {
        ruleId: "PRIVACY_HIGH_SENSITIVITY_CAPABILITIES",
        evidence: [{ source: "capabilities", detail: `Detected together: ${sensitive.join(", ")}` }],
      },
    ];
  },

  // --- Coverage ----------------------------------------------------------
  ({ manifest }) =>
    manifest.parsed
      ? []
      : [
          {
            ruleId: "COVERAGE_MANIFEST_UNPARSED",
            evidence: [{ source: "pipeline", detail: manifest.parseError ?? "Manifest decoding failed" }],
          },
        ],

  ({ dex }) =>
    dex.parsed
      ? []
      : [
          {
            ruleId: "COVERAGE_DEX_UNPARSED",
            evidence: [{ source: "pipeline", detail: dex.error ?? "No readable classes*.dex entries" }],
          },
        ],

  ({ dex }) =>
    dex.parsed && dex.truncated
      ? [{ ruleId: "COVERAGE_DEX_TRUNCATED", evidence: [{ source: "pipeline", detail: "String scan limit reached" }] }]
      : [],

  ({ file }) =>
    file.hasResourcesArsc
      ? []
      : [{ ruleId: "COVERAGE_NO_RESOURCE_TABLE", evidence: [{ source: "apk:entries", detail: "resources.arsc not present" }] }],
];

export function evaluateRules(context: RuleContext): Finding[] {
  const findings: Finding[] = [];

  for (const predicate of predicates) {
    for (const hit of predicate(context)) {
      const definition = RULE_INDEX[hit.ruleId];
      if (!definition) continue;
      const occurrences = Math.max(1, hit.occurrences ?? 1);
      const uncapped = definition.weight * occurrences;
      const weight = definition.maxDeduction ? Math.min(uncapped, definition.maxDeduction) : Math.min(uncapped, definition.weight * 3);

      findings.push({
        id: `${definition.id}:${findings.length}`,
        ruleId: definition.id,
        category: definition.category,
        severity: definition.severity,
        confidence: hit.confidenceOverride ?? "HIGH",
        title: occurrences > 1 ? `${definition.title} (${occurrences})` : definition.title,
        description: definition.description,
        recommendation: definition.recommendation,
        evidence: hit.evidence,
        weight,
        scoreTarget: definition.scoreTarget,
      });
    }
  }

  const order = { HIGH: 0, MEDIUM: 1, LOW: 2, INFO: 3 } as const;
  return findings.sort((a, b) => order[a.severity] - order[b.severity] || b.weight - a.weight);
}

export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  const units = ["KB", "MB", "GB"];
  let value = bytes / 1024;
  let unitIndex = 0;
  while (value >= 1024 && unitIndex < units.length - 1) {
    value /= 1024;
    unitIndex += 1;
  }
  return `${value.toFixed(value >= 100 ? 0 : 1)} ${units[unitIndex]}`;
}