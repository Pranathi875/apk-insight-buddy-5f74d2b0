import { LIBRARY_SIGNATURES } from "./config/libraries";
import type { Confidence, DexFacts, Evidence, LibraryResult } from "./types";

export interface LibraryInput {
  dex: DexFacts;
  entryNames: string[];
}

export function detectLibraries(input: LibraryInput): LibraryResult[] {
  const classes = input.dex.matchedClasses.map((value) => value.toLowerCase());
  const prefixes = input.dex.packagePrefixes.map((value) => value.toLowerCase());
  const entries = input.entryNames.map((value) => value.toLowerCase());
  const results: LibraryResult[] = [];

  for (const signature of LIBRARY_SIGNATURES) {
    const evidence: Evidence[] = [];
    let classHits = 0;

    for (const packageName of signature.packages) {
      const needle = packageName.toLowerCase();
      if (classes.some((value) => value.startsWith(needle) || value.includes(needle))) {
        classHits += 1;
        evidence.push({ source: "dex:classes", detail: `Class descriptors under ${packageName}` });
      } else if (prefixes.some((value) => value.startsWith(needle.replace(/\.$/, "")))) {
        classHits += 1;
        evidence.push({ source: "dex:packages", detail: `Package prefix ${packageName}` });
      }
    }

    let entryHit = false;
    for (const entry of signature.entries ?? []) {
      if (entries.some((value) => value.includes(entry.toLowerCase()))) {
        entryHit = true;
        evidence.push({ source: "apk:entries", detail: `Packaged marker ${entry}` });
      }
    }

    if (evidence.length === 0) continue;

    const version = extractVersion(signature.versionPatterns ?? [], input.dex.matchedStrings);
    if (version) evidence.push({ source: "dex:strings", detail: `Version token ${version}` });

    const confidence: Confidence = classHits >= 2 || (classHits >= 1 && entryHit) ? "HIGH" : classHits >= 1 ? "MEDIUM" : "LOW";

    results.push({
      id: signature.id,
      name: signature.name,
      category: signature.category,
      version,
      confidence,
      evidence,
    });
  }

  return results.sort((a, b) => a.category.localeCompare(b.category) || a.name.localeCompare(b.name));
}

function extractVersion(patterns: string[], strings: string[]): string | null {
  for (const pattern of patterns) {
    const regex = new RegExp(pattern, "i");
    for (const value of strings) {
      const match = regex.exec(value);
      if (match?.[1]) return match[1];
    }
  }
  return null;
}