import { PERMISSION_CATALOG, classifyUnknownPermission } from "./config/permissions";
import type { ManifestModel, PermissionInfo } from "./types";

export function analyzePermissions(manifest: ManifestModel): PermissionInfo[] {
  const declared = new Set(manifest.declaredPermissions);
  return manifest.permissions
    .map((permission) => {
      const rule = PERMISSION_CATALOG[permission.name] ?? classifyUnknownPermission(permission.name);
      const parts = permission.name.split(".");
      return {
        name: permission.name,
        shortName: parts[parts.length - 1] ?? permission.name,
        category: rule.category,
        group: rule.group,
        whyItMatters: rule.whyItMatters,
        commonlyExpected: rule.commonlyExpected,
        severityHint: rule.severityHint,
        maxSdkVersion: permission.maxSdkVersion,
        declaredOnly: declared.has(permission.name),
      } satisfies PermissionInfo;
    })
    .sort((a, b) => severityRank(b) - severityRank(a) || a.name.localeCompare(b.name));
}

function severityRank(permission: PermissionInfo): number {
  const order = { HIGH: 4, MEDIUM: 3, LOW: 2, INFO: 1 } as const;
  const categoryBoost = permission.category === "SPECIAL" ? 1 : 0;
  return order[permission.severityHint] * 2 + categoryBoost;
}

export function countByCategory(permissions: PermissionInfo[]): Record<string, number> {
  return permissions.reduce<Record<string, number>>((accumulator, permission) => {
    accumulator[permission.category] = (accumulator[permission.category] ?? 0) + 1;
    return accumulator;
  }, {});
}