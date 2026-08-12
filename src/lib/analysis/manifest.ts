/**
 * Turns the decoded AndroidManifest tree into a typed manifest model.
 */

import { attr, attrBool, attrInt, findElements, parseAxml, type AxmlNode } from "./axml";
import type { ComponentInfo, IntentFilterInfo, ManifestModel } from "./types";

const EMPTY_MANIFEST: ManifestModel = {
  packageName: null,
  versionName: null,
  versionCode: null,
  compileSdkVersion: null,
  minSdkVersion: null,
  targetSdkVersion: null,
  maxSdkVersion: null,
  applicationLabel: null,
  debuggable: false,
  allowBackup: null,
  usesCleartextTraffic: null,
  networkSecurityConfig: null,
  hasBackupRules: false,
  permissions: [],
  declaredPermissions: [],
  features: [],
  components: [],
  metaData: [],
  usesLibraries: [],
  supportsRtl: null,
  parsed: false,
  parseError: null,
};

export function buildManifestModel(bytes: Uint8Array): ManifestModel {
  let root: AxmlNode;
  try {
    root = parseAxml(bytes);
  } catch (cause) {
    return {
      ...EMPTY_MANIFEST,
      parseError: cause instanceof Error ? cause.message : "Unknown manifest parse failure",
    };
  }

  const manifestNode = findElements(root, "manifest")[0];
  if (!manifestNode) return { ...EMPTY_MANIFEST, parseError: "No <manifest> element found" };

  const applicationNode = findElements(manifestNode, "application")[0];
  const usesSdkNode = findElements(manifestNode, "uses-sdk")[0];

  const components: ComponentInfo[] = [];
  const componentTags: ComponentInfo["type"][] = [
    "activity",
    "activity-alias",
    "service",
    "receiver",
    "provider",
  ];

  if (applicationNode) {
    for (const tag of componentTags) {
      for (const node of findElements(applicationNode, tag)) {
        components.push(buildComponent(tag, node));
      }
    }
  }

  const compileSdk = attrInt(manifestNode, "compileSdkVersion");

  return {
    packageName: attr(manifestNode, "package"),
    versionName: attr(manifestNode, "versionName"),
    versionCode: attrInt(manifestNode, "versionCode"),
    compileSdkVersion: compileSdk,
    minSdkVersion: usesSdkNode ? attrInt(usesSdkNode, "minSdkVersion") : null,
    targetSdkVersion: usesSdkNode ? attrInt(usesSdkNode, "targetSdkVersion") : null,
    maxSdkVersion: usesSdkNode ? attrInt(usesSdkNode, "maxSdkVersion") : null,
    applicationLabel: applicationNode ? attr(applicationNode, "label") : null,
    debuggable: applicationNode ? attrBool(applicationNode, "debuggable") === true : false,
    allowBackup: applicationNode ? attrBool(applicationNode, "allowBackup") : null,
    usesCleartextTraffic: applicationNode ? attrBool(applicationNode, "usesCleartextTraffic") : null,
    networkSecurityConfig: applicationNode ? attr(applicationNode, "networkSecurityConfig") : null,
    hasBackupRules: applicationNode
      ? Boolean(attr(applicationNode, "fullBackupContent") ?? attr(applicationNode, "dataExtractionRules"))
      : false,
    supportsRtl: applicationNode ? attrBool(applicationNode, "supportsRtl") : null,
    permissions: findElements(manifestNode, "uses-permission")
      .concat(findElements(manifestNode, "uses-permission-sdk-23"))
      .map((node) => ({
        name: attr(node, "name") ?? "",
        maxSdkVersion: attrInt(node, "maxSdkVersion"),
      }))
      .filter((permission) => permission.name.length > 0),
    declaredPermissions: findElements(manifestNode, "permission")
      .map((node) => attr(node, "name") ?? "")
      .filter(Boolean),
    features: findElements(manifestNode, "uses-feature")
      .map((node) => ({
        name: attr(node, "name") ?? "",
        required: attrBool(node, "required") !== false,
      }))
      .filter((feature) => feature.name.length > 0),
    metaData: findElements(manifestNode, "meta-data")
      .map((node) => ({ name: attr(node, "name") ?? "", value: attr(node, "value") ?? "" }))
      .filter((entry) => entry.name.length > 0),
    usesLibraries: findElements(manifestNode, "uses-library")
      .map((node) => attr(node, "name") ?? "")
      .filter(Boolean),
    components,
    parsed: true,
    parseError: null,
  };
}

function buildComponent(type: ComponentInfo["type"], node: AxmlNode): ComponentInfo {
  const intentFilters: IntentFilterInfo[] = findElements(node, "intent-filter").map((filter) => ({
    actions: findElements(filter, "action").map((entry) => attr(entry, "name") ?? ""),
    categories: findElements(filter, "category").map((entry) => attr(entry, "name") ?? ""),
    dataSchemes: findElements(filter, "data")
      .map((entry) => attr(entry, "scheme") ?? "")
      .filter(Boolean),
    dataHosts: findElements(filter, "data")
      .map((entry) => attr(entry, "host") ?? "")
      .filter(Boolean),
    autoVerify: attrBool(filter, "autoVerify") === true,
  }));

  const explicitExported = attrBool(node, "exported");
  // Implicit default: a component with an intent filter was exported by
  // default before Android 12; after that the attribute is mandatory.
  const exported = explicitExported ?? intentFilters.length > 0;

  const extra: Record<string, string> = {};
  for (const key of ["authorities", "grantUriPermissions", "process", "launchMode", "taskAffinity"]) {
    const value = attr(node, key);
    if (value !== null) extra[key] = value;
  }

  const notes: string[] = [];
  if (explicitExported === null && intentFilters.length > 0) {
    notes.push("android:exported is not declared; treated as exported because intent filters are present.");
  }
  if (type === "provider" && exported && extra["grantUriPermissions"] === "true") {
    notes.push("Provider grants URI permissions to other apps.");
  }

  return {
    type,
    name: attr(node, "name") ?? "(unnamed)",
    exported,
    exportedExplicit: explicitExported !== null,
    permission: attr(node, "permission"),
    intentFilters,
    enabled: attrBool(node, "enabled") !== false,
    extra,
    notes,
  };
}