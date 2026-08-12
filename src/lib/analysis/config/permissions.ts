/**
 * Permission catalogue.
 *
 * Categories follow the publicly documented Android protection levels. They
 * are data, not logic: update this table as Android evolves without touching
 * the analyzers.
 */

import type { PermissionInfo, Severity } from "../types";

export interface PermissionRule {
  category: PermissionInfo["category"];
  group: string;
  whyItMatters: string;
  commonlyExpected: boolean;
  severityHint: Severity;
}

export const PERMISSION_CATALOG: Record<string, PermissionRule> = {
  "android.permission.CAMERA": {
    category: "DANGEROUS",
    group: "Camera",
    whyItMatters: "Grants access to camera hardware, enabling photo/video capture and live preview frames.",
    commonlyExpected: false,
    severityHint: "MEDIUM",
  },
  "android.permission.RECORD_AUDIO": {
    category: "DANGEROUS",
    group: "Microphone",
    whyItMatters: "Allows capturing audio from the device microphone.",
    commonlyExpected: false,
    severityHint: "MEDIUM",
  },
  "android.permission.ACCESS_FINE_LOCATION": {
    category: "DANGEROUS",
    group: "Location",
    whyItMatters: "Provides precise location, typically GPS-grade, which is high-sensitivity personal data.",
    commonlyExpected: false,
    severityHint: "MEDIUM",
  },
  "android.permission.ACCESS_COARSE_LOCATION": {
    category: "DANGEROUS",
    group: "Location",
    whyItMatters: "Provides approximate location derived from network sources.",
    commonlyExpected: false,
    severityHint: "LOW",
  },
  "android.permission.ACCESS_BACKGROUND_LOCATION": {
    category: "SPECIAL",
    group: "Location",
    whyItMatters: "Allows location access while the app is not in the foreground; subject to extra store review.",
    commonlyExpected: false,
    severityHint: "HIGH",
  },
  "android.permission.READ_CONTACTS": {
    category: "DANGEROUS",
    group: "Contacts",
    whyItMatters: "Reads the user's address book, including third parties who never used the app.",
    commonlyExpected: false,
    severityHint: "MEDIUM",
  },
  "android.permission.WRITE_CONTACTS": {
    category: "DANGEROUS",
    group: "Contacts",
    whyItMatters: "Modifies the user's address book.",
    commonlyExpected: false,
    severityHint: "MEDIUM",
  },
  "android.permission.READ_SMS": {
    category: "DANGEROUS",
    group: "SMS",
    whyItMatters: "Reads SMS content, which frequently carries one-time passcodes.",
    commonlyExpected: false,
    severityHint: "HIGH",
  },
  "android.permission.RECEIVE_SMS": {
    category: "DANGEROUS",
    group: "SMS",
    whyItMatters: "Receives incoming SMS broadcasts.",
    commonlyExpected: false,
    severityHint: "HIGH",
  },
  "android.permission.SEND_SMS": {
    category: "DANGEROUS",
    group: "SMS",
    whyItMatters: "Sends SMS messages, which can incur cost for the user.",
    commonlyExpected: false,
    severityHint: "HIGH",
  },
  "android.permission.READ_PHONE_STATE": {
    category: "DANGEROUS",
    group: "Phone",
    whyItMatters: "Exposes telephony state and, on older platforms, device identifiers.",
    commonlyExpected: false,
    severityHint: "MEDIUM",
  },
  "android.permission.CALL_PHONE": {
    category: "DANGEROUS",
    group: "Phone",
    whyItMatters: "Initiates calls without the dialer confirmation step.",
    commonlyExpected: false,
    severityHint: "MEDIUM",
  },
  "android.permission.READ_EXTERNAL_STORAGE": {
    category: "DANGEROUS",
    group: "Storage",
    whyItMatters: "Broad read access to shared storage on platforms before scoped storage enforcement.",
    commonlyExpected: false,
    severityHint: "MEDIUM",
  },
  "android.permission.WRITE_EXTERNAL_STORAGE": {
    category: "DANGEROUS",
    group: "Storage",
    whyItMatters: "Broad write access to shared storage on older platforms.",
    commonlyExpected: false,
    severityHint: "MEDIUM",
  },
  "android.permission.MANAGE_EXTERNAL_STORAGE": {
    category: "SPECIAL",
    group: "Storage",
    whyItMatters: "All-files access. Requires a store policy declaration and is rarely justified.",
    commonlyExpected: false,
    severityHint: "HIGH",
  },
  "android.permission.READ_MEDIA_IMAGES": {
    category: "DANGEROUS",
    group: "Media",
    whyItMatters: "Scoped read access to the user's image collection.",
    commonlyExpected: false,
    severityHint: "LOW",
  },
  "android.permission.READ_MEDIA_VIDEO": {
    category: "DANGEROUS",
    group: "Media",
    whyItMatters: "Scoped read access to the user's video collection.",
    commonlyExpected: false,
    severityHint: "LOW",
  },
  "android.permission.READ_MEDIA_AUDIO": {
    category: "DANGEROUS",
    group: "Media",
    whyItMatters: "Scoped read access to the user's audio collection.",
    commonlyExpected: false,
    severityHint: "LOW",
  },
  "android.permission.POST_NOTIFICATIONS": {
    category: "DANGEROUS",
    group: "Notifications",
    whyItMatters: "Runtime notification permission introduced in Android 13.",
    commonlyExpected: true,
    severityHint: "INFO",
  },
  "android.permission.BLUETOOTH_SCAN": {
    category: "DANGEROUS",
    group: "Bluetooth",
    whyItMatters: "Scanning for nearby devices can be used to infer location.",
    commonlyExpected: false,
    severityHint: "MEDIUM",
  },
  "android.permission.BLUETOOTH_CONNECT": {
    category: "DANGEROUS",
    group: "Bluetooth",
    whyItMatters: "Connects to paired Bluetooth devices.",
    commonlyExpected: false,
    severityHint: "LOW",
  },
  "android.permission.BLUETOOTH": {
    category: "NORMAL",
    group: "Bluetooth",
    whyItMatters: "Legacy Bluetooth permission for platforms before Android 12.",
    commonlyExpected: false,
    severityHint: "INFO",
  },
  "android.permission.BLUETOOTH_ADMIN": {
    category: "NORMAL",
    group: "Bluetooth",
    whyItMatters: "Legacy permission to discover and pair devices.",
    commonlyExpected: false,
    severityHint: "INFO",
  },
  "android.permission.NFC": {
    category: "NORMAL",
    group: "NFC",
    whyItMatters: "Enables near-field communication transactions.",
    commonlyExpected: false,
    severityHint: "INFO",
  },
  "android.permission.INTERNET": {
    category: "NORMAL",
    group: "Network",
    whyItMatters: "Allows arbitrary network access. Expected in almost every modern app.",
    commonlyExpected: true,
    severityHint: "INFO",
  },
  "android.permission.ACCESS_NETWORK_STATE": {
    category: "NORMAL",
    group: "Network",
    whyItMatters: "Reads connectivity state for retry and offline handling.",
    commonlyExpected: true,
    severityHint: "INFO",
  },
  "android.permission.ACCESS_WIFI_STATE": {
    category: "NORMAL",
    group: "Network",
    whyItMatters: "Reads Wi-Fi state; historically used for device fingerprinting.",
    commonlyExpected: false,
    severityHint: "LOW",
  },
  "android.permission.WAKE_LOCK": {
    category: "NORMAL",
    group: "System",
    whyItMatters: "Keeps the CPU awake; can affect battery life.",
    commonlyExpected: true,
    severityHint: "INFO",
  },
  "android.permission.VIBRATE": {
    category: "NORMAL",
    group: "System",
    whyItMatters: "Controls the vibrator; low risk.",
    commonlyExpected: true,
    severityHint: "INFO",
  },
  "android.permission.FOREGROUND_SERVICE": {
    category: "NORMAL",
    group: "System",
    whyItMatters: "Required to run user-visible foreground services.",
    commonlyExpected: true,
    severityHint: "INFO",
  },
  "android.permission.RECEIVE_BOOT_COMPLETED": {
    category: "NORMAL",
    group: "System",
    whyItMatters: "Allows work to start at device boot, affecting startup cost and background behaviour.",
    commonlyExpected: false,
    severityHint: "LOW",
  },
  "android.permission.SYSTEM_ALERT_WINDOW": {
    category: "SPECIAL",
    group: "System",
    whyItMatters: "Draws over other apps. Frequently abused for overlay attacks; requires explicit user grant.",
    commonlyExpected: false,
    severityHint: "HIGH",
  },
  "android.permission.REQUEST_INSTALL_PACKAGES": {
    category: "SPECIAL",
    group: "System",
    whyItMatters: "Allows prompting the user to install other APKs, a common sideloading vector.",
    commonlyExpected: false,
    severityHint: "HIGH",
  },
  "android.permission.QUERY_ALL_PACKAGES": {
    category: "SPECIAL",
    group: "Privacy",
    whyItMatters: "Reveals the full list of installed apps; store policy restricts legitimate use cases.",
    commonlyExpected: false,
    severityHint: "MEDIUM",
  },
  "com.google.android.gms.permission.AD_ID": {
    category: "NORMAL",
    group: "Privacy",
    whyItMatters: "Access to the advertising identifier, relevant to privacy disclosures.",
    commonlyExpected: false,
    severityHint: "LOW",
  },
  "android.permission.BODY_SENSORS": {
    category: "DANGEROUS",
    group: "Sensors",
    whyItMatters: "Reads body sensor data such as heart rate.",
    commonlyExpected: false,
    severityHint: "MEDIUM",
  },
  "android.permission.ACTIVITY_RECOGNITION": {
    category: "DANGEROUS",
    group: "Sensors",
    whyItMatters: "Infers physical activity such as walking or driving.",
    commonlyExpected: false,
    severityHint: "LOW",
  },
};

/** Heuristic fallback for permissions that are not in the catalogue. */
export function classifyUnknownPermission(name: string): PermissionRule {
  const isAndroid = name.startsWith("android.permission.");
  return {
    category: "UNKNOWN",
    group: isAndroid ? "Platform (uncatalogued)" : "Vendor / custom",
    whyItMatters: isAndroid
      ? "Platform permission not present in the configured catalogue. Review against current Android documentation."
      : "Custom or third-party permission. Its protection level is defined by the declaring app and cannot be resolved from this APK alone.",
    commonlyExpected: false,
    severityHint: "INFO",
  };
}