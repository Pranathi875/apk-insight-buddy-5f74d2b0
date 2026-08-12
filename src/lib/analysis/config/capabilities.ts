/**
 * Capability signature configuration.
 *
 * Every capability is described purely as data: manifest permissions,
 * declared hardware features, class/package indicators, string indicators
 * and native library names. Detection logic lives in capabilities.ts and is
 * generic across all entries here.
 */

export interface CapabilitySignature {
  id: string;
  label: string;
  description: string;
  /** Weighted evidence sources. Total strength decides state + confidence. */
  permissions?: { name: string; weight: number }[];
  features?: { name: string; weight: number }[];
  /** Matched against DEX class descriptors (case-insensitive substring). */
  classIndicators?: { token: string; weight: number; note?: string }[];
  /** Matched against DEX string pool entries. */
  stringIndicators?: { token: string; weight: number; note?: string }[];
  /** Matched against native library file names. */
  nativeIndicators?: { token: string; weight: number }[];
  /** Matched against APK entry names (assets, resources, models). */
  entryIndicators?: { token: string; weight: number }[];
  /** Matched against manifest <meta-data> names. */
  metaDataIndicators?: { token: string; weight: number }[];
  /** >= detectedAt means DETECTED, >= uncertainAt means UNCERTAIN. */
  detectedAt: number;
  uncertainAt: number;
}

export const CAPABILITY_SIGNATURES: CapabilitySignature[] = [
  {
    id: "camera",
    label: "Camera",
    description: "Captures still images or video, or renders a live camera preview.",
    permissions: [{ name: "android.permission.CAMERA", weight: 4 }],
    features: [
      { name: "android.hardware.camera", weight: 2 },
      { name: "android.hardware.camera.any", weight: 2 },
      { name: "android.hardware.camera.autofocus", weight: 1 },
    ],
    classIndicators: [
      { token: "android.hardware.camera2", weight: 3, note: "Camera2 API reference" },
      { token: "androidx.camera", weight: 3, note: "CameraX reference" },
      { token: "android.hardware.camera", weight: 2, note: "Legacy Camera API reference" },
    ],
    stringIndicators: [{ token: "camera2", weight: 1 }],
    detectedAt: 5,
    uncertainAt: 2,
  },
  {
    id: "qr_barcode",
    label: "QR / Barcode scanning",
    description:
      "Decodes 1D/2D optical codes. Detected generically from public scanning libraries, ML APIs and code-related identifiers.",
    classIndicators: [
      { token: "com.google.zxing", weight: 4, note: "ZXing barcode library" },
      { token: "journeyapps.barcodescanner", weight: 4, note: "ZXing Android Embedded" },
      { token: "com.google.mlkit.vision.barcode", weight: 4, note: "ML Kit barcode scanning" },
      { token: "com.google.android.gms.vision.barcode", weight: 3, note: "Legacy Play Services vision barcode" },
      { token: "boofcv", weight: 2, note: "BoofCV computer-vision library" },
      { token: "me.dm7.barcodescanner", weight: 3, note: "Third-party barcode scanner view" },
      { token: "budiyev.android.codescanner", weight: 3, note: "Code scanner view" },
    ],
    stringIndicators: [
      { token: "qr_code", weight: 2 },
      { token: "qrcode", weight: 2 },
      { token: "barcode", weight: 2 },
      { token: "datamatrix", weight: 1 },
      { token: "ean_13", weight: 1 },
      { token: "aztec", weight: 1 },
    ],
    nativeIndicators: [
      { token: "barhopper", weight: 3 },
      { token: "zxing", weight: 3 },
    ],
    entryIndicators: [{ token: "barcode", weight: 1 }],
    metaDataIndicators: [{ token: "vision.barcode", weight: 3 }],
    detectedAt: 4,
    uncertainAt: 2,
  },
  {
    id: "location",
    label: "Location",
    description: "Reads device position from GPS, network or fused providers.",
    permissions: [
      { name: "android.permission.ACCESS_FINE_LOCATION", weight: 4 },
      { name: "android.permission.ACCESS_COARSE_LOCATION", weight: 3 },
      { name: "android.permission.ACCESS_BACKGROUND_LOCATION", weight: 2 },
    ],
    features: [{ name: "android.hardware.location.gps", weight: 2 }],
    classIndicators: [
      { token: "android.location.locationmanager", weight: 3 },
      { token: "gms.location.fusedlocation", weight: 3 },
    ],
    detectedAt: 4,
    uncertainAt: 2,
  },
  {
    id: "bluetooth",
    label: "Bluetooth",
    description: "Communicates with Bluetooth or BLE peripherals.",
    permissions: [
      { name: "android.permission.BLUETOOTH_CONNECT", weight: 3 },
      { name: "android.permission.BLUETOOTH_SCAN", weight: 3 },
      { name: "android.permission.BLUETOOTH", weight: 2 },
      { name: "android.permission.BLUETOOTH_ADMIN", weight: 2 },
    ],
    features: [
      { name: "android.hardware.bluetooth", weight: 2 },
      { name: "android.hardware.bluetooth_le", weight: 2 },
    ],
    classIndicators: [{ token: "android.bluetooth", weight: 3 }],
    detectedAt: 4,
    uncertainAt: 2,
  },
  {
    id: "nfc",
    label: "NFC",
    description: "Reads or emulates near-field communication tags.",
    permissions: [{ name: "android.permission.NFC", weight: 4 }],
    features: [{ name: "android.hardware.nfc", weight: 2 }],
    classIndicators: [{ token: "android.nfc", weight: 3 }],
    detectedAt: 4,
    uncertainAt: 2,
  },
  {
    id: "webview",
    label: "WebView / embedded browser",
    description: "Renders web content inside the app process.",
    classIndicators: [
      { token: "android.webkit.webview", weight: 4 },
      { token: "androidx.webkit", weight: 2 },
      { token: "org.chromium", weight: 2 },
    ],
    stringIndicators: [
      { token: "setjavascriptenabled", weight: 2 },
      { token: "addjavascriptinterface", weight: 3 },
    ],
    detectedAt: 4,
    uncertainAt: 2,
  },
  {
    id: "network",
    label: "Network access",
    description: "Performs HTTP or socket communication.",
    permissions: [{ name: "android.permission.INTERNET", weight: 4 }],
    classIndicators: [
      { token: "okhttp3", weight: 2 },
      { token: "java.net.httpurlconnection", weight: 2 },
      { token: "retrofit2", weight: 2 },
    ],
    detectedAt: 4,
    uncertainAt: 2,
  },
  {
    id: "microphone",
    label: "Microphone / audio capture",
    description: "Records audio input.",
    permissions: [{ name: "android.permission.RECORD_AUDIO", weight: 4 }],
    features: [{ name: "android.hardware.microphone", weight: 2 }],
    classIndicators: [
      { token: "android.media.audiorecord", weight: 3 },
      { token: "android.media.mediarecorder", weight: 2 },
    ],
    detectedAt: 4,
    uncertainAt: 2,
  },
  {
    id: "sensors",
    label: "Motion / body sensors",
    description: "Reads accelerometer, gyroscope or body sensor data.",
    permissions: [
      { name: "android.permission.BODY_SENSORS", weight: 4 },
      { name: "android.permission.ACTIVITY_RECOGNITION", weight: 3 },
    ],
    features: [
      { name: "android.hardware.sensor.accelerometer", weight: 2 },
      { name: "android.hardware.sensor.gyroscope", weight: 2 },
    ],
    classIndicators: [
      { token: "android.hardware.sensormanager", weight: 3 },
      { token: "android.hardware.sensorevent", weight: 2 },
    ],
    detectedAt: 4,
    uncertainAt: 2,
  },
  {
    id: "storage_media",
    label: "Storage / media access",
    description: "Reads or writes user documents and media collections.",
    permissions: [
      { name: "android.permission.READ_EXTERNAL_STORAGE", weight: 3 },
      { name: "android.permission.WRITE_EXTERNAL_STORAGE", weight: 3 },
      { name: "android.permission.MANAGE_EXTERNAL_STORAGE", weight: 4 },
      { name: "android.permission.READ_MEDIA_IMAGES", weight: 3 },
      { name: "android.permission.READ_MEDIA_VIDEO", weight: 3 },
      { name: "android.permission.READ_MEDIA_AUDIO", weight: 3 },
    ],
    classIndicators: [
      { token: "android.provider.mediastore", weight: 2 },
      { token: "androidx.documentfile", weight: 2 },
    ],
    detectedAt: 4,
    uncertainAt: 2,
  },
];

/** Every token the DEX scanner should retain for capability matching. */
export function capabilityTokens(): string[] {
  const tokens: string[] = [];
  for (const signature of CAPABILITY_SIGNATURES) {
    signature.classIndicators?.forEach((indicator) => tokens.push(indicator.token));
    signature.stringIndicators?.forEach((indicator) => tokens.push(indicator.token));
  }
  return tokens;
}