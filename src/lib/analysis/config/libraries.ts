/**
 * Third-party library signatures. Data only; the matcher is generic.
 */

export interface LibrarySignature {
  id: string;
  name: string;
  category: string;
  /** Package prefixes in class descriptors (dotted, lowercase). */
  packages: string[];
  /** Optional entry-name markers, e.g. bundled properties files. */
  entries?: string[];
  /** Optional regex applied to matched DEX strings to recover a version. */
  versionPatterns?: string[];
}

export const LIBRARY_SIGNATURES: LibrarySignature[] = [
  {
    id: "okhttp",
    name: "OkHttp",
    category: "Networking",
    packages: ["okhttp3.", "okio."],
    versionPatterns: ["okhttp/([0-9]+\\.[0-9]+(?:\\.[0-9]+)?)"],
  },
  {
    id: "retrofit",
    name: "Retrofit",
    category: "Networking",
    packages: ["retrofit2."],
  },
  {
    id: "volley",
    name: "Volley",
    category: "Networking",
    packages: ["com.android.volley"],
  },
  {
    id: "firebase",
    name: "Firebase",
    category: "Backend / analytics",
    packages: ["com.google.firebase"],
    entries: ["firebase-common.properties"],
  },
  {
    id: "play_services",
    name: "Google Play services",
    category: "Platform services",
    packages: ["com.google.android.gms"],
  },
  {
    id: "mlkit",
    name: "Google ML Kit",
    category: "On-device ML",
    packages: ["com.google.mlkit"],
  },
  {
    id: "zxing",
    name: "ZXing",
    category: "Optical codes",
    packages: ["com.google.zxing", "com.journeyapps.barcodescanner"],
  },
  {
    id: "glide",
    name: "Glide",
    category: "Image loading",
    packages: ["com.bumptech.glide"],
  },
  {
    id: "picasso",
    name: "Picasso",
    category: "Image loading",
    packages: ["com.squareup.picasso"],
  },
  {
    id: "coil",
    name: "Coil",
    category: "Image loading",
    packages: ["coil."],
  },
  {
    id: "gson",
    name: "Gson",
    category: "Serialization",
    packages: ["com.google.gson"],
  },
  {
    id: "moshi",
    name: "Moshi",
    category: "Serialization",
    packages: ["com.squareup.moshi"],
  },
  {
    id: "kotlinx_serialization",
    name: "kotlinx.serialization",
    category: "Serialization",
    packages: ["kotlinx.serialization"],
  },
  {
    id: "kotlin_stdlib",
    name: "Kotlin stdlib / coroutines",
    category: "Language runtime",
    packages: ["kotlin.", "kotlinx.coroutines"],
  },
  {
    id: "androidx_compose",
    name: "Jetpack Compose",
    category: "UI toolkit",
    packages: ["androidx.compose"],
  },
  {
    id: "androidx_room",
    name: "Room",
    category: "Persistence",
    packages: ["androidx.room"],
  },
  {
    id: "realm",
    name: "Realm",
    category: "Persistence",
    packages: ["io.realm"],
  },
  {
    id: "dagger_hilt",
    name: "Dagger / Hilt",
    category: "Dependency injection",
    packages: ["dagger.", "dagger.hilt"],
  },
  {
    id: "rxjava",
    name: "RxJava",
    category: "Reactive",
    packages: ["io.reactivex"],
  },
  {
    id: "react_native",
    name: "React Native",
    category: "Cross-platform runtime",
    packages: ["com.facebook.react"],
  },
  {
    id: "flutter",
    name: "Flutter",
    category: "Cross-platform runtime",
    packages: ["io.flutter"],
    entries: ["flutter_assets/"],
  },
  {
    id: "cordova",
    name: "Apache Cordova",
    category: "Cross-platform runtime",
    packages: ["org.apache.cordova"],
  },
  {
    id: "unity",
    name: "Unity",
    category: "Game engine",
    packages: ["com.unity3d"],
  },
  {
    id: "exoplayer",
    name: "ExoPlayer / Media3",
    category: "Media",
    packages: ["com.google.android.exoplayer2", "androidx.media3"],
  },
  {
    id: "crashlytics",
    name: "Crashlytics",
    category: "Diagnostics",
    packages: ["com.google.firebase.crashlytics", "com.crashlytics"],
  },
  {
    id: "sentry",
    name: "Sentry",
    category: "Diagnostics",
    packages: ["io.sentry"],
  },
  {
    id: "facebook_sdk",
    name: "Facebook SDK",
    category: "Social / analytics",
    packages: ["com.facebook.appevents", "com.facebook.login"],
  },
  {
    id: "adjust",
    name: "Adjust",
    category: "Attribution",
    packages: ["com.adjust.sdk"],
  },
  {
    id: "appsflyer",
    name: "AppsFlyer",
    category: "Attribution",
    packages: ["com.appsflyer"],
  },
  {
    id: "stripe",
    name: "Stripe",
    category: "Payments",
    packages: ["com.stripe.android"],
  },
  {
    id: "sqlcipher",
    name: "SQLCipher",
    category: "Cryptography",
    packages: ["net.sqlcipher"],
  },
  {
    id: "bouncycastle",
    name: "Bouncy Castle / Conscrypt",
    category: "Cryptography",
    packages: ["org.bouncycastle", "org.conscrypt"],
  },
];

export function libraryTokens(): string[] {
  return LIBRARY_SIGNATURES.flatMap((signature) => signature.packages);
}