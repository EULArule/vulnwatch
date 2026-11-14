// Applied on top of the Android project that `tauri android init` generates (gen/android):
// our Kotlin sources, the notification icon, the manifest entries for background work, and the
// WorkManager dependency. Safe to run repeatedly.
import { cpSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const app = join(here, '..', 'gen', 'android', 'app');
const MARK = 'vulnwatch-overlay';

const kotlin = join(app, 'src', 'main', 'java', 'app', 'vulnwatch');
mkdirSync(kotlin, { recursive: true });
for (const f of readdirSync(join(here, 'kotlin'))) cpSync(join(here, 'kotlin', f), join(kotlin, f));
cpSync(join(here, 'res'), join(app, 'src', 'main', 'res'), { recursive: true });

const manifestPath = join(app, 'src', 'main', 'AndroidManifest.xml');
let manifest = readFileSync(manifestPath, 'utf8');
if (!manifest.includes(MARK)) {
  const permissions = `    <!-- ${MARK} -->
    <uses-permission android:name="android.permission.POST_NOTIFICATIONS" />
    <uses-permission android:name="android.permission.RECEIVE_BOOT_COMPLETED" />
    <uses-permission android:name="android.permission.FOREGROUND_SERVICE" />
    <uses-permission android:name="android.permission.FOREGROUND_SERVICE_SPECIAL_USE" />
    <uses-permission android:name="android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS" />
`;
  const components = `        <service
            android:name=".WatchService"
            android:exported="false"
            android:foregroundServiceType="specialUse">
            <property
                android:name="android.app.PROPERTY_SPECIAL_USE_FGS_SUBTYPE"
                android:value="Checks public vulnerability feeds every few minutes, when the user turns on always-on alerts" />
        </service>
        <receiver android:name=".BootReceiver" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.BOOT_COMPLETED" />
                <action android:name="android.intent.action.MY_PACKAGE_REPLACED" />
            </intent-filter>
        </receiver>
`;
  if (!/^\s*<application/m.test(manifest) || !manifest.includes('</application>')) {
    throw new Error('unexpected AndroidManifest.xml layout');
  }
  manifest = manifest
    .replace(/^(\s*)<application/m, (m) => permissions + m)
    .replace(/^(\s*)<\/application>/m, (m) => components + m);
  writeFileSync(manifestPath, manifest);
}
// Added later than the block above, so it has its own check (the project may already be marked).
// Lets the "battery friendly" alarm fire on time once the user allows "Alarms & reminders".
if (!manifest.includes('SCHEDULE_EXACT_ALARM')) {
  manifest = manifest.replace(
    /^(\s*)<application/m,
    (m) => `    <uses-permission android:name="android.permission.SCHEDULE_EXACT_ALARM" />\n` + m,
  );
  writeFileSync(manifestPath, manifest);
}

const gradlePath = join(app, 'build.gradle.kts');
let gradle = readFileSync(gradlePath, 'utf8');
if (!gradle.includes(MARK)) {
  gradle += `
// ${MARK}
dependencies {
    implementation("androidx.work:work-runtime-ktx:2.10.0")
    implementation("androidx.core:core-ktx:1.13.1")
}
`;
  writeFileSync(gradlePath, gradle);
}
// The release build is shrunk by R8. Keep what is only reached by reflection or from Rust:
// WorkManager's Room database and workers, and our own classes (JNI, manifest components).
writeFileSync(
  join(app, 'proguard-vulnwatch.pro'),
  `-keep class app.vulnwatch.** { *; }
-keep class * extends androidx.room.RoomDatabase { <init>(...); }
-keep class androidx.work.impl.** { *; }
-keep class * extends androidx.work.ListenableWorker { <init>(...); }
-keep class * extends androidx.startup.Initializer { <init>(...); }
-keepattributes *Annotation*
-dontwarn androidx.work.**
`,
);
console.log('android overlay applied');
