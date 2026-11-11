#!/bin/sh
# Build vulnwatch without installing any toolchain: everything runs in containers
# (podman or docker). Results land in ./dist.
#
#   ./build.sh            the server with the web UI built in   -> dist/vulnwatch
#   ./build.sh android    the Android app                       -> dist/vulnwatch.apk
#   ./build.sh test       unit tests and UI type checks
#
# Android options (environment):
#   VULNWATCH_ANDROID_TARGETS   ABIs to include, default "aarch64 armv7" (also: x86_64 i686)
#   VULNWATCH_KEYSTORE          keystore to sign with (default: one is created at
#                               ui/src-tauri/android/release.jks; keep it to be able to update the app)
#   VULNWATCH_KEYSTORE_PASS     its password (default "vulnwatch")
set -eu
cd "$(dirname "$0")"

if command -v podman >/dev/null 2>&1; then C=podman; elif command -v docker >/dev/null 2>&1; then C=docker; else
  echo "podman or docker is needed" >&2; exit 1
fi
RUN="$C run --rm --network host --security-opt label=disable -v $PWD:/src -v vulnwatch-cargo:/usr/local/cargo/registry"
mkdir -p dist

ui() {
  $RUN -v vulnwatch-npm:/root/.npm -w /src/ui docker.io/library/node:24-alpine \
    sh -c "npm ci --no-audit --no-fund && npm run check && npm run build"
}

case "${1:-server}" in
  server)
    ui
    $RUN -w /src docker.io/library/rust:1-slim-bookworm cargo build --release -p vulnwatch-server
    cp target/release/vulnwatch dist/vulnwatch
    echo "Built dist/vulnwatch — run it and open the link it prints."
    ;;
  test)
    ui
    $RUN -w /src docker.io/library/rust:1-slim-bookworm cargo test --workspace
    ;;
  android)
    $C build -q -t vulnwatch-android -f tools/android.Containerfile tools
    KS="${VULNWATCH_KEYSTORE:-ui/src-tauri/android/release.jks}"
    $RUN -v vulnwatch-npm:/root/.npm -v vulnwatch-gradle:/root/.gradle -w /src/ui \
      -e TARGETS="${VULNWATCH_ANDROID_TARGETS:-aarch64 armv7}" \
      -e KS="/src/$KS" -e KS_PASS="${VULNWATCH_KEYSTORE_PASS:-vulnwatch}" \
      vulnwatch-android sh -eu -c '
        npm ci --no-audit --no-fund
        [ -d src-tauri/gen/android ] || npx tauri android init --ci
        npx tauri icon public/icon.svg > /dev/null
        node src-tauri/android/overlay.mjs
        npx tauri android build --apk --ci --target $TARGETS
        [ -f "$KS" ] || keytool -genkeypair -keystore "$KS" -storepass "$KS_PASS" -alias vulnwatch \
          -keyalg RSA -keysize 3072 -validity 10000 -dname "CN=vulnwatch" 2> /dev/null
        BT=$(ls -d $ANDROID_HOME/build-tools/* | tail -1)
        APK=$(ls src-tauri/gen/android/app/build/outputs/apk/universal/release/*.apk | head -1)
        $BT/zipalign -f -p 4 "$APK" /tmp/aligned.apk
        $BT/apksigner sign --ks "$KS" --ks-pass "pass:$KS_PASS" --out /src/dist/vulnwatch.apk /tmp/aligned.apk
        rm -f /src/dist/vulnwatch.apk.idsig
      '
    echo "Built dist/vulnwatch.apk — copy it to the phone and open it to install."
    ;;
  *)
    sed -n "2,13p" "$0" | sed "s/^# \{0,1\}//"; exit 1 ;;
esac
