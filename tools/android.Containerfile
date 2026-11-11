# Everything needed to build the Android app: Rust + Android targets, JDK, Node, Android SDK/NDK.
# Used by ./build.sh android; nothing from here ends up on your machine except the APK.
FROM docker.io/library/node:24-bookworm-slim AS node

FROM docker.io/library/rust:1-slim-bookworm
RUN apt-get update \
 && apt-get install -y --no-install-recommends openjdk-17-jdk-headless curl unzip ca-certificates git pkg-config file \
 && rm -rf /var/lib/apt/lists/*
COPY --from=node /usr/local/bin/node /usr/local/bin/node
COPY --from=node /usr/local/lib/node_modules /usr/local/lib/node_modules
RUN ln -s ../lib/node_modules/npm/bin/npm-cli.js /usr/local/bin/npm \
 && ln -s ../lib/node_modules/npm/bin/npx-cli.js /usr/local/bin/npx

ENV ANDROID_HOME=/opt/android \
    JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64
ARG CMDLINE_TOOLS=13114758
ARG NDK=27.2.12479018
RUN mkdir -p $ANDROID_HOME/cmdline-tools \
 && curl -fsSL -o /tmp/tools.zip https://dl.google.com/android/repository/commandlinetools-linux-${CMDLINE_TOOLS}_latest.zip \
 && unzip -q /tmp/tools.zip -d $ANDROID_HOME/cmdline-tools \
 && mv $ANDROID_HOME/cmdline-tools/cmdline-tools $ANDROID_HOME/cmdline-tools/latest \
 && rm /tmp/tools.zip \
 && yes | $ANDROID_HOME/cmdline-tools/latest/bin/sdkmanager --licenses > /dev/null \
 && $ANDROID_HOME/cmdline-tools/latest/bin/sdkmanager "platform-tools" "platforms;android-36" "build-tools;36.0.0" "ndk;${NDK}" > /dev/null \
 && chmod -R a+rwX $ANDROID_HOME
ENV NDK_HOME=$ANDROID_HOME/ndk/$NDK \
    PATH=$PATH:$ANDROID_HOME/platform-tools:$ANDROID_HOME/cmdline-tools/latest/bin
RUN rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android i686-linux-android
WORKDIR /src
