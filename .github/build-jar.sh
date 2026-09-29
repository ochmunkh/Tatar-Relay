#!/usr/bin/env bash
# Build the Tatar Relay Burp extension jar on Linux CI (JDK 17, no Gradle).
# Mirrors burp/build.ps1: compile against Montoya (compile-only) + bundle Gson.
set -euo pipefail
cd "$(dirname "$0")/../burp"

MONTOYA=2023.12.1
GSON=2.10.1
mkdir -p lib out build/libs

[ -f lib/montoya-api.jar ] || curl -fsSL -o lib/montoya-api.jar \
  "https://repo1.maven.org/maven2/net/portswigger/burp/extensions/montoya-api/${MONTOYA}/montoya-api-${MONTOYA}.jar"
[ -f lib/gson.jar ] || curl -fsSL -o lib/gson.jar \
  "https://repo1.maven.org/maven2/com/google/code/gson/gson/${GSON}/gson-${GSON}.jar"

rm -rf out/* 
javac --release 17 -cp "lib/montoya-api.jar:lib/gson.jar" -d out \
  $(find src/main/java/relay -name '*.java')

# bundle Gson into the fat jar
( cd out && jar xf ../lib/gson.jar )
rm -rf out/META-INF out/module-info.class

rm -f build/libs/tatar-relay-burp.jar
jar cf build/libs/tatar-relay-burp.jar -C out .
echo "OK -> burp/build/libs/tatar-relay-burp.jar ($(du -k build/libs/tatar-relay-burp.jar | cut -f1) KB)"
