#!/usr/bin/env bash
# Does the Burp extension actually load?
#
# Burp itself cannot answer that here. Burp Community is GUI-only -- loading an
# extension and reading back "it registered" is a Professional/Enterprise
# feature, with no supported headless path -- so CI checks the part that can be
# checked without Burp: that initialize() runs to completion against a
# well-behaved MontoyaApi and registers what it promises.
#
# Run AFTER .github/build-jar.sh, which downloads burp/lib/*.jar.
set -euo pipefail
cd "$(dirname "$0")/../burp"

MONTOYA=2023.12.1
GSON=2.10.1
mkdir -p lib test-out

[ -f lib/montoya-api.jar ] || curl -fsSL -o lib/montoya-api.jar \
  "https://repo1.maven.org/maven2/net/portswigger/burp/extensions/montoya-api/${MONTOYA}/montoya-api-${MONTOYA}.jar"
[ -f lib/gson.jar ] || curl -fsSL -o lib/gson.jar \
  "https://repo1.maven.org/maven2/com/google/code/gson/gson/${GSON}/gson-${GSON}.jar"

CP="lib/montoya-api.jar:lib/gson.jar"

rm -rf test-out/*
# The test sources are compiled to a SEPARATE directory and are never fed to
# build-jar.sh, so nothing here can reach the shipped jar.
javac --release 17 -cp "$CP" -d test-out \
  $(find src/main/java src/test/java -name '*.java')

java -cp "test-out:$CP" relay.ExtensionLoadTest
