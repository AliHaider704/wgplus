#!/usr/bin/env bash
set -euo pipefail

# CI helper to build app/libs/wgbridge.aar on Linux runners (because /app/libs/*.aar is git-ignored).
# Defaults to android/amd64 (x86_64) for KVM emulators; pass e.g. "android/arm64,android/arm" for release/FTL.

TARGETS="${1:-android/amd64}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GO_DIR="$REPO_ROOT/wgbridge-go"
OUTPUT_AAR="$REPO_ROOT/app/libs/wgbridge.aar"
OUTPUT_SOURCES_JAR="$REPO_ROOT/app/libs/wgbridge-sources.jar"

export PATH="$(go env GOPATH)/bin:${PATH}"

if ! command -v gomobile >/dev/null 2>&1; then
  echo "[1/4] Installing gomobile..."
  go install golang.org/x/mobile/cmd/gomobile@latest
fi

echo "[2/4] Initializing gomobile and building wgbridge.aar (targets=${TARGETS})..."
gomobile init

mkdir -p "$(dirname "$OUTPUT_AAR")"
pushd "$GO_DIR" >/dev/null
go test -v ./...
gomobile bind "-target=${TARGETS}" -androidapi 21 -trimpath "-ldflags=-s -w -buildid=" -o "$OUTPUT_AAR" .
popd >/dev/null

echo "[3/4] Applying LSPatch InMemoryDexClassLoader guard to go/Seq.class..."
WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

AAR_DIR="$WORKDIR/aar"
SRC_DIR="$WORKDIR/src"
CLS_DIR="$WORKDIR/cls"
mkdir -p "$AAR_DIR" "$SRC_DIR" "$CLS_DIR"

(cd "$AAR_DIR" && jar xf "$OUTPUT_AAR")
(cd "$SRC_DIR" && jar xf "$OUTPUT_SOURCES_JAR")

SEQ_JAVA="$SRC_DIR/go/Seq.java"
python3 - "$SEQ_JAVA" <<'PYEOF'
import pathlib, sys
p = pathlib.Path(sys.argv[1])
src = p.read_text(encoding="utf-8")
needle = 'System.loadLibrary("gojni");'
repl = 'try { System.loadLibrary("gojni"); } catch (UnsatisfiedLinkError ignored) { /* Preloaded via System.load in NativeBridgeLoader */ }'
if needle not in src:
    raise SystemExit("Expected System.loadLibrary(\"gojni\") not found in generated go/Seq.java")
p.write_text(src.replace(needle, repl), encoding="utf-8")
PYEOF

(cd "$CLS_DIR" && jar xf "$AAR_DIR/classes.jar")

ANDROID_HOME_EFF="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-}}"
ANDROID_JAR="$(find "$ANDROID_HOME_EFF/platforms" -maxdepth 2 -name android.jar | sort | tail -n 1)"
if [ -z "$ANDROID_JAR" ] || [ ! -f "$ANDROID_JAR" ]; then
  echo "android.jar not found under $ANDROID_HOME_EFF/platforms" >&2
  exit 1
fi

javac -source 8 -target 8 -bootclasspath "$ANDROID_JAR" -cp "$CLS_DIR" -d "$CLS_DIR" "$SEQ_JAVA"

rm -f "$AAR_DIR/classes.jar"
jar cf "$AAR_DIR/classes.jar" -C "$CLS_DIR" .

rm -f "$OUTPUT_SOURCES_JAR"
(cd "$SRC_DIR" && jar cf "$OUTPUT_SOURCES_JAR" .)

rm -f "$OUTPUT_AAR"
jar cf "$OUTPUT_AAR" -C "$AAR_DIR" .

echo "[4/4] Verifying exported Wgbridge methods and go.Seq catch table..."
javap -cp "$AAR_DIR/classes.jar" wgbridge.Wgbridge
if ! javap -c -cp "$AAR_DIR/classes.jar" go.Seq | grep -q "java/lang/UnsatisfiedLinkError"; then
  echo "Verification failed: UnsatisfiedLinkError catch table missing in go.Seq.<clinit>" >&2
  exit 1
fi

echo "SUCCESS: CI x86_64 wgbridge.aar built and verified at $OUTPUT_AAR"
