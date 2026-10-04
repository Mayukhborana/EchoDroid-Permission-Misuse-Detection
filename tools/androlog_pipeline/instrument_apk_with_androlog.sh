#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -lt 3 ]; then
  echo "Usage: $0 <apk_path> <output_dir> <tag> [platforms_dir]" >&2
  exit 1
fi

APK_PATH=$(realpath "$1")
# OUT_DIR=$(realpath "$2")
OUT_DIR="$2"
mkdir -p "$OUT_DIR"
OUT_DIR=$(cd "$OUT_DIR" && pwd)
TAG="$3"
PLATFORMS_DIR="${4:-}"

# Resolve workspace-relative tool paths (no hardcoded user directories)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TOOLS_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"   # .../permission_misuse/tools

# Prefer env-provided paths, else fall back to common defaults
if [ -z "$PLATFORMS_DIR" ]; then
  if [ -n "${ANDROID_SDK_ROOT:-}" ] && [ -d "${ANDROID_SDK_ROOT}/platforms" ]; then
    PLATFORMS_DIR="${ANDROID_SDK_ROOT}/platforms"
  elif [ -n "${ANDROID_HOME:-}" ] && [ -d "${ANDROID_HOME}/platforms" ]; then
    PLATFORMS_DIR="${ANDROID_HOME}/platforms"
  else
    PLATFORMS_DIR="/Users/Library/Android/sdk/platforms/"
  fi
fi

JAVA_BIN="${JAVA_BIN:-java}"
ANDROLOG_JAR="${ANDROLOG_JAR:-$TOOLS_DIR/AndroLog/target/androlog-0.1-jar-with-dependencies.jar}"

mkdir -p "$OUT_DIR"

if [ ! -f "$APK_PATH" ]; then
  echo "APK not found: $APK_PATH" >&2
  exit 1
fi

if [ ! -f "$ANDROLOG_JAR" ]; then
  echo "AndroLog jar not found: $ANDROLOG_JAR" >&2
  exit 1
fi

{
  echo "APK_PATH=$APK_PATH"
  echo "OUT_DIR=$OUT_DIR"
  echo "TAG=$TAG"
  echo "PLATFORMS_DIR=$PLATFORMS_DIR"
  echo "START_TS=$(date '+%Y-%m-%d %H:%M:%S')"
} > "$OUT_DIR/run.meta"

# aapt dump badging "$APK_PATH" > "$OUT_DIR/aapt_badging.txt" 2>&1 || true
/Users/Library/Android/sdk/build-tools/36.1.0/aapt2 dump badging "$APK_PATH" > "$OUT_DIR/aapt_badging.txt" 2>&1 || true
export ANDROID_HOME="/Users/Library/Android/sdk"
export ANDROID_SDK_ROOT="/Users/Library/Android/sdk"
export PATH="/Users/Library/Android/sdk/build-tools/36.1.0:$PATH"

"$JAVA_BIN" -jar "$ANDROLOG_JAR" \
  -a "$APK_PATH" \
  -p "$PLATFORMS_DIR" \
  -l "$TAG" \
  -o "$OUT_DIR" \
  -m -cp -n > "$OUT_DIR/instrument.log" 2>&1 || true

if [ -f "$OUT_DIR/base.apk" ]; then
  aapt dump badging "$OUT_DIR/base.apk" > "$OUT_DIR/instrumented_aapt_badging.txt" 2>&1 || true
fi
if [ -f "$OUT_DIR/youtube_base.apk" ]; then
  aapt dump badging "$OUT_DIR/youtube_base.apk" > "$OUT_DIR/instrumented_aapt_badging.txt" 2>&1 || true
fi

{
  echo "END_TS=$(date '+%Y-%m-%d %H:%M:%S')"
  if grep -q "DexPrinterException\|Exception in thread" "$OUT_DIR/instrument.log" 2>/dev/null; then
    echo "STATUS=export_failed"
  else
    echo "STATUS=finished"
  fi
} >> "$OUT_DIR/run.meta"

echo "DONE:$OUT_DIR"
