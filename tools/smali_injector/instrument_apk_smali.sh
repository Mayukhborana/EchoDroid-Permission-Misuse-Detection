#!/usr/bin/env bash
# =============================================================================
# instrument_apk_smali.sh
# Instruments ANY APK (including Android 14/15/16, R8/D8, obfuscated) by:
#   1. Decompiling with apktool
#   2. Injecting Log.d("TAG","METHOD=<sig>") at every method entry via smali
#   3. Recompiling with apktool
#   4. Signing with apksigner (debug keystore)
#
# Works where AndroLog/Soot FAILS (modern commercial APKs, R8 obfuscation).
#
# Usage:
#   ./instrument_apk_smali.sh <apk_path> [app_name] [log_tag]
#
# Output:
#   instrumented_app/<app_name>_smali_instrumented.apk
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$HOME/Desktop/backdoor_permission"
APKSIGNER="$HOME/Android/Sdk/build-tools/36.1.0/apksigner"
KEYSTORE="$HOME/.android/debug.keystore"
INSTR_DIR="$ROOT/instrumented_app"
WORK_BASE="$ROOT/pipeline_work"

APK_PATH="${1:-}"
APP_NAME="${2:-}"
LOG_TAG="${3:-}"

if [[ -z "$APK_PATH" ]]; then
    echo "Usage: $0 <apk_path> [app_name] [log_tag]"
    echo ""
    echo "Examples:"
    echo "  $0 /path/to/app.apk MyApp MYAPP_LOG"
    echo "  $0 /path/to/snapchat.apk Snapchat SNAPCHAT_LOG"
    exit 1
fi

APK_PATH=$(realpath "$APK_PATH")
if [[ ! -f "$APK_PATH" ]]; then
    echo "[ERR] APK not found: $APK_PATH"
    exit 1
fi

# Default app name from filename
if [[ -z "$APP_NAME" ]]; then
    APP_NAME=$(basename "$APK_PATH" .apk | sed 's/com\.\|android\.\|org\.//g' | cut -c1-30)
fi

# Default log tag from app name (uppercase, underscores, max 23 chars for logcat)
if [[ -z "$LOG_TAG" ]]; then
    LOG_TAG=$(echo "${APP_NAME^^}" | tr -cd '[:alnum:]_' | cut -c1-23)
    LOG_TAG="${LOG_TAG}_LOG"
fi

TS=$(date +%Y%m%d_%H%M%S)
WORKDIR="$WORK_BASE/${APP_NAME}_smali_${TS}"
DECODED_DIR="$WORKDIR/decoded"
RECOMPILED_APK="$WORKDIR/recompiled.apk"
ALIGNED_APK="$WORKDIR/aligned.apk"
SIGNED_APK="$WORKDIR/signed.apk"
OUT_APK="$INSTR_DIR/${APP_NAME}_smali_instrumented.apk"

mkdir -p "$WORKDIR" "$INSTR_DIR"

echo ""
echo "╔══════════════════════════════════════════════════════════╗"
echo "║          Smali Method Injector — APK Instrumenter        ║"
echo "╠══════════════════════════════════════════════════════════╣"
printf "║  App     : %-46s║\n" "$APP_NAME"
printf "║  Tag     : %-46s║\n" "$LOG_TAG"
printf "║  APK     : %-46s║\n" "$(basename "$APK_PATH")"
printf "║  WorkDir : %-46s║\n" "$WORKDIR"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""

# ── STEP 1: Decompile with apktool ───────────────────────────────────────────
echo "[1/5] Decompiling APK with apktool..."
apktool d -f "$APK_PATH" -o "$DECODED_DIR" --no-res 2>&1 | tail -5
echo "[OK]  Decompiled to: $DECODED_DIR"

# Count smali dirs (multidex has smali, smali_classes2, smali_classes3 etc.)
SMALI_DIRS=$(find "$DECODED_DIR" -maxdepth 1 -name "smali*" -type d | sort)
SMALI_COUNT=$(echo "$SMALI_DIRS" | wc -l)
echo "[OK]  Found $SMALI_COUNT smali dir(s): $(echo "$SMALI_DIRS" | xargs -I{} basename {} | tr '\n' ' ')"

# ── STEP 2: Inject METHOD= log calls into all smali dirs ─────────────────────
echo ""
echo "[2/5] Injecting METHOD= log probes into smali..."
TOTAL_INJECTED=0
for SMALI_DIR in $SMALI_DIRS; do
    echo "      Processing: $(basename "$SMALI_DIR") ..."
    RESULT=$(python3 "$SCRIPT_DIR/inject_methods.py" "$SMALI_DIR" "$LOG_TAG" 2>&1)
    echo "      $RESULT" | grep -E "Files|Methods|Err" || true
    COUNT=$(echo "$RESULT" | grep "Methods injected" | grep -oE '[0-9]+' || echo 0)
    TOTAL_INJECTED=$(( TOTAL_INJECTED + COUNT ))
done
echo "[OK]  Total methods injected: $TOTAL_INJECTED"

if [[ $TOTAL_INJECTED -eq 0 ]]; then
    echo "[WARN] No methods were injected — APK may be empty or smali not found"
fi

# ── STEP 3: Recompile with apktool ───────────────────────────────────────────
echo ""
echo "[3/5] Recompiling instrumented smali..."
apktool b "$DECODED_DIR" -o "$RECOMPILED_APK" 2>&1 | tail -8
if [[ ! -f "$RECOMPILED_APK" ]]; then
    echo "[ERR] Recompilation failed — check apktool output above"
    exit 1
fi
echo "[OK]  Recompiled: $RECOMPILED_APK ($(du -h "$RECOMPILED_APK" | cut -f1))"

# ── STEP 4: Zipalign ─────────────────────────────────────────────────────────
echo ""
echo "[4/5] Zipaligning..."
ZIPALIGN=$(find $HOME/Android/Sdk/build-tools -name zipalign | sort -V | tail -1)
if [[ -n "$ZIPALIGN" ]]; then
    "$ZIPALIGN" -f 4 "$RECOMPILED_APK" "$ALIGNED_APK" && echo "[OK]  Zipaligned"
else
    echo "[WARN] zipalign not found — skipping (APK may still work)"
    cp "$RECOMPILED_APK" "$ALIGNED_APK"
fi

# ── STEP 5: Sign with debug keystore ─────────────────────────────────────────
echo ""
echo "[5/5] Signing with debug keystore..."
"$APKSIGNER" sign \
    --min-sdk-version 21 \
    --ks "$KEYSTORE" \
    --ks-key-alias androiddebugkey \
    --ks-pass pass:android \
    --key-pass pass:android \
    --out "$SIGNED_APK" \
    "$ALIGNED_APK" 2>&1

if [[ ! -f "$SIGNED_APK" ]]; then
    echo "[ERR] Signing failed"
    exit 1
fi
echo "[OK]  Signed: $SIGNED_APK"

# Copy to instrumented_app/
cp -f "$SIGNED_APK" "$OUT_APK"

echo ""
echo "════════════════════════════════════════════════════════"
echo "  ✓ INSTRUMENTATION COMPLETE"
echo "  Output APK   : $OUT_APK"
echo "  Methods      : $TOTAL_INJECTED log probes injected"
echo "  Logcat tag   : $LOG_TAG"
echo "  WorkDir      : $WORKDIR"
echo ""
echo "  Next steps:"
echo "  1. Install:  adb install -r \"$OUT_APK\""
echo "  2. Run pipeline:"
echo "     cd $ROOT/MismatchDroid-fastbot-custom-more-detection"
echo "     ./run_backdoor_detection.sh \"$OUT_APK\" \"$APP_NAME\" 300"
echo "════════════════════════════════════════════════════════"
