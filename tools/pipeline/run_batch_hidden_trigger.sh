#!/usr/bin/env bash
# Batch run: Instrument with AndroLog + run MismatchDroid for N apps from a Drebin subset folder
# Usage: ./run_batch_hidden_trigger.sh <samples_dir> [count=5] [duration=300]
set -euo pipefail
SAMPLES_DIR=${1:-}
COUNT=${2:-5}
DUR=${3:-300}
if [[ -z "$SAMPLES_DIR" || ! -d "$SAMPLES_DIR" ]]; then
  echo "Usage: $0 <samples_dir> [count=5] [duration=300]" >&2
  exit 1
fi
ROOT="$HOME/Desktop/backdoor_permission"
OUTBASE="$ROOT/new_output"
WORKBASE="$ROOT/pipeline_work"
PLATFORMS="$HOME/Android/Sdk/platforms"
ANDROLOG_JAR="$ROOT/tools/AndroLog/target/androlog-0.1-jar-with-dependencies.jar"
APKSIGNER="$HOME/Android/Sdk/build-tools/36.1.0/apksigner"
LLM_RUN="$ROOT/MismatchDroid-fastbot-custom-more-detection/run_backdoor_detection.sh"
AAPT_BIN="aapt"
MANIFEST_CSV="$SAMPLES_DIR/manifest.csv"

if [[ ! -f "$ANDROLOG_JAR" ]]; then echo "[ERR] AndroLog JAR missing: $ANDROLOG_JAR"; exit 1; fi
if [[ ! -d "$PLATFORMS" ]]; then echo "[ERR] Android platforms not found: $PLATFORMS"; exit 1; fi
mkdir -p "$OUTBASE" "$WORKBASE"

# Read top N rows from manifest.csv or fallback to *.apk in folder
mapfile -t FILES < <(
  if [[ -f "$MANIFEST_CSV" ]]; then
    tail -n +2 "$MANIFEST_CSV" | head -n "$COUNT" | awk -F, '{print $5","$3","$2}'
  else
    ls -1 "$SAMPLES_DIR"/*.apk 2>/dev/null | head -n "$COUNT" | awk -v OFS="," '{print $0, "", ""}'
  fi
)

echo "[INFO] Will process ${#FILES[@]} app(s) from $SAMPLES_DIR"

for row in "${FILES[@]}"; do
  IFS=',' read -r FILE_NAME PKG FAMILY <<<"$row"
  APK_PATH="$SAMPLES_DIR/$FILE_NAME"
  if [[ ! -f "$APK_PATH" ]]; then
    # maybe FILE_NAME is a full path
    APK_PATH="$FILE_NAME"
  fi
  if [[ ! -f "$APK_PATH" ]]; then echo "[WARN] APK not found: $APK_PATH (skip)"; continue; fi
  if [[ -z "${PKG:-}" ]]; then
    # derive with aapt if missing
    PKG=$($AAPT_BIN dump badging "$APK_PATH" 2>/dev/null | awk -F"'" '/^package: /{print $2; exit}')
  fi
  APPNAME=$(basename "$APK_PATH" .apk)
  TS=$(date +%Y%m%d_%H%M%S)
  OUTDIR="$OUTBASE/${APPNAME}_backdoor_${TS}"
  WORKDIR="$WORKBASE/${APPNAME}_$TS"
  mkdir -p "$OUTDIR" "$WORKDIR/androlog_out"

  echo "\n=== Processing: $APPNAME ($FAMILY) ==="
  echo "APK: $APK_PATH"
  echo "PKG: ${PKG:-unknown}"
  echo "OUT: $OUTDIR"

  echo "[1/5] AndroLog instrumentation..."
  set +e
  java -jar "$ANDROLOG_JAR" -a "$APK_PATH" -p "$PLATFORMS" -l BATCH_LOG -o "$WORKDIR/androlog_out" -m -cp -n \
    >"$OUTDIR/androlog_instrument.log" 2>&1
  RC=$?
  set -e
  INST_APK=$(ls -1 "$WORKDIR/androlog_out"/*.apk 2>/dev/null | head -1 || true)
  if [[ $RC -ne 0 || -z "$INST_APK" ]]; then
    echo "[WARN] Instrumentation failed or empty; falling back to original" | tee -a "$OUTDIR/androlog_instrument.log"
    INST_APK="$APK_PATH"
  fi

  echo "[2/5] Sign/verify (if needed)..."
  set +e
  "$APKSIGNER" verify "$INST_APK" >/dev/null 2>&1
  if [[ $? -ne 0 ]]; then
    SIGNED="$WORKDIR/instrumented-signed.apk"
    "$APKSIGNER" sign --min-sdk-version 21 \
      --ks "$HOME/.android/debug.keystore" --ks-key-alias androiddebugkey \
      --ks-pass pass:android --key-pass pass:android \
      --out "$SIGNED" "$INST_APK" >>"$OUTDIR/androlog_instrument.log" 2>&1 || true
    if [[ -s "$SIGNED" ]]; then INST_APK="$SIGNED"; fi
  fi
  set -e

  echo "[3/5] Start MismatchDroid ($DUR s)..."
  export MISMATCHDROID_PROMPT_OUTPUT_DIR="$OUTDIR"
  "$LLM_RUN" "$INST_APK" "$APPNAME" "$DUR" >"$OUTDIR/pipeline.log" 2>&1 &
  RUN_PID=$!
  echo $RUN_PID >"$OUTDIR/run.pid"

  echo "[4/5] Start triggers (1s interval)..."
  TRIG_CMD=""
  case "${FAMILY,,}" in
    *droidkungfu*) TRIG_CMD="adb shell am broadcast -a android.intent.action.BOOT_COMPLETED --receiver-include-background";;
    *ginmaster*)   TRIG_CMD="adb shell am broadcast -a android.intent.action.PACKAGE_ADDED --uri package:com.example.newapp";;
    *basebridge*)  TRIG_CMD="adb shell am broadcast -a android.net.conn.CONNECTIVITY_CHANGE";;
    *geinimi*)     TRIG_CMD="adb shell am startservice --include-background ${PKG:-com.example}/.Service";;
    *droiddream*)  TRIG_CMD="adb shell am broadcast -a android.intent.action.MAIN";;
    *)             TRIG_CMD="";;
  esac
  if [[ -n "$TRIG_CMD" ]]; then
    bash -lc "for i in \$(seq 1 $DUR); do $TRIG_CMD >/dev/null 2>&1; echo [\$(date +%T)] TRIGGER \$i; sleep 1; done" \
      >"$OUTDIR/trigger_log_1s.txt" 2>&1 &
    echo $! >"$OUTDIR/trigger_1s.pid"
  else
    echo "[WARN] No trigger preset for family '$FAMILY'" | tee -a "$OUTDIR/pipeline.log"
  fi

  echo "[5/5] Waiting for run to finish..."
  wait $RUN_PID || true
  echo "[OK] Finished: $OUTDIR"
  # Small cool-down
  sleep 3

done

echo "\nAll requested apps processed."
