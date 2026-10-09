#!/usr/bin/env bash
# Hidden_trigger_run.sh
# One-shot pipeline: AndroLog instrument → install → EchoDroid run → trigger loop
# Usage:
#   ./Hidden_trigger_run.sh <apk_path> [app_name] [duration_seconds=300] [trigger_cmd="adb shell am broadcast -a android.intent.action.MAIN"] [trigger_interval_sec=1]
# Example (DroidKungFu):
#   ./Hidden_trigger_run.sh /path/08_DroidKungFu_e7d07c08.apk DroidKungFu_e7d07c08 300 "adb shell am broadcast -a android.intent.action.BOOT_COMPLETED --receiver-include-background" 1
set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 <apk_path> [app_name] [duration_seconds] [trigger_cmd] [trigger_interval_sec]" >&2
  exit 1
fi

APK_PATH=$(realpath "$1")
APP_NAME=${2:-$(basename "$APK_PATH" .apk)}
DUR=${3:-300}
TRIGGER_CMD=${4:-"adb shell am broadcast -a android.intent.action.MAIN"}
TRIGGER_IVL=${5:-1}

ROOT="/home/Desktop/mismatch_permission"
PLATFORMS="/home/Android/Sdk/platforms"
ANDROLOG_JAR="$ROOT/tools/AndroLog/target/androlog-0.1-jar-with-dependencies.jar"
APKSIGNER="/home/Android/Sdk/build-tools/36.1.0/apksigner"
LLM_RUN="$ROOT/EchoDroid-fastbot-custom-more-detection/run_mismatch_detection.sh"
INSTR_DIR="$ROOT/instrumented_app"
WORKDIR="$ROOT/pipeline_work/${APP_NAME}_$$"
OUTBASE="$ROOT/hidden_mismatch_output"

mkdir -p "$INSTR_DIR" "$WORKDIR/androlog_out" "$OUTBASE"

echo "[1/5] AndroLog instrumentation..."
set +e
java -jar "$ANDROLOG_JAR" -a "$APK_PATH" -p "$PLATFORMS" -l HIDDEN_TRIG_LOG -o "$WORKDIR/androlog_out" -m -cp -n \
  >"$WORKDIR/androlog_instrument.log" 2>&1
RC=$?
set -e
INST_APK=$(ls -1 "$WORKDIR/androlog_out"/*.apk 2>/dev/null | head -1 || true)
if [[ $RC -ne 0 || -z "$INST_APK" ]]; then
  echo "[WARN] Instrumentation failed or no APK produced; using original" | tee -a "$WORKDIR/androlog_instrument.log"
  INST_APK="$APK_PATH"
else
  # Some APKs cause AndroLog to emit a 0-byte/corrupt output without throwing.
  # Validate it looks like a real ZIP/APK before continuing.
  if [[ ! -s "$INST_APK" ]]; then
    echo "[WARN] Instrumented APK is empty; using original" | tee -a "$WORKDIR/androlog_instrument.log"
    INST_APK="$APK_PATH"
  elif ! unzip -tq "$INST_APK" >/dev/null 2>&1; then
    echo "[WARN] Instrumented APK is not a valid ZIP; using original" | tee -a "$WORKDIR/androlog_instrument.log"
    INST_APK="$APK_PATH"
  fi
fi

# Sign if needed
set +e
"$APKSIGNER" verify "$INST_APK" >/dev/null 2>&1
if [[ $? -ne 0 ]]; then
  SIGNED="$WORKDIR/instrumented-signed.apk"
  "$APKSIGNER" sign --min-sdk-version 21 --ks "$HOME/.android/debug.keystore" \
    --ks-key-alias androiddebugkey --ks-pass pass:android --key-pass pass:android \
    --out "$SIGNED" "$INST_APK" >>"$WORKDIR/androlog_instrument.log" 2>&1 || true
  if [[ -s "$SIGNED" ]]; then INST_APK="$SIGNED"; fi
fi
set -e

OUT_APK="$INSTR_DIR/${APP_NAME}_instrumented.apk"
cp -f "$INST_APK" "$OUT_APK"
echo "[OK] Instrumented APK: $OUT_APK"

# Install on emulator
if adb install -r "$OUT_APK" >/dev/null 2>&1; then
  echo "[OK] Installed on emulator"
else
  echo "[WARN] adb install failed; retrying via pm install --force-sdk" 
  adb push "$OUT_APK" /data/local/tmp/echodroid_target.apk >/dev/null 2>&1 || true
  adb shell pm install --force-sdk -r /data/local/tmp/echodroid_target.apk >/dev/null 2>&1 && echo "[OK] Installed via --force-sdk" || echo "[WARN] Install reported issues"
fi

# Wait for full boot (prevents Fastbot from crashing if services aren't ready)
START=$(date +%s)
while true; do
  BC=$(adb shell getprop sys.boot_completed 2>/dev/null | tr -d '\r' || true)
  ANIM=$(adb shell getprop init.svc.bootanim 2>/dev/null | tr -d '\r' || true)
  if [[ "$BC" == "1" && "$ANIM" == "stopped" ]]; then
    echo "[OK] Emulator boot completed"
    break
  fi
  if [[ $(( $(date +%s) - START )) -ge 180 ]]; then
    echo "[WARN] Timed out waiting for boot completion; continuing"
    break
  fi
  sleep 2
done

# Prepare output run folder
TS=$(date +%Y%m%d_%H%M%S)
RUN_OUT="$OUTBASE/${APP_NAME}_mismatch_${TS}"
mkdir -p "$RUN_OUT"

# Start EchoDroid
export ECHODROID_PROMPT_OUTPUT_DIR="$RUN_OUT"
"$LLM_RUN" "$OUT_APK" "$APP_NAME" "$DUR" >"$RUN_OUT/pipeline.log" 2>&1 &
RUN_PID=$!
echo $RUN_PID >"$RUN_OUT/run.pid"

# Trigger loop (run for ~DUR seconds, firing every TRIGGER_IVL seconds)
(
  END_TIME=$(( $(date +%s) + DUR ))
  i=1
  while [[ $(date +%s) -lt $END_TIME ]]; do
    # TRIGGER_CMD is a full shell command (e.g., adb shell am broadcast ...)
    eval "$TRIGGER_CMD" >/dev/null 2>&1 || true
    echo "[$(date +%T)] TRIGGER $i"
    i=$(( i + 1 ))
    sleep "$TRIGGER_IVL"
  done
) >"$RUN_OUT/trigger_log.txt" 2>&1 &
TRIG_PID=$!
echo $TRIG_PID >"$RUN_OUT/trigger.pid"

echo "[OK] Started run"
echo "RUN_OUT=$RUN_OUT"
echo "  - pipeline.log, trigger_log.txt, mismatch-detection-outputs/ (on completion)"
