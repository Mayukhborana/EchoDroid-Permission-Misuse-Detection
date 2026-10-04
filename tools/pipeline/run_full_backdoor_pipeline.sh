#!/usr/bin/env bash
# =============================================================================
# run_full_backdoor_pipeline.sh
# One-command pipeline: AndroLog instrumentation → MismatchDroid Fastbot run → Triggers
# Saves a complete report under new_output/<app>_<timestamp>/ capturing patterns.
# =============================================================================
# Usage:
#   ./run_full_backdoor_pipeline.sh <apk_path> [app_name] [duration_seconds=300] [trigger_preset=auto]
#
# Trigger presets:
#   auto         → fire a suite: ACTION_MAIN, BOOT_COMPLETED, PACKAGE_ADDED, CONNECTIVITY_CHANGE
#   droidkungfu  → BOOT_COMPLETED
#   ginmaster    → PACKAGE_ADDED (obfuscated)
#   basebridge   → CONNECTIVITY_CHANGE
#   geinimi      → startservice com.ubermind.ilightr/.Service
#   droiddream   → ACTION_MAIN (broadcast)
# =============================================================================
set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 <apk_path> [app_name] [duration_seconds] [trigger_preset]" >&2
  exit 1
fi

APK_PATH=$(realpath "$1")
APP_NAME=${2:-$(basename "$APK_PATH" | sed 's/\.[aA][pP][kK]$//')}
DURATION=${3:-300}
TRIGGER_PRESET=${4:-auto}

# Workspace paths
ROOT="$HOME/Desktop/backdoor_permission"
OUT_ROOT="$ROOT/new_output"
WORK_DIR="$ROOT/pipeline_work/${APP_NAME}_$(date +%Y%m%d_%H%M%S)"
ANDROLOG_JAR="$ROOT/tools/AndroLog/target/androlog-0.1-jar-with-dependencies.jar"
ANDROID_PLATFORMS="$HOME/Android/Sdk/platforms"
AAPT_BIN="aapt"
APKSIGNER="$HOME/Android/Sdk/build-tools/36.1.0/apksigner"
ZIPALIGN="$HOME/Android/Sdk/build-tools/36.1.0/zipalign"
MISMATCHDROID_RUN="$ROOT/MismatchDroid-fastbot-custom-more-detection/run_backdoor_detection.sh"

mkdir -p "$OUT_ROOT" "$WORK_DIR"

log() { echo -e "[INFO] $*"; }
ok()  { echo -e "[OK]   $*"; }
err() { echo -e "[ERR]  $*" >&2; }

if [[ ! -f "$APK_PATH" ]]; then err "APK not found: $APK_PATH"; exit 1; fi
if [[ ! -f "$ANDROLOG_JAR" ]]; then err "AndroLog jar missing: $ANDROLOG_JAR"; exit 1; fi
if [[ ! -d "$ANDROID_PLATFORMS" ]]; then err "Android platforms dir missing: $ANDROID_PLATFORMS"; exit 1; fi
if ! command -v aapt >/dev/null 2>&1; then err "aapt not in PATH"; exit 1; fi

RUN_TS=$(date +%Y%m%d_%H%M%S)
RUN_DIR="$OUT_ROOT/${APP_NAME}_backdoor_${RUN_TS}"
mkdir -p "$RUN_DIR"

# Extract package info
PKG=$("$AAPT_BIN" dump badging "$APK_PATH" 2>/dev/null | awk -F"'" '/^package: /{print $2; exit}')
PKG=${PKG:-unknown.package}
log "APK: $APK_PATH"
log "Package: $PKG"
log "Output: $RUN_DIR"

# -----------------------------------------------------------------------------
# Step 1: AndroLog instrumentation
# -----------------------------------------------------------------------------
log "Instrumenting APK with AndroLog..."
INST_DIR="$WORK_DIR/androlog_out"
mkdir -p "$INST_DIR"

# Try instrumentation
set +e
java -jar "$ANDROLOG_JAR" \
  -a "$APK_PATH" \
  -p "$ANDROID_PLATFORMS" \
  -l "${APP_NAME}_LOG" \
  -o "$INST_DIR" \
  -m -cp -n >"$RUN_DIR/androlog_instrument.log" 2>&1
RC=$?
set -e
if [[ $RC -ne 0 ]]; then
  err "AndroLog returned non-zero (rc=$RC). Check $RUN_DIR/androlog_instrument.log"
fi

# Locate instrumented APK (AndroLog sometimes writes base.apk or <name>.apk)
INST_APK=""
if ls "$INST_DIR"/*.apk >/dev/null 2>&1; then
  # pick non-zero sized first
  while IFS= read -r f; do
    if [[ -s "$f" ]]; then INST_APK="$f"; break; fi
  done < <(ls -1 "$INST_DIR"/*.apk | sort)
fi

if [[ -z "$INST_APK" ]]; then
  # Fallback: use original if instrumentation artifact missing; MismatchDroid will still collect methods
  warn_msg="Instrumented APK not found or empty; falling back to original"
  echo "[WARN] $warn_msg" | tee -a "$RUN_DIR/androlog_instrument.log"
  INST_APK="$APK_PATH"
else
  ok "Instrumented APK: $INST_APK"
fi

# Optional: verify/sign if needed
if [[ -x "$APKSIGNER" ]]; then
  set +e
  "$APKSIGNER" verify "$INST_APK" >/dev/null 2>&1
  if [[ $? -ne 0 ]]; then
    log "Signing instrumented APK with debug keystore..."
    UNSIGNED="$INST_APK"
    SIGNED="$WORK_DIR/instrumented-signed.apk"
    "$APKSIGNER" sign --min-sdk-version 21 \
      --ks "$HOME/.android/debug.keystore" --ks-key-alias androiddebugkey \
      --ks-pass pass:android --key-pass pass:android \
      --out "$SIGNED" "$UNSIGNED" >>"$RUN_DIR/androlog_instrument.log" 2>&1 || true
    if [[ -s "$SIGNED" ]]; then INST_APK="$SIGNED"; ok "Signed APK ready"; fi
  fi
  set -e
fi

# -----------------------------------------------------------------------------
# Step 2: Launch MismatchDroid run (Fastbot + Prompts)
# -----------------------------------------------------------------------------
log "Starting MismatchDroid run ($DURATION s)..."
export MISMATCHDROID_PROMPT_OUTPUT_DIR="$RUN_DIR"
# Pass through OPENAI_API_KEY if configured in root config.json
if [[ -f "$ROOT/config.json" ]]; then
  export OPENAI_API_KEY=$(python3 - <<'PY'
import json,sys
try:
  cfg=json.load(open("$HOME/Desktop/backdoor_permission/config.json"))
  print(cfg.get("ApiKey",""))
except Exception:
  print("")
PY
  )
fi

nohup "$MISMATCHDROID_RUN" "$INST_APK" "$APP_NAME" "$DURATION" >"$RUN_DIR/pipeline.log" 2>&1 &
LLM_PID=$!
echo $LLM_PID >"$RUN_DIR/run.pid"
ok "MismatchDroid started (PID $LLM_PID)"

# -----------------------------------------------------------------------------
# Step 3: Fire triggers according to preset (in background)
# -----------------------------------------------------------------------------
TRIGGER_LOG="$RUN_DIR/trigger_log.txt"
(
  case "$TRIGGER_PRESET" in
    droidkungfu)
      adb shell am broadcast -a android.intent.action.BOOT_COMPLETED --receiver-include-background ;;
    ginmaster)
      adb shell am broadcast -a android.intent.action.PACKAGE_ADDED --uri package:com.example.newapp ;;
    basebridge)
      adb shell am broadcast -a android.net.conn.CONNECTIVITY_CHANGE ;;
    geinimi)
      adb shell am startservice --include-background com.ubermind.ilightr/.Service ;;
    droiddream)
      adb shell am broadcast -a android.intent.action.MAIN ;;
    auto|*)
      # Fire a broad suite to capture multiple hidden triggers
      adb shell am broadcast -a android.intent.action.MAIN || true
      adb shell am broadcast -a android.intent.action.BOOT_COMPLETED --receiver-include-background || true
      adb shell am broadcast -a android.net.conn.CONNECTIVITY_CHANGE || true
      adb shell am broadcast -a android.intent.action.PACKAGE_ADDED --uri package:com.example.newapp || true
      ;;
  esac
  # Repeat every 60s, 4 times
  for i in 1 2 3 4; do
    sleep 60
    case "$TRIGGER_PRESET" in
      droidkungfu) adb shell am broadcast -a android.intent.action.BOOT_COMPLETED --receiver-include-background || true ;;
      ginmaster)   adb shell am broadcast -a android.intent.action.PACKAGE_ADDED --uri package:com.example.newapp || true ;;
      basebridge)  adb shell am broadcast -a android.net.conn.CONNECTIVITY_CHANGE || true ;;
      geinimi)     adb shell am startservice --include-background com.ubermind.ilightr/.Service || true ;;
      droiddream)  adb shell am broadcast -a android.intent.action.MAIN || true ;;
      auto|*)
        adb shell am broadcast -a android.intent.action.MAIN || true
        adb shell am broadcast -a android.intent.action.BOOT_COMPLETED --receiver-include-background || true
        adb shell am broadcast -a android.net.conn.CONNECTIVITY_CHANGE || true
        adb shell am broadcast -a android.intent.action.PACKAGE_ADDED --uri package:com.example.newapp || true
        ;;
    esac
  done
) >"$TRIGGER_LOG" 2>&1 &
TRIG_PID=$!
echo $TRIG_PID >"$RUN_DIR/trigger.pid"
ok "Triggers started (PID $TRIG_PID, preset: $TRIGGER_PRESET)"

# -----------------------------------------------------------------------------
# Step 4: Wait for completion then summarise
# -----------------------------------------------------------------------------
log "Waiting for MismatchDroid to finish (~$DURATION s)..."
wait $LLM_PID || true
ok "Run complete. Results at: $RUN_DIR"

# Copy MismatchDroid internal results folder (if any) into RUN_DIR for single-place review
if ls $HOME/Desktop/MismatchDroid/MismatchDroid/Overall_test_output/backdoor_results/${APP_NAME}_backdoor_* >/dev/null 2>&1; then
  LLM_OUT=$(ls -td $HOME/Desktop/MismatchDroid/MismatchDroid/Overall_test_output/backdoor_results/${APP_NAME}_backdoor_* | head -1)
  mkdir -p "$RUN_DIR/mismatchdroid_raw"
  cp -r "$LLM_OUT"/* "$RUN_DIR/mismatchdroid_raw/" 2>/dev/null || true
fi

# Quick pointers
{
  echo "APP=$APP_NAME"
  echo "PACKAGE=$PKG"
  echo "APK_USED=$INST_APK"
  echo "OUTPUT_DIR=$RUN_DIR"
} >"$RUN_DIR/run.meta"

log "Artifacts:"
ls -lh "$RUN_DIR" | sed -n '1,120p'

log "Backdoor report (if generated):"
if ls "$RUN_DIR"/backdoor-detection-outputs/*.json >/dev/null 2>&1; then
  ls -lh "$RUN_DIR"/backdoor-detection-outputs/*.json
else
  echo "(report will appear here if prompts ran with API key)"
fi
