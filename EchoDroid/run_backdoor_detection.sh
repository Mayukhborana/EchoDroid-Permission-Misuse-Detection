#!/usr/bin/env bash
# =============================================================================
# run_backdoor_detection.sh
# EchoDroid  –  Backdoor Detection Runner
# =============================================================================
#
# USAGE:
#   ./run_backdoor_detection.sh <APK_PATH_OR_PACKAGE> [APP_NAME] [DURATION_SECONDS]
#
# EXAMPLES:
#   ./run_backdoor_detection.sh /path/to/myapp_instrumented.apk "MyApp" 120
#   ./run_backdoor_detection.sh com.example.myapp "MyApp" 60
#
# WHAT IT DOES:
#   1.  Installs the APK on emulator-5554  (skip if package given)
#   2.  Extracts AndroidManifest permissions + exported components via aapt
#   3.  Builds config.json for Prompt_BackdoorDetection.py
#   4.  Pushes Fastbot jars to device
#   5.  Runs Fastbot + AndroLog (method-level instrumentation coverage)
#   6.  In the background, takes periodic UI dumps (uiautomator) every 5 s
#   7.  Pulls logcat, activity stats, and UI dump XMLs from device
#   8.  Extracts AndroLog METHOD= lines from logcat → androlog_methods.txt
#   9.  Extracts UI widget text from XML dumps → ui_widget_text.txt
#  10.  Runs Prompt_BackdoorDetection.py (3 LLM prompts)
#  11.  Saves final backdoor_detection_report.json
#
# OUTPUT DIRECTORY:
#   Overall_test_output/backdoor_results/<appname>_<timestamp>/
#
# =============================================================================

set -euo pipefail

# ── Colour helpers ──────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

info()  { echo -e "${BLUE}[INFO]${NC}  $*"; }
ok()    { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
err()   { echo -e "${RED}[ERR]${NC}   $*"; }
step()  { echo -e "\n${CYAN}━━━ $* ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"; }

# Wait until Android framework has fully booted (prevents Fastbot/Monkey crashes)
wait_for_boot_completed() {
  local serial="$1"
  local timeout_s="${2:-120}"
  local start
  start=$(date +%s)
  while true; do
    # sys.boot_completed=1 when boot is done
    local bc
    bc=$(adb -s "$serial" shell getprop sys.boot_completed 2>/dev/null | tr -d '\r') || bc=""
    local anim
    anim=$(adb -s "$serial" shell getprop init.svc.bootanim 2>/dev/null | tr -d '\r') || anim=""
    if [[ "$bc" == "1" && "$anim" == "stopped" ]]; then
      return 0
    fi
    if [[ $(( $(date +%s) - start )) -ge $timeout_s ]]; then
      warn "Timed out waiting for boot completion (sys.boot_completed=$bc bootanim=$anim). Continuing anyway."
      return 0
    fi
    sleep 2
  done
}

# ── Workspace paths (configurable) ──────────────────────────────────────────
# Use env overrides when provided, else default to this project folder
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE="${PERMISSION_MISSUSE_WORKSPACE:-${ECHODROID_WORKSPACE:-/Users/Desktop/permission_misuse}}"
DETECT_DIR="$SCRIPT_DIR"
RESULTS_BASE="${ECHODROID_RESULTS_BASE:-$WORKSPACE/new_output}"
mkdir -p "$RESULTS_BASE"

# ── Parse arguments ─────────────────────────────────────────────────────────
if [[ $# -lt 1 ]]; then
  echo "Usage: $0 <APK_PATH_or_PACKAGE> [APP_NAME] [DURATION_SECONDS]"
  echo ""
  echo "  APK_PATH_or_PACKAGE : path to .apk file  OR  installed package name"
  echo "  APP_NAME            : human-readable app name  (default: derived)"
  echo "  DURATION_SECONDS    : test duration in seconds (default: 120)"
  exit 1
fi

ARG1="$1"
APP_NAME="${2:-}"
DURATION="${3:-120}"
# Auto-detect running emulator; fallback to emulator-5554
# Prefer the first emulator/device listed by `adb devices` that matches emulator-*
EMULATOR="$(adb devices | awk '/^emulator-/{print $1; exit}')"
if [[ -z "$EMULATOR" ]]; then
  EMULATOR="emulator-5554"
fi

# ── Determine APK path vs package name ──────────────────────────────────────
APK_PATH=""
PACKAGE=""
TEMP_APK_PATH=""

if [[ "$ARG1" == *.apk ]]; then
  APK_PATH=$(realpath "$ARG1")
  if [[ ! -f "$APK_PATH" ]]; then
    err "APK file not found: $APK_PATH"
    exit 1
  fi
  # Extract package name from APK
  PACKAGE=$(aapt dump badging "$APK_PATH" 2>/dev/null | grep "^package:" | head -1 | sed -E "s/^package: name='([^']+)'.*/\1/") || true
  if [[ -z "$PACKAGE" ]]; then
    PACKAGE=$(basename "$APK_PATH" .apk | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9]/_/g')
  fi
else
  PACKAGE="$ARG1"
  # Try to pull the APK from device for manifest analysis
  TEMP_APK_PATH="/tmp/${PACKAGE}_for_analysis.apk"
  info "Pulling APK from device for manifest analysis..."
  APK_ON_DEVICE=$(adb -s "$EMULATOR" shell pm path "$PACKAGE" 2>/dev/null | sed 's/package://' | head -1 | tr -d '\r') || true
  if [[ -n "$APK_ON_DEVICE" ]]; then
    adb -s "$EMULATOR" pull "$APK_ON_DEVICE" "$TEMP_APK_PATH" >/dev/null 2>&1 && APK_PATH="$TEMP_APK_PATH" || true
  fi
fi

# Default app name from package if not provided
if [[ -z "$APP_NAME" ]]; then
  APP_NAME=$(echo "$PACKAGE" | awk -F'.' '{print $NF}' | sed 's/\b\(.\)/\U\1/g')
fi

# Timestamp
TS=$(date +%Y%m%d_%H%M%S)
RUN_ID="${APP_NAME// /_}_backdoor_${TS}"
OUT_DIR="$RESULTS_BASE/$RUN_ID"
REMOTE_OUT="/sdcard/${RUN_ID}"

mkdir -p "$OUT_DIR"
mkdir -p "$OUT_DIR/ui_dumps"

echo ""
echo -e "${BLUE}╔══════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║    EchoDroid Backdoor Detection Pipeline                              ║${NC}"
echo -e "${BLUE}╠══════════════════════════════════════════════════════════════════╣${NC}"
printf  "${BLUE}║${NC}  App     : %-53s${BLUE}║${NC}\n" "$APP_NAME"
printf  "${BLUE}║${NC}  Package : %-53s${BLUE}║${NC}\n" "$PACKAGE"
printf  "${BLUE}║${NC}  Duration: %-2d seconds%47s${BLUE}║${NC}\n" "$DURATION" ""
printf  "${BLUE}║${NC}  Output  : %-53s${BLUE}║${NC}\n" "$OUT_DIR"
echo -e "${BLUE}╚══════════════════════════════════════════════════════════════════╝${NC}"

# ── STEP 1: Install APK (if path provided) ───────────────────────────────────
step "STEP 1: Install APK"
if [[ -n "$APK_PATH" && "$APK_PATH" != "${TEMP_APK_PATH:-}" ]]; then
  info "Installing $APK_PATH ..."
  adb -s "$EMULATOR" wait-for-device >/dev/null
  wait_for_boot_completed "$EMULATOR" 180
  # Uninstall old version first (ignore failures)
  adb -s "$EMULATOR" uninstall "$PACKAGE" >/dev/null 2>&1 || true
  INSTALL_OUT=$(adb -s "$EMULATOR" install -r "$APK_PATH" 2>&1 || true)
  if echo "$INSTALL_OUT" | grep -q "INSTALL_FAILED_VERSION_DOWNGRADE"; then
    warn "Version downgrade – retrying with -d flag"
    adb -s "$EMULATOR" install -r -d "$APK_PATH"
  elif echo "$INSTALL_OUT" | grep -q "INSTALL_FAILED_DEPRECATED_SDK_VERSION"; then
    warn "Device blocked install due to deprecated targetSdkVersion. Retrying via 'pm install --force-sdk'..."
    TMP_ON_DEVICE="/data/local/tmp/echodroid_target.apk"
    adb -s "$EMULATOR" push "$APK_PATH" "$TMP_ON_DEVICE" >/dev/null
    INSTALL_OUT_PM=$(adb -s "$EMULATOR" shell pm install --force-sdk -r "$TMP_ON_DEVICE" 2>&1 || true)
    if echo "$INSTALL_OUT_PM" | grep -qi "Success"; then
      ok "APK installed with --force-sdk: $PACKAGE"
    else
      err "APK install failed (pm --force-sdk): $INSTALL_OUT_PM"
      exit 1
    fi
  elif echo "$INSTALL_OUT" | grep -q "Failure"; then
    err "APK install failed: $INSTALL_OUT"
    exit 1
  fi
  ok "APK installed: $PACKAGE"
else
  info "Using already-installed package: $PACKAGE"
fi

# ── STEP 2: Extract Manifest Permissions & Exported Components ───────────────
step "STEP 2: Manifest Analysis"

PERMISSIONS_JSON="[]"
EXPORTED_COMPS_JSON="[]"

if [[ -n "$APK_PATH" && -f "$APK_PATH" ]]; then
  info "Running aapt dump permissions..."
  PERMISSIONS_JSON=$(aapt dump permissions "$APK_PATH" 2>/dev/null \
    | grep "uses-permission" \
    | sed "s/.*name='//;s/'.*//" \
    | python3 -c "import sys,json; lines=[l.strip() for l in sys.stdin if l.strip()]; print(json.dumps(lines))" \
    2>/dev/null) || PERMISSIONS_JSON="[]"
  ok "Permissions extracted: $(echo "$PERMISSIONS_JSON" | python3 -c "import sys,json; d=json.load(sys.stdin); print(len(d))" 2>/dev/null || echo '?') entries"

  info "Running aapt dump xmltree for exported components..."
  EXPORTED_COMPS_JSON=$(aapt dump xmltree "$APK_PATH" AndroidManifest.xml 2>/dev/null \
    | python3 - "$PACKAGE" <<'PY'
import sys, re, json
pkg = sys.argv[1] if len(sys.argv) > 1 else ""
data = sys.stdin.read()
lines = data.splitlines()
exported = []
current_name = None
for line in lines:
    nm = re.search(r'android:name\b.*?="([^"]+)"', line)
    if nm:
        current_name = nm.group(1)
        if current_name.startswith('.'):
            current_name = pkg + current_name
    ex = re.search(r'android:exported.*?"true"', line)
    if ex and current_name:
        exported.append(current_name)
        current_name = None
print(json.dumps(list(set(exported))))
PY
  2>/dev/null) || EXPORTED_COMPS_JSON="[]"
  ok "Exported components: $(echo "$EXPORTED_COMPS_JSON" | python3 -c "import sys,json; d=json.load(sys.stdin); print(len(d))" 2>/dev/null || echo '?') found"
else
  warn "No APK file available; manifest analysis skipped (add ManifestPermissions to config manually)"
fi

# ── STEP 3: Detect AndroLog Tag & TotalMethod ────────────────────────────────
step "STEP 3: AndroLog Configuration"

ANDROID_LOG_TAG="${PACKAGE//./_}_LOG"
TOTAL_METHOD=1

# Try to read TotalMethod from existing instrumentation.
# Note: This runner does NOT instrument the APK; it only *detects* existing
# AndroLog instrumentation (decompiled/smali* with METHOD= markers).
if [[ -n "$APK_PATH" && -f "$APK_PATH" ]]; then
  APK_DIR=$(dirname "$APK_PATH")
  INSTR_PARENT=$(dirname "$APK_DIR")

  # Allow explicit override (preferred)
  INSTR_DIR_CANDIDATES=()
  if [[ -n "${ECHODROID_INSTRUMENT_DIR:-}" ]]; then
    INSTR_DIR_CANDIDATES+=("$ECHODROID_INSTRUMENT_DIR")
  fi
  # Common layouts: output_dir/{base.apk,decompiled/} or output_dir/apk/base.apk
  INSTR_DIR_CANDIDATES+=("$APK_DIR" "$INSTR_PARENT")

  FOUND_DECOMP=""
  for cand in "${INSTR_DIR_CANDIDATES[@]}"; do
    [[ -z "$cand" ]] && continue
    if [[ -d "$cand/decompiled" ]]; then
      FOUND_DECOMP="$cand/decompiled"
      break
    fi
  done

  if [[ -n "$FOUND_DECOMP" ]]; then
    COUNT=$( (grep -Rh "METHOD=" "$FOUND_DECOMP"/smali* 2>/dev/null || true) | wc -l | tr -d ' ' )
    if [[ "$COUNT" -gt 0 ]]; then
      TOTAL_METHOD="$COUNT"
      ok "TotalMethod from smali instrumentation: $TOTAL_METHOD"
    else
      warn "Found decompiled smali but no METHOD= markers; using TotalMethod=1"
    fi
  else
    warn "No AndroLog instrumentation folder found (missing decompiled/smali*); using TotalMethod=1"
  fi
fi

# ── STEP 4: Build config.json ────────────────────────────────────────────────
step "STEP 4: Build config.json"

# Read API key from workspace root config.json
API_KEY=$(python3 -c "
import json
from pathlib import Path
for p in ['$WORKSPACE/config.json', '$DETECT_DIR/config.json']:
    try:
        cfg = json.loads(Path(p).read_text())
        k = cfg.get('ApiKey', '')
        if k:
            print(k)
            break
    except: pass
" 2>/dev/null) || API_KEY=""

if [[ -z "$API_KEY" ]]; then
  warn "No ApiKey found in config.json; LLM prompts will run in dry-run mode"
fi

APK_PATH_FOR_CONFIG="${APK_PATH:-}"

python3 - <<PY
import json
from pathlib import Path

config = {
    "AppName": "$APP_NAME",
    "Description": "Android app under backdoor detection analysis by EchoDroid",
    "ApiKey": "$API_KEY",
    "TotalMethod": int("$TOTAL_METHOD"),
    "Tag": "$ANDROID_LOG_TAG",
    "Model": "gpt-4.1",
    "BaseUrl": "https://api.openai.com/v1",
    "PackageName": "$PACKAGE",
    "ManifestPath": "$APK_PATH_FOR_CONFIG",
    "ManifestPermissions": ${PERMISSIONS_JSON},
    "ExportedComponents": ${EXPORTED_COMPS_JSON},
}
Path("$OUT_DIR/config.json").write_text(json.dumps(config, indent=2))
print("Config written to $OUT_DIR/config.json")
PY
ok "config.json written"

# ── STEP 5: Push Fastbot files to device ─────────────────────────────────────
step "STEP 5: Push Fastbot to Device"

adb -s "$EMULATOR" wait-for-device >/dev/null
wait_for_boot_completed "$EMULATOR" 180
adb -s "$EMULATOR" shell "pkill -f 'com.android.commands.monkey.Monkey' || true" >/dev/null 2>&1 || true

# Push Fastbot libraries
adb -s "$EMULATOR" shell rm -rf /sdcard/echodroid_backdoor >/dev/null 2>&1 || true
adb -s "$EMULATOR" shell mkdir -p /sdcard/echodroid_backdoor >/dev/null
adb -s "$EMULATOR" shell mkdir -p /data/local/tmp/x86_64 >/dev/null 2>&1 || true

adb -s "$EMULATOR" push "$DETECT_DIR/monkey/libs/"* /sdcard/echodroid_backdoor/ >/dev/null 2>&1 || true
adb -s "$EMULATOR" push "$DETECT_DIR/monkeyq.jar"          /sdcard/echodroid_backdoor/monkeyq.jar >/dev/null
adb -s "$EMULATOR" push "$DETECT_DIR/fastbot-thirdpart.jar" /sdcard/echodroid_backdoor/fastbot-thirdpart.jar >/dev/null
adb -s "$EMULATOR" push "$DETECT_DIR/framework.jar"         /sdcard/echodroid_backdoor/framework.jar >/dev/null

adb -s "$EMULATOR" push "$DETECT_DIR/monkeyq.jar" /data/local/tmp/monkeyq.jar >/dev/null
adb -s "$EMULATOR" push "$DETECT_DIR/fastbot-thirdpart.jar" /data/local/tmp/fastbot-thirdpart.jar >/dev/null
adb -s "$EMULATOR" push "$DETECT_DIR/framework.jar" /data/local/tmp/framework.jar >/dev/null

# Push native .so
DEVICE_ABI=$(adb -s "$EMULATOR" shell getprop ro.product.cpu.abi | tr -d '\r')
info "Device ABI: $DEVICE_ABI"

NATIVE_SO=""

for candidate in \
  "$DETECT_DIR/libs/$DEVICE_ABI/libfastbot_native.so" \
  "$DETECT_DIR/monkey/build/intermediates/cmake/release/obj/$DEVICE_ABI/libfastbot_native.so" \
  "$DETECT_DIR/monkey/build/intermediates/cmake/debug/obj/$DEVICE_ABI/libfastbot_native.so" \
  "$DETECT_DIR/monkey/build/intermediates/merged_native_libs/release/out/lib/$DEVICE_ABI/libfastbot_native.so" \
  "$DETECT_DIR/monkey/build/intermediates/merged_native_libs/debug/out/lib/$DEVICE_ABI/libfastbot_native.so"; do
  if [[ -f "$candidate" ]]; then
    NATIVE_SO="$candidate"
    break
  fi
done

if [[ -n "$NATIVE_SO" ]]; then
  adb -s "$EMULATOR" shell mkdir -p "/data/local/tmp/$DEVICE_ABI" >/dev/null 2>&1 || true
  adb -s "$EMULATOR" push "$NATIVE_SO" "/data/local/tmp/$DEVICE_ABI/libfastbot_native.so" >/dev/null
  ok "Native library pushed: $NATIVE_SO -> /data/local/tmp/$DEVICE_ABI/libfastbot_native.so"
else
  warn "libfastbot_native.so not found for ABI=$DEVICE_ABI – Fastbot may fail"
fi
 

# Push config.json
adb -s "$EMULATOR" push "$OUT_DIR/config.json" /sdcard/config.json >/dev/null
ok "Fastbot files pushed to device"

# ── STEP 6: Launch app ───────────────────────────────────────────────────────
step "STEP 6: Launch App"
adb -s "$EMULATOR" shell am force-stop "$PACKAGE" >/dev/null 2>&1 || true
sleep 1
adb -s "$EMULATOR" shell monkey -p "$PACKAGE" -c android.intent.category.LAUNCHER 1 >/dev/null 2>&1 || true
sleep 3
ok "App launched: $PACKAGE"

# Clear logcat before run
adb -s "$EMULATOR" logcat -c 2>/dev/null || true
sleep 1

# ── STEP 7: Start background UI dump capture ─────────────────────────────────
# step "STEP 7: Start Background UI Capture"

# UI_DUMP_COUNT=0
# UI_DUMP_INTERVAL=5   # seconds between each UI dump

# # Background loop that periodically captures UI hierarchy to XML
# (
#   DUMP_IDX=0
#   END_TIME=$(( $(date +%s) + DURATION + 10 ))
#   while [[ $(date +%s) -lt $END_TIME ]]; do
#     sleep "$UI_DUMP_INTERVAL"
#     adb -s "$EMULATOR" shell uiautomator dump /sdcard/ui_dump_${DUMP_IDX}.xml >/dev/null 2>&1 || true
#     DUMP_IDX=$(( DUMP_IDX + 1 ))
#   done
# ) &
# UI_DUMP_PID=$!
# info "UI dump capture started (PID $UI_DUMP_PID, every ${UI_DUMP_INTERVAL}s)"
step "STEP 7: Skip Background UI Capture During Fastbot"

UI_DUMP_PID=""
info "Skip uiautomator dump while Fastbot is running to avoid UiAutomation conflict"

# ── STEP 8: Run Fastbot + AndroLog ───────────────────────────────────────────
step "STEP 8: Run Fastbot + AndroLog (${DURATION}s)"

LOGCAT_FILE="$OUT_DIR/logcat_with_methods.log"
CONSOLE_FILE="$OUT_DIR/console.txt"

# Start logcat capture on host (captures METHOD= lines in real time)
adb -s "$EMULATOR" logcat -v time > "$LOGCAT_FILE" 2>&1 &
LOGCAT_PID=$!
info "Logcat capture started (PID $LOGCAT_PID)"

# Run Fastbot with AndroLog
# info "Starting Fastbot + AndroLog for $DURATION seconds..."
# CLASSPATH_DEV="${REMOTE_TOOL_DIR}/monkeyq.jar:${REMOTE_TOOL_DIR}/framework.jar:${REMOTE_TOOL_DIR}/fastbot-thirdpart.jar"

# FASTBOT_START_TS=$(date +%s)

# timeout $(( DURATION + 30 )) adb -s "$EMULATOR" shell \
#   CLASSPATH="${CLASSPATH_DEV}" \
#   exec app_process /system/bin com.android.commands.monkey.Monkey \
#     -p "$PACKAGE" \
#     --agent reuseq \
#     --use-code-coverage androlog \
#     --running-minutes "$(( DURATION / 60 < 1 ? 1 : DURATION / 60 ))" \
#     --throttle 3000 \
#     --output-directory "$REMOTE_OUT" \
#     -v -v --bugreport \
#   > "$CONSOLE_FILE" 2>&1 || warn "Fastbot exited with non-zero status (may be normal)"

info "Starting Fastbot + AndroLog for $DURATION seconds..."

CLASSPATH_DEV="/data/local/tmp/monkeyq.jar:/data/local/tmp/framework.jar:/data/local/tmp/fastbot-thirdpart.jar"

TIMEOUT_CMD="$(command -v gtimeout || command -v timeout || true)"

if [[ -z "$TIMEOUT_CMD" ]]; then
  warn "Neither gtimeout nor timeout found; running Fastbot without timeout"
fi

FASTBOT_START_TS=$(date +%s)

FASTBOT_CMD="
export CLASSPATH=${CLASSPATH_DEV}
exec app_process /system/bin com.android.commands.monkey.Monkey \
-p ${PACKAGE} \
--agent reuseq \
--pct-rotation 0 \
--use-code-coverage androlog \
--running-minutes $(( DURATION / 60 < 1 ? 1 : DURATION / 60 )) \
--throttle 3000 \
--output-directory ${REMOTE_OUT} \
-v -v --bugreport
"

if [[ -n "$TIMEOUT_CMD" ]]; then
  "$TIMEOUT_CMD" $(( DURATION + 30 )) \
    adb -s "$EMULATOR" shell "$FASTBOT_CMD" \
    > "$CONSOLE_FILE" 2>&1 \
    || warn "Fastbot exited with non-zero status (may be normal)"
else
  adb -s "$EMULATOR" shell "$FASTBOT_CMD" \
    > "$CONSOLE_FILE" 2>&1 \
    || warn "Fastbot exited with non-zero status (may be normal)"
fi

FASTBOT_END_TS=$(date +%s)
FASTBOT_ELAPSED=$(( FASTBOT_END_TS - FASTBOT_START_TS ))

# FASTBOT_END_TS=$(date +%s)
# FASTBOT_ELAPSED=$(( FASTBOT_END_TS - FASTBOT_START_TS ))

# Guard against clock adjustments (NTP/time sync) producing negative elapsed
# or an excessively large remaining time, which can cause multi-hour sleeps.
if [[ $FASTBOT_ELAPSED -lt 0 ]]; then
  warn "Clock anomaly detected (FASTBOT_ELAPSED=${FASTBOT_ELAPSED}). Clamping to 0s."
  FASTBOT_ELAPSED=0
fi

if [[ $FASTBOT_ELAPSED -ge $DURATION ]]; then
  FASTBOT_REMAINING=0
else
  FASTBOT_REMAINING=$(( DURATION - FASTBOT_ELAPSED ))
fi

info "Fastbot elapsed=${FASTBOT_ELAPSED}s remaining=${FASTBOT_REMAINING}s"

# ── Fallback: if Fastbot exited early, use adb monkey to keep exercising the
#    app for the remaining time so UI dumps and logcat keep collecting.
if [[ $FASTBOT_REMAINING -gt 30 ]]; then
  warn "Fastbot ran only ${FASTBOT_ELAPSED}s / ${DURATION}s — running adb monkey fallback for remaining ${FASTBOT_REMAINING}s"
  # Re-launch the app in case Fastbot left it in background
  adb -s "$EMULATOR" shell monkey -p "$PACKAGE" -c android.intent.category.LAUNCHER 1 >/dev/null 2>&1 || true
  sleep 2
  FALLBACK_EVENTS=$(( FASTBOT_REMAINING * 1000 / 2000 + 1 ))
  adb -s "$EMULATOR" shell monkey \
    -p "$PACKAGE" \
    --throttle 2000 \
    --ignore-crashes \
    --ignore-timeouts \
    --ignore-security-exceptions \
    -v "$FALLBACK_EVENTS" \
    >> "$CONSOLE_FILE" 2>&1 &
  FALLBACK_PID=$!
  info "Fallback adb monkey started (PID $FALLBACK_PID, ${FALLBACK_EVENTS} events)"
  sleep "$FASTBOT_REMAINING"
  kill "$FALLBACK_PID" 2>/dev/null || true
  ok "Fallback monkey run completed"
fi

ok "Fastbot run completed"

for i in $(seq 0 5); do

  adb -s "$EMULATOR" shell uiautomator dump "/sdcard/ui_dump_${i}.xml" >/dev/null 2>&1 || true

  sleep 2

done

# Stop logcat and UI dump captures
sleep 2
kill "$LOGCAT_PID" 2>/dev/null || true
# kill "$UI_DUMP_PID" 2>/dev/null || true
if [[ -n "${UI_DUMP_PID:-}" ]]; then

  kill "$UI_DUMP_PID" 2>/dev/null || true

fi
sleep 1

# ── STEP 9: Pull data from device ────────────────────────────────────────────
step "STEP 9: Pull Data from Device"

# Pull Fastbot output directory
adb -s "$EMULATOR" pull "$REMOTE_OUT" "$OUT_DIR/" >/dev/null 2>&1 || warn "Could not pull remote output dir"

# Pull max.activity.statistics.log (activity coverage)
ACTIVITY_LOG_ON_DEVICE=$(adb -s "$EMULATOR" shell "find /sdcard/${RUN_ID} -name 'max.activity.statistics.log' 2>/dev/null | head -1" 2>/dev/null | tr -d '\r') || true
ACTIVITY_FILE="$OUT_DIR/max.activity.statistics.log"
if [[ -n "$ACTIVITY_LOG_ON_DEVICE" ]]; then
  adb -s "$EMULATOR" pull "$ACTIVITY_LOG_ON_DEVICE" "$ACTIVITY_FILE" >/dev/null 2>&1 || true
  ok "Activity statistics pulled"
else
  # Try to find it in the pulled directory
  FOUND_ACTIVITY=$(find "$OUT_DIR" -name "max.activity.statistics.log" 2>/dev/null | head -1) || true
  [[ -n "$FOUND_ACTIVITY" ]] && ACTIVITY_FILE="$FOUND_ACTIVITY" || warn "Activity statistics not found"
fi

# Pull UI dump XMLs
info "Pulling UI dump XMLs..."
UI_DUMP_PULLED=0
for i in $(seq 0 100); do
  XML_REMOTE="/sdcard/ui_dump_${i}.xml"
  XML_LOCAL="$OUT_DIR/ui_dumps/ui_dump_${i}.xml"
  adb -s "$EMULATOR" pull "$XML_REMOTE" "$XML_LOCAL" >/dev/null 2>&1 && \
    adb -s "$EMULATOR" shell rm -f "$XML_REMOTE" >/dev/null 2>&1 && \
    UI_DUMP_PULLED=$(( UI_DUMP_PULLED + 1 )) || true
done
ok "Pulled $UI_DUMP_PULLED UI dump XMLs"

ok "All device data pulled"

# ── STEP 10: Extract AndroLog method signatures ───────────────────────────────
step "STEP 10: Extract AndroLog Methods"

METHODS_TXT="$OUT_DIR/androlog_methods.txt"

python3 - <<PY
import re

logcat_path = "$LOGCAT_FILE"
console_path = "$CONSOLE_FILE"

method_angle_re = re.compile(r"METHOD=<([^>]+)>")
# Fallback for variants like: METHOD=com.pkg.Clz->m()V
method_plain_re = re.compile(r"METHOD=([^\s>]+)")

seen = set()
results = []

for path in (logcat_path, console_path):
  try:
    with open(path, encoding="utf-8", errors="replace") as fh:
      for line in fh:
        m = method_angle_re.search(line)
        if not m:
          m = method_plain_re.search(line)
        if m:
          sig = m.group(1).strip("<> ")
          if sig and sig not in seen:
            seen.add(sig)
            results.append(sig)
  except FileNotFoundError:
    pass

with open("$METHODS_TXT", "w", encoding="utf-8") as out:
  out.write("\n".join(results))

print(f"Extracted {len(results)} unique AndroLog method signatures")
PY
ok "Method signatures extracted: $METHODS_TXT"

# ── STEP 11: Extract UI widget text from XML dumps ───────────────────────────
step "STEP 11: Extract UI Widget Text"

UI_TEXT_FILE="$OUT_DIR/ui_widget_text.txt"

python3 - <<PY
import os, re
from xml.etree import ElementTree as ET

dump_dir = "$OUT_DIR/ui_dumps"
collected = []
xml_count = 0
for fname in sorted(os.listdir(dump_dir)) if os.path.isdir(dump_dir) else []:
    if not fname.endswith(".xml"):
        continue
    xml_path = os.path.join(dump_dir, fname)
    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
        for node in root.iter():
            text = node.attrib.get("text", "").strip()
            desc = node.attrib.get("content-desc", "").strip()
            if text and len(text) > 1:
                collected.append(text)
            if desc and len(desc) > 1 and desc != text:
                collected.append(desc)
        xml_count += 1
    except Exception:
        pass

# Also include activity names from activity log as UI evidence
try:
    import json
    with open("$ACTIVITY_FILE", encoding="utf-8") as f:
        act = json.load(f)
    for a in act.get("TestedActivity", []) + act.get("TotalActivity", []):
        parts = a.split(".")
        if parts:
            collected.append(parts[-1])  # Short activity name as UI signal
except Exception:
    pass

unique_text = list(dict.fromkeys(t for t in collected if t))
with open("$UI_TEXT_FILE", "w", encoding="utf-8") as out:
    out.write("\n".join(unique_text))
print(f"Extracted {len(unique_text)} unique UI text strings from {xml_count} XML dumps")
PY
ok "UI widget text extracted: $UI_TEXT_FILE"

# ── STEP 12: Run Backdoor Detection Python Pipeline ───────────────────────────
step "STEP 12: LLM Backdoor Detection Analysis"

PROMPT_OUT_DIR="$OUT_DIR/backdoor_analysis"
mkdir -p "$PROMPT_OUT_DIR"

# Copy config.json where the Python script can find it
cp "$OUT_DIR/config.json" "$DETECT_DIR/config.json"

export ECHODROID_LOGCAT_FILE="$LOGCAT_FILE"
export ECHODROID_ACTIVITY_FILE="$ACTIVITY_FILE"
export ECHODROID_UI_TEXT_FILE="$UI_TEXT_FILE"
export ECHODROID_UI_DUMP_DIR="$OUT_DIR/ui_dumps"
export ECHODROID_PROMPT_OUTPUT_DIR="$PROMPT_OUT_DIR"
export ECHODROID_CONFIG_FILE="$OUT_DIR/config.json"

info "Running Prompt_BackdoorDetection.py..."
python3 "$DETECT_DIR/Prompt_BackdoorDetection.py" \
  "$LOGCAT_FILE" \
  "$ACTIVITY_FILE" \
  > "$OUT_DIR/backdoor_pipeline.log" 2>&1 && PIPELINE_OK=1 || PIPELINE_OK=0

# Restore original config
if [[ -f "$DETECT_DIR/config.json.bak" ]]; then
  mv "$DETECT_DIR/config.json.bak" "$DETECT_DIR/config.json"
fi

REPORT_FILE="$PROMPT_OUT_DIR/backdoor_detection_report.json"

# ── FINAL SUMMARY ─────────────────────────────────────────────────────────────
step "FINAL RESULTS"

if [[ -f "$REPORT_FILE" ]]; then
  python3 - <<PY
import json, sys
try:
    with open("$REPORT_FILE", encoding="utf-8") as f:
        report = json.load(f)
    verdict = report.get("backdoor_verdict", {})
    patterns = report.get("backdoor_patterns", [])

    print("=" * 70)
    print(f"  APP          : {report.get('app', {}).get('name', '?')}")
    print(f"  PACKAGE      : {report.get('app', {}).get('package', '?')}")
    print(f"  VERDICT      : {verdict.get('verdict', '?')}")
    print(f"  RISK LEVEL   : {verdict.get('risk_level', '?').upper()}")
    print(f"  CONFIDENCE   : {verdict.get('confidence', 0):.0%}")
    print(f"  PATTERNS     : {verdict.get('total_patterns_found', 0)} found")
    print("=" * 70)

    if patterns:
        print("\n  BACKDOOR PATTERN SUMMARY:")
        for i, p in enumerate(patterns, 1):
            print(f"  [{i}] {p.get('backdoor_type','?'):22s} | "
                  f"category={p.get('permission_category','?'):14s} | "
                  f"risk={p.get('risk_level','?'):8s}")
            expl = p.get('explanation', '')
            if expl:
                print(f"       {expl[:80]}")

    recs = report.get("recommendations", [])
    if recs:
        print("\n  RECOMMENDATIONS:")
        for r in recs[:4]:
            print(f"  • {r}")

    print(f"\n  FULL REPORT: $REPORT_FILE")
except Exception as e:
    print(f"[WARN] Could not parse report: {e}")
PY
else
  warn "Backdoor report not generated; check $OUT_DIR/backdoor_pipeline.log"
  if [[ -f "$OUT_DIR/backdoor_pipeline.log" ]]; then
    echo ""
    echo "=== Pipeline log (last 30 lines) ==="
    tail -30 "$OUT_DIR/backdoor_pipeline.log"
  fi
fi

echo ""
echo -e "${GREEN}Run complete.${NC}"
echo -e "  Output directory : $OUT_DIR"
echo -e "  Analysis results : $PROMPT_OUT_DIR"
[[ -f "$REPORT_FILE" ]] && echo -e "  Backdoor report  : $REPORT_FILE"
echo ""
