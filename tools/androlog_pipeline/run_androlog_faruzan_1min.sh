#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -lt 7 ]; then
  echo "Usage: $0 <project_dir> <apk_path> <package> <app_name> <tag> <run_prefix> <instrument_dir_or_dash>" >&2
  exit 1
fi

BASE=$HOME/Desktop/MismatchDroid/MismatchDroid
PROJECT_DIR=$(realpath "$1")
APK_PATH=$(realpath "$2")
PKG="$3"
APP_NAME="$4"
TAG="$5"
RUN_PREFIX="$6"
INSTRUMENT_DIR="$7"
TS=$(date +%Y%m%d_%H%M%S)
OUT_BASE="$BASE/Overall_test_output/test_results/${RUN_PREFIX}_${TS}"
REMOTE_OUT="/sdcard/${RUN_PREFIX}_${TS}"
mkdir -p "$OUT_BASE"

TOTAL_METHOD=1
if [ "$INSTRUMENT_DIR" != "-" ] && [ -d "$INSTRUMENT_DIR/decompiled" ]; then
  COUNT=$(grep -Rh "METHOD=" "$INSTRUMENT_DIR/decompiled"/smali* 2>/dev/null | wc -l | tr -d ' ' || true)
  if [ -n "$COUNT" ] && [ "$COUNT" != "0" ]; then
    TOTAL_METHOD="$COUNT"
  fi
fi

python3 - <<PY
import json
from pathlib import Path
base = Path("$BASE")
out = Path("$OUT_BASE/config.json")
api = json.loads((base / 'config.json').read_text()).get('ApiKey', '')
cfg = {
  'AppName': '$APP_NAME',
  'Description': '$APP_NAME automated 1-minute run',
  'ApiKey': api,
  'TotalMethod': int('$TOTAL_METHOD'),
  'Tag': '$TAG',
  'Model': 'gpt-4o-mini',
  'BaseUrl': 'https://api.openai.com/v1'
}
out.write_text(json.dumps(cfg, indent=2))
print('Wrote config with ApiKey length:', len(api))
PY

adb -s emulator-5554 wait-for-device >/dev/null
adb -s emulator-5554 shell "pkill -f 'com.android.commands.monkey.Monkey' || true" >/dev/null 2>&1 || true
adb -s emulator-5554 uninstall "$PKG" >/dev/null 2>&1 || true
# Install APK; use -d (allow downgrade) to handle older APK versions.
INSTALL_OUT=$(adb -s emulator-5554 install -r "$APK_PATH" 2>&1 || true)
if echo "$INSTALL_OUT" | grep -q "INSTALL_FAILED_VERSION_DOWNGRADE"; then
  echo "Version downgrade detected, retrying with -d flag..."
  adb -s emulator-5554 install -r -d "$APK_PATH"
elif echo "$INSTALL_OUT" | grep -q "Failure"; then
  echo "Install failed: $INSTALL_OUT" && exit 1
fi

adb -s emulator-5554 shell rm -rf /sdcard/faruzan >/dev/null 2>&1 || true
adb -s emulator-5554 shell mkdir /sdcard/faruzan >/dev/null
adb -s emulator-5554 push "$OUT_BASE/config.json" /sdcard/config.json >/dev/null
adb -s emulator-5554 push "$PROJECT_DIR/monkey/libs/"* /sdcard/faruzan/ >/dev/null
adb -s emulator-5554 push "$PROJECT_DIR/monkeyq.jar" /sdcard/faruzan/monkeyq.jar >/dev/null
adb -s emulator-5554 push "$PROJECT_DIR/fastbot-thirdpart.jar" /sdcard/faruzan/fastbot-thirdpart.jar >/dev/null
adb -s emulator-5554 push "$PROJECT_DIR/framework.jar" /sdcard/faruzan/framework.jar >/dev/null
adb -s emulator-5554 shell mkdir -p /data/local/tmp/x86_64 >/dev/null
if [ -f "$PROJECT_DIR/libs/x86_64/libfastbot_native.so" ]; then
  adb -s emulator-5554 push "$PROJECT_DIR/libs/x86_64/libfastbot_native.so" /data/local/tmp/x86_64/libfastbot_native.so >/dev/null
elif [ -f "$BASE/MismatchDroid-Fastbot/libs/x86_64/libfastbot_native.so" ]; then
  adb -s emulator-5554 push "$BASE/MismatchDroid-Fastbot/libs/x86_64/libfastbot_native.so" /data/local/tmp/x86_64/libfastbot_native.so >/dev/null
fi

adb -s emulator-5554 shell am force-stop "$PKG" >/dev/null 2>&1 || true
adb -s emulator-5554 shell monkey -p "$PKG" -c android.intent.category.LAUNCHER 1 >/dev/null 2>&1 || true
sleep 2
adb -s emulator-5554 shell rm -rf "$REMOTE_OUT" >/dev/null 2>&1 || true

adb -s emulator-5554 shell CLASSPATH=/sdcard/faruzan/monkeyq.jar:/sdcard/faruzan/framework.jar:/sdcard/faruzan/fastbot-thirdpart.jar:/sdcard/faruzan/org.jacoco.core-0.8.8.jar:/sdcard/faruzan/asm-9.2.jar:/sdcard/faruzan/asm-analysis-9.2.jar:/sdcard/faruzan/asm-commons-9.2.jar:/sdcard/faruzan/asm-tree-9.2.jar exec app_process /system/bin com.android.commands.monkey.Monkey -p "$PKG" --agent reuseq --use-code-coverage androlog --running-minutes 1 --throttle 3000 --output-directory "$REMOTE_OUT" -v -v --bugreport > "$OUT_BASE/console.txt" 2>&1 || true

adb -s emulator-5554 pull "$REMOTE_OUT" "$OUT_BASE/" >/dev/null 2>&1 || true

EC_DIR="$OUT_BASE/ec_files"
mkdir -p "$EC_DIR"
adb -s emulator-5554 shell "find /sdcard /storage/emulated/0 -path '*$PKG*' -name '*.ec' 2>/dev/null" > "$OUT_BASE/ec_files_on_device.txt" || true
adb -s emulator-5554 shell "run-as $PKG sh -c 'find . -name \"*.ec\" 2>/dev/null | sed \"s#^#RUN_AS:$PKG/#\"'" >> "$OUT_BASE/ec_files_on_device.txt" 2>/dev/null || true
sort -u "$OUT_BASE/ec_files_on_device.txt" -o "$OUT_BASE/ec_files_on_device.txt" || true
while IFS= read -r ec_path; do
  [ -n "$ec_path" ] || continue
  case "$ec_path" in
    RUN_AS:*)
      rel_path="${ec_path#RUN_AS:}"
      safe_name=$(echo "$rel_path" | sed 's#/#_#g')
      adb -s emulator-5554 exec-out run-as "$PKG" cat "${rel_path#${PKG}/}" > "$EC_DIR/$safe_name" 2>/dev/null || rm -f "$EC_DIR/$safe_name"
      ;;
    *)
      adb -s emulator-5554 pull "$ec_path" "$EC_DIR/" >/dev/null 2>&1 || true
      ;;
  esac
done < "$OUT_BASE/ec_files_on_device.txt"

python3 - <<PY
import re, json
from pathlib import Path
base = Path("$OUT_BASE")
txt = (base / 'console.txt').read_text(errors='ignore') if (base / 'console.txt').exists() else ''
ec_files = sorted(str(p.name) for p in (base / 'ec_files').glob('*.ec')) if (base / 'ec_files').exists() else []
m = [float(x) for x in re.findall(r'currentCodeCoverage:\\s*([0-9]+\\.[0-9]+)', txt)]
a = [float(x) for x in re.findall(r'Activity of Coverage:\\s*([0-9]+\\.[0-9]+)', txt)]
summary = {
  'code_coverage_final': m[-1] if m else None,
  'code_coverage_max': max(m) if m else None,
  'code_coverage_samples': len(m),
  'activity_coverage_final': a[-1] if a else None,
  'activity_coverage_max': max(a) if a else None,
  'activity_coverage_samples': len(a),
  'set_key_failed': ('Set key failed' in txt),
  'mutex_crash': ('destroyed mutex' in txt),
  'ec_files_found': len(ec_files),
  'ec_files': ec_files,
  'total_method': int('$TOTAL_METHOD')
}
(base / 'coverage_summary.json').write_text(json.dumps(summary, indent=2))
print(json.dumps(summary, indent=2))
print('RESULT_DIR=' + str(base))
PY
