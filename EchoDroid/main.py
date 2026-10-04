#!/usr/bin/env python3
"""
Prompt_BackdoorDetection.py  ─  UI-vs-Backend Backdoor Detection Pipeline
==========================================================================
EchoDroid-fastbot-custom-more-detection

THEORY
------
A backdoor in an Android app exists when the app performs sensitive operations
(accessing SMS, location, contacts, device identifiers, etc.) WITHOUT ever
disclosing or justifying that behaviour to the user through the UI.

We detect this by crossing three data sources collected during a Fastbot run:

  1. UI Evidence   – Activity names visited + on-screen widget text (what the
                     user sees and what the app *claims* to do)
  2. Backend Data  – AndroLog method call log (what the app *actually* executes)
  3. Manifest      – Declared permissions (what the app is *allowed* to do)

BACKDOOR PATTERNS
-----------------
  SILENT_EXEC    – Backend uses a sensitive API that the UI never mentions
  COVERT_COLLECT – Sensitive data (location, contacts, SMS) harvested silently
  OVER_DECLARED  – Permission declared but never used anywhere (zombie / steganographic)
  HIDDEN_TRIGGER – Exported component triggers sensitive API with no UI entry point

PIPELINE (3 LLM Prompts)
------------------------
  Prompt 1  : UI Surface Analysis   → what capabilities/permissions the UI presents
  Prompt 2  : Backend Analysis      → what sensitive APIs the backend actually calls
  Prompt 3  : Mismatch Detection    → cross-reference to find backdoor indicators

DATA SOURCES (resolved via env-vars or config, all optional with graceful fallback)
-------------------
    ECHODROID_LOGCAT_FILE     → full logcat file; METHOD= lines extracted automatically
    ECHODROID_ACTIVITY_FILE   → max.activity.statistics.log  (JSON)
    ECHODROID_UI_TEXT_FILE    → text file with concatenated UI widget text from dumps
    ECHODROID_ANDROLOG_METHODS_FILE → pre-extracted methods txt (one sig per line)
  config.json              → ManifestPath | ManifestPermissions | ExportedComponents
"""

import json
import os
import re
import subprocess
import sys
import zipfile
from datetime import datetime
from xml.etree import ElementTree as ET

try:
    from openai import OpenAI
except ImportError:
    print("[WARN] openai package not found; LLM prompts will be skipped (dry-run mode)")
    OpenAI = None  # type: ignore

# ---------------------------------------------------------------------------
# CONFIG
# ---------------------------------------------------------------------------
# Per-run config path (set by run_backdoor_detection.sh to avoid concurrent-run races)
_ENV_CONFIG = os.environ.get("ECHODROID_CONFIG_FILE", "").strip()
_CONFIG_SEARCH_PATHS = (
    [_ENV_CONFIG] if _ENV_CONFIG else []
) + ["/sdcard/config.json", "./config.json"]

config: dict = {}
for _p in _CONFIG_SEARCH_PATHS:
    if _p and os.path.exists(_p):
        with open(_p, encoding="utf-8") as _f:
            config = json.load(_f)
        print(f"[CONFIG] Loaded from: {_p}")
        break

if not config:
    print("[WARN] config.json not found; using env defaults only")

APP_NAME   = config.get("AppName", os.environ.get("ECHODROID_APP_NAME", "UnknownApp"))
APP_DESC   = config.get("Description", "")
API_KEY    = config.get("ApiKey", os.environ.get("OPENAI_API_KEY", ""))
MODEL      = config.get("Model", "gpt-4.1")
BASE_URL   = config.get("BaseUrl", "https://api.openai.com/v1")

MANIFEST_PATH       = config.get("ManifestPath", "")
MANIFEST_PERMS_CFG  = config.get("ManifestPermissions", [])
EXPORTED_COMPS_CFG  = config.get("ExportedComponents", [])
PKG_NAME            = config.get("PackageName", config.get("Tag", "").replace("_LOG", "").lower())

# Output directory
_OUT_DIR_ENV = os.environ.get("ECHODROID_PROMPT_OUTPUT_DIR", "").strip()
if _OUT_DIR_ENV:
    OUTPUT_DIR = _OUT_DIR_ENV
else:
    OUTPUT_DIR = os.path.join(os.getcwd(), "backdoor-detection-outputs")
os.makedirs(OUTPUT_DIR, exist_ok=True)

# LLM client
_llm_client = None
if OpenAI and API_KEY:
    _llm_client = OpenAI(api_key=API_KEY)
    _llm_client.base_url = BASE_URL
    _llm_client.timeout  = 60000

# ---------------------------------------------------------------------------
# PERMISSION → METHOD KEYWORD MAPPING
# (maps Android permission categories to lower-cased Java/Kotlin method/class
#  name substrings that indicate that permission is being exercised)
# ---------------------------------------------------------------------------
PERMISSION_SIGNAL_MAP: dict = {
    "sms": {
        "keywords":  ["sendtextmessage", "senddatasmsmessage", "sendmultiparttext",
                      "smsmanager", "sms", "mms"],
        "class_hints": ["SmsManager", "MmsManager"],
        "permissions": ["android.permission.SEND_SMS", "android.permission.READ_SMS",
                        "android.permission.RECEIVE_SMS"],
        "ui_keywords": ["sms", "text message", "otp", "verification code", "send message"],
    },
    "location": {
        "keywords":  ["getlastknownlocation", "requestlocationupdates", "fusedlocation",
                      "locationmanager", "locationservices", "getcurrentlocation",
                      "getlocation", "gpslocation"],
        "class_hints": ["LocationManager", "FusedLocationProvider", "LocationClient"],
        "permissions": ["android.permission.ACCESS_FINE_LOCATION",
                        "android.permission.ACCESS_COARSE_LOCATION",
                        "android.permission.ACCESS_BACKGROUND_LOCATION"],
        "ui_keywords": ["location", "gps", "map", "nearby", "find me", "where am i"],
    },
    "contacts": {
        "keywords":  ["contactscontract", "contentresolver", "rawcontacts",
                      "getaccounts", "accountmanager", "contactsuri",
                      "read_contacts", "write_contacts"],
        "class_hints": ["ContactsContract", "AccountManager"],
        "permissions": ["android.permission.READ_CONTACTS",
                        "android.permission.WRITE_CONTACTS",
                        "android.permission.GET_ACCOUNTS",
                        "android.permission.READ_PROFILE"],
        "ui_keywords": ["contacts", "address book", "friends", "people"],
    },
    "camera": {
        "keywords":  ["cameramanager", "cameracapture", "imageanalysis", "takepicture",
                      "opencamera", "camera2", "camerax", "previewview"],
        "class_hints": ["CameraManager", "Camera2", "CameraX"],
        "permissions": ["android.permission.CAMERA"],
        "ui_keywords": ["camera", "photo", "scan", "qr", "barcode", "selfie"],
    },
    "microphone": {
        "keywords":  ["audiorecord", "startrecording", "mediarecorder", "audiocapturer",
                      "setaudiosource", "record_audio"],
        "class_hints": ["AudioRecord", "MediaRecorder"],
        "permissions": ["android.permission.RECORD_AUDIO"],
        "ui_keywords": ["microphone", "record", "voice", "audio", "speak"],
    },
    "phone_state": {
        "keywords":  ["getdeviceid", "getimei", "getimsi", "getsimoperator",
                      "getline1number", "getsubscriberid", "telephonymanager",
                      "read_phone_state"],
        "class_hints": ["TelephonyManager"],
        "permissions": ["android.permission.READ_PHONE_STATE",
                        "android.permission.READ_CALL_LOG",
                        "android.permission.CALL_PHONE"],
        "ui_keywords": ["phone", "call", "dial", "imei"],
    },
    "storage": {
        "keywords":  ["fileoutputstream", "fileinputstream", "getexternalstorage",
                      "getexternalfilesdir", "environment.getexternalstorage",
                      "write_external_storage", "read_external_storage",
                      "manage_external_storage", "storagestatsmanager"],
        "class_hints": ["File", "StorageManager"],
        "permissions": ["android.permission.READ_EXTERNAL_STORAGE",
                        "android.permission.WRITE_EXTERNAL_STORAGE",
                        "android.permission.MANAGE_EXTERNAL_STORAGE"],
        "ui_keywords": ["storage", "files", "download", "save", "backup"],
    },
    "device_admin": {
        "keywords":  ["devicepolicymanager", "lockscreen", "wipedata", "resetpassword",
                      "setpasswordquality", "bind_device_admin"],
        "class_hints": ["DevicePolicyManager"],
        "permissions": ["android.permission.BIND_DEVICE_ADMIN"],
        "ui_keywords": ["device admin", "lock screen", "device policy"],
    },
    "accessibility": {
        "keywords":  ["accessibilityservice", "accessibilityevent", "performaction",
                      "bind_accessibility_service"],
        "class_hints": ["AccessibilityService"],
        "permissions": ["android.permission.BIND_ACCESSIBILITY_SERVICE"],
        "ui_keywords": ["accessibility", "screen reader"],
    },
    "network": {
        "keywords":  ["httpurlconnection", "okhttp", "retrofit", "volley", "urlconnection",
                      "socket", "sslsocket", "https://", "openconnection"],
        "class_hints": ["OkHttpClient", "HttpURLConnection", "SSLSocket"],
        "permissions": ["android.permission.INTERNET",
                        "android.permission.ACCESS_NETWORK_STATE"],
        "ui_keywords": ["internet", "online", "connect", "network"],
    },
    "device_id": {
        "keywords":  ["getdeviceid", "getimei", "getandroidid", "advertisingid",
                      "gethardwareaddress", "getimsi", "getsubscriberid"],
        "class_hints": ["TelephonyManager", "Settings.Secure"],
        "permissions": ["android.permission.READ_PHONE_STATE"],
        "ui_keywords": ["device id", "identifier"],
    },
    "process_exec": {
        "keywords":  ["runtime.exec", "processbuilder", "exec(", "getruntime().exec"],
        "class_hints": ["Runtime", "ProcessBuilder"],
        "permissions": [],
        "ui_keywords": [],
    },
}

# All known dangerous / sensitive Android permissions
ALL_SENSITIVE_PERMISSIONS = {p for cat in PERMISSION_SIGNAL_MAP.values()
                               for p in cat.get("permissions", [])}

# ---------------------------------------------------------------------------
# UTILITIES
# ---------------------------------------------------------------------------

def _utc_now() -> str:
    return datetime.utcnow().isoformat() + "Z"


def _save_json(filename: str, payload: dict) -> str:
    path = os.path.join(OUTPUT_DIR, filename)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, ensure_ascii=False, indent=2)
    return path


def _safe_llm_json(raw: str, default: dict | None = None) -> dict:
    """Extract the first JSON object/array from an LLM text response."""
    if default is None:
        default = {}
    if isinstance(raw, (dict, list)):
        return raw  # type: ignore
    if not isinstance(raw, str):
        return default
    raw = raw.strip()
    start = raw.find('{')
    end   = raw.rfind('}') + 1
    if start != -1 and end > start:
        try:
            return json.loads(raw[start:end])
        except Exception:
            pass
    try:
        return json.loads(raw)
    except Exception:
        return default


def _call_llm(system_msg: str, user_msg: str, tag: str) -> dict:
    """Call the LLM and return parsed JSON. Falls back gracefully."""
    if _llm_client is None:
        print(f"[DRY-RUN] Skipping LLM call for {tag}")
        return {"_dry_run": True, "tag": tag}
    try:
        response = _llm_client.chat.completions.create(
            model=MODEL,
            messages=[
                {"role": "system", "content": system_msg},
                {"role": "user",   "content": user_msg},
            ],
            temperature=0.1,
        )
        raw = response.choices[0].message.content or ""
        result = _safe_llm_json(raw)
        _save_json(f"{tag}_raw_response.txt", {"raw": raw})
        return result
    except Exception as exc:
        print(f"[ERROR] LLM call failed for {tag}: {exc}")
        return {"_llm_error": str(exc), "tag": tag}


# ---------------------------------------------------------------------------
# DATA LOADERS
# ---------------------------------------------------------------------------

def _parse_aapt_permissions(apk_path: str) -> list:
    """Run `aapt/aapt2 dump permissions <apk>` and return list of permission strings with fallbacks."""
    if not apk_path or not os.path.exists(apk_path):
        return []
    for tool in ["aapt", "aapt2"]:
        try:
            cmd = [tool, "dump", "permissions", apk_path]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
            perms: list[str] = []
            for line in result.stdout.splitlines():
                m = re.search(r"name='([^']+)'", line)
                if m:
                    perms.append(m.group(1))
            if perms:
                return perms
        except Exception:
            continue
    # Last resort — try androguard if present, else empty
    try:
        try:
            from androguard.core.bytecodes.apk import APK  # type: ignore
            apk = APK(apk_path)
            perms = apk.get_permissions()
            if perms:
                return perms
        except Exception:
            pass
        with zipfile.ZipFile(apk_path, 'r') as zf:
            if 'AndroidManifest.xml' in zf.namelist():
                return []
    except Exception:
        pass
    return []


def _parse_aapt_exported_components(apk_path: str) -> list:
    """
    Try to extract exported component names via aapt xmltree on AndroidManifest.xml.
    Returns list of component class names that are externally reachable.

    Notes on exported inference (legacy behavior):
    - If android:exported="true"  -> exported
    - If android:exported="false" -> NOT exported
    - If android:exported is absent but the component has an <intent-filter>,
      it is implicitly exported on older Android versions. Many Drebin-era APKs
      rely on this and will otherwise appear as having 0 exported components.
    """
    if not apk_path or not os.path.exists(apk_path):
        return []
    try:
        result = subprocess.run(
            ["aapt", "dump", "xmltree", apk_path, "AndroidManifest.xml"],
            capture_output=True, text=True, timeout=20
        )
        exported: list[str] = []

        # Parse aapt xmltree indentation to associate attributes + intent-filters
        # with the nearest component element.
        comp_re = re.compile(r"\bE:\s+(activity|receiver|service|provider)\b")
        name_re = re.compile(r"A:\s+android:name\b.*=\"([^\"]+)\"")
        exported_re = re.compile(r"A:\s+android:exported\b.*=\"(true|false)\"")

        current: dict | None = None

        def _finalize(cur: dict | None):
            if not cur:
                return
            nm = (cur.get("name") or "").strip()
            if not nm:
                return
            exp = cur.get("exported")
            has_if = bool(cur.get("has_intent_filter"))
            # Decide exportability
            if exp is True:
                exported.append(nm)
            elif exp is False:
                return
            else:
                # Legacy implicit-export rule
                if has_if:
                    exported.append(nm)

        for raw in result.stdout.splitlines():
            line = raw.rstrip("\n")
            indent = len(line) - len(line.lstrip(" "))

            # Start of a new component element
            if comp_re.search(line):
                _finalize(current)
                current = {
                    "indent": indent,
                    "name": None,
                    "exported": None,
                    "has_intent_filter": False,
                }
                continue

            if not current:
                continue

            # If we moved back to same/shallower indent, the current component ended.
            if indent <= int(current.get("indent", 10**9)) and line.lstrip().startswith("E:"):
                _finalize(current)
                current = None
                continue

            # Attributes within current component
            nm = name_re.search(line)
            if nm:
                # aapt xmltree contains many nested android:name attributes
                # (e.g., intent-filter action/category). Keep the *component*
                # name (first occurrence inside the component block).
                if not current.get("name"):
                    current["name"] = nm.group(1)
                continue
            ex = exported_re.search(line)
            if ex:
                current["exported"] = (ex.group(1) == "true")
                continue
            if "E: intent-filter" in line:
                current["has_intent_filter"] = True

        _finalize(current)

        return sorted(set(exported))
    except Exception as e:
        print(f"[WARN] aapt exported components parse failed: {e}")
        return []


def load_manifest_data() -> dict:
    """
    Collect manifest permissions and exported components from all sources.
    Priority: ManifestPath (aapt) > ManifestPermissions list in config.
    """
    perms    = []
    exported = list(EXPORTED_COMPS_CFG)

    if MANIFEST_PATH:
        perms_from_aapt = _parse_aapt_permissions(MANIFEST_PATH)
        if perms_from_aapt:
            perms = perms_from_aapt
        if not EXPORTED_COMPS_CFG:
            exported = _parse_aapt_exported_components(MANIFEST_PATH)

    if not perms:
        perms = list(MANIFEST_PERMS_CFG)

    sensitive = [p for p in perms if p in ALL_SENSITIVE_PERMISSIONS]
    by_category: dict = {}
    for cat, rule in PERMISSION_SIGNAL_MAP.items():
        matched = [p for p in perms if p in rule["permissions"]]
        if matched:
            by_category[cat] = matched

    return {
        "all_permissions":       perms,
        "sensitive_permissions": sensitive,
        "by_category":           by_category,
        "exported_components":   exported,
    }


def load_androlog_methods(logcat_file: str = "") -> list:
    """
    Parse all METHOD=<...> lines from an AndroLog logcat file.
    Also accepts a plain pre-extracted methods file (one signature per line).

    Returns list of dicts:
      { full_sig, class_name, short_class, method_name, is_sensitive,
        matched_categories }
    """
    if not logcat_file:
        logcat_file = os.environ.get("ECHODROID_LOGCAT_FILE", "")
    if not logcat_file:
        logcat_file = os.environ.get("ECHODROID_ANDROLOG_METHODS_FILE", "")
    if not logcat_file or not os.path.exists(logcat_file):
        # Try default device-pulled location
        for candidate in ["/sdcard/echodroid_logcat.txt", "./logcat.txt"]:
            if os.path.exists(candidate):
                logcat_file = candidate
                break

    if not logcat_file or not os.path.exists(logcat_file):
        print("[WARN] No AndroLog logcat file found; backend analysis will be limited")
        return []

    # Regex for METHOD=<ClassName: returnType methodName(params)> and logcat timestamp
    method_re = re.compile(r"METHOD=<([^>]+)>")
    timestamp_re = re.compile(r"(\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d+)")
    seen: set = set()
    methods: list = []

    first_ts: str | None = None
    with open(logcat_file, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            m = method_re.search(line)
            if not m:
                continue
            full_sig = m.group(1).strip()
            if full_sig in seen:
                continue
            seen.add(full_sig)
            ts_match = timestamp_re.search(line)
            timestamp = ts_match.group(1) if ts_match else None
            if timestamp and first_ts is None:
                first_ts = timestamp

            # Parse: "com.example.Foo: ReturnType methodName(params)"
            class_name   = ""
            method_name  = ""
            colon_idx = full_sig.find(":")
            if colon_idx != -1:
                class_name  = full_sig[:colon_idx].strip()
                rest = full_sig[colon_idx+1:].strip()
                # rest = "ReturnType methodName(params)" or "void methodName()"
                paren = rest.find("(")
                before_paren = rest[:paren].strip() if paren != -1 else rest.strip()
                parts = before_paren.split()
                method_name = parts[-1] if parts else before_paren
            else:
                class_name  = full_sig
                method_name = ""

            short_class = class_name.split(".")[-1]
            sig_lower   = (class_name + " " + method_name).lower()

            # Classify into permission categories
            matched_cats: list = []
            for cat, rule in PERMISSION_SIGNAL_MAP.items():
                if any(kw in sig_lower for kw in rule["keywords"]):
                    matched_cats.append(cat)
                if any(hint.lower() in class_name.lower() for hint in rule["class_hints"]):
                    if cat not in matched_cats:
                        matched_cats.append(cat)

            entry = {
                "full_sig":          full_sig,
                "class_name":        class_name,
                "short_class":       short_class,
                "method_name":       method_name,
                "is_sensitive":      len(matched_cats) > 0,
                "matched_categories": matched_cats,
            }
            if timestamp:
                entry["timestamp"] = timestamp
                try:
                    if first_ts:
                        fmt = "%m-%d %H:%M:%S.%f"
                        t0 = datetime.strptime(first_ts, fmt)
                        t1 = datetime.strptime(timestamp, fmt)
                        entry["fires_immediately"] = (t1 - t0).total_seconds() < 3.0
                except Exception:
                    pass
            methods.append(entry)

    print(f"[DATA] Loaded {len(methods)} unique method signatures from AndroLog")
    return methods


def load_activity_data(activity_file: str = "") -> dict:
    """
    Load max.activity.statistics.log — JSON with TestedActivity, TotalActivity, Coverage.
    """
    if not activity_file:
        activity_file = os.environ.get("ECHODROID_ACTIVITY_FILE", "")
    if not activity_file or not os.path.exists(activity_file):
        for candidate in ["/sdcard/max.activity.statistics.log",
                          "./max.activity.statistics.log"]:
            if os.path.exists(candidate):
                activity_file = candidate
                break

    if not activity_file or not os.path.exists(activity_file):
        print("[WARN] Activity statistics file not found; using empty activity list")
        return {"TestedActivity": [], "TotalActivity": [], "Coverage": 0}

    try:
        with open(activity_file, encoding="utf-8", errors="replace") as fh:
            data = json.load(fh)
        return data
    except Exception as e:
        print(f"[WARN] Failed to load activity file: {e}")
        return {"TestedActivity": [], "TotalActivity": [], "Coverage": 0}


def load_ui_text(ui_text_file: str = "", ui_dump_dir: str = "") -> str:
    """
    Load concatenated UI widget text from:
    1. A single merged text file  (ECHODROID_UI_TEXT_FILE)
    2. A directory of uiautomator XML dumps  (ECHODROID_UI_DUMP_DIR)
    Returns a plain text string with all visible UI labels/descriptions.
    """
    if not ui_text_file:
        ui_text_file = os.environ.get("ECHODROID_UI_TEXT_FILE", "")
    if not ui_dump_dir:
        ui_dump_dir  = os.environ.get("ECHODROID_UI_DUMP_DIR", "")

    collected: list = []

    # Option A: single text file
    if ui_text_file and os.path.exists(ui_text_file):
        with open(ui_text_file, encoding="utf-8", errors="replace") as fh:
            collected.append(fh.read())

    # Option B: directory of XML dumps
    if ui_dump_dir and os.path.isdir(ui_dump_dir):
        for fname in sorted(os.listdir(ui_dump_dir)):
            if not fname.endswith(".xml"):
                continue
            xml_path = os.path.join(ui_dump_dir, fname)
            try:
                tree = ET.parse(xml_path)
                root = tree.getroot()
                for node in root.iter():
                    text = node.attrib.get("text", "").strip()
                    desc = node.attrib.get("content-desc", "").strip()
                    if text:
                        collected.append(text)
                    if desc and desc != text:
                        collected.append(desc)
            except Exception:
                pass

    result = "\n".join(collected)
    if result:
        print(f"[DATA] Loaded {len(result)} chars of UI text")
    else:
        print("[WARN] No UI text found; UI analysis will rely on activity names only")
    return result


# ---------------------------------------------------------------------------
# TEXT & EVIDENCE HELPERS
# ---------------------------------------------------------------------------

def has_ui_keyword(ui_text: str, activity_text: str, keywords: list) -> bool:
    """Word-boundary matching to avoid substr false-positives (e.g., 'sms' in 'assessment')."""
    combined = f"{ui_text} {activity_text}"
    for kw in keywords or []:
        if not kw:
            continue
        pattern = r"\b" + re.escape(kw) + r"\b"
        if re.search(pattern, combined, re.IGNORECASE):
            return True
    return False


def clean_ui_text(ui_text: str, max_chars: int = 6000) -> str:
    lines = ui_text.split("\n") if ui_text else []
    seen = set()
    uniq = []
    for ln in lines:
        s = ln.strip()
        if s and s not in seen and len(s) > 1:
            seen.add(s)
            uniq.append(s)
    result = "\n".join(uniq)
    return result[:max_chars]


def calibrate_confidence(base_confidence: float, activity_coverage: float, ui_text_length: int, methods_count: int) -> float:
    calibrated = base_confidence
    if activity_coverage < 10:
        calibrated *= 0.5
    elif activity_coverage < 25:
        calibrated *= 0.7
    elif activity_coverage < 50:
        calibrated *= 0.85
    if ui_text_length < 100:
        calibrated *= 0.6
    elif ui_text_length < 500:
        calibrated *= 0.8
    if methods_count < 50:
        calibrated *= 0.7
    return round(min(calibrated, base_confidence), 2)


# ---------------------------------------------------------------------------
# PRE-PROCESSING: summarise method evidence per permission category
# ---------------------------------------------------------------------------

def build_backend_category_summary(methods: list) -> dict:
    """
    Group sensitive method signatures by permission category.
    Returns {category: [full_sig, ...]}  (up to 15 examples each)
    """
    cat_map: dict = {}
    for m in methods:
        for cat in m["matched_categories"]:
            cat_map.setdefault(cat, [])
            if len(cat_map[cat]) < 15:
                cat_map[cat].append(m["full_sig"])
    return cat_map


def build_class_summary(methods: list) -> list:
    """
    Return a de-duplicated list of short class names from all called methods.
    """
    return sorted({m["short_class"] for m in methods if m["short_class"]})


# ---------------------------------------------------------------------------
# PROMPT 1 — UI Surface Analysis
# What capabilities does the app present / justify through its UI?
# ---------------------------------------------------------------------------
PROMPT1_SYSTEM = """
You are a mobile-security analyst specialising in Android app backdoor detection.

Your task: analyse the USER-VISIBLE side of an Android app (activity names visited +
on-screen text captured during automated UI testing) and determine:

  1. What permission-sensitive capabilities does the UI EXPLICITLY present to the user?
     (e.g., "Share your location", a login screen, a camera shutter button, SMS compose)
  2. For each sensitive permission category below, does the UI JUSTIFY the usage?
     Categories: sms, location, contacts, camera, microphone, phone_state, storage,
                 device_admin, accessibility, network, device_id, process_exec
  3. What is the user-stated purpose of this app from the UI?
  4. Which permission categories are COMPLETELY ABSENT from the UI (no mention at all)?

Return ONLY valid JSON — no markdown, no prose:
{
  "app_ui_stated_purpose": "short string",
  "ui_permission_claims": {
    "<category>": {
      "visible_in_ui": true,
      "justification_strength": "explicit|implied|absent",
      "ui_evidence": ["list of exact UI text or activity names that prove this"]
    }
  },
  "categories_absent_from_ui": ["sms", "..."],
  "sensitive_flows_detected": [
    {"flow_name": "string", "activities": ["..."], "description": "string"}
  ],
  "overall_ui_transparency_score": 0.0
}
""".strip()


def run_prompt1_ui_analysis(
    activity_data: dict,
    ui_text: str,
    manifest_data: dict,
) -> dict:
    """Prompt 1: analyse what the UI presents to the user."""
    tested   = activity_data.get("TestedActivity", [])
    total    = activity_data.get("TotalActivity", [])
    coverage = activity_data.get("Coverage", 0)

    # Clean and truncate UI text to avoid context overflow while preserving diversity
    ui_text_truncated = clean_ui_text(ui_text, max_chars=6000)

    user_msg = f"""APP: {APP_NAME}
DESCRIPTION: {APP_DESC}
PACKAGE: {PKG_NAME}

MANIFEST PERMISSIONS DECLARED: {json.dumps(manifest_data['all_permissions'])}
EXPORTED COMPONENTS: {json.dumps(manifest_data['exported_components'])}

ACTIVITIES VISITED DURING TESTING ({len(tested)} of {len(total)} total, coverage={coverage}%):
{json.dumps(tested, indent=2)}

ALL ACTIVITIES IN APP:
{json.dumps(total[:60], indent=2)}

UI WIDGET TEXT OBSERVED ON-SCREEN (from captured screenshots):
---
{ui_text_truncated if ui_text_truncated else "(no UI text captured – rely on activity names)"}
---

Based on the activity names and on-screen text above, analyse what the UI presents.
"""
    print("[P1] Running UI Surface Analysis...")
    result = _call_llm(PROMPT1_SYSTEM, user_msg, "prompt1_ui")
    _save_json("prompt1_ui_analysis.json", result)
    return result


# ---------------------------------------------------------------------------
# PROMPT 2 — Backend Execution Analysis
# What sensitive APIs does the backend actually call?
# ---------------------------------------------------------------------------
PROMPT2_SYSTEM = """
You are a mobile-security analyst specialising in Android runtime analysis.

You will receive:
  • A categorised map of sensitive methods actually CALLED at runtime (from AndroLog)
  • A sample of ALL unique class names observed at runtime
  • The declared manifest permissions

Your task:
  1. For EACH permission category with runtime evidence, confirm it is genuinely active
     (not just a library method, test utility, or benign usage).
  2. Flag any methods that are UNUSUAL, SUSPICIOUS, or indicative of MALICIOUS intent.
  3. Identify if any sensitive capability is exercised from a NON-ACTIVITY class
     (e.g., a background Service or BroadcastReceiver) — this is a strong backdoor signal.
  4. Identify any STEALTHY patterns:
     - Device fingerprinting (IMEI/IMSI/Android ID without user knowledge)
     - Silent SMS sending
     - Background location harvesting
     - Keylogging via accessibility service
     - Command-and-control patterns (exec/shell execution)

Return ONLY valid JSON:
{
  "backend_active_capabilities": {
    "<category>": {
      "active": true,
      "confidence": "high|medium|low",
      "triggering_methods": ["method sigs (up to 5)"],
      "triggering_classes": ["class names"],
      "is_background_only": false,
      "notes": "any observations"
    }
  },
  "suspicious_methods": [
    {
      "full_sig": "...",
      "reason": "why suspicious",
            "backdoor_pattern": "SILENT_EXEC|COVERT_COLLECT|HIDDEN_TRIGGER|NONE"
    }
  ],
  "background_sensitive_classes": ["classes that are NOT activities but call sensitive APIs"],
  "stealthy_patterns_found": ["description1", "description2"]
}
""".strip()


def run_prompt2_backend_analysis(
    methods: list,
    backend_cat_summary: dict,
    manifest_data: dict,
) -> dict:
    """Prompt 2: analyse what the backend actually executes."""
    class_names = build_class_summary(methods)[:80]

    # Build suspicious-looking methods sample (max 30)
    suspicious_sample = [m["full_sig"] for m in methods if m["is_sensitive"]][:30]

    user_msg = f"""APP: {APP_NAME}
PACKAGE: {PKG_NAME}

TOTAL UNIQUE METHODS CALLED AT RUNTIME: {len(methods)}

SENSITIVE METHODS GROUPED BY PERMISSION CATEGORY (from runtime AndroLog log):
{json.dumps(backend_cat_summary, indent=2)}

ALL UNIQUE CLASS NAMES SEEN AT RUNTIME (sample, max 80):
{json.dumps(class_names, indent=2)}

SENSITIVE METHOD SIGNATURES SAMPLE (max 30):
{json.dumps(suspicious_sample, indent=2)}

DECLARED MANIFEST PERMISSIONS:
{json.dumps(manifest_data['all_permissions'], indent=2)}

EXPORTED COMPONENTS (can be triggered externally without user interaction):
{json.dumps(manifest_data['exported_components'], indent=2)}

Analyse the backend runtime behaviour for sensitive/malicious activity.
"""
    print("[P2] Running Backend Execution Analysis...")
    result = _call_llm(PROMPT2_SYSTEM, user_msg, "prompt2_backend")
    _save_json("prompt2_backend_analysis.json", result)
    return result


# ---------------------------------------------------------------------------
# PROMPT 3 — Backdoor Mismatch Detection (the key insight)
# Cross-reference UI claims vs backend reality
# ---------------------------------------------------------------------------
PROMPT3_SYSTEM = """
You are a senior Android malware analyst performing BACKDOOR DETECTION.

You will receive:
  • UI Analysis  (Prompt 1): what the app claims / shows to the user
  • Backend Analysis (Prompt 2): what the app actually does at runtime
  • Manifest: declared permissions
  • Exported components: components accessible from outside the app

YOUR MISSION: Find UI-vs-Backend MISMATCHES that indicate a BACKDOOR.

BACKDOOR PATTERNS TO DETECT
────────────────────────────
  SILENT_EXEC     Backend uses sensitive capability X, but UI NEVER mentions X.
                  → The user has no idea the app is accessing X.

  COVERT_COLLECT  Sensitive personal data (location, contacts, SMS, device ID) is
                  harvested silently with no user notification or justification.

  OVER_DECLARED   Permission is declared in manifest but NEVER exercised at runtime
                  AND never mentioned in the UI. Could be a zombie permission planted
                  for future activation or to evade static permission analysis.

  HIDDEN_TRIGGER  An exported component (activity/service/receiver) that can be
                  triggered externally and executes sensitive APIs not reachable
                  from the normal UI flow.

For each mismatch you find, provide:
    • backdoor_type: one of the types above
  • permission_category: e.g. "sms", "location", "phone_state"
  • risk_level: "critical" | "high" | "medium" | "low"
  • ui_claim: what the UI said (or "not present in UI")
  • backend_evidence: what methods were actually called
  • explanation: concise, specific, technical explanation
  • confidence: 0.0–1.0

OVERALL VERDICT (choose one):
    "HAS_BACKDOOR"   – high confidence (≥1 critical/high SILENT_EXEC or COVERT_COLLECT)
  "SUSPICIOUS"     – medium confidence (OVER_DECLARED or HIDDEN_TRIGGER, or low-confidence patterns)
  "LIKELY_CLEAN"   – no meaningful mismatches found
  "INSUFFICIENT_DATA" – not enough runtime data to make a determination

Return ONLY valid JSON:
{
  "verdict": "HAS_BACKDOOR|SUSPICIOUS|LIKELY_CLEAN|INSUFFICIENT_DATA",
  "overall_risk_level": "critical|high|medium|low|none",
  "confidence": 0.0,
  "backdoor_patterns": [
    {
      "backdoor_type": "SILENT_EXEC",
      "permission_category": "sms",
      "risk_level": "critical",
      "ui_claim": "not present in UI",
      "backend_evidence": ["com.example.SmsHelper: void sendOtp(String)"],
      "explanation": "...",
      "confidence": 0.9
    }
  ],
  "mismatch_summary": {
    "categories_in_ui_not_in_backend": [],
    "categories_in_backend_not_in_ui": [],
    "categories_in_manifest_not_used": [],
    "categories_used_without_permission": []
  },
  "recommendations": ["..."],
  "analyst_notes": "..."
}
""".strip()


def run_prompt3_backdoor_detection(
    prompt1_result: dict,
    prompt2_result: dict,
    manifest_data:  dict,
) -> dict:
    """Prompt 3: cross-reference UI vs backend to detect backdoor patterns."""
    user_msg = f"""APP: {APP_NAME}
PACKAGE: {PKG_NAME}

═══ UI ANALYSIS (Prompt 1 output) ═══
{json.dumps(prompt1_result, indent=2)[:3000]}

═══ BACKEND ANALYSIS (Prompt 2 output) ═══
{json.dumps(prompt2_result, indent=2)[:3000]}

═══ MANIFEST PERMISSIONS ═══
All declared: {json.dumps(manifest_data['all_permissions'])}
Sensitive:    {json.dumps(manifest_data['sensitive_permissions'])}
By category:  {json.dumps(manifest_data['by_category'])}

═══ EXPORTED COMPONENTS ═══
{json.dumps(manifest_data['exported_components'])}

Now perform the BACKDOOR MISMATCH DETECTION. Be thorough but accurate.
Focus on HIGH-CONFIDENCE mismatches. Avoid false positives for standard app patterns.
"""
    print("[P3] Running Backdoor Mismatch Detection...")
    result = _call_llm(PROMPT3_SYSTEM, user_msg, "prompt3_backdoor")
    _save_json("prompt3_backdoor_detection.json", result)
    return result


# ---------------------------------------------------------------------------
# LOCAL (non-LLM) MISMATCH ANALYSIS
# Rule-based pre-analysis done BEFORE the LLM; provides extra evidence + acts
# as a fallback when the API is unavailable.
# ---------------------------------------------------------------------------

def local_mismatch_analysis(
    methods: list,
    backend_cat_summary: dict,
    manifest_data: dict,
    activity_data: dict,
    ui_text: str,
) -> dict:
    """
    Rule-based backdoor indicator analysis without LLM.
    Returns structured mismatch indicators to supplement / validate LLM output.
    """
    tested_activities  = [a.lower() for a in activity_data.get("TestedActivity", [])]
    manifest_perms_set = set(manifest_data["all_permissions"])
    ui_lower           = ui_text.lower()
    activity_text      = " ".join(tested_activities)

    silent_exec_flags:  list = []
    over_declared_flags: list = []
    hidden_trigger_flags: list = []
    covert_collect_flags: list = []

    for cat, rule in PERMISSION_SIGNAL_MAP.items():
        has_backend = cat in backend_cat_summary and len(backend_cat_summary[cat]) > 0
        has_ui      = has_ui_keyword(ui_lower, activity_text, rule["ui_keywords"]) if rule.get("ui_keywords") else False
        has_manifest= any(p in manifest_perms_set for p in rule["permissions"])

        # SILENT_EXEC: backend uses it, UI doesn't mention it
        if has_backend and not has_ui:
            silent_exec_flags.append({
                "backdoor_type":      "SILENT_EXEC",
                "permission_category": cat,
                "risk_level":          "high" if cat in {"sms", "phone_state", "device_id",
                                                          "location", "contacts"} else "medium",
                "ui_claim":            "not present in UI",
                "backend_evidence":    backend_cat_summary[cat][:5],
                "explanation":         (
                    f"The app calls {cat} APIs at runtime but the UI contains no "
                    f"UI elements, labels, or activity names that mention or justify "
                    f"this capability."
                ),
                "confidence": 0.75,
                "source": "local_rule",
            })

        # OVER_DECLARED: manifest has it, backend never uses it, UI never mentions it
        if has_manifest and not has_backend and not has_ui:
            over_declared_flags.append({
                "backdoor_type":      "OVER_DECLARED",
                "permission_category": cat,
                "risk_level":          "medium",
                "ui_claim":            "not present in UI",
                "backend_evidence":    [],
                "explanation":         (
                    f"Permission declared in AndroidManifest but no runtime method "
                    f"calls or UI evidence for {cat} were found. This may be a "
                    f"zombie permission or a permission awaiting remote activation."
                ),
                "confidence": 0.55,
                "source": "local_rule",
            })

        # COVERT_COLLECT: device-ID / location / contacts used, but app claims to be simple utility
        if has_backend and cat in {"device_id", "phone_state"} and not has_ui:
            covert_collect_flags.append({
                "backdoor_type":      "COVERT_COLLECT",
                "permission_category": cat,
                "risk_level":          "critical",
                "ui_claim":            "not present in UI",
                "backend_evidence":    backend_cat_summary.get(cat, [])[:5],
                "explanation":         (
                    f"Device identifier / phone state harvesting ({cat}) detected "
                    f"without any UI disclosure or user consent flow."
                ),
                "confidence": 0.85,
                "source": "local_rule",
            })

    # HIDDEN_TRIGGER: fixed exported matching against sensitive methods
    exported_set: set[str] = set()
    for comp in manifest_data["exported_components"]:
        lc = comp.lower()
        exported_set.add(lc)
        parts = lc.split('.')
        if parts:
            exported_set.add(parts[-1])
        if len(parts) > 1:
            exported_set.add(parts[-2])

    for m in methods:
        if not m["is_sensitive"]:
            continue
        class_lower  = m["class_name"].lower()
        short_cls    = (m.get("short_class") or class_lower.split('.')[-1]).lower()
        is_exported  = (class_lower in exported_set) or (short_cls in exported_set)
        is_activity  = any(x in class_lower for x in ["activity", "fragment", "mainactivity"])  # UI entry patterns
        if is_exported and not is_activity:
            hidden_trigger_flags.append({
                "backdoor_type":      "HIDDEN_TRIGGER",
                "permission_category": ", ".join(m.get("matched_categories", [])) or "",
                "risk_level":          "high",
                "ui_claim":            "exported component – triggerable externally",
                "backend_evidence":    [m.get("full_sig", "")],
                "explanation":         (
                    f"Exported component {short_cls} calls sensitive method(s) and can be triggered externally without normal UI entry."
                ),
                "confidence": 0.80,
                "source": "local_rule",
            })

    all_flags = (silent_exec_flags + covert_collect_flags +
                 over_declared_flags + hidden_trigger_flags)

    # Confidence calibration based on coverage, UI text and methods count
    coverage = activity_data.get("Coverage", 0)
    ui_len   = len(ui_text)
    n_methods = len(methods)
    for grp in (silent_exec_flags, covert_collect_flags, over_declared_flags, hidden_trigger_flags):
        for flag in grp:
            if "confidence" in flag:
                flag["confidence"] = calibrate_confidence(flag["confidence"], coverage, ui_len, n_methods)

    # Compute local verdict
    critical_or_high = [f for f in all_flags if f["risk_level"] in {"critical", "high"}]
    if any(f["backdoor_type"] in {"SILENT_EXEC", "COVERT_COLLECT"}
           and f["risk_level"] in {"critical", "high"} for f in all_flags):
        local_verdict = "HAS_BACKDOOR"
    elif critical_or_high:
        local_verdict = "SUSPICIOUS"
    elif all_flags:
        local_verdict = "SUSPICIOUS"
    else:
        local_verdict = "LIKELY_CLEAN"

    return {
        "local_verdict":          local_verdict,
        "total_flags":            len(all_flags),
        "silent_exec_flags":      silent_exec_flags,
        "covert_collect_flags":   covert_collect_flags,
        "over_declared_flags":    over_declared_flags,
        "hidden_trigger_flags":   hidden_trigger_flags,
        "all_flags":              all_flags,
    }


# ---------------------------------------------------------------------------
# FINAL REPORT ASSEMBLER
# ---------------------------------------------------------------------------

def assemble_report(
    manifest_data:    dict,
    activity_data:    dict,
    methods:          list,
    backend_summary:  dict,
    local_analysis:   dict,
    prompt1_result:   dict,
    prompt2_result:   dict,
    prompt3_result:   dict,
) -> dict:
    """Combine all pipeline outputs into a single structured backdoor report."""

    # Decide final verdict (LLM overrides local if available and not dry-run)
    llm_verdict = prompt3_result.get("verdict", "")
    if llm_verdict and "_dry_run" not in prompt3_result and "_llm_error" not in prompt3_result:
        final_verdict    = llm_verdict
        final_risk_level = prompt3_result.get("overall_risk_level", "unknown")
        final_confidence = prompt3_result.get("confidence", 0.0)
        llm_patterns     = prompt3_result.get("backdoor_patterns", [])
    else:
        final_verdict    = local_analysis["local_verdict"]
        final_risk_level = ("critical" if any(f["risk_level"] == "critical"
                                              for f in local_analysis["all_flags"])
                            else "high" if any(f["risk_level"] == "high"
                                               for f in local_analysis["all_flags"])
                            else "medium" if local_analysis["all_flags"]
                            else "none")
        final_confidence = 0.6 if local_analysis["all_flags"] else 0.3
        llm_patterns     = []

    # Choose pattern source: LLM-only when available, else local rules
    if llm_patterns:
        all_patterns = llm_patterns
    else:
        all_patterns = list(local_analysis["all_flags"])  # fallback only

    report = {
        "pipeline": "EchoDroid-fastbot-custom-more-detection (Backdoor Detection)",
        "version":  "1.0.0",
        "timestamp": _utc_now(),
        "app": {
            "name":        APP_NAME,
            "description": APP_DESC,
            "package":     PKG_NAME,
        },

        # ── VERDICT ────────────────────────────────────────────────────────
        "backdoor_verdict": {
            "verdict":       final_verdict,
            "risk_level":    final_risk_level,
            "confidence":    final_confidence,
            "total_patterns_found": len(all_patterns),
            "verdict_explanation": {
                "HAS_BACKDOOR":      "High-confidence UI-vs-backend mismatch indicating hidden malicious behaviour.",
                "SUSPICIOUS":        "Moderate mismatch signals; warrants further manual investigation.",
                "LIKELY_CLEAN":      "No significant UI-backend mismatches detected.",
                "INSUFFICIENT_DATA": "Insufficient runtime data to make a reliable determination.",
            }.get(final_verdict, ""),
        },

        # ── BACKDOOR PATTERNS ──────────────────────────────────────────────
        "backdoor_patterns": all_patterns,

        # ── MISMATCH SUMMARY ──────────────────────────────────────────────
        "mismatch_summary": prompt3_result.get("mismatch_summary", local_analysis.get("mismatch_summary", {})),

        # ── DATA EVIDENCE ──────────────────────────────────────────────────
        "evidence": {
            "manifest": {
                "all_permissions":       manifest_data["all_permissions"],
                "sensitive_permissions": manifest_data["sensitive_permissions"],
                "by_category":           manifest_data["by_category"],
                "exported_components":   manifest_data["exported_components"],
            },
            "runtime": {
                "total_unique_methods_called": len(methods),
                "sensitive_methods_found":     sum(1 for m in methods if m["is_sensitive"]),
                "backend_active_categories":   list(backend_summary.keys()),
                "backend_category_details":    backend_summary,
                "activities_tested":           activity_data.get("TestedActivity", []),
                "activity_coverage":           activity_data.get("Coverage", 0),
            },
        },

        # ── LLM OUTPUTS ────────────────────────────────────────────────────
        "llm_analysis": {
            "prompt1_ui_analysis":        prompt1_result,
            "prompt2_backend_analysis":   prompt2_result,
            "prompt3_backdoor_detection": prompt3_result,
        },

        # ── LOCAL RULE ANALYSIS ────────────────────────────────────────────
        "local_rule_analysis": local_analysis,

        # ── RECOMMENDATIONS ───────────────────────────────────────────────
        "recommendations": (
            prompt3_result.get("recommendations", []) or [
                "Run with longer test duration (5–10 min) for better method coverage.",
                "Enable UI dump capture via ECHODROID_UI_DUMP_DIR for richer UI evidence.",
                "Manually decompile the APK and cross-check flagged class names.",
                "Submit to VirusTotal and cross-reference with known malware families.",
            ]
        ),
    }

    # Optional Drebin validation (if configured via config.json)
    drebin_dir = config.get("DrebinFeaturesDir", "").strip()
    drebin_sha = config.get("DrebinSha256", "").strip().lower()
    drebin_fam = config.get("DrebinFamily", "").strip()
    if drebin_dir and drebin_sha:
        try:
            app_file = os.path.join(drebin_dir, f"{drebin_sha}.data")
            feats = {}
            if os.path.exists(app_file):
                with open(app_file, encoding="utf-8", errors="ignore") as fh:
                    for line in fh:
                        s = line.strip()
                        if s:
                            feats[s] = 1
            our_patterns = {p.get("backdoor_type", "") for p in report.get("backdoor_patterns", [])}
            drebin_sms  = any("sendTextMessage" in k or "SmsManager" in k or "SEND_SMS" in k for k in feats)
            drebin_boot = any("RECEIVE_BOOT_COMPLETED" in k for k in feats)
            val = {
                "drebin_family": drebin_fam,
                "drebin_sms": drebin_sms,
                "drebin_boot": drebin_boot,
                "our_verdict": report["backdoor_verdict"]["verdict"],
                "our_patterns": list(our_patterns),
                "ground_truth_match": {},
            }
            if drebin_sms and "SILENT_EXEC" in our_patterns:
                val["ground_truth_match"]["SILENT_EXEC"] = "TP"
            elif drebin_sms and "SILENT_EXEC" not in our_patterns:
                val["ground_truth_match"]["SILENT_EXEC"] = "FN"
            if drebin_boot and "HIDDEN_TRIGGER" in our_patterns:
                val["ground_truth_match"]["HIDDEN_TRIGGER"] = "TP"
            elif drebin_boot and "HIDDEN_TRIGGER" not in our_patterns:
                val["ground_truth_match"]["HIDDEN_TRIGGER"] = "FN"
            report["drebin_validation"] = val
        except Exception:
            report["drebin_validation_error"] = "failed_to_validate"

    return report


# ---------------------------------------------------------------------------
# MAIN PIPELINE
# ---------------------------------------------------------------------------

def main():
    # Allow direct APK invocation: python Prompt_BackdoorDetection.py /path/app.apk
    if len(sys.argv) > 1 and os.path.isfile(sys.argv[1]) and sys.argv[1].lower().endswith('.apk'):
        apk_path = os.path.abspath(sys.argv[1])
        # Set manifest path for aapt-based parsing
        global MANIFEST_PATH
        MANIFEST_PATH = apk_path
        # Derive package name when possible
        try:
            res = subprocess.run(["aapt", "dump", "badging", apk_path], capture_output=True, text=True, timeout=10)
            m = re.search(r"package: name='([^']+)'", res.stdout)
            if m:
                config["PackageName"] = m.group(1)
        except Exception:
            pass
        # Force Overall_output path format
        base_out = "/home/Desktop/backdoor_permission/Overall_output"
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        base_name = os.path.splitext(os.path.basename(apk_path))[0]
        out_dir = os.path.join(base_out, f"{base_name}_backdoor_{ts}")
        try:
            os.makedirs(out_dir, exist_ok=True)
            global OUTPUT_DIR
            OUTPUT_DIR = out_dir
        except Exception:
            pass

    print("=" * 70)
    print(" EchoDroid Backdoor Detection Pipeline")
    print(f" App     : {APP_NAME}")
    print(f" Package : {PKG_NAME}")
    print(f" Output  : {OUTPUT_DIR}")
    print("=" * 70)

    # 1. Load manifest data
    print("\n[1/6] Loading manifest data...")
    manifest_data = load_manifest_data()
    print(f"      Permissions: {len(manifest_data['all_permissions'])} declared, "
          f"{len(manifest_data['sensitive_permissions'])} sensitive")
    print(f"      Exported components: {len(manifest_data['exported_components'])}")

    # 2. Load AndroLog methods
    print("\n[2/6] Loading AndroLog backend methods...")
    logcat_file  = sys.argv[1] if len(sys.argv) > 1 else ""
    methods      = load_androlog_methods(logcat_file)
    backend_summary = build_backend_category_summary(methods)
    print(f"      Active sensitive categories: {list(backend_summary.keys())}")

    # 3. Load activity data
    print("\n[3/6] Loading activity coverage data...")
    act_file      = sys.argv[2] if len(sys.argv) > 2 else ""
    activity_data = load_activity_data(act_file)
    print(f"      Tested activities: {len(activity_data.get('TestedActivity', []))}")

    # 4. Load UI text
    print("\n[4/6] Loading UI text...")
    ui_text = load_ui_text()

    # 5. Local (rule-based) analysis
    print("\n[5/6] Running local rule-based mismatch analysis...")
    local_analysis = local_mismatch_analysis(
        methods, backend_summary, manifest_data, activity_data, ui_text
    )
    print(f"      Local flags: {local_analysis['total_flags']} "
          f"(verdict: {local_analysis['local_verdict']})")

    # 6. LLM prompts
    print("\n[6/6] Running LLM prompts...")
    prompt1 = run_prompt1_ui_analysis(activity_data, ui_text, manifest_data)
    prompt2 = run_prompt2_backend_analysis(methods, backend_summary, manifest_data)
    prompt3 = run_prompt3_backdoor_detection(prompt1, prompt2, manifest_data)

    # 7. Assemble final report
    print("\nAssembling final backdoor detection report...")
    report = assemble_report(
        manifest_data, activity_data, methods, backend_summary,
        local_analysis, prompt1, prompt2, prompt3
    )

    report_path = _save_json("backdoor_detection_report.json", report)
    print(f"\n{'=' * 70}")
    print(f" BACKDOOR VERDICT : {report['backdoor_verdict']['verdict']}")
    print(f" RISK LEVEL       : {report['backdoor_verdict']['risk_level'].upper()}")
    print(f" CONFIDENCE       : {report['backdoor_verdict']['confidence']:.0%}")
    print(f" PATTERNS FOUND   : {report['backdoor_verdict']['total_patterns_found']}")
    print(f" REPORT SAVED     : {report_path}")
    print("=" * 70)

    # Print summary of patterns
    if report["backdoor_patterns"]:
        print("\n📍 BACKDOOR PATTERN SUMMARY:")
        for i, p in enumerate(report["backdoor_patterns"], 1):
            print(f"  [{i}] {p.get('backdoor_type','?'):20s} | "
                  f"category={p.get('permission_category','?'):15s} | "
                  f"risk={p.get('risk_level','?'):8s} | "
                  f"conf={p.get('confidence', 0):.0%}")
            print(f"       {p.get('explanation','')[:80]}")

    return 0 if report["backdoor_verdict"]["verdict"] != "HAS_BACKDOOR" else 1


if __name__ == "__main__":
    sys.exit(main())
