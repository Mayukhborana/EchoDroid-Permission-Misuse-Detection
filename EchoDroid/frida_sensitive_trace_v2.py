#!/usr/bin/env python3
"""frida_sensitive_trace_v2.py

Dynamic tracer (Frida) to capture sensitive Android API calls.

It writes log lines in this format:
  METHOD=<Class: returnType method(argTypes...)>

so the existing backend parser in Prompt_MismatchDetection.py can consume them.

Usage:
  python3 frida_sensitive_trace_v2.py <package> <out_file> [duration_seconds]

Notes:
  - Requires frida-server running on the device/emulator.
  - Set ANDROID_SERIAL to target a specific device/emulator.
"""

from __future__ import annotations

import os
import subprocess
import sys
import time
from typing import Any


def _now() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S")


FRIDA_JS = r"""
function emitMethod(sig) { send({ type: 'method', sig: sig }); }
function status(msg) { send({ type: 'status', msg: msg }); }

function hookAllOverloads(clazz, method) {
  try {
    var C = Java.use(clazz);
    if (!C[method] || !C[method].overloads) return;

    C[method].overloads.forEach(function (ov) {
      try {
        var sig = (function() {
          var args = [];
          try {
            var at = ov.argumentTypes || [];
            for (var j = 0; j < at.length; j++) args.push(at[j].className);
          } catch (e) {}
          var ret = 'java.lang.Object';
          try { ret = (ov.returnType && ov.returnType.className) ? ov.returnType.className : ret; } catch (e) {}
          return clazz + ': ' + ret + ' ' + method + '(' + args.join(',') + ')';
        })();

        ov.implementation = function () {
          try { emitMethod(sig); } catch (e) {}
          return ov.apply(this, arguments);
        };
      } catch (e) {}
    });
  } catch (e) {}
}

Java.perform(function () {
  status('Java.perform entered; installing hooks');

  // Liveness: should fire frequently in most apps
  hookAllOverloads('android.app.Activity', 'onResume');

  // SMS
  hookAllOverloads('android.telephony.SmsManager', 'sendTextMessage');
  hookAllOverloads('android.telephony.SmsManager', 'sendMultipartTextMessage');

  // Device identifiers / telephony
  hookAllOverloads('android.telephony.TelephonyManager', 'getDeviceId');
  hookAllOverloads('android.telephony.TelephonyManager', 'getImei');
  hookAllOverloads('android.telephony.TelephonyManager', 'getMeid');
  hookAllOverloads('android.telephony.TelephonyManager', 'getSubscriberId');
  hookAllOverloads('android.telephony.TelephonyManager', 'getSimSerialNumber');
  hookAllOverloads('android.os.Build', 'getSerial');

  // Location
  hookAllOverloads('android.location.LocationManager', 'getLastKnownLocation');
  hookAllOverloads('android.location.LocationManager', 'requestLocationUpdates');
  hookAllOverloads('android.location.LocationManager', 'getCurrentLocation');

  // Settings ANDROID_ID
  hookAllOverloads('android.provider.Settings$Secure', 'getString');

  // Advertising ID (if present)
  hookAllOverloads('com.google.android.gms.ads.identifier.AdvertisingIdClient', 'getAdvertisingIdInfo');

  // Installed apps enumeration
  hookAllOverloads('android.app.ApplicationPackageManager', 'getInstalledPackages');
  hookAllOverloads('android.app.ApplicationPackageManager', 'getInstalledApplications');

  // Clipboard
  hookAllOverloads('android.content.ClipboardManager', 'getPrimaryClip');

  // Wi-Fi identifiers
  hookAllOverloads('android.net.wifi.WifiInfo', 'getMacAddress');
  hookAllOverloads('android.net.wifi.WifiInfo', 'getSSID');

  // Process execution
  hookAllOverloads('java.lang.Runtime', 'exec');

  // Networking (commonly hit)
  hookAllOverloads('java.net.InetAddress', 'getByName');
  hookAllOverloads('java.net.Socket', 'connect');

  // Contacts/SMS/Calllog data access via ContentResolver
  try {
    var CR = Java.use('android.content.ContentResolver');
    if (CR.query && CR.query.overloads) {
      CR.query.overloads.forEach(function (ov) {
        try {
          ov.implementation = function () {
            try {
              var uri = arguments.length > 0 ? arguments[0] : null;
              var s = uri ? uri.toString() : '';
              if (s.indexOf('contacts') !== -1) {
                emitMethod('android.content.ContentResolver: android.database.Cursor query(android.net.Uri,...) [contacts]');
              } else if (s.indexOf('sms') !== -1) {
                emitMethod('android.content.ContentResolver: android.database.Cursor query(android.net.Uri,...) [sms]');
              } else if (s.indexOf('call_log') !== -1) {
                emitMethod('android.content.ContentResolver: android.database.Cursor query(android.net.Uri,...) [call_log]');
              }
            } catch (e) {}
            return ov.apply(this, arguments);
          };
        } catch (e) {}
      });
    }
  } catch (e) {}

  status('Hooks installed');
});
"""


def _adb_cmd() -> list[str]:
    serial = os.environ.get("ANDROID_SERIAL", "").strip()
    if serial:
        return ["adb", "-s", serial]
    return ["adb"]


def _pidof(package: str) -> int | None:
    try:
        out = subprocess.check_output(
            _adb_cmd() + ["shell", "pidof", package],
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=5,
        ).strip()
        if not out:
            return None
        return int(out.split()[0])
    except Exception:
        return None


def main() -> int:
    if len(sys.argv) < 3:
        print("Usage: frida_sensitive_trace_v2.py <package> <out_file> [duration_seconds]", file=sys.stderr)
        return 2

    pkg = sys.argv[1].strip()
    out_file = os.path.abspath(sys.argv[2])
    duration = int(sys.argv[3]) if len(sys.argv) > 3 else 30

    os.makedirs(os.path.dirname(out_file), exist_ok=True)

    try:
        import frida  # type: ignore
    except Exception as e:
        print(f"[{_now()}] [FRIDA] python-frida not installed: {e}", file=sys.stderr)
        return 1

    fh = open(out_file, "a", encoding="utf-8")
    seen: set[str] = set()

    def on_message(message: dict, data: Any) -> None:
        try:
            mtype = message.get("type")
            if mtype == "error":
                print(f"[{_now()}] [FRIDA] script error: {message}", file=sys.stderr, flush=True)
                return
            if mtype != "send":
                return
            payload = message.get("payload") or {}
            ptype = payload.get("type")
            if ptype == "method":
                sig = str(payload.get("sig") or "").strip()
                if not sig:
                    return
                line = f"METHOD=<{sig}>"
                if line in seen:
                    return
                seen.add(line)
                fh.write(line + "\n")
                fh.flush()
                return
            if ptype == "status":
                msg = str(payload.get("msg") or "").strip()
                if msg:
                    print(f"[{_now()}] [FRIDA] STATUS: {msg}", flush=True)
        except Exception:
            return

    device = None
    for _ in range(10):
        try:
            device = frida.get_usb_device(timeout=5)
            break
        except Exception:
            time.sleep(1)
    if device is None:
        print(f"[{_now()}] [FRIDA] Could not get USB device", file=sys.stderr)
        return 1

    deadline = time.time() + max(15, duration + 15)
    pid = None
    while time.time() < deadline:
        pid = _pidof(pkg)
        if pid:
            break
        time.sleep(1)
    if not pid:
        print(f"[{_now()}] [FRIDA] pidof failed for {pkg}", file=sys.stderr)
        return 1

    try:
        session = device.attach(pid)
        # Use V8 runtime so the Android Java bridge (`Java.perform`) is available.
        try:
          script = session.create_script(FRIDA_JS, runtime="v8")  # type: ignore[arg-type]
        except TypeError:
          # Older frida-python may not expose the runtime parameter.
          script = session.create_script(FRIDA_JS)
        script.on("message", on_message)
        script.load()
        print(f"[{_now()}] [FRIDA] Attached to {pkg} (pid={pid}), logging to {out_file}", flush=True)
        time.sleep(max(5, duration))
        return 0
    except Exception as e:
        print(f"[{_now()}] [FRIDA] attach/load failed: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
