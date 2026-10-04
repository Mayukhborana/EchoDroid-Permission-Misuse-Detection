#!/usr/bin/env python3
"""frida_sensitive_trace.py

Dynamic tracer (Frida) to capture sensitive Android API calls.

It writes log lines in this format:
	METHOD=<Class: returnType method(argTypes...)>

so the existing `Prompt_BackdoorDetection.py` backend parser can consume them.

Usage:
	python3 frida_sensitive_trace.py <package> <out_file> [duration_seconds]

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
// Sensitive API tracer
// Emits:
//   send({type:'method', sig:'Class: ret name(args)'})
//   send({type:'status', msg:'...'})
//   send({type:'error', msg:'...'})

function emitMethod(sig) {
	send({ type: 'method', sig: sig });
}

function status(msg) {
	send({ type: 'status', msg: msg });
}

function err(msg) {
	send({ type: 'error', msg: msg });
}

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
			} catch (e) {
				// ignore
			}
		});
	} catch (e) {
		// ignore missing classes
	}
}

Java.perform(function () {
	status('Java.perform entered; installing hooks');

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
				print("Usage: frida_sensitive_trace.py <package> <out_file> [duration_seconds]", file=sys.stderr)
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

		# Append so repeated runs accumulate; write only unique METHOD lines per run.
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
						if ptype in {"status", "error"}:
								msg = str(payload.get("msg") or "").strip()
								if msg:
										stream = sys.stderr if ptype == "error" else sys.stdout
										print(f"[{_now()}] [FRIDA] {ptype.upper()}: {msg}", file=stream, flush=True)
				except Exception:
						return

		# Get device
		device = None
		for _ in range(10):
				try:
						device = frida.get_usb_device(timeout=5)
						break
				except Exception as e:
						time.sleep(1)
		if device is None:
				print(f"[{_now()}] [FRIDA] Could not get USB device", file=sys.stderr)
				return 1

		# Wait for PID then attach
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
				try {
					var Build = Java.use('android.os.Build');
					// Just accessing static fields isn't hookable; hook Build.getSerial where available.
					hookAllOverloads('android.os.Build', 'getSerial', function(c, m, ov, args) { return defaultSig(c, m, ov); });
				} catch (e) {}
		'android.telephony.TelephonyManager',
		'getSubscriberId',
				hookAllOverloads('android.location.LocationManager', 'getLastKnownLocation', function(c, m, ov, args) { return defaultSig(c, m, ov); });
				hookAllOverloads('android.location.LocationManager', 'requestLocationUpdates', function(c, m, ov, args) { return defaultSig(c, m, ov); });
				hookAllOverloads('android.location.LocationManager', 'getCurrentLocation', function(c, m, ov, args) { return defaultSig(c, m, ov); });
		'android.location.LocationManager',
		'requestLocationUpdates',
		['java.lang.String', 'long', 'float', 'android.location.LocationListener'],
		function(args) {
					// Hook all overloads and inspect first arg if it's a Uri
					if (CR.query && CR.query.overloads) {
						CR.query.overloads.forEach(function(ov) {
							try {
								ov.implementation = function() {
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
				} else if (s.indexOf('sms') !== -1) {
					emit('android.content.ContentResolver: android.database.Cursor query(android.net.Uri,...) [sms]');
				} else if (s.indexOf('call_log') !== -1) {
				hookAllOverloads('java.lang.Runtime', 'exec', function(c, m, ov, args) { return defaultSig(c, m, ov); });
	safeHook(
		'java.lang.Runtime',
		'exec',
		['java.lang.String'],
		function(args) {
			return 'java.lang.Runtime: java.lang.Process exec(java.lang.String)';
		}
	);

	// Settings.Secure.getString (ANDROID_ID and other device identifiers)
	try {
		var Secure = Java.use('android.provider.Settings$Secure');
		var gs = Secure.getString.overload('android.content.ContentResolver', 'java.lang.String');
		gs.implementation = function(cr, name) {
			try {
				var n = name ? name.toString() : '';
				if (n.toLowerCase().indexOf('android_id') !== -1) {
					emitMethod('android.provider.Settings$Secure: java.lang.String getString(android.content.ContentResolver,java.lang.String) [ANDROID_ID]');
				}
			} catch (e) {}
			return gs.call(this, cr, name);
		};
	} catch (e) {}

	// Google Advertising ID (common in many apps)
	hookAllOverloads('com.google.android.gms.ads.identifier.AdvertisingIdClient', 'getAdvertisingIdInfo', function(c, m, ov, args) { return defaultSig(c, m, ov); });

	// Installed packages enumeration (QUERY_ALL_PACKAGES style behavior)
	hookAllOverloads('android.app.ApplicationPackageManager', 'getInstalledPackages', function(c, m, ov, args) { return defaultSig(c, m, ov); });
	hookAllOverloads('android.app.ApplicationPackageManager', 'getInstalledApplications', function(c, m, ov, args) { return defaultSig(c, m, ov); });

	// Wi-Fi identifiers
	hookAllOverloads('android.net.wifi.WifiInfo', 'getMacAddress', function(c, m, ov, args) { return defaultSig(c, m, ov); });
	hookAllOverloads('android.net.wifi.WifiInfo', 'getSSID', function(c, m, ov, args) { return defaultSig(c, m, ov); });

	// Clipboard reads (often sensitive)
	hookAllOverloads('android.content.ClipboardManager', 'getPrimaryClip', function(c, m, ov, args) { return defaultSig(c, m, ov); });

	// Camera2 openCamera
	hookAllOverloads('android.hardware.camera2.CameraManager', 'openCamera', function(c, m, ov, args) { return defaultSig(c, m, ov); });

	status('Hooks installed');

	// ---- Liveness hooks (not sensitive, but proves the tracer is working) ----
	safeHook(
		'android.app.Activity',
		'onResume',
		[],
		function(args) {
			return 'android.app.Activity: void onResume()';
		}
	);
	safeHook(
		'android.app.Activity',
		'onPause',
		[],
		function(args) {
			return 'android.app.Activity: void onPause()';
		}
	);
	safeHook(
		'android.app.Activity',
		'onCreate',
		['android.os.Bundle'],
		function(args) {
			return 'android.app.Activity: void onCreate(android.os.Bundle)';
		}
	);
	safeHook(
		'android.app.Application',
		'onCreate',
		[],
		function(args) {
			return 'android.app.Application: void onCreate()';
		}
	);

	// Binder transactions happen constantly in Android apps; logging once proves the hook works.
	safeHook(
		'android.os.BinderProxy',
		'transact',
		['int', 'android.os.Parcel', 'android.os.Parcel', 'int'],
		function(args) {
			return 'android.os.BinderProxy: boolean transact(int,android.os.Parcel,android.os.Parcel,int)';
		}
	);

	// SystemProperties.get is commonly used by libraries/SDKs.
	safeHook(
		'android.os.SystemProperties',
		'get',
		['java.lang.String'],
		function(args) {
			return 'android.os.SystemProperties: java.lang.String get(java.lang.String)';
		}
	);

	send({ type: 'status', msg: 'hooks_installed' });
});
"""


def main() -> int:

    if len(sys.argv) < 3:
        print("Usage: frida_sensitive_trace.py <package> <out_file> [duration_seconds]", file=sys.stderr)
        return 2

    pkg = sys.argv[1].strip()
    out_file = os.path.abspath(sys.argv[2])
    duration = int(sys.argv[3]) if len(sys.argv) > 3 else 300

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
                print(f"[{_now()}] [FRIDA] script error: {message}", flush=True)
                return
            if mtype != "send":
                return
            payload = message.get("payload") or {}
            ptype = payload.get("type")
            if ptype == "status":
                print(f"[{_now()}] [FRIDA] status: {payload.get('msg')}", flush=True)
                return
            if ptype != "method":
                return
            sig = str(payload.get("sig") or "").strip()
            if not sig:
                return
            line = f"METHOD=<{sig}>"
            if line in seen:
                return
            seen.add(line)
            fh.write(line + "\n")
            fh.flush()
        except Exception:
            return

    # Allow a little extra time to attach, especially for short durations
    deadline = time.time() + max(30, duration + 20)
    attached = False

    device = None
    while time.time() < deadline and device is None:
        try:
            device = frida.get_usb_device(timeout=5)
        except Exception as e:
            print(f"[{_now()}] [FRIDA] No USB device yet: {e}", file=sys.stderr)
            time.sleep(2)

    if device is None:
        print(f"[{_now()}] [FRIDA] Could not get USB device", file=sys.stderr)
        return 1

    def get_pid_via_adb(package: str) -> int | None:
        try:
            out = subprocess.check_output(
                ["adb", "shell", "pidof", package],
                stderr=subprocess.DEVNULL,
                text=True,
                timeout=5,
            ).strip()
            if not out:
                return None
            return int(out.split()[0])
        except Exception:
            return None

    while time.time() < deadline:
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

				# Debug/status messages
				if ptype in {"status", "error"}:
					msg = str(payload.get("msg") or "").strip()
					if msg:
						stream = sys.stderr if ptype == "error" else sys.stdout
						print(f"[{_now()}] [FRIDA] {ptype.upper()}: {msg}", file=stream, flush=True)
					return
            print(f"[{_now()}] [FRIDA] Attached to {pkg} (pid={pid}), logging to {out_file}", flush=True)

            end_run = time.time() + max(10, duration)
            while time.time() < end_run:
                time.sleep(1)
            break
        except Exception:
            time.sleep(1)
            continue

    if not attached:
        print(f"[{_now()}] [FRIDA] Failed to attach to {pkg} before timeout", file=sys.stderr, flush=True)
        return 1

    return 0


if __name__ == "__main__":
		raise SystemExit(main())

