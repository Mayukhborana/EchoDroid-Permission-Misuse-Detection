import os
import csv
import gzip
import requests

# ==============================
# CONFIG
# ==============================
API_KEY = os.environ.get("ANDROZOO_API_KEY", "").strip()

# Prefer env override; else use a project-relative default (avoids hardcoded user paths)
CSV_FILE = os.environ.get(
    "ANDROZOO_CSV_FILE",
    os.path.join(os.path.dirname(__file__), "appdata", "latest.csv.gz"),
)

DOWNLOAD_DIR = "./vt_malware_apks"
os.makedirs(DOWNLOAD_DIR, exist_ok=True)

TARGET_APPS = 2
MAX_ATTEMPTS = 500

MIN_VT = 5   # higher = more likely malicious

# ==============================
# DOWNLOAD FUNCTION
# ==============================
def download_apk(sha256):
    url = f"https://androzoo.uni.lu/api/download?apikey={API_KEY}&sha256={sha256}"
    path = os.path.join(DOWNLOAD_DIR, sha256 + ".apk")

    try:
        r = requests.get(url, stream=True, timeout=30)

        if r.status_code == 200:
            with open(path, "wb") as f:
                for chunk in r.iter_content(8192):
                    f.write(chunk)
            print(f"[DOWNLOADED] {sha256}")
            return True

        else:
            return False

    except:
        return False

# ==============================
# MAIN
# ==============================
if __name__ == "__main__":
    success = 0
    attempts = 0

    with gzip.open(CSV_FILE, "rt", encoding="utf-8", errors="ignore") as f:
        reader = csv.DictReader(f)

        for row in reader:
            if success >= TARGET_APPS or attempts >= MAX_ATTEMPTS:
                break

            attempts += 1

            # ---- VT FILTER ----
            try:
                vt = int(row.get("vt_detection", 0))
            except:
                vt = 0

            if vt < MIN_VT:
                continue

            # ---- SKIP GOOGLE PLAY (important) ----
            markets = row.get("markets", "")
            if "play.google.com" in markets:
                continue

            sha256 = row.get("sha256")
            pkg = row.get("pkg_name", "unknown")

            print(f"\n🎯 Trying: {pkg} | VT={vt}")

            if sha256 and download_apk(sha256):
                success += 1
                print(f"✅ Success count: {success}")

    print("\n=============================")
    print(f"Downloaded: {success}")
    print(f"Attempts  : {attempts}")
    print("=============================")