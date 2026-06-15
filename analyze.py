# analyze.py - Suspicious file analyzer with VirusTotal integration
# Usage: python analyze.py --input data/inventory.json

import json
import argparse
import time
import os
import requests
from pathlib import Path
from dotenv import load_dotenv

# Load variables from .env file into environment
# This reads VT_API_KEY without ever hardcoding it in the script
load_dotenv()

# ── Constants ─────────────────────────────────────────────────────────────────

SENSITIVE_EXTENSIONS = {".exe", ".ps1", ".bat", ".cmd", ".vbs", ".js", ".scr", ".lnk"}

UNUSUAL_PATH_FRAGMENTS = [
    "\\temp\\", "\\tmp\\", "\\appdata\\roaming\\",
    "\\appdata\\local\\temp\\", "\\public\\", "\\recycle",
    "/tmp/", "/temp/",
]

# Path fragments that whitelist .js files from being flagged as suspicious.
# A .js file inside node_modules, a build output, or a known framework folder
# is almost certainly legitimate — flagging it is noise, not signal.
JS_WHITELIST_PATH_FRAGMENTS = [
    "node_modules", "dist", "build", ".next", ".nuxt",
    "vendor", "bower_components", "public/js", "static/js",
    "assets/js", "wwwroot",
]

RISK_HIGH   = 3
RISK_MEDIUM = 1

# Path to the local malware hash database (JSON array of known bad hashes)
LOCAL_DB_PATH = Path("data/known_malware_hashes.json")

# VirusTotal free tier allows 4 requests per minute
# We wait 16 seconds between requests to stay safely under that limit
VT_RATE_LIMIT_SECONDS = 16

# If this many AV engines flag the hash, we consider it confirmed malware
VT_MALICIOUS_THRESHOLD = 3

# ── Argument parsing ──────────────────────────────────────────────────────────

parser = argparse.ArgumentParser(description="Analyze file inventory for suspicious indicators")
parser.add_argument("--input", default="data/inventory.json", help="Path to inventory JSON")
args = parser.parse_args()

# Read API key from .env (loaded above) — falls back to None if not set
# Can still be overridden by setting VT_API_KEY in the shell environment
args.vt_key = os.getenv("VT_API_KEY")

# ── Load local hash database ──────────────────────────────────────────────────

def load_local_db(db_path: Path) -> dict:
    """
    Load known_malware_hashes.json into a dict keyed by sha256 (lowercase).
    Returns an empty dict if the file doesn't exist — DB is optional.

    Structure of each entry in the JSON:
      { "sha256": "abc...", "name": "...", "family": "...", "severity": "HIGH" }

    We key by sha256 so lookup is O(1) — just db[hash] instead of looping.
    """
    if not db_path.exists():
        print(f"[!] Local DB not found at {db_path} — skipping local check")
        return {}

    with open(db_path, "r", encoding="utf-8") as f:
        entries = json.load(f)

    # Build a dict: { "abc123...": { full entry } }
    db = {entry["sha256"].lower(): entry for entry in entries}
    print(f"[*] Local DB loaded: {len(db)} known hash(es)")
    return db


def check_local_db(sha256: str, db: dict) -> dict | None:
    """
    Check if a SHA-256 hash exists in the local malware database.
    Returns the matching entry dict if found, None otherwise.
    Lookup is case-insensitive.
    """
    return db.get(sha256.lower())


# Load DB once at startup — used for every file in the inventory
local_db = load_local_db(LOCAL_DB_PATH)

# ── Load inventory ────────────────────────────────────────────────────────────

input_path = Path(args.input)

if not input_path.exists():
    print(f"[ERROR] Inventory file not found: {input_path}")
    exit(1)

with open(input_path, "r", encoding="utf-8-sig") as f:
    inventory = json.load(f)

# PowerShell exports a single object (not array) when only 1 file is found
# Wrap it in a list so the rest of the code always works with a list
if isinstance(inventory, dict):
    inventory = [inventory]

print(f"[*] Loaded {len(inventory)} file(s) from inventory")

# ── VirusTotal lookup ─────────────────────────────────────────────────────────

def lookup_virustotal(sha256: str, api_key: str) -> dict:
    """
    Send one SHA-256 hash to the VirusTotal API and return a summary.

    VT API v3 endpoint for file reports:
      GET https://www.virustotal.com/api/v3/files/{hash}

    The response contains a 'last_analysis_stats' dict like:
      { "malicious": 5, "suspicious": 1, "undetected": 60, ... }

    Returns a dict with:
      - found        (bool)  : whether VT has seen this hash before
      - malicious    (int)   : number of AV engines that flagged it
      - suspicious   (int)   : number of AV engines that marked it suspicious
      - total        (int)   : total AV engines that scanned it
      - permalink    (str)   : direct link to the VT report
      - error        (str)   : error message if the request failed
    """
    url = f"https://www.virustotal.com/api/v3/files/{sha256}"

    # VT requires the API key in the request header, not as a query param
    headers = {"x-apikey": api_key}

    try:
        response = requests.get(url, headers=headers, timeout=10)

        # 404 = VT has never seen this file — not necessarily clean, just unknown
        if response.status_code == 404:
            return {"found": False, "malicious": 0, "suspicious": 0, "total": 0,
                    "permalink": "", "error": None}

        # 429 = rate limit hit — we slept too little between requests
        if response.status_code == 429:
            return {"found": False, "malicious": 0, "suspicious": 0, "total": 0,
                    "permalink": "", "error": "Rate limit hit — wait and retry"}

        response.raise_for_status()  # raise exception for any other 4xx/5xx

        data = response.json()

        # Navigate the nested JSON response to the stats we care about
        stats     = data["data"]["attributes"]["last_analysis_stats"]
        malicious = stats.get("malicious",  0)
        suspicious= stats.get("suspicious", 0)
        undetected= stats.get("undetected", 0)
        total     = malicious + suspicious + undetected + stats.get("harmless", 0)

        # Build a permanent link the analyst can open in a browser
        permalink = f"https://www.virustotal.com/gui/file/{sha256}"

        return {
            "found":      True,
            "malicious":  malicious,
            "suspicious": suspicious,
            "total":      total,
            "permalink":  permalink,
            "error":      None,
        }

    except requests.RequestException as e:
        # Network error, timeout, etc. — don't crash the whole analysis
        return {"found": False, "malicious": 0, "suspicious": 0, "total": 0,
                "permalink": "", "error": str(e)}

# ── Detection functions ───────────────────────────────────────────────────────

def has_double_extension(filename: str) -> bool:
    """Detect filenames like document.pdf.exe — multiple suffixes = suspicious."""
    return len(Path(filename).suffixes) >= 2


def has_sensitive_extension(extension: str, full_path: str = "") -> bool:
    """
    Check if extension is in our executable/abused watchlist.
    .js is special-cased: whitelisted when found inside known framework/build folders
    to avoid flooding reports with false positives from Node.js projects.
    """
    ext = extension.lower()
    if ext not in SENSITIVE_EXTENSIONS:
        return False

    # .js in a known framework/build path → not suspicious
    if ext == ".js":
        path_lower = full_path.lower()
        if any(fragment in path_lower for fragment in JS_WHITELIST_PATH_FRAGMENTS):
            return False

    return True


def is_unusual_path(full_path: str) -> bool:
    """Check if file lives in a known suspicious location."""
    path_lower = full_path.lower()
    return any(fragment in path_lower for fragment in UNUSUAL_PATH_FRAGMENTS)


def score_file(entry: dict) -> tuple[int, list[str]]:
    """
    Assign a risk score. Returns (score, reasons).
    VT result is NOT scored here — it is applied separately after the API call
    so we can add a higher penalty for confirmed malware.
    """
    score   = 0
    reasons = []

    if has_double_extension(entry["Name"]):
        score += 3
        reasons.append("Double extension detected (e.g. file.pdf.exe)")

    if has_sensitive_extension(entry["Extension"], entry["FullPath"]):
        score += 2
        reasons.append(f"Sensitive extension: {entry['Extension']}")

    if is_unusual_path(entry["FullPath"]):
        score += 2
        reasons.append("Located in an unusual/suspicious path")

    return score, reasons

# ── Run analysis ──────────────────────────────────────────────────────────────

results = []

vt_enabled = args.vt_key is not None
if vt_enabled:
    print(f"[*] VirusTotal lookup enabled ({len(inventory)} request(s), ~{len(inventory) * VT_RATE_LIMIT_SECONDS}s estimated)")
else:
    print("[*] VirusTotal lookup disabled (pass --vt-key to enable)")

for i, entry in enumerate(inventory):
    score, reasons = score_file(entry)

    # Default VT result — used when API is disabled or lookup fails
    vt_result = {"found": False, "malicious": 0, "suspicious": 0,
                 "total": 0, "permalink": "", "error": None}

    # Track whether this hash was already confirmed by local DB
    # If yes, we skip the VT API call — no need to spend a request quota
    local_match = None

    # ── Layer 1: Local database check (offline, instant) ──────────────────────
    if local_db:
        local_match = check_local_db(entry["SHA256"], local_db)

        if local_match:
            # Hash found in our local known-bad database
            score += 10
            reasons.append(
                f"KNOWN MALWARE in local DB: {local_match['name']} "
                f"(family: {local_match['family']}, severity: {local_match['severity']})"
            )
            print(f"  [{i+1}/{len(inventory)}] LOCAL DB HIT: {entry['Name']} → {local_match['name']}")

    # ── Layer 2: VirusTotal API check (online, costs 1 request) ───────────────
    # Only query VT if:
    #   - VT is enabled (API key set)
    #   - Local DB didn't already confirm it as malware (save API quota)
    if vt_enabled and local_match is None:
        print(f"  [{i+1}/{len(inventory)}] Checking VT: {entry['Name']} ... ", end="", flush=True)

        vt_result = lookup_virustotal(entry["SHA256"], args.vt_key)

        if vt_result["error"]:
            print(f"ERROR ({vt_result['error']})")
        elif not vt_result["found"]:
            print("not in VT database")
        else:
            print(f"{vt_result['malicious']}/{vt_result['total']} engines flagged")

        # Apply extra score based on VT findings
        if vt_result["malicious"] >= VT_MALICIOUS_THRESHOLD:
            score += 10
            reasons.append(
                f"CONFIRMED MALWARE by VirusTotal: "
                f"{vt_result['malicious']}/{vt_result['total']} engines flagged — "
                f"{vt_result['permalink']}"
            )
        elif vt_result["malicious"] > 0 or vt_result["suspicious"] > 0:
            score += 4
            reasons.append(
                f"Flagged by VirusTotal: "
                f"{vt_result['malicious']} malicious, {vt_result['suspicious']} suspicious "
                f"out of {vt_result['total']} engines — {vt_result['permalink']}"
            )
        elif vt_result["found"]:
            reasons.append(f"VirusTotal: clean ({vt_result['total']} engines checked)")

        # Respect the free-tier rate limit between requests
        if i < len(inventory) - 1:
            time.sleep(VT_RATE_LIMIT_SECONDS)

    results.append({
        "Name":           entry["Name"],
        "Extension":      entry["Extension"],
        "SizeBytes":      entry["SizeBytes"],
        "FullPath":       entry["FullPath"],
        "SHA256":         entry["SHA256"],
        "Score":          score,
        "Reasons":        reasons,
        # Local DB fields — None means hash was not in the local database
        "LocalDBMatch":   local_match["name"]   if local_match else None,
        "LocalDBFamily":  local_match["family"] if local_match else None,
        # VirusTotal fields
        "VTFound":        vt_result["found"],
        "VTMalicious":    vt_result["malicious"],
        "VTTotal":        vt_result["total"],
        "VTLink":         vt_result["permalink"],
        "RiskLevel":      "HIGH" if score >= RISK_HIGH else ("MEDIUM" if score >= RISK_MEDIUM else "LOW"),
    })

# Sort most suspicious first
results.sort(key=lambda x: x["Score"], reverse=True)

high   = sum(1 for r in results if r["RiskLevel"] == "HIGH")
medium = sum(1 for r in results if r["RiskLevel"] == "MEDIUM")
low    = sum(1 for r in results if r["RiskLevel"] == "LOW")
print(f"\n[*] Risk summary -> HIGH: {high}  MEDIUM: {medium}  LOW: {low}")

# ── Export results ────────────────────────────────────────────────────────────

results_dir = Path("results")
results_dir.mkdir(exist_ok=True)

# -- 1. Full JSON report
report_json = results_dir / "risk_report.json"
with open(report_json, "w", encoding="utf-8") as f:
    json.dump(results, f, indent=2, ensure_ascii=False)
print(f"[+] JSON report  -> {report_json}")

# -- 2. SHA-256 hash list (sha256sum format)
hash_list = results_dir / "hashes.txt"
with open(hash_list, "w", encoding="utf-8") as f:
    for r in results:
        f.write(f"{r['SHA256']}  {r['Name']}\n")
print(f"[+] Hash list    -> {hash_list}")

# -- 3. Human-readable TXT report
report_txt = results_dir / "risk_report.txt"
with open(report_txt, "w", encoding="utf-8") as f:
    f.write("=" * 60 + "\n")
    f.write("  SUSPICIOUS FILE ANALYSIS REPORT\n")
    if vt_enabled:
        f.write("  (VirusTotal lookup: ENABLED)\n")
    f.write("=" * 60 + "\n\n")
    f.write(f"Total files scanned : {len(results)}\n")
    f.write(f"HIGH risk           : {high}\n")
    f.write(f"MEDIUM risk         : {medium}\n")
    f.write(f"LOW risk            : {low}\n\n")
    f.write("-" * 60 + "\n")

    for r in results:
        if r["Score"] == 0:
            continue
        f.write(f"\n[{r['RiskLevel']}] {r['Name']}\n")
        f.write(f"  Path      : {r['FullPath']}\n")
        f.write(f"  Size      : {r['SizeBytes']} bytes\n")
        f.write(f"  SHA-256   : {r['SHA256']}\n")
        f.write(f"  Score     : {r['Score']}\n")
        if r["LocalDBMatch"]:
            f.write(f"  Local DB  : MATCH — {r['LocalDBMatch']} (family: {r['LocalDBFamily']})\n")
        if r["VTFound"]:
            f.write(f"  VT Result : {r['VTMalicious']}/{r['VTTotal']} engines flagged\n")
            f.write(f"  VT Link   : {r['VTLink']}\n")
        f.write(f"  Reasons   :\n")
        for reason in r["Reasons"]:
            f.write(f"    - {reason}\n")

    f.write("\n" + "=" * 60 + "\n")
    f.write("End of report\n")

print(f"[+] TXT report   -> {report_txt}")
print("[*] Analysis complete.")
