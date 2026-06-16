# analyze.py - Suspicious file analyzer with VirusTotal integration
# Usage: python analyze.py --input data/inventory.json

import json
import argparse
import time
import os
import requests
from pathlib import Path
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

# ── Constants ─────────────────────────────────────────────────────────────────

SENSITIVE_EXTENSIONS = {".exe", ".ps1", ".bat", ".cmd", ".vbs", ".js", ".scr", ".lnk"}

UNUSUAL_PATH_FRAGMENTS = [
    "\\temp\\", "\\tmp\\", "\\appdata\\roaming\\",
    "\\appdata\\local\\temp\\", "\\public\\", "\\recycle",
    "/tmp/", "/temp/",
]

JS_WHITELIST_PATH_FRAGMENTS = [
    "node_modules", "dist", "build", ".next", ".nuxt",
    "vendor", "bower_components", "public/js", "static/js",
    "assets/js", "wwwroot",
]

# Words commonly used in malware filenames to trick users into opening them
LURE_WORDS = [
    "invoice", "facture", "password", "mot_de_passe", "crack", "keygen",
    "free", "gratuit", "update", "install", "setup", "patch", "hack",
    "cheat", "loader", "dropper", "payload", "exploit", "urgent", "important",
]

# Legitimate Windows process names attackers impersonate with slight variations
# e.g. svchost32.exe, explorер.exe (with cyrillic е), svch0st.exe
SYSTEM_PROCESS_NAMES = [
    "svchost", "explorer", "lsass", "csrss", "winlogon",
    "services", "spoolsv", "taskhost", "rundll32", "regsvr32",
]

RISK_HIGH   = 3
RISK_MEDIUM = 1

LOCAL_DB_PATH         = Path("data/known_malware_hashes.json")
VT_RATE_LIMIT_SECONDS = 16
VT_MALICIOUS_THRESHOLD = 3

# ── Argument parsing ──────────────────────────────────────────────────────────

parser = argparse.ArgumentParser(description="Analyze file inventory for suspicious indicators")
parser.add_argument("--input", default="data/inventory.json", help="Path to inventory JSON")
args = parser.parse_args()
args.vt_key = os.getenv("VT_API_KEY")

# ── Local DB ──────────────────────────────────────────────────────────────────

def load_local_db(db_path: Path) -> dict:
    if not db_path.exists():
        print(f"[!] Local DB not found at {db_path} - skipping local check")
        return {}
    with open(db_path, "r", encoding="utf-8") as f:
        entries = json.load(f)
    db = {entry["sha256"].lower(): entry for entry in entries}
    print(f"[*] Local DB loaded: {len(db)} known hash(es)")
    return db

def check_local_db(sha256: str, db: dict) -> dict | None:
    return db.get(sha256.lower())

local_db = load_local_db(LOCAL_DB_PATH)

# ── Load inventory ────────────────────────────────────────────────────────────

input_path = Path(args.input)
if not input_path.exists():
    print(f"[ERROR] Inventory file not found: {input_path}")
    exit(1)

with open(input_path, "r", encoding="utf-8-sig") as f:
    inventory = json.load(f)

if isinstance(inventory, dict):
    inventory = [inventory]

print(f"[*] Loaded {len(inventory)} file(s) from inventory\n")

# ── VirusTotal ────────────────────────────────────────────────────────────────

def lookup_virustotal(sha256: str, api_key: str) -> dict:
    url     = f"https://www.virustotal.com/api/v3/files/{sha256}"
    headers = {"x-apikey": api_key}
    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 404:
            return {"found": False, "malicious": 0, "suspicious": 0,
                    "total": 0, "permalink": "", "error": None}
        if response.status_code == 429:
            return {"found": False, "malicious": 0, "suspicious": 0,
                    "total": 0, "permalink": "", "error": "Rate limit hit"}
        response.raise_for_status()
        data       = response.json()
        stats      = data["data"]["attributes"]["last_analysis_stats"]
        malicious  = stats.get("malicious",  0)
        suspicious = stats.get("suspicious", 0)
        total      = malicious + suspicious + stats.get("undetected", 0) + stats.get("harmless", 0)
        return {
            "found":      True,
            "malicious":  malicious,
            "suspicious": suspicious,
            "total":      total,
            "permalink":  f"https://www.virustotal.com/gui/file/{sha256}",
            "error":      None,
        }
    except requests.RequestException as e:
        return {"found": False, "malicious": 0, "suspicious": 0,
                "total": 0, "permalink": "", "error": str(e)}

# ── Detection functions ───────────────────────────────────────────────────────

def check_double_extension(name: str) -> tuple[bool, str]:
    """file.pdf.exe → attacker hides real extension behind a fake one."""
    if len(Path(name).suffixes) >= 2:
        return True, f"Double extension: {name} (real ext hidden behind fake one)"
    return False, ""

def check_sensitive_extension(ext: str, path: str) -> tuple[bool, str]:
    """Executable or script extension — can run code on the system."""
    e = ext.lower()
    if e not in SENSITIVE_EXTENSIONS:
        return False, ""
    if e == ".js":
        if any(f in path.lower() for f in JS_WHITELIST_PATH_FRAGMENTS):
            return False, ""
    return True, f"Executable/script extension: {e}"

def check_unusual_path(path: str) -> tuple[bool, str]:
    """Files in Temp, AppData, Public etc. are abnormal for legit software."""
    for fragment in UNUSUAL_PATH_FRAGMENTS:
        if fragment in path.lower():
            return True, f"Suspicious location: path contains '{fragment}'"
    return False, ""

def check_suspicious_name(name: str) -> list[str]:
    """
    Two checks:
    1. Lure words — attacker uses social engineering names like 'invoice.exe'
       to trick the user into thinking it's a document.
    2. System process impersonation — 'svchost32.exe' looks like 'svchost.exe'
       (a real Windows process). The '32' or '_' suffix is the giveaway.
    """
    hits = []
    stem = Path(name).stem.lower()  # filename without extension

    # Check 1: lure words
    for word in LURE_WORDS:
        if word in stem:
            hits.append(f"Lure word in filename: '{word}' (social engineering tactic)")
            break

    # Check 2: system process impersonation
    # If the stem starts with a known process name but has extra chars → suspicious
    for proc in SYSTEM_PROCESS_NAMES:
        if stem.startswith(proc) and stem != proc:
            hits.append(f"Possible system process impersonation: '{name}' resembles '{proc}.exe'")
            break

    return hits

def check_timestamp_anomaly(entry: dict) -> list[str]:
    """
    Two timestamp checks:

    1. Modified before created — impossible under normal conditions.
       Means the attacker manually set the timestamps to hide activity
       (called 'timestomping' in forensics).

    2. Odd-hour creation — files created between midnight and 5am are unusual
       for user activity. Malware droppers often run at night to avoid detection.
       Only flagged on executable/script extensions to reduce false positives.
    """
    hits = []

    try:
        created  = datetime.strptime(entry["CreatedAt"],  "%Y-%m-%d %H:%M:%S")
        modified = datetime.strptime(entry["ModifiedAt"], "%Y-%m-%d %H:%M:%S")
    except (ValueError, KeyError):
        return hits  # malformed dates — skip silently

    # Check 1: modified before created = timestomping
    if modified < created:
        hits.append(
            f"Timestamp anomaly: modified ({entry['ModifiedAt']}) "
            f"is BEFORE created ({entry['CreatedAt']}) — possible timestomping"
        )

    # Check 2: created between 0h and 5h — suspicious for executables only
    if entry.get("Extension", "").lower() in SENSITIVE_EXTENSIONS:
        if 0 <= created.hour < 5:
            hits.append(
                f"Created at odd hour: {entry['CreatedAt']} "
                f"(between midnight and 5am — unusual for user activity)"
            )

    return hits

# ── Main analysis loop ────────────────────────────────────────────────────────

results    = []
vt_enabled = args.vt_key is not None

print("=" * 60)
print("  ANALYSIS STARTING")
print("=" * 60)

for i, entry in enumerate(inventory):
    print(f"\n[{i+1}/{len(inventory)}] {entry['Name']}")
    print(f"    Path    : {entry['FullPath']}")
    print(f"    Size    : {entry['SizeBytes']} bytes")
    print(f"    Created : {entry.get('CreatedAt', 'N/A')}")
    print(f"    Modified: {entry.get('ModifiedAt', 'N/A')}")
    print(f"    SHA-256 : {entry['SHA256']}")
    print(f"    Checks  :")

    score   = 0
    reasons = []

    # -- Rule checks ----------------------------------------------------------

    hit, msg = check_double_extension(entry["Name"])
    if hit:
        score += 3
        reasons.append(msg)
        print(f"      [!] +3  {msg}")
    else:
        print(f"      [ ]     No double extension")

    hit, msg = check_sensitive_extension(entry["Extension"], entry["FullPath"])
    if hit:
        score += 2
        reasons.append(msg)
        print(f"      [!] +2  {msg}")
    else:
        print(f"      [ ]     Extension not sensitive ({entry['Extension']})")

    hit, msg = check_unusual_path(entry["FullPath"])
    if hit:
        score += 2
        reasons.append(msg)
        print(f"      [!] +2  {msg}")
    else:
        print(f"      [ ]     Path looks normal")

    name_hits = check_suspicious_name(entry["Name"])
    for msg in name_hits:
        score += 2
        reasons.append(msg)
        print(f"      [!] +2  {msg}")
    if not name_hits:
        print(f"      [ ]     Filename looks normal")

    ts_hits = check_timestamp_anomaly(entry)
    for msg in ts_hits:
        score += 2
        reasons.append(msg)
        print(f"      [!] +2  {msg}")
    if not ts_hits:
        print(f"      [ ]     Timestamps look normal")

    # -- Local DB check -------------------------------------------------------

    local_match = None
    if local_db:
        local_match = check_local_db(entry["SHA256"], local_db)
        if local_match:
            score += 10
            msg = (f"KNOWN MALWARE in local DB: {local_match['name']} "
                   f"(family: {local_match['family']}, severity: {local_match['severity']})")
            reasons.append(msg)
            print(f"      [!] +10 {msg}")
        else:
            print(f"      [ ]     Hash not in local malware DB")

    # -- VirusTotal check -----------------------------------------------------

    vt_result = {"found": False, "malicious": 0, "suspicious": 0,
                 "total": 0, "permalink": "", "error": None}

    if vt_enabled and local_match is None:
        print(f"      [~]     Querying VirusTotal ...", end="", flush=True)
        vt_result = lookup_virustotal(entry["SHA256"], args.vt_key)

        if vt_result["error"]:
            print(f" ERROR: {vt_result['error']}")
        elif not vt_result["found"]:
            print(f" hash unknown to VT (file never seen before)")
        elif vt_result["malicious"] >= VT_MALICIOUS_THRESHOLD:
            score += 10
            msg = (f"CONFIRMED MALWARE by VirusTotal: "
                   f"{vt_result['malicious']}/{vt_result['total']} engines flagged - "
                   f"{vt_result['permalink']}")
            reasons.append(msg)
            print(f" {vt_result['malicious']}/{vt_result['total']} engines flagged -> +10")
        elif vt_result["malicious"] > 0 or vt_result["suspicious"] > 0:
            score += 4
            msg = (f"Flagged by VirusTotal: {vt_result['malicious']} malicious, "
                   f"{vt_result['suspicious']} suspicious out of {vt_result['total']} engines - "
                   f"{vt_result['permalink']}")
            reasons.append(msg)
            print(f" {vt_result['malicious']} malicious / {vt_result['suspicious']} suspicious -> +4")
        else:
            reasons.append(f"VirusTotal: clean ({vt_result['total']} engines checked)")
            print(f" CLEAN ({vt_result['total']} engines)")

        if i < len(inventory) - 1:
            time.sleep(VT_RATE_LIMIT_SECONDS)

    elif local_match:
        print(f"      [ ]     VT skipped (local DB already confirmed malware)")
    else:
        print(f"      [ ]     VT disabled (no API key in .env)")

    # -- Final risk level -----------------------------------------------------

    risk = "HIGH" if score >= RISK_HIGH else ("MEDIUM" if score >= RISK_MEDIUM else "LOW")
    print(f"    Result  : {risk} (score: {score})")

    results.append({
        "Name":          entry["Name"],
        "Extension":     entry["Extension"],
        "SizeBytes":     entry["SizeBytes"],
        "CreatedAt":     entry.get("CreatedAt", ""),
        "ModifiedAt":    entry.get("ModifiedAt", ""),
        "FullPath":      entry["FullPath"],
        "SHA256":        entry["SHA256"],
        "Score":         score,
        "Reasons":       reasons,
        "LocalDBMatch":  local_match["name"]   if local_match else None,
        "LocalDBFamily": local_match["family"] if local_match else None,
        "VTFound":       vt_result["found"],
        "VTMalicious":   vt_result["malicious"],
        "VTTotal":       vt_result["total"],
        "VTLink":        vt_result["permalink"],
        "RiskLevel":     risk,
    })

# Sort most suspicious first
results.sort(key=lambda x: x["Score"], reverse=True)

high   = sum(1 for r in results if r["RiskLevel"] == "HIGH")
medium = sum(1 for r in results if r["RiskLevel"] == "MEDIUM")
low    = sum(1 for r in results if r["RiskLevel"] == "LOW")

print(f"\n{'=' * 60}")
print(f"  SUMMARY: {len(results)} file(s) scanned")
print(f"  HIGH: {high}   MEDIUM: {medium}   LOW: {low}")
print(f"{'=' * 60}\n")

# ── Export results ────────────────────────────────────────────────────────────

results_dir = Path("results")
results_dir.mkdir(exist_ok=True)

# -- 1. JSON
report_json = results_dir / "risk_report.json"
with open(report_json, "w", encoding="utf-8") as f:
    json.dump(results, f, indent=2, ensure_ascii=False)
print(f"[+] JSON report  -> {report_json}")

# -- 2. Hash list
hash_list = results_dir / "hashes.txt"
with open(hash_list, "w", encoding="utf-8") as f:
    for r in results:
        f.write(f"{r['SHA256']}  {r['Name']}\n")
print(f"[+] Hash list    -> {hash_list}")

# -- 3. TXT report
report_txt = results_dir / "risk_report.txt"
with open(report_txt, "w", encoding="utf-8") as f:
    f.write("=" * 60 + "\n")
    f.write("  SUSPICIOUS FILE ANALYSIS REPORT\n")
    f.write(f"  VirusTotal: {'ENABLED' if vt_enabled else 'DISABLED'}\n")
    f.write("=" * 60 + "\n\n")
    f.write(f"Total files scanned : {len(results)}\n")
    f.write(f"HIGH risk           : {high}\n")
    f.write(f"MEDIUM risk         : {medium}\n")
    f.write(f"LOW risk            : {low}\n\n")
    f.write("-" * 60 + "\n")
    for r in results:
        if r["Score"] == 0:
            continue
        f.write(f"\n[{r['RiskLevel']}] {r['Name']}  (score: {r['Score']})\n")
        f.write(f"  Path      : {r['FullPath']}\n")
        f.write(f"  Size      : {r['SizeBytes']} bytes\n")
        f.write(f"  Created   : {r['CreatedAt']}\n")
        f.write(f"  Modified  : {r['ModifiedAt']}\n")
        f.write(f"  SHA-256   : {r['SHA256']}\n")
        if r["LocalDBMatch"]:
            f.write(f"  Local DB  : MATCH - {r['LocalDBMatch']} (family: {r['LocalDBFamily']})\n")
        if r["VTFound"]:
            f.write(f"  VT Result : {r['VTMalicious']}/{r['VTTotal']} engines flagged\n")
            f.write(f"  VT Link   : {r['VTLink']}\n")
        f.write(f"  Reasons   :\n")
        for reason in r["Reasons"]:
            f.write(f"    - {reason}\n")
    f.write("\n" + "=" * 60 + "\n")
    f.write("End of report\n")
print(f"[+] TXT report   -> {report_txt}")

# -- 4. HTML report -----------------------------------------------------------

def risk_badge(level: str) -> str:
    colors = {"HIGH": "#e74c3c", "MEDIUM": "#e67e22", "LOW": "#27ae60"}
    return (f'<span style="background:{colors[level]};color:#fff;padding:3px 10px;'
            f'border-radius:12px;font-size:0.8em;font-weight:700;">{level}</span>')

def size_human(b: int) -> str:
    if b < 1024: return f"{b} B"
    if b < 1024**2: return f"{b/1024:.1f} KB"
    return f"{b/1024**2:.1f} MB"

report_html = results_dir / "risk_report.html"
with open(report_html, "w", encoding="utf-8") as f:
    f.write(f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Suspicious File Analysis Report</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: 'Segoe UI', Arial, sans-serif; background: #0f1117; color: #e0e0e0; padding: 30px; }}
  h1 {{ font-size: 1.6em; color: #fff; margin-bottom: 4px; }}
  .subtitle {{ color: #888; font-size: 0.9em; margin-bottom: 30px; }}
  .cards {{ display: flex; gap: 16px; margin-bottom: 30px; flex-wrap: wrap; }}
  .card {{ background: #1a1d27; border-radius: 10px; padding: 20px 28px; min-width: 140px; text-align: center; border-top: 4px solid #444; }}
  .card.high {{ border-color: #e74c3c; }}
  .card.medium {{ border-color: #e67e22; }}
  .card.low {{ border-color: #27ae60; }}
  .card.total {{ border-color: #3498db; }}
  .card-num {{ font-size: 2.2em; font-weight: 700; color: #fff; }}
  .card-label {{ font-size: 0.8em; color: #888; margin-top: 4px; text-transform: uppercase; letter-spacing: 1px; }}
  table {{ width: 100%; border-collapse: collapse; background: #1a1d27; border-radius: 10px; overflow: hidden; }}
  th {{ background: #22263a; color: #aaa; font-size: 0.78em; text-transform: uppercase; letter-spacing: 1px; padding: 12px 16px; text-align: left; }}
  td {{ padding: 12px 16px; border-bottom: 1px solid #22263a; font-size: 0.88em; vertical-align: top; }}
  tr:last-child td {{ border-bottom: none; }}
  tr:hover td {{ background: #1e2235; }}
  .hash {{ font-family: monospace; font-size: 0.78em; color: #7f8c8d; word-break: break-all; }}
  .path {{ font-family: monospace; font-size: 0.8em; color: #95a5a6; word-break: break-all; }}
  .meta {{ font-size: 0.78em; color: #666; margin-top: 4px; }}
  .reasons li {{ margin-left: 16px; color: #bdc3c7; font-size: 0.85em; margin-bottom: 3px; }}
  .vt-link {{ color: #3498db; text-decoration: none; font-size: 0.82em; }}
  .vt-link:hover {{ text-decoration: underline; }}
  .db-hit {{ background: #2d1f1f; color: #e74c3c; padding: 2px 8px; border-radius: 6px; font-size: 0.8em; }}
  .ts-warn {{ background: #2d2710; color: #e67e22; padding: 2px 8px; border-radius: 6px; font-size: 0.8em; }}
  .section-title {{ font-size: 1em; color: #aaa; margin: 28px 0 12px; text-transform: uppercase; letter-spacing: 1px; border-bottom: 1px solid #22263a; padding-bottom: 6px; }}
  .vt-on {{ color: #2ecc71; }} .vt-off {{ color: #888; }}
  .check-row {{ display: flex; gap: 6px; align-items: baseline; font-size: 0.82em; margin-bottom: 2px; }}
  .check-hit {{ color: #e74c3c; }} .check-ok {{ color: #555; }}
</style>
</head>
<body>
<h1>Suspicious File Analysis Report</h1>
<p class="subtitle">VirusTotal: <span class='{"vt-on" if vt_enabled else "vt-off"}'>{"ENABLED" if vt_enabled else "DISABLED"}</span></p>
<div class="cards">
  <div class="card total"><div class="card-num">{len(results)}</div><div class="card-label">Total Files</div></div>
  <div class="card high"><div class="card-num">{high}</div><div class="card-label">High Risk</div></div>
  <div class="card medium"><div class="card-num">{medium}</div><div class="card-label">Medium Risk</div></div>
  <div class="card low"><div class="card-num">{low}</div><div class="card-label">Low Risk</div></div>
</div>
<p class="section-title">File Details</p>
<table>
  <thead>
    <tr>
      <th>Risk</th><th>File</th><th>Size</th><th>Timestamps</th><th>SHA-256</th><th>Detections</th>
    </tr>
  </thead>
  <tbody>
""")

    for r in results:
        # Build detections cell
        reasons_html = ""
        if r["Reasons"]:
            reasons_html = "<ul class='reasons'>"
            for reason in r["Reasons"]:
                tag = "db-hit" if "local DB" in reason.lower() else ("ts-warn" if "timestamp" in reason.lower() or "odd hour" in reason.lower() else "")
                if tag:
                    reasons_html += f"<li><span class='{tag}'>{reason}</span></li>"
                else:
                    reasons_html += f"<li>{reason}</li>"
            reasons_html += "</ul>"
        else:
            reasons_html = "<span style='color:#555'>No detections</span>"

        vt_html = ""
        if r["LocalDBMatch"]:
            vt_html += f'<br><span class="db-hit">Local DB: {r["LocalDBMatch"]}</span>'
        if r["VTFound"]:
            vt_html += f'<br><a class="vt-link" href="{r["VTLink"]}" target="_blank">{r["VTMalicious"]}/{r["VTTotal"]} VT engines flagged</a>'
        elif vt_enabled and not r["LocalDBMatch"]:
            vt_html += '<br><span style="color:#555;font-size:0.82em">Not in VT database</span>'

        f.write(f"""    <tr>
      <td>{risk_badge(r["RiskLevel"])}<br><span style="color:#888;font-size:0.78em">score: {r["Score"]}</span></td>
      <td>
        <strong>{r["Name"]}</strong><br>
        <span class="path">{r["FullPath"]}</span>
      </td>
      <td style="white-space:nowrap">{size_human(r["SizeBytes"])}</td>
      <td class="meta">
        Created:<br><span style="color:#aaa">{r["CreatedAt"]}</span><br>
        Modified:<br><span style="color:#aaa">{r["ModifiedAt"]}</span>
      </td>
      <td><span class="hash">{r["SHA256"]}</span></td>
      <td>{reasons_html}{vt_html}</td>
    </tr>
""")

    f.write("  </tbody>\n</table>\n</body>\n</html>\n")

print(f"[+] HTML report  -> {report_html}")
print("[*] Analysis complete.")
