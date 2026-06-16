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

def size_human(b: int) -> str:
    if b < 1024: return f"{b} B"
    if b < 1024**2: return f"{b/1024:.1f} KB"
    return f"{b/1024**2:.1f} MB"

def score_bar_html(score: int) -> str:
    # Visual bar showing score out of 20 (max realistic score)
    pct   = min(100, int(score / 20 * 100))
    color = "#e74c3c" if score >= RISK_HIGH else ("#e67e22" if score >= RISK_MEDIUM else "#27ae60")
    return (f'<div style="background:#22263a;border-radius:4px;height:6px;width:100%;margin-top:6px;">'
            f'<div style="background:{color};width:{pct}%;height:6px;border-radius:4px;"></div></div>')

def check_row(label: str, hit: bool, detail: str, score_add: int = 0) -> str:
    if hit:
        icon  = "&#9888;"  # warning triangle
        badge = f'<span style="background:#2d1414;color:#e74c3c;padding:1px 6px;border-radius:4px;font-size:0.75em;margin-left:6px;">+{score_add}</span>' if score_add else ""
        return (f'<div class="check-row check-hit">'
                f'<span class="check-icon">{icon}</span>'
                f'<div><span class="check-label">{label}</span>{badge}'
                f'<div class="check-detail">{detail}</div></div></div>')
    else:
        icon = "&#10003;"  # checkmark
        return (f'<div class="check-row check-ok">'
                f'<span class="check-icon">{icon}</span>'
                f'<div><span class="check-label">{label}</span>'
                f'<div class="check-detail">{detail}</div></div></div>')

report_html = results_dir / "risk_report.html"
with open(report_html, "w", encoding="utf-8") as f:

    # Precompute per-file check details for the HTML
    # We re-run the checks here just for display — results are already stored
    file_checks = []
    for r in results:
        entry_mock = {
            "Name": r["Name"], "Extension": r["Extension"],
            "FullPath": r["FullPath"], "SHA256": r["SHA256"],
            "SizeBytes": r["SizeBytes"],
            "CreatedAt": r.get("CreatedAt", ""),
            "ModifiedAt": r.get("ModifiedAt", ""),
        }
        dbl_hit,  dbl_msg  = check_double_extension(r["Name"])
        ext_hit,  ext_msg  = check_sensitive_extension(r["Extension"], r["FullPath"])
        path_hit, path_msg = check_unusual_path(r["FullPath"])
        name_hits          = check_suspicious_name(r["Name"])
        ts_hits            = check_timestamp_anomaly(entry_mock)
        file_checks.append({
            "dbl":  (dbl_hit,  dbl_msg),
            "ext":  (ext_hit,  ext_msg),
            "path": (path_hit, path_msg),
            "name": name_hits,
            "ts":   ts_hits,
        })

    vt_status = "ENABLED" if vt_enabled else "DISABLED"
    vt_color  = "#2ecc71" if vt_enabled else "#7f8c8d"

    f.write(f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Suspicious File Analysis Report</title>
<style>
  *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: 'Segoe UI', system-ui, sans-serif; background: #0a0c14; color: #d0d4e8; min-height: 100vh; }}

  /* ── Layout ── */
  .page {{ max-width: 1200px; margin: 0 auto; padding: 36px 24px; }}

  /* ── Header ── */
  .header {{ display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 32px; flex-wrap: wrap; gap: 16px; }}
  .header-left h1 {{ font-size: 1.5em; color: #fff; font-weight: 700; letter-spacing: -0.5px; }}
  .header-left .tagline {{ color: #556; font-size: 0.82em; margin-top: 4px; }}
  .vt-badge {{ padding: 6px 14px; border-radius: 20px; font-size: 0.78em; font-weight: 600; letter-spacing: 0.5px; border: 1px solid; }}
  .vt-on  {{ border-color: #27ae60; color: #2ecc71; background: #0d1f14; }}
  .vt-off {{ border-color: #444; color: #888; background: #1a1a1a; }}

  /* ── Summary cards ── */
  .summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(130px, 1fr)); gap: 14px; margin-bottom: 32px; }}
  .scard {{ background: #12151f; border: 1px solid #1e2235; border-radius: 12px; padding: 18px 20px; text-align: center; position: relative; overflow: hidden; }}
  .scard::before {{ content: ''; position: absolute; top: 0; left: 0; right: 0; height: 3px; }}
  .scard.total::before  {{ background: #3498db; }}
  .scard.high::before   {{ background: #e74c3c; }}
  .scard.medium::before {{ background: #e67e22; }}
  .scard.low::before    {{ background: #27ae60; }}
  .scard-num {{ font-size: 2.4em; font-weight: 800; color: #fff; line-height: 1; }}
  .scard.high   .scard-num {{ color: #e74c3c; }}
  .scard.medium .scard-num {{ color: #e67e22; }}
  .scard.low    .scard-num {{ color: #27ae60; }}
  .scard-label {{ font-size: 0.72em; color: #556; text-transform: uppercase; letter-spacing: 1.2px; margin-top: 6px; }}

  /* ── Filters ── */
  .filters {{ display: flex; gap: 8px; margin-bottom: 20px; flex-wrap: wrap; align-items: center; }}
  .filters span {{ font-size: 0.8em; color: #556; margin-right: 4px; }}
  .filter-btn {{ padding: 6px 16px; border-radius: 20px; border: 1px solid #1e2235; background: #12151f; color: #889; font-size: 0.8em; cursor: pointer; transition: all 0.15s; }}
  .filter-btn:hover {{ border-color: #3498db; color: #fff; }}
  .filter-btn.active {{ background: #1a2035; border-color: #3498db; color: #fff; }}
  .filter-btn.f-high.active   {{ background: #1f1010; border-color: #e74c3c; color: #e74c3c; }}
  .filter-btn.f-medium.active {{ background: #1f1608; border-color: #e67e22; color: #e67e22; }}
  .filter-btn.f-low.active    {{ background: #0d1a10; border-color: #27ae60; color: #27ae60; }}
  .count-label {{ font-size: 0.78em; color: #446; margin-left: auto; }}

  /* ── File cards ── */
  .file-card {{ background: #12151f; border: 1px solid #1e2235; border-radius: 14px; margin-bottom: 16px; overflow: hidden; transition: border-color 0.15s; }}
  .file-card:hover {{ border-color: #2a2f4a; }}
  .file-card.risk-HIGH   {{ border-left: 3px solid #e74c3c; }}
  .file-card.risk-MEDIUM {{ border-left: 3px solid #e67e22; }}
  .file-card.risk-LOW    {{ border-left: 3px solid #27ae60; }}

  /* Card header (always visible) */
  .card-header {{ display: flex; align-items: center; gap: 14px; padding: 16px 20px; cursor: pointer; user-select: none; }}
  .risk-pill {{ padding: 4px 12px; border-radius: 20px; font-size: 0.72em; font-weight: 700; letter-spacing: 0.8px; white-space: nowrap; }}
  .risk-pill.HIGH   {{ background: #2d1010; color: #e74c3c; }}
  .risk-pill.MEDIUM {{ background: #2d1e08; color: #e67e22; }}
  .risk-pill.LOW    {{ background: #0d1f10; color: #27ae60; }}
  .card-title {{ flex: 1; min-width: 0; }}
  .card-title .fname {{ font-size: 0.95em; font-weight: 600; color: #e8ecff; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }}
  .card-title .fpath {{ font-size: 0.75em; color: #445; font-family: 'Cascadia Code', 'Consolas', monospace; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; margin-top: 2px; }}
  .card-meta {{ display: flex; gap: 20px; align-items: center; flex-wrap: wrap; }}
  .meta-item {{ text-align: right; }}
  .meta-item .label {{ font-size: 0.68em; color: #445; text-transform: uppercase; letter-spacing: 0.8px; }}
  .meta-item .value {{ font-size: 0.82em; color: #889; }}
  .chevron {{ color: #334; font-size: 0.9em; transition: transform 0.2s; margin-left: 8px; }}
  .card-header.open .chevron {{ transform: rotate(180deg); }}

  /* Card body (collapsible) */
  .card-body {{ display: none; border-top: 1px solid #1a1d2e; padding: 20px; gap: 20px; grid-template-columns: 1fr 1fr; }}
  .card-body.open {{ display: grid; }}

  /* ── Section inside card ── */
  .section-box {{ background: #0e1018; border: 1px solid #1a1d2e; border-radius: 10px; padding: 14px 16px; }}
  .section-box h3 {{ font-size: 0.7em; text-transform: uppercase; letter-spacing: 1px; color: #445; margin-bottom: 12px; }}

  /* ── Check rows ── */
  .check-row {{ display: flex; gap: 10px; margin-bottom: 10px; font-size: 0.83em; line-height: 1.4; }}
  .check-row:last-child {{ margin-bottom: 0; }}
  .check-icon {{ width: 16px; flex-shrink: 0; margin-top: 1px; }}
  .check-label {{ font-weight: 600; }}
  .check-detail {{ color: #556; font-size: 0.9em; margin-top: 1px; }}
  .check-hit .check-icon {{ color: #e74c3c; }}
  .check-hit .check-label {{ color: #e8ecff; }}
  .check-hit .check-detail {{ color: #c0b8b8; }}
  .check-ok .check-icon {{ color: #2d3550; }}
  .check-ok .check-label {{ color: #334; }}
  .score-badge {{ display: inline-block; background: #1a0d0d; color: #e74c3c; border: 1px solid #3d1515; padding: 1px 7px; border-radius: 4px; font-size: 0.75em; margin-left: 6px; font-weight: 700; }}

  /* ── File info ── */
  .info-grid {{ display: grid; grid-template-columns: auto 1fr; gap: 6px 14px; font-size: 0.82em; }}
  .info-key {{ color: #445; text-align: right; white-space: nowrap; }}
  .info-val {{ color: #889; font-family: 'Cascadia Code', 'Consolas', monospace; word-break: break-all; }}
  .info-val.warn {{ color: #e67e22; }}

  /* ── Hash ── */
  .hash-box {{ display: flex; align-items: center; gap: 8px; background: #0a0c14; border: 1px solid #1a1d2e; border-radius: 8px; padding: 10px 12px; margin-top: 10px; }}
  .hash-val {{ font-family: 'Cascadia Code', 'Consolas', monospace; font-size: 0.75em; color: #556; flex: 1; word-break: break-all; }}
  .copy-btn {{ background: #1a1d2e; border: 1px solid #252840; color: #778; padding: 4px 10px; border-radius: 6px; font-size: 0.72em; cursor: pointer; white-space: nowrap; transition: all 0.15s; flex-shrink: 0; }}
  .copy-btn:hover {{ background: #252840; color: #aab; }}
  .copy-btn.copied {{ background: #0d2010; border-color: #27ae60; color: #27ae60; }}

  /* ── VT / DB badges ── */
  .vt-section {{ margin-top: 10px; }}
  .vt-clean {{ color: #27ae60; font-size: 0.82em; }}
  .vt-unknown {{ color: #556; font-size: 0.82em; }}
  .vt-warn {{ background: #1f1608; border: 1px solid #5a3a10; border-radius: 8px; padding: 8px 12px; font-size: 0.82em; color: #e67e22; }}
  .vt-danger {{ background: #1f0808; border: 1px solid #5a1010; border-radius: 8px; padding: 8px 12px; font-size: 0.82em; color: #e74c3c; }}
  .vt-link {{ color: #3498db; text-decoration: none; font-size: 0.85em; display: inline-block; margin-top: 4px; }}
  .vt-link:hover {{ text-decoration: underline; }}
  .db-danger {{ background: #1f0808; border: 1px solid #5a1010; border-radius: 8px; padding: 8px 12px; font-size: 0.82em; color: #e74c3c; margin-top: 8px; }}

  /* ── Score bar ── */
  .score-bar-wrap {{ margin-top: 8px; }}
  .score-bar-track {{ background: #1a1d2e; border-radius: 4px; height: 5px; }}
  .score-bar-fill  {{ height: 5px; border-radius: 4px; }}

  /* ── Footer ── */
  .footer {{ margin-top: 40px; text-align: center; font-size: 0.75em; color: #2a2e40; }}

  /* Span full width on small screens */
  @media (max-width: 700px) {{
    .card-body {{ grid-template-columns: 1fr; }}
    .card-meta {{ display: none; }}
  }}
</style>
</head>
<body>
<div class="page">

  <!-- Header -->
  <div class="header">
    <div class="header-left">
      <h1>Suspicious File Analysis Report</h1>
      <div class="tagline">Defensive file analysis &mdash; PowerShell + Python pipeline</div>
    </div>
    <span class="vt-badge {'vt-on' if vt_enabled else 'vt-off'}">
      VirusTotal {vt_status}
    </span>
  </div>

  <!-- Summary cards -->
  <div class="summary">
    <div class="scard total">
      <div class="scard-num">{len(results)}</div>
      <div class="scard-label">Total Files</div>
    </div>
    <div class="scard high">
      <div class="scard-num">{high}</div>
      <div class="scard-label">High Risk</div>
    </div>
    <div class="scard medium">
      <div class="scard-num">{medium}</div>
      <div class="scard-label">Medium Risk</div>
    </div>
    <div class="scard low">
      <div class="scard-num">{low}</div>
      <div class="scard-label">Low Risk</div>
    </div>
  </div>

  <!-- Filters -->
  <div class="filters">
    <span>Filter:</span>
    <button class="filter-btn active" onclick="filterCards('ALL')">All ({len(results)})</button>
    <button class="filter-btn f-high"   onclick="filterCards('HIGH')">High ({high})</button>
    <button class="filter-btn f-medium" onclick="filterCards('MEDIUM')">Medium ({medium})</button>
    <button class="filter-btn f-low"    onclick="filterCards('LOW')">Low ({low})</button>
  </div>

  <!-- File cards -->
  <div id="cards">
""")

    for idx, (r, checks) in enumerate(zip(results, file_checks)):
        score     = r["Score"]
        risk      = r["RiskLevel"]
        bar_pct   = min(100, int(score / 20 * 100))
        bar_color = "#e74c3c" if score >= RISK_HIGH else ("#e67e22" if score >= RISK_MEDIUM else "#27ae60")

        # ── Checks column ──
        checks_html = ""

        dbl_hit, dbl_msg = checks["dbl"]
        checks_html += check_row(
            "Double Extension", dbl_hit,
            dbl_msg if dbl_hit else "No double extension detected",
            score_add=3
        )

        ext_hit, ext_msg = checks["ext"]
        checks_html += check_row(
            "Sensitive Extension", ext_hit,
            ext_msg if ext_hit else f"Extension '{r['Extension']}' is not in watchlist",
            score_add=2
        )

        path_hit, path_msg = checks["path"]
        checks_html += check_row(
            "Unusual Path", path_hit,
            path_msg if path_hit else "File location looks normal",
            score_add=2
        )

        if checks["name"]:
            for msg in checks["name"]:
                checks_html += check_row("Suspicious Name", True, msg, score_add=2)
        else:
            checks_html += check_row("Suspicious Name", False, "Filename looks normal")

        if checks["ts"]:
            for msg in checks["ts"]:
                checks_html += check_row("Timestamp Anomaly", True, msg, score_add=2)
        else:
            checks_html += check_row("Timestamp Anomaly", False, "Timestamps look normal")

        # ── VT / DB column ──
        intel_html = ""
        if r["LocalDBMatch"]:
            intel_html += f"""
            <div class="db-danger">
              <strong>Local DB Match</strong><br>
              {r["LocalDBMatch"]} &mdash; family: {r["LocalDBFamily"]}
            </div>"""

        if r["VTFound"]:
            if r["VTMalicious"] >= VT_MALICIOUS_THRESHOLD:
                intel_html += f"""
            <div class="vt-danger" style="margin-top:8px">
              <strong>VirusTotal: Confirmed Malware</strong><br>
              {r["VTMalicious"]}/{r["VTTotal"]} engines flagged<br>
              <a class="vt-link" href="{r["VTLink"]}" target="_blank">View full report &rarr;</a>
            </div>"""
            elif r["VTMalicious"] > 0 or r["VTSuspicious"] if "VTSuspicious" in r else False:
                intel_html += f"""
            <div class="vt-warn" style="margin-top:8px">
              <strong>VirusTotal: Flagged</strong><br>
              {r["VTMalicious"]}/{r["VTTotal"]} engines flagged<br>
              <a class="vt-link" href="{r["VTLink"]}" target="_blank">View full report &rarr;</a>
            </div>"""
            else:
                intel_html += f'<div class="vt-clean" style="margin-top:8px">&#10003; VirusTotal: Clean &mdash; {r["VTTotal"]} engines checked</div>'
        elif vt_enabled and not r["LocalDBMatch"]:
            intel_html += '<div class="vt-unknown" style="margin-top:8px">Hash not found in VirusTotal database</div>'
        elif not vt_enabled:
            intel_html += '<div class="vt-unknown" style="margin-top:8px">VirusTotal disabled &mdash; set VT_API_KEY in .env</div>'

        f.write(f"""
    <div class="file-card risk-{risk}" data-risk="{risk}">

      <!-- Always-visible header -->
      <div class="card-header" onclick="toggleCard(this)">
        <span class="risk-pill {risk}">{risk}</span>
        <div class="card-title">
          <div class="fname">{r["Name"]}</div>
          <div class="fpath">{r["FullPath"]}</div>
        </div>
        <div class="card-meta">
          <div class="meta-item">
            <div class="label">Size</div>
            <div class="value">{size_human(r["SizeBytes"])}</div>
          </div>
          <div class="meta-item">
            <div class="label">Score</div>
            <div class="value">{score}</div>
          </div>
          <div class="meta-item">
            <div class="label">Extension</div>
            <div class="value">{r["Extension"] or "none"}</div>
          </div>
        </div>
        <span class="chevron">&#9660;</span>
      </div>

      <!-- Collapsible body -->
      <div class="card-body">

        <!-- Left: Checks + Intel -->
        <div>
          <div class="section-box">
            <h3>Detection Checks</h3>
            {checks_html}
          </div>
          <div class="section-box" style="margin-top:12px;">
            <h3>Threat Intelligence</h3>
            {intel_html}
          </div>
        </div>

        <!-- Right: File metadata + hash -->
        <div>
          <div class="section-box">
            <h3>File Metadata</h3>
            <div class="info-grid">
              <span class="info-key">Name</span>
              <span class="info-val">{r["Name"]}</span>
              <span class="info-key">Extension</span>
              <span class="info-val">{r["Extension"] or "none"}</span>
              <span class="info-key">Size</span>
              <span class="info-val">{r["SizeBytes"]} bytes ({size_human(r["SizeBytes"])})</span>
              <span class="info-key">Created</span>
              <span class="info-val {'warn' if any('timestomp' in ts.lower() or 'odd hour' in ts.lower() for ts in checks['ts']) else ''}">{r.get("CreatedAt", "N/A")}</span>
              <span class="info-key">Modified</span>
              <span class="info-val {'warn' if any('before created' in ts.lower() for ts in checks['ts']) else ''}">{r.get("ModifiedAt", "N/A")}</span>
              <span class="info-key">Full Path</span>
              <span class="info-val">{r["FullPath"]}</span>
            </div>
            <div class="score-bar-wrap">
              <div style="display:flex;justify-content:space-between;font-size:0.72em;color:#445;margin-bottom:4px;">
                <span>Risk Score</span><span>{score} / 20</span>
              </div>
              <div class="score-bar-track">
                <div class="score-bar-fill" style="width:{bar_pct}%;background:{bar_color};"></div>
              </div>
            </div>
          </div>
          <div class="section-box" style="margin-top:12px;">
            <h3>SHA-256 Hash</h3>
            <div class="hash-box">
              <span class="hash-val" id="hash-{idx}">{r["SHA256"]}</span>
              <button class="copy-btn" onclick="copyHash('hash-{idx}', this)">Copy</button>
            </div>
          </div>
        </div>

      </div>
    </div>
""")

    f.write(f"""
  </div><!-- #cards -->

  <div class="footer">
    Generated by Analyseur de fichiers suspects &mdash; {len(results)} file(s) scanned
  </div>

</div><!-- .page -->

<script>
  function toggleCard(header) {{
    header.classList.toggle('open');
    header.nextElementSibling.classList.toggle('open');
  }}

  function filterCards(level) {{
    document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
    event.target.classList.add('active');
    document.querySelectorAll('.file-card').forEach(card => {{
      card.style.display = (level === 'ALL' || card.dataset.risk === level) ? '' : 'none';
    }});
  }}

  function copyHash(id, btn) {{
    const text = document.getElementById(id).textContent;
    navigator.clipboard.writeText(text).then(() => {{
      btn.textContent = 'Copied!';
      btn.classList.add('copied');
      setTimeout(() => {{ btn.textContent = 'Copy'; btn.classList.remove('copied'); }}, 2000);
    }});
  }}

  // Auto-expand HIGH risk cards on load
  document.querySelectorAll('.file-card.risk-HIGH .card-header').forEach(h => {{
    h.classList.add('open');
    h.nextElementSibling.classList.add('open');
  }});
</script>
</body>
</html>
""")

print(f"[+] HTML report  -> {report_html}")
print("[*] Analysis complete.")
