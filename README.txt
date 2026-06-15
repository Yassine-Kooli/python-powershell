================================================================
  ANALYSEUR DE FICHIERS SUSPECTS
  Suspicious File Analyzer — PowerShell + Python
================================================================

DESCRIPTION
-----------
Two-script pipeline for defensive file analysis in investigation
contexts. Combines Windows-native collection with Python-based
detection and VirusTotal threat-intel lookup.

  1. collect.ps1  — runs on Windows, scans a folder recursively,
                    exports metadata + SHA-256 hashes to data/.
  2. analyze.py   — runs on any OS, reads the inventory, scores
                    each file across 4 detection layers, generates
                    reports to results/.

----------------------------------------------------------------
PROJECT STRUCTURE
----------------------------------------------------------------

python-powershell/
├── collect.ps1                  PowerShell collector
├── analyze.py                   Python analyzer
├── .env                         API keys (never commit this)
├── .gitignore                   Excludes .env, data/, results/
├── data/
│   ├── inventory.csv            Human-readable spreadsheet
│   ├── inventory.json           Input for analyze.py
│   ├── known_malware_hashes.json  Local threat database
│   └── skipped_files.txt        Files collect.ps1 could not read
└── results/
    ├── risk_report.txt          Human-readable risk report
    ├── risk_report.json         Full structured report
    └── hashes.txt               SHA-256 list (sha256sum format)

----------------------------------------------------------------
REQUIREMENTS
----------------------------------------------------------------

PowerShell step (Windows only):
  - Windows PowerShell 5.1+ or PowerShell 7+
  - No external modules needed

Python step (Windows / Linux / Mac):
  - Python 3.10+
  - Dependencies: requests, python-dotenv
  - Install: pip install requests python-dotenv
    Or with uv: uv pip install requests python-dotenv

----------------------------------------------------------------
CONFIGURATION — API KEY SETUP
----------------------------------------------------------------

1. Create a free account at https://www.virustotal.com
2. Go to your profile → API key → copy the key
3. Open .env and set:

     VT_API_KEY=your_key_here

The script reads the key automatically from .env.
If VT_API_KEY is not set, VirusTotal lookup is silently skipped
and only local detection rules + local DB are used.

----------------------------------------------------------------
STEP 1 — RUN THE POWERSHELL COLLECTOR (Windows)
----------------------------------------------------------------

Open PowerShell (no admin required for user folders), then run:

    cd path\to\python-powershell
    .\collect.ps1 -TargetFolder "C:\path\to\folder\to\scan"

If execution policy blocks the script, allow it for this session:

    Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass

Output files created:
  data\inventory.csv
  data\inventory.json
  data\skipped_files.txt   (only if some files could not be read)

Note: files that are locked by the OS (e.g. system files) are
automatically skipped and logged — the scan continues normally.

----------------------------------------------------------------
STEP 2 — RUN THE PYTHON ANALYZER
----------------------------------------------------------------

From the project root:

    python analyze.py

Or explicitly:

    python analyze.py --input data/inventory.json

Output files created:
  results\risk_report.txt
  results\risk_report.json
  results\hashes.txt

----------------------------------------------------------------
DETECTION LAYERS
----------------------------------------------------------------

Layer   Source          Trigger                         Score
------  --------------  ------------------------------  ------
1       Rules           Double extension (.pdf.exe)     +3
1       Rules           Sensitive extension             +2
1       Rules           Unusual path (\Temp\, etc.)     +2
2       Local DB        Match in known_malware_hashes   +10
3       VirusTotal      3+ AV engines flagged           +10
3       VirusTotal      1-2 AV engines flagged          +4

Risk levels:
  HIGH   — score >= 3
  MEDIUM — score >= 1
  LOW    — score  = 0

Sensitive extensions watched:
  .exe  .ps1  .bat  .cmd  .vbs  .js  .scr  .lnk

Note: .js files inside node_modules/, dist/, build/, .next/,
vendor/ and similar framework folders are whitelisted to avoid
false positives from Node.js projects.

----------------------------------------------------------------
ADDING HASHES TO THE LOCAL DATABASE
----------------------------------------------------------------

Edit data/known_malware_hashes.json and add an entry:

  {
    "sha256": "the_full_sha256_hash_here",
    "name": "Trojan.GenericKD.12345",
    "family": "GenericKD",
    "severity": "HIGH",
    "source": "virustotal"
  }

Sources for known malware hashes:
  - VirusTotal reports (copy the SHA256 from the file page)
  - MalwareBazaar: https://bazaar.abuse.ch
  - CIRCL hashlookup: https://hashlookup.circl.lu

----------------------------------------------------------------
CROSS-REFERENCING HASHES MANUALLY
----------------------------------------------------------------

results\hashes.txt uses the sha256sum format:
  HASH  filename

Submit individual hashes to VirusTotal:
  https://www.virustotal.com/gui/home/search

----------------------------------------------------------------
IMPORTANT — LEGAL AND ETHICAL NOTICE
----------------------------------------------------------------

- Run only on machines you own or have explicit written
  authorization to analyze.
- Scripts are strictly read-only and non-destructive.
- No passwords, tokens, browser data, or personal information
  are ever collected or transmitted.
- Do NOT run against production systems without authorization.
- All Red Team simulations must remain local and controlled.

================================================================
