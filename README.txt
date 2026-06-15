================================================================
  ANALYSEUR DE FICHIERS SUSPECTS
  Suspicious File Analyzer — PowerShell + Python
================================================================

DESCRIPTION
-----------
Two-script pipeline for defensive file analysis:
  1. collect.ps1  — runs on Windows, scans a folder, exports an
                    inventory with metadata and SHA-256 hashes.
  2. analyze.py   — runs on any OS, reads the inventory, scores
                    each file for suspicion, generates reports.

----------------------------------------------------------------
PROJECT STRUCTURE
----------------------------------------------------------------

python-powershell/
├── collect.ps1          PowerShell collector
├── analyze.py           Python analyzer
├── data/                Raw output from collect.ps1
│   ├── inventory.csv    Human-readable spreadsheet
│   └── inventory.json   Machine-readable (input for analyze.py)
├── results/             Output from analyze.py
│   ├── risk_report.txt  Human-readable risk report
│   ├── risk_report.json Full structured report (JSON)
│   └── hashes.txt       SHA-256 list (sha256sum format)
└── README.txt           This file

----------------------------------------------------------------
REQUIREMENTS
----------------------------------------------------------------

PowerShell step:
  - Windows PowerShell 5.1+ or PowerShell 7+
  - No external modules needed (Get-FileHash is built-in)

Python step:
  - Python 3.10+ (uses built-in json, argparse, pathlib only)
  - No pip install required

----------------------------------------------------------------
STEP 1 — RUN THE POWERSHELL COLLECTOR (Windows)
----------------------------------------------------------------

Open PowerShell as a normal user (no admin needed for read-only
scanning), then run:

    cd path\to\python-powershell
    .\collect.ps1 -TargetFolder "C:\path\to\folder\to\scan"

If execution policy blocks the script, allow it for this session:

    Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass

Output files created:
  data\inventory.csv
  data\inventory.json

----------------------------------------------------------------
STEP 2 — RUN THE PYTHON ANALYZER
----------------------------------------------------------------

From the project root (works on Windows, Linux, Mac):

    python analyze.py --input data/inventory.json

Or on systems where python3 is the command:

    python3 analyze.py --input data/inventory.json

Output files created:
  results\risk_report.txt
  results\risk_report.json
  results\hashes.txt

----------------------------------------------------------------
DETECTION RULES
----------------------------------------------------------------

Rule                    Score added   Description
----------------------  -----------   ---------------------------
Double extension        +3            file.pdf.exe, photo.jpg.bat
Sensitive extension     +2            .exe .ps1 .bat .cmd .vbs
                                      .js .scr .lnk
Unusual path            +2            \Temp\ \AppData\Roaming\
                                      \Public\ \Recycle ...

Risk levels:
  HIGH   — score >= 3
  MEDIUM — score >= 1
  LOW    — score  = 0

----------------------------------------------------------------
CROSS-REFERENCING HASHES
----------------------------------------------------------------

The file results\hashes.txt uses the same format as sha256sum.
You can submit individual hashes to VirusTotal manually:
  https://www.virustotal.com/gui/home/search

----------------------------------------------------------------
IMPORTANT — LEGAL AND ETHICAL NOTICE
----------------------------------------------------------------

- Run only on machines you own or have explicit written permission
  to analyze.
- Scripts are read-only and non-destructive.
- No passwords, tokens, or personal data are collected.
- Do NOT run against production systems without authorization.

================================================================
