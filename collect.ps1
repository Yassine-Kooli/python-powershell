# collect.ps1 - PowerShell file inventory collector
# Usage: .\collect.ps1 -TargetFolder "C:\path\to\folder"

param(
    [Parameter(Mandatory=$true)]
    [string]$TargetFolder
)

# Continue on errors — we handle them per-file below instead of crashing the whole script
# "Continue" means PowerShell logs the error but keeps running
$ErrorActionPreference = "Continue"

# ── Validate input ────────────────────────────────────────────────────────────

if (-not (Test-Path -Path $TargetFolder -PathType Container)) {
    Write-Error "Folder not found: $TargetFolder"
    exit 1
}

Write-Host "[*] Scanning folder: $TargetFolder" -ForegroundColor Cyan

# ── Scan files ────────────────────────────────────────────────────────────────

$files = Get-ChildItem -Path $TargetFolder -Recurse -File

Write-Host "[*] Found $($files.Count) file(s)" -ForegroundColor Cyan

# ── Build inventory ───────────────────────────────────────────────────────────

$inventory = @()   # successfully processed files
$skipped   = @()   # files we couldn't read (locked, no permission, etc.)

foreach ($file in $files) {

    # Wrap each file in Try/Catch so one locked/protected file doesn't
    # stop the entire scan — we log it and move on to the next file
    try {

        # Get-FileHash will throw if the file is locked or unreadable
        $hash = (Get-FileHash -Path $file.FullName -Algorithm SHA256 -ErrorAction Stop).Hash

        $entry = [PSCustomObject]@{
            Name       = $file.Name
            Extension  = $file.Extension.ToLower()
            SizeBytes  = $file.Length
            CreatedAt  = $file.CreationTime.ToString("yyyy-MM-dd HH:mm:ss")
            ModifiedAt = $file.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss")
            FullPath   = $file.FullName
            SHA256     = $hash
        }

        $inventory += $entry

    } catch {
        # $_.Exception.Message contains the actual error (e.g. "Access is denied")
        Write-Warning "Skipped (cannot read): $($file.FullName) — $($_.Exception.Message)"

        # Record skipped files separately so the analyst knows what was missed
        $skipped += [PSCustomObject]@{
            FullPath = $file.FullName
            Reason   = $_.Exception.Message
        }
    }
}

Write-Host "[*] Processed: $($inventory.Count) file(s), Skipped: $($skipped.Count) file(s)" -ForegroundColor Cyan

# ── Export to data/ ───────────────────────────────────────────────────────────

$dataFolder = Join-Path $PSScriptRoot "data"

if (-not (Test-Path $dataFolder)) {
    New-Item -ItemType Directory -Path $dataFolder | Out-Null
}

$csvPath     = Join-Path $dataFolder "inventory.csv"
$jsonPath    = Join-Path $dataFolder "inventory.json"
$skippedPath = Join-Path $dataFolder "skipped_files.txt"

# ── CSV export ────────────────────────────────────────────────────────────────

$inventory | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
Write-Host "[+] CSV saved      -> $csvPath" -ForegroundColor Green

# ── JSON export ───────────────────────────────────────────────────────────────

# @() forces an array even when $inventory has only 1 item
# Without this, ConvertTo-Json outputs {} instead of [{}] and breaks Python
(@($inventory) | ConvertTo-Json -Depth 3) | Set-Content -Path $jsonPath -Encoding UTF8
Write-Host "[+] JSON saved     -> $jsonPath" -ForegroundColor Green

# ── Skipped files log ─────────────────────────────────────────────────────────

if ($skipped.Count -gt 0) {
    $skipped | ForEach-Object { "$($_.FullPath) — $($_.Reason)" } |
        Set-Content -Path $skippedPath -Encoding UTF8
    Write-Host "[!] Skipped log    -> $skippedPath ($($skipped.Count) file(s))" -ForegroundColor Yellow
}

Write-Host "[*] Done." -ForegroundColor Cyan
