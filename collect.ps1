# collect.ps1 - PowerShell file inventory collector
# Usage: .\collect.ps1 -TargetFolder "C:\path\to\folder"

param(
    [Parameter(Mandatory=$true)]
    [string]$TargetFolder
)

# Continue on errors - we handle them per-file below instead of crashing
$ErrorActionPreference = "Continue"

# -- Validate input -----------------------------------------------------------

if (-not (Test-Path -Path $TargetFolder -PathType Container)) {
    Write-Error "Folder not found: $TargetFolder"
    exit 1
}

Write-Host "[*] Scanning folder: $TargetFolder" -ForegroundColor Cyan

# -- Scan files ---------------------------------------------------------------

# Get-ChildItem lists files; -Recurse goes into subfolders; -File skips folders
$files = Get-ChildItem -Path $TargetFolder -Recurse -File

Write-Host "[*] Found $($files.Count) file(s)" -ForegroundColor Cyan

# -- Build inventory ----------------------------------------------------------

$inventory = @()
$skipped   = @()

foreach ($file in $files) {

    # Try/Catch per file so one locked file does not stop the whole scan
    try {

        # Get-FileHash throws if file is locked or access is denied
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
        # Record which file failed and why, then continue to the next one
        $reason = $_.Exception.Message
        Write-Warning "Skipped (cannot read): $($file.FullName) - $reason"

        $skipped += [PSCustomObject]@{
            FullPath = $file.FullName
            Reason   = $reason
        }
    }
}

Write-Host "[*] Processed: $($inventory.Count) file(s), Skipped: $($skipped.Count) file(s)" -ForegroundColor Cyan

# -- Export to data/ ----------------------------------------------------------

$dataFolder = Join-Path $PSScriptRoot "data"

if (-not (Test-Path $dataFolder)) {
    New-Item -ItemType Directory -Path $dataFolder | Out-Null
}

$csvPath     = Join-Path $dataFolder "inventory.csv"
$jsonPath    = Join-Path $dataFolder "inventory.json"
$skippedPath = Join-Path $dataFolder "skipped_files.txt"

# -- CSV ----------------------------------------------------------------------

$inventory | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
Write-Host "[+] CSV saved      -> $csvPath" -ForegroundColor Green

# -- JSON ---------------------------------------------------------------------

# @() forces an array even when $inventory has only 1 item
# Without this, ConvertTo-Json outputs {} instead of [{}] and breaks Python
$json = @($inventory) | ConvertTo-Json -Depth 3
$json | Set-Content -Path $jsonPath -Encoding UTF8
Write-Host "[+] JSON saved     -> $jsonPath" -ForegroundColor Green

# -- Skipped files log --------------------------------------------------------

if ($skipped.Count -gt 0) {
    $lines = $skipped | ForEach-Object { "$($_.FullPath) - $($_.Reason)" }
    $lines | Set-Content -Path $skippedPath -Encoding UTF8
    Write-Host "[!] Skipped log    -> $skippedPath ($($skipped.Count) file(s))" -ForegroundColor Yellow
}

Write-Host "[*] Done." -ForegroundColor Cyan
