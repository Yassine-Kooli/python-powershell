# collect.ps1 - PowerShell file inventory collector
# Usage: .\collect.ps1 -TargetFolder "C:\path\to\folder"

# -TargetFolder is a required argument the user passes when running the script
param(
    [Parameter(Mandatory=$true)]
    [string]$TargetFolder
)

# Stop the script immediately if any error occurs instead of silently continuing
$ErrorActionPreference = "Stop"

# ── Validate input ────────────────────────────────────────────────────────────

# Check the folder actually exists before doing anything
if (-not (Test-Path -Path $TargetFolder -PathType Container)) {
    Write-Error "Folder not found: $TargetFolder"
    exit 1
}

Write-Host "[*] Scanning folder: $TargetFolder" -ForegroundColor Cyan

# ── Scan files ────────────────────────────────────────────────────────────────

# Get-ChildItem lists files; -Recurse goes into subfolders; -File skips folders
$files = Get-ChildItem -Path $TargetFolder -Recurse -File

Write-Host "[*] Found $($files.Count) file(s)" -ForegroundColor Cyan

# ── Build inventory ───────────────────────────────────────────────────────────

# We will collect one object per file and store them all in this list
$inventory = @()

foreach ($file in $files) {

    # Compute SHA-256 hash of the file content
    # Get-FileHash returns an object; .Hash is the hex string
    $hash = (Get-FileHash -Path $file.FullName -Algorithm SHA256).Hash

    # Build a structured object with all the fields we need
    $entry = [PSCustomObject]@{
        Name         = $file.Name                        # filename with extension
        Extension    = $file.Extension.ToLower()         # e.g. ".exe" (lowercase for easy comparison)
        SizeBytes    = $file.Length                      # size in bytes
        CreatedAt    = $file.CreationTime.ToString("yyyy-MM-dd HH:mm:ss")
        ModifiedAt   = $file.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss")
        FullPath     = $file.FullName                    # absolute path on disk
        SHA256       = $hash
    }

    $inventory += $entry
}

# ── Export to CSV ─────────────────────────────────────────────────────────────

# Resolve the data/ folder relative to where this script lives
$dataFolder = Join-Path $PSScriptRoot "data"

# Create the data/ folder if it doesn't exist yet
if (-not (Test-Path $dataFolder)) {
    New-Item -ItemType Directory -Path $dataFolder | Out-Null
}

$csvPath  = Join-Path $dataFolder "inventory.csv"
$jsonPath = Join-Path $dataFolder "inventory.json"

# Export-Csv writes one row per object; -NoTypeInformation removes the noisy header line PS adds
$inventory | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8

Write-Host "[+] CSV saved  -> $csvPath" -ForegroundColor Green

# ── Export to JSON ────────────────────────────────────────────────────────────

# ConvertTo-Json serializes the array; -Depth 3 ensures nested objects are fully expanded
$inventory | ConvertTo-Json -Depth 3 | Set-Content -Path $jsonPath -Encoding UTF8

Write-Host "[+] JSON saved -> $jsonPath" -ForegroundColor Green
Write-Host "[*] Done." -ForegroundColor Cyan
