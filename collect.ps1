# collect.ps1 - PowerShell file inventory collector
# Usage: .\collect.ps1 -TargetFolder "C:\path\to\folder"

param(
    [Parameter(Mandatory=$true)]
    [string]$TargetFolder
)

# TODO: validate folder exists
# TODO: scan files recursively
# TODO: collect name, extension, size, dates, full path, SHA-256
# TODO: export to data/inventory.csv and data/inventory.json
