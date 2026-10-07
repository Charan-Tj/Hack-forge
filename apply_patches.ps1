# KavachForge - Windows PowerShell Patch Applier
param(
    [Parameter(Mandatory=$true, Position=0)]
    [string]$AppDir,

    [Parameter(Mandatory=$false, Position=1)]
    [string]$Name = "final"
)

if (-not (Test-Path $AppDir)) {
    Write-Host "Error: Target app directory not found: $AppDir" -ForegroundColor Red
    exit 1
}

$patches = Get-ChildItem -Path "artifacts/$Name/pr/*/fix.patch" -ErrorAction SilentlyContinue
if (-not $patches) {
    Write-Host "No verified patches found in artifacts/$Name/pr/" -ForegroundColor Yellow
    exit 0
}

$applied = 0
foreach ($p in $patches) {
    Write-Host "Applying $($p.FullName) to $AppDir ..."
    $res = git -C $AppDir apply --check $p.FullName 2>&1
    if ($LASTEXITCODE -eq 0) {
        git -C $AppDir apply $p.FullName
        Write-Host "  [OK] Applied: $($p.Name)" -ForegroundColor Green
        $applied++
    } else {
        Write-Host "  ! Skipped: does not apply cleanly" -ForegroundColor Yellow
    }
}

Write-Host "$applied / $($patches.Count) patch(es) applied." -ForegroundColor Cyan
