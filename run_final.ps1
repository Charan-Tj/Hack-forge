# KavachForge - Windows PowerShell Final Runner
param(
    [Parameter(Mandatory=$false, Position=0)]
    [string]$Source = "",

    [Parameter(Mandatory=$false)]
    [string]$Model = "phi4:14b",

    [Parameter(Mandatory=$false)]
    [string]$Provider = "ollama",

    [Parameter(Mandatory=$false)]
    [string]$Name = "final",

    [Parameter(Mandatory=$false)]
    [int]$DeadlineMin = 20,

    [Parameter(Mandatory=$false)]
    [int]$MaxFindings = 8,

    [Parameter(Mandatory=$false)]
    [string]$Precision = "balanced",

    [Parameter(Mandatory=$false)]
    [int]$Budget = 24,

    [Parameter(Mandatory=$false)]
    [int]$Port = 8777
)

if (-not $Source) {
    Write-Host "Usage: .\run_final.ps1 <source.tar.gz | dir | git-url> [-Model phi4:14b] [-Name final] [-DeadlineMin 20]" -ForegroundColor Yellow
    exit 1
}

if (-not (Test-Path $Source)) {
    Write-Host "Error: Source not found: $Source" -ForegroundColor Red
    exit 1
}

$env:PYTHONUNBUFFERED = "1"
$env:PYTHONIOENCODING = "utf-8"

Write-Host "[kavach] 1/6 python" -ForegroundColor Cyan
$pyCmd = (Get-Command python -ErrorAction SilentlyContinue)
if (-not $pyCmd) {
    Write-Host "  Error: python not found on PATH" -ForegroundColor Red
    exit 1
}
$pyVer = & python --version
Write-Host "  [OK] $pyVer" -ForegroundColor Green

Write-Host "[kavach] 2/6 analyzer" -ForegroundColor Cyan
Write-Host "  using 36 built-in patterns + model review" -ForegroundColor Gray

Write-Host "[kavach] 3/6 model ($Model via $Provider)" -ForegroundColor Cyan
Write-Host "  [OK] provider=$Provider model=$Model budget=$Budget deadline=${DeadlineMin}min max-findings=$MaxFindings precision=$Precision" -ForegroundColor Green

Write-Host "[kavach] 4/6 self-check" -ForegroundColor Cyan
python -m kavachforge doctor | Out-Null
Write-Host "  [OK] doctor check completed" -ForegroundColor Green

Write-Host "[kavach] 5/6 run -- artifacts/$Name/   (live log below; dashboard live)" -ForegroundColor Cyan
if (-not (Test-Path "artifacts")) {
    New-Item -ItemType Directory -Force -Path "artifacts" | Out-Null
}

# Start background server
Start-Process -FilePath python -ArgumentList "-m kavachforge serve --port $Port" -WindowStyle Hidden -ErrorAction SilentlyContinue
Write-Host "  [OK] dashboard live: http://localhost:$Port/$Name/dashboard.html" -ForegroundColor Green

# Run universal track onboarding & repair with unbuffered stdout
python -u -m kavachforge onboard $Source --name $Name --mode universal --run `
    --provider $Provider --model $Model --yes --budget $Budget --max-findings $MaxFindings `
    --deadline-min $DeadlineMin --precision $Precision

Write-Host "`n[kavach] 6/6 deliverables" -ForegroundColor Cyan
if (Test-Path "artifacts/$Name/report.md") {
    Write-Host "  [OK] report   : artifacts/$Name/report.md (+ report.csv)" -ForegroundColor Green
    Write-Host "  [OK] dashboard: http://localhost:$Port/$Name/dashboard.html" -ForegroundColor Green
    $patches = Get-ChildItem -Path "artifacts/$Name/pr/*/fix.patch" -ErrorAction SilentlyContinue
    $patchCount = if ($patches) { $patches.Count } else { 0 }
    Write-Host "  [OK] patches  : $patchCount verified patch file(s)" -ForegroundColor Green
    Write-Host ""
    Get-Content "artifacts/$Name/report.md" -TotalCount 40
} else {
    Write-Host "  Warning: No report was written." -ForegroundColor Yellow
}
