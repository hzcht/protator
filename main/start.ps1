# Start protator as a background process (no console window).
# Safe to re-run: stops any existing instance first, so it also doubles as a
# restart. Useful for ops:
#   .\start.ps1               normal start
#   .\start.ps1 -Config alt   different config file
#   .\start.ps1 -NoBuild      use the existing main.exe as-is
#   .\start.ps1 -Check        validate config + files, then exit (no daemon)
param(
    [string]$Config = "config/config.toml",
    [switch]$Check,
    [switch]$NoBuild
)

$ErrorActionPreference = "Stop"

$exe = Join-Path $PSScriptRoot "main.exe"
$root = Split-Path $PSScriptRoot -Parent

# Rebuild by default. Skipping this is how you end up running yesterday's
# binary: a stale main.exe in this directory is silently "the app", and the
# symptom is a fix that looks like it did nothing (e.g. an admin page that
# never got its new routes).
if (-not $Check -and -not $NoBuild) {
    Push-Location $PSScriptRoot
    try {
        Write-Host "building..."
        & go build -o main.exe .
        if ($LASTEXITCODE -ne 0) {
            Write-Error "go build failed (exit $LASTEXITCODE)"
            exit 1
        }
    } finally {
        Pop-Location
    }
}

if (-not (Test-Path $exe)) {
    Write-Error "main.exe not found in $PSScriptRoot (run 'go build -o main.exe .' first)"
    exit 1
}
if (-not (Test-Path (Join-Path $root $Config))) {
    Write-Error "config file not found: $Config"
    exit 1
}

$err = Join-Path $root "data/instance_err.log"

if ($Check) {
    & $exe -config (Join-Path $root $Config) -check
    exit $LASTEXITCODE
}

# Restart semantics: kill whatever is running so a stale instance with an old
# config never survives a deploy.
$old = Get-Process -Name "main" -ErrorAction SilentlyContinue
if ($old) {
    $old | Stop-Process -Force
    Start-Sleep -Milliseconds 500
    Write-Host "stopped old instance(s): $($old.Id -join ', ')"
}

Start-Process -FilePath $exe `
    -ArgumentList "-config", (Join-Path $root $Config) `
    -WorkingDirectory ".." `
    -WindowStyle Hidden `
    -RedirectStandardError (Join-Path $root "data/instance_err.log")

Start-Sleep -Seconds 1
$p = Get-Process -Name "main" -ErrorAction SilentlyContinue
if (-not $p) {
    Write-Error "instance failed to start - see $err"
    exit 1
}
Write-Host "started pid(s): $($p.Id -join ', ')"