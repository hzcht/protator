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

# Stop the old instance BEFORE building: Windows denies writing a running
# exe, so build-first broke every restart by default. Match by path, not
# name (-Name "main" would kill unrelated main.exe processes).
$old = @(Get-Process -ErrorAction SilentlyContinue |
    Where-Object { $_.Path -and $_.Path -eq $exe })
if ($old) {
    # Prefer the graceful stop (cooperative shutdown + save); it lives next
    # to this script and falls back to a hard kill on its own.
    & (Join-Path $PSScriptRoot "stop.ps1")
    foreach ($p in $old) {
        try { $p.WaitForExit(5000) | Out-Null } catch { }
    }
    $still = @(Get-Process -ErrorAction SilentlyContinue |
        Where-Object { $_.Path -and $_.Path -eq $exe })
    if ($still) {
        $still | Stop-Process -Force
        Write-Host "stopped old instance(s) after timeout: $($still.Id -join ', ')"
    } else {
        Write-Host "stopped old instance(s): $($old.Id -join ', ')"
    }
}

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

if ($Check) {
    & $exe -config (Join-Path $root $Config) -check
    exit $LASTEXITCODE
}

# The daemon reads config/ and data/ by relative path, so its working
# directory must be the repo root — ".." resolved against the invoker's CWD
# (the old bug) put those paths outside the repo and started with an empty
# queue and no sites every time the script was run from elsewhere.
Start-Process -FilePath $exe `
    -ArgumentList "-config", (Join-Path $root $Config) `
    -WorkingDirectory $root `
    -WindowStyle Hidden `
    -RedirectStandardError (Join-Path $root "data/instance_err.log")

Start-Sleep -Seconds 1
$p = @(Get-Process -ErrorAction SilentlyContinue |
    Where-Object { $_.Path -and $_.Path -eq $exe })
if (-not $p) {
    Write-Error "instance failed to start - see $(Join-Path $root 'data/instance_err.log')"
    exit 1
}
Write-Host "started pid(s): $($p.Id -join ', ')"
