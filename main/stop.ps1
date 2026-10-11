# Stop the running protator instance.
#
# Windows has no SIGTERM: Stop-Process is TerminateProcess, so the Go graceful
# path (drain, stopAndWait, saveQueue, pool.Close) never runs on a hard kill —
# every scheduled stop would lose the queue tail. The real stop is therefore
# cooperative: POST /api/shutdown, which cancels the process context and lets
# main's own shutdown sequence drain and save. The hard kill is only the
# fallback for a hung instance (and is labeled as data-losing).
#
# Processes are matched by executable path, not by name: -Name "main" would
# kill any main.exe on the box.
$ErrorActionPreference = "Stop"

$exe = Join-Path $PSScriptRoot "main.exe"
$root = Split-Path $PSScriptRoot -Parent

$procs = @(Get-Process -ErrorAction SilentlyContinue |
    Where-Object { $_.Path -and $_.Path -eq $exe })
if (-not $procs) {
    Write-Host "no protator instance running"
    exit 0
}

# Cooperative stop: default admin listener, token from config if set.
$port = 9090
$token = ""
$cfgPath = Join-Path $root "config/config.toml"
if (Test-Path $cfgPath) {
    foreach ($line in Get-Content $cfgPath) {
        if ($line -match '^\s*admin_listen\s*=\s*"127\.0\.0\.1:(\d+)"') { $port = [int]$Matches[1] }
        elseif ($line -match '^\s*admin_listen\s*=\s*"0\.0\.0\.0:(\d+)"') { $port = [int]$Matches[1] }
        elseif ($line -match '^\s*admin_token\s*=\s*"([^"]+)"') { $token = $Matches[1] }
    }
}
$headers = @{}
if ($token) { $headers["Authorization"] = "Bearer $token" }
try {
    Invoke-WebRequest -Uri "http://127.0.0.1:$port/api/shutdown" -Method POST `
        -Headers $headers -UseBasicParsing -TimeoutSec 5 | Out-Null
    Write-Host "cooperative shutdown requested (port $port)"
} catch {
    Write-Host "cooperative shutdown unavailable ($($_.Exception.Message)) - falling back to hard kill"
}

foreach ($p in $procs) {
    if (-not $p.WaitForExit(30000)) {
        Write-Host "pid $($p.Id) did not exit within 30s - forcing (queue tail may be lost)"
        $p | Stop-Process -Force
    } else {
        Write-Host "stopped pid $($p.Id) gracefully"
    }
}
