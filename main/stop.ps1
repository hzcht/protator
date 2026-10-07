# Stop the running protator instance. Graceful: SIGTERM gives in-flight
# requests the shutdown_timeout budget from the config to finish, and the
# queue is saved after the drain. Falls back to -Force if it doesn't exit.
$ErrorActionPreference = "Stop"

$p = Get-Process -Name "main" -ErrorAction SilentlyContinue
if (-not $p) {
    Write-Host "no main.exe instance running"
    exit 0
}

$p | Stop-Process
if (-not $p.WaitForExit(20000)) {
    Write-Host "no graceful exit within 20s - forcing"
    $p | Stop-Process -Force
}
Write-Host "stopped pid(s): $($p.Id -join ', ')"