<#--
servertest/stress.ps1 - load test for the running instance.

Hammers the front-ends with concurrent requests through the proxy and reports
what an operator needs: success rate, throughput, latency percentiles, how many
distinct exit IPs the rotating pool produced, the app's OWN counters for the
same window (/api/metrics before/after: served, dial failures, evictions, block
pages), and the goroutine count before vs after (a leak shows here, not in the
request stats).

Exit codes: 0 = thresholds met, 1 = thresholds missed, 2 = front-end unusable.
#>
[CmdletBinding()]
param(
    [string]$HttpFront = "http://127.0.0.1:8888",
    [string]$HttpsFront = "https://127.0.0.1:8443",
    [string]$Socks = "127.0.0.1:1080",
    [string]$Admin = "http://127.0.0.1:9090",
    [string]$Url = "https://api.ipify.org",
    [ValidateSet("http", "https", "socks5")] [string]$Front = "http",
    [int]$Concurrency = 20,
    [int]$Requests = 400,
    [int]$TimeoutSec = 25,
    [int]$SuccessPct = 95,
    [int]$P99Ms = 10000,
    [int]$SettleSec = 10
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

function Get-Metrics {
    try { return (Invoke-RestMethod -Uri "$Admin/api/metrics?format=text" -TimeoutSec 10 -ErrorAction Stop) } catch { return $null }
}
function MetricValue([string]$raw, [string]$name) {
    if (-not $raw) { return 0 }
    $line = ($raw -split "`n" | Where-Object { $_ -match "^\s*$([regex]::Escape($name))\s" } | Select-Object -First 1)
    if (-not $line) { return 0 }
    $v = ($line.Trim() -split "\s+")[1]
    return [int64]$v
}
function HealthField([string]$name) {
    try {
        $h = Invoke-RestMethod -Uri "$Admin/health" -TimeoutSec 10 -ErrorAction Stop
        return $h.$name
    } catch { return $null }
}

Write-Host ("stress: front=$Front url=$Url conc=$Concurrency requests=$Requests (success>=${SuccessPct}% p99<=${P99Ms}ms)") -ForegroundColor Cyan

$m0raw = Get-Metrics
function Delta([string]$name) {
    $a = MetricValue $m0raw $name
    $b = MetricValue (Get-Metrics) $name
    return [int64]([Math]::Max(0, $b - $a))
}
$gBefore = HealthField "goroutines"

$results = New-Object System.Collections.Generic.List[string]
$lock = New-Object object
$perWorker = [Math]::Max(1, [Math]::Floor($Requests / $Concurrency))

$start = Get-Date
$jobs = 1..$Concurrency | ForEach-Object {
    Start-Job -ScriptBlock {
        param($front, $url, $count, $timeout, $httpFront, $httpsFront, $socks)
        # NB: not $args - that is a PowerShell automatic variable. Assigning to
        # it silently does nothing useful, and the proxy flags were lost, so
        # every request went direct: the client saw success (the internet works
        # without us) while the app's counters stayed flat.
        $curlArgs = @("-s", "-A", "servertest/1.0", "-w", "`n__STATS__ %{http_code} %{time_total} %{size_download}",
                      "--max-time", "$timeout", "--connect-timeout", "10")
        switch ($front) {
            "http"   { $curlArgs += @("-x", $httpFront) }
            # -k for the target, --proxy-insecure for the proxy's own self-signed
            # certificate: curl verifies the two chains separately, and skipping
            # the second one fails every HTTPS-proxy request (exit 52/56).
            "https"  { $curlArgs += @("-k", "--proxy-insecure", "-x", $httpsFront) }
            "socks5" { $curlArgs += @("-k", "--socks5-hostname", $socks) }
        }
        if (-not ($curlArgs -contains "-x" -or $curlArgs -contains "--socks5-hostname")) {
            throw "no proxy flag was built for front '$front' - the run would bypass the proxy"
        }
        $out = for ($i = 0; $i -lt $count; $i++) {
            $psi = New-Object System.Diagnostics.ProcessStartInfo
            $psi.FileName = "curl"
            $psi.Arguments = (($curlArgs + $url) | ForEach-Object { '"' + $_ + '"' }) -join " "
            $psi.RedirectStandardOutput = $true
            $psi.RedirectStandardError = $true
            $psi.UseShellExecute = $false
            $p = [System.Diagnostics.Process]::Start($psi)
            $raw = $p.StandardOutput.ReadToEnd()
            $p.WaitForExit()
            $rc = $p.ExitCode
            $lines = $raw -split "`r?`n" | Where-Object { $_ -ne "" }
            $stats = ($lines | Where-Object { $_ -like "__STATS__*" } | Select-Object -Last 1)
            $body = ($lines | Where-Object { $_ -notlike "__STATS__*" } | Select-Object -First 1)
            $parts = ($stats -split "\s+")
            $code = if ($parts.Count -ge 2) { $parts[1] } else { "000" }
            $ms = if ($parts.Count -ge 3) { [int]([double]$parts[2] * 1000) } else { 0 }
            "{0} {1} {2} {3}" -f $code, $ms, $rc, $body
        }
        return ,$out
    } -ArgumentList $Front, $Url, $perWorker, $TimeoutSec, $HttpFront, $HttpsFront, $Socks
}
$jobs | Wait-Job -Timeout 3600 | Out-Null
foreach ($j in $jobs) {
    if ($j.HasMoreData) { foreach ($l in (Receive-Job $j)) { $null = $lock; $results.Add([string]$l) } }
    Remove-Job $j -Force
}
$elapsed = (Get-Date) - $start

# --- aggregate ---------------------------------------------------------------
$codes = @{}
$failures = @{}
$lat = New-Object System.Collections.Generic.List[int]
$ips = @{}
$ok = 0
foreach ($line in $results) {
    $p = $line -split "\s+"
    $code = [int]$p[0]; $ms = [int]$p[1]; $rc = [int]$p[2]; $body = if ($p.Count -ge 4) { $p[3] } else { "" }
    $lat.Add($ms) | Out-Null
    if ($body -match '^\d{1,3}(\.\d{1,3}){3}$') { $ips[$body] = $true }
    if ($code -ge 200 -and $code -lt 400 -and $rc -eq 0) { $ok++ } else { $failures["$code"] = 1 + $failures["$code"] }
}
$sorted = $lat.ToArray(); [Array]::Sort($sorted)
$pct = { param($q) if ($sorted.Count -eq 0) { 0 } else { $sorted[[Math]::Min($sorted.Count - 1, [int]($sorted.Count * $q))] } }
$n = $results.Count
$secs = [Math]::Max(0.001, $elapsed.TotalSeconds)
Write-Host ""
Write-Host ("requests      : {0} in {1:N1}s ({2:N1} req/s)" -f $n, $elapsed.TotalSeconds, ($n / $secs))
Write-Host ("success       : {0}/{1} ({2:N1}%)" -f $ok, $n, ($ok * 100.0 / [Math]::Max(1, $n)))
Write-Host ("latency ms    : avg {0:N0}  p50 {1}  p90 {2}  p99 {3}  max {4}" -f
    ($lat | Measure-Object -Average).Average, (& $pct 0.50), (& $pct 0.90), (& $pct 0.99), $sorted[-1])
Write-Host ("exit IPs      : {0} distinct" -f $ips.Count)
if ($failures.Count) {
    Write-Host ("failures      : " + (($failures.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join " "))
}

$verdict = 0
if ($ok * 100.0 / [Math]::Max(1, $n) -lt $SuccessPct) { Write-Host "VERDICT FAIL  : success rate below $SuccessPct%" -ForegroundColor Red; $verdict = 1 }
elseif ((& $pct 0.99) -gt $P99Ms) { Write-Host "VERDICT FAIL  : p99 latency above ${P99Ms}ms" -ForegroundColor Red; $verdict = 1 }
elseif ($ips.Count -lt 2 -and $n -ge 20) { Write-Host "VERDICT WARN  : only one exit IP under load" -ForegroundColor Yellow }
if ($verdict -eq 0) { Write-Host "VERDICT PASS" -ForegroundColor Green }

# --- the app's own counters for the same window ------------------------------
Write-Host ""
Write-Host "-- app counters for the same window --"
# The app's counters are taken once more after a pause: a tunnel's served/OK
# accounting lands when the relay notices the client's EOF, which can trail the
# client's own exit by a moment. Snapshotting immediately after the last curl
# exits therefore under-reports, and a counter that reads "+0" for a run that
# succeeded looks like a metrics bug rather than a timing artefact.
Start-Sleep -Seconds 2
$d = @{
    served_ok      = Delta "served_ok_total"
    dial_failures  = Delta "dial_failures_total"
    serve_failures = Delta "serve_failures_total"
    evictions      = Delta "evictions_total"
    block_pages    = Delta "block_pages_total"
}
foreach ($k in $d.Keys) { Write-Host ("  {0,-15} +{1}" -f $k, $d[$k]) }
$dreq = Delta "requests_total"
if ($dreq -gt 0) {
    Write-Host ("  internal error share: {0:N1}% of client requests hit a dial failure" -f ($d["dial_failures"] * 100.0 / $dreq))
}

# --- leak check --------------------------------------------------------------
Start-Sleep -Seconds $SettleSec
$gAfter = HealthField "goroutines"
Write-Host ("  goroutines    : {0} -> {1} after {2}s settle" -f $gBefore, $gAfter, $SettleSec)
if ($gBefore -and $gAfter -and $gAfter -gt ($gBefore + $Concurrency)) {
    Write-Host "  WARNING: goroutines grew by more than the concurrency; possible leak" -ForegroundColor Yellow
    $verdict = 1
}
$live = HealthField "queue_live"; $proven = HealthField "queue_proven"
Write-Host ("  queue         : live={0} proven={1}" -f $live, $proven)

Write-Host ""
exit $verdict
