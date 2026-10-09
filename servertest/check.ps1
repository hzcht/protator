<#--
servertest/check.ps1 - proxy smoke test against the running instance.

Feeds every line of urls.txt through the local front-ends, checks the response
against the expectation, and prints diagnostics: status, latency, which front
answered, how many distinct exit IPs the rotating pool produced, and whether the
upstream leaked our own address.

Exit codes: 0 = all passed, 1 = at least one failure, 2 = front-end unreachable.
#>
[CmdletBinding()]
param(
    [string]$HttpFront = "http://127.0.0.1:8888",
    [string]$HttpsFront = "https://127.0.0.1:8443",
    [string]$Socks = "127.0.0.1:1080",
    [string]$UrlsFile = "",
    [int]$Runs = 8,                 # rotation samples against the echo endpoint
    [int]$TimeoutSec = 25,
    [string[]]$Fronts = @("http", "https", "socks5")
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

# urls.txt lives next to this script; resolve it whether the script is run with
# -File (no $PSScriptRoot) or dot-sourced, and from any working directory.
if (-not $UrlsFile) {
    $dir = Split-Path -Parent $MyInvocation.MyCommand.Path
    if (-not $dir) { $dir = "servertest" }
    $UrlsFile = Join-Path $dir "urls.txt"
}
if (-not (Test-Path -LiteralPath $UrlsFile)) {
    throw "urls.txt not found (looked in $UrlsFile); pass -UrlsFile explicitly"
}

$script:pass = 0
$script:warn = 0
$script:fail = 0
$script:slow = 0
$script:rows = New-Object System.Collections.Generic.List[object]

function Record([string]$verdict, [string]$name, [string]$detail, [double]$ms) {
    switch ($verdict) {
        "PASS" { $script:pass++ }
        "WARN" { $script:warn++ }
        default { $script:fail++ }
    }
    if ($ms -ge 5000) { $script:slow++ }
    $colour = switch ($verdict) { "PASS" { "Green" } "WARN" { "Yellow" } default { "Red" } }
    Write-Host ("[{0,-4}] {1,-52} {2,7} ms  {3}" -f $verdict, $name, [int]$ms, $detail) -ForegroundColor $colour
    $script:rows.Add([pscustomobject]@{ verdict = $verdict; test = $name; ms = [int]$ms; detail = $detail })
}

# Runs one curl invocation through a front and returns @{code; body; ms; err}.
# Args are passed as an array: an HTTPS *proxy* needs -k for the target AND
# --proxy-insecure for the proxy's own self-signed certificate, because curl
# verifies those two chains separately. Missing the second one fails every
# request with SEC_E_UNTRUSTED_ROOT (curl exit 52/56), which is exactly what a
# plain "-k -x https://host" test does.
function Fetch([string]$front, [string]$url, [string[]]$extraArgs) {
    $body = [System.IO.Path]::GetTempFileName()
    try {
        # NB: not $args - that is a PowerShell automatic variable and assigning
        # to it silently misbehaves.
        $curlArgs = @("-s", "-A", "servertest/1.0", "-o", $body, "-w", "%{http_code} %{time_total}",
                      "--max-time", "$TimeoutSec", "--connect-timeout", "10")
        if ($extraArgs) { $curlArgs += $extraArgs }
        $curlArgs += $url
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = "curl"
        $psi.Arguments = ($curlArgs | ForEach-Object { '"' + $_ + '"' }) -join " "
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError = $true
        $psi.UseShellExecute = $false
        $p = [System.Diagnostics.Process]::Start($psi)
        $stdout = $p.StandardOutput.ReadToEnd().Trim()
        $p.WaitForExit()
        $ms = 0.0
        $code = 0
        if ($stdout -match "^(\d{3})\s+([0-9.]+)") {
            $code = [int]$Matches[1]
            $ms = [double]$Matches[2] * 1000
        }
        $text = (Get-Content -LiteralPath $body -Raw -ErrorAction SilentlyContinue)
        if ($null -eq $text) { $text = "" }
        return @{ code = $code; body = $text.Trim(); ms = $ms; err = $p.ExitCode }
    } finally {
        Remove-Item $body -Force -ErrorAction SilentlyContinue
    }
}

function ProxyArgs([string]$front) {
    switch ($front) {
        "http"   { return @("-x", $HttpFront) }
        "https"  { return @("-k", "--proxy-insecure", "-x", $HttpsFront) } # self-signed front cert
        "socks5" { return @("-k", "--socks5-hostname", $Socks) }
    }
    return @()
}

function DirectArgs() { return "--noproxy *" }

Write-Host "servertest: fronts http=$HttpFront https=$HttpsFront socks5=$Socks" -ForegroundColor Cyan
Write-Host ""

# --- 0. where do we sit from here? (for the exit-IP and leak comparisons) ---
$direct = Fetch "direct" "https://api.ipify.org" @("--noproxy", "*")
$myIp = ($direct.body -split "[^0-9.]" | Where-Object { $_ -match "^\d+\.\d+\.\d+\.\d+$" } | Select-Object -First 1)
if ($direct.code -ne 200 -or -not $myIp) {
    Write-Host "cannot reach the internet directly ($($direct.code)); running the tests but the" -ForegroundColor Yellow
    Write-Host "leak checks will be skipped." -ForegroundColor Yellow
    $myIp = ""
} else {
    Write-Host "our own address (direct): $myIp" -ForegroundColor Cyan
}

# --- 1. every URL in urls.txt, over each front ---
$tests = Get-Content -LiteralPath $UrlsFile | Where-Object { $_ -match "^\s*[a-z]+://" -and $_ -notmatch "^\s*#" }
foreach ($front in $Fronts) {
    Write-Host ""
    Write-Host "-- front: $front --" -ForegroundColor Cyan
    foreach ($line in $tests) {
        $parts = $line -split "\|", 3
        $url = $parts[0].Trim()
        $kind = $parts[1].Trim()
        $want = if ($parts.Count -gt 2) { $parts[2].Trim() } else { "" }
        $r = Fetch $front $url (ProxyArgs $front)
        $name = "$front $($url -replace '^https?://', '')"
        if ($r.err -ne 0 -and $r.code -eq 0) {
            Record "FAIL" $name "curl exit $($r.err) (dial/tunnel failed)" ([int]$r.ms)
            continue
        }
        $body = $r.body
        $ok = $false
        $why = "status $($r.code)"
        switch ($kind) {
            "status"   { $ok = ($r.code -eq [int]$want); $why = "status $($r.code), want $want" }
            "contains" { $ok = ($body -match [regex]::Escape($want)); $why = "contains '$want': $ok" }
            "regex"    { $ok = ($body -match $want); $why = "matches /$want/: $ok" }
            # IPv4 or IPv6: what matters is "this request left through another
            # network", and some exits answer with their AAAA address.
            "ip"       { $ok = ($body -match "^([0-9]{1,3}(\.\d{1,3}){3}|[0-9a-fA-F:]*:[0-9a-fA-F:]*)$"); $why = "body '$body'" }
            "ipjson"   { $ok = ($body -match '"ip"\s*:\s*"\d{1,3}(\.\d{1,3}){3}"'); $why = "ip field: $ok" }
            "nonempty" { $ok = ($body.Length -gt 0); $why = "$($body.Length) bytes" }
            "noleak"   {
                if ($myIp -eq "") { Record "WARN" $name "leak check skipped (no direct IP)" ([int]$r.ms); continue }
                $ok = ($body -notmatch [regex]::Escape($myIp))
                $why = if ($ok) { "our IP not present" } else { "OUR IP $myIp LEAKED in the response" }
            }
        }
        if (-not $ok -and $r.code -eq 200) {
            Record "FAIL" $name "$why; body starts: $($body.Substring(0, [Math]::Min(80, $body.Length)))" ([int]$r.ms)
        } elseif (-not $ok) {
            Record "FAIL" $name $why ([int]$r.ms)
        } else {
            Record "PASS" $name $why ([int]$r.ms)
        }
    }
}

# --- 2. rotation: a rotating forward proxy must give more than one exit IP ---
Write-Host ""
Write-Host "-- rotation ($Runs samples of api.ipify.org) --" -ForegroundColor Cyan
$seen = @{}
$latencies = @()
for ($i = 0; $i -lt $Runs; $i++) {
    $r = Fetch "http" "https://api.ipify.org" (ProxyArgs "http")
    if ($r.code -eq 200 -and $r.body -match "^([0-9]{1,3}(\.\d{1,3}){3}|[0-9a-fA-F:]*:[0-9a-fA-F:]*)$") {
        $seen[$r.body] = $true
        $latencies += $r.ms
    }
}
if ($seen.Count -ge 2) {
    Record "PASS" "rotation" "$($seen.Count) distinct exit IPs: $(( $seen.Keys | Sort-Object ) -join ', ')"
} elseif ($seen.Count -eq 1) {
    Record "WARN" "rotation" "only one exit IP $($seen.Keys): the pool may be exhausted or pins are sticky"
} else {
    Record "FAIL" "rotation" "no exit IP returned in $Runs samples"
}
if ($latencies.Count -gt 1) {
    $avg = ($latencies | Measure-Object -Average).Average
    $max = ($latencies | Measure-Object -Maximum).Maximum
    Write-Host ("       exit latency: avg {0} ms, max {1} ms" -f [int]$avg, [int]$max)
}

# --- 3. the front-end rules must still be applied ---
Write-Host ""
Write-Host "-- rules (config: waste_hosts / block_connect) --" -ForegroundColor Cyan
# Plain HTTP on purpose: waste_hosts is an absolute-URI request rule, it never
# sees a CONNECT. Asking over https:// would tunnel to the real site and prove
# nothing about the rule.
$r = Fetch "http" "http://analytics.google.com/" (ProxyArgs "http")
if ($r.body -match "^Waste") {
    Record "PASS" "waste_hosts" "short-circuited with 'Waste'"
} else {
    Record "WARN" "waste_hosts" "expected 'Waste', got status $($r.code) body '$($r.body.Substring(0,[Math]::Min(40,$r.body.Length)))'"
}
$r = Fetch "http" "https://google.com:443" (ProxyArgs "http")
if ($r.err -ne 0 -or $r.code -ge 400) {
    Record "PASS" "block_connect" "google.*:443 rejected (curl exit $($r.err), status $($r.code))"
} else {
    Record "WARN" "block_connect" "expected a reject, got status $($r.code)"
}

# --- 4. the app's own verdict about itself ---
$admin = $HttpFront -replace ":\d+$", ":9090"
try {
    $health = Invoke-RestMethod -Uri "$admin/health" -TimeoutSec 5 -ErrorAction Stop
    Write-Host ""
    Write-Host "-- app health ($admin) --" -ForegroundColor Cyan
    Write-Host ("       queue live={0} proven={1} hot={2} pool={3} served={4} dialfail={5}" -f
        $health.queue_live, $health.queue_proven, $health.queue_hot, $health.pool_candidates,
        $health.served_ok_total, $health.dial_failures_total)
    if ($health.beats -and $health.beats.collector_stale) { Write-Host "       WARNING: collector has not run a cycle recently" -ForegroundColor Yellow }
    if ($health.beats -and $health.beats.revalidate_stale) { Write-Host "       WARNING: revalidation is stale" -ForegroundColor Yellow }
    if ($health.worker_restarts -and $health.worker_restarts -gt 0) {
        Record "WARN" "worker_restarts" "$($health.worker_restarts) checker worker restarts - see checker.log"
    }
} catch {
    Write-Host ""
    Write-Host "-- app health: admin API not reachable at $admin --" -ForegroundColor DarkGray
}

# --- summary ---
Write-Host ""
Write-Host ("servertest: {0} passed, {1} warnings, {2} failed, {3} slow (>=5s)" -f $script:pass, $script:warn, $script:fail, $script:slow) -ForegroundColor Cyan
if ($script:fail -gt 0) {
    Write-Host "failed tests:" -ForegroundColor Red
    $script:rows | Where-Object { $_.verdict -eq "FAIL" } | ForEach-Object { Write-Host "  - $($_.test): $($_.detail)" }
    exit 1
}
exit 0
