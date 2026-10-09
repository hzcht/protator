#!/usr/bin/env bash
# servertest/stress.sh - load test for the running instance.
#
# Hammers the front-ends with concurrent requests through the proxy, then
# reports what an operator actually needs to know:
#
#   * success rate, throughput, latency percentiles (p50/p90/p99/max)
#   * how many distinct exit IPs the rotating pool produced under load
#   * the app's OWN verdicts for the same window: served vs dial failures vs
#     evictions vs block pages (pulled from /api/metrics before and after)
#   * goroutine count before vs after (a leak shows here, not in the request
#     stats)
#
# Exit codes: 0 = thresholds met, 1 = thresholds missed, 2 = front-end unusable.
set -u

HTTP_FRONT="${HTTP_FRONT:-http://127.0.0.1:8888}"
HTTPS_FRONT="${HTTPS_FRONT:-https://127.0.0.1:8443}"
SOCKS="${SOCKS:-127.0.0.1:1080}"
ADMIN="${ADMIN:-http://127.0.0.1:9090}"
URL="${URL:-https://api.ipify.org}"
FRONT="${FRONT:-http}"
CONC="${CONC:-20}"
REQUESTS="${REQUESTS:-400}"
TIMEOUT="${TIMEOUT:-25}"
SUCCESS_PCT="${SUCCESS_PCT:-95}"
P99_MS="${P99_MS:-10000}"
SETTLE="${SETTLE:-10}"

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

# --- one request: "code ms size rc ip" -------------------------------------
one() {
    local url="$1" front="$2"
    local args=(-s -A 'servertest/1.0' -w '\n__STATS__ %{http_code} %{time_total} %{size_download}\n'
                --max-time "$TIMEOUT" --connect-timeout 10)
    case "$front" in
        http)   args+=(-x "$HTTP_FRONT") ;;
        # -k for the target, --proxy-insecure for the proxy's own self-signed
        # certificate: curl verifies the two chains separately, and skipping the
        # second one fails every HTTPS-proxy request (exit 52/56).
        https)  args+=(-k --proxy-insecure -x "$HTTPS_FRONT") ;;
        socks5) args+=(-k --socks5-hostname "$SOCKS") ;;
    esac
    local raw rc line body
    raw=$(curl "${args[@]}" "$url" 2>/dev/null); rc=$?
    line=$(printf '%s\n' "$raw" | grep '^__STATS__' | tail -n 1)
    body=$(printf '%s\n' "$raw" | grep -v -e '^__STATS__' -e '^$' | head -n 1 | tr -d '\r')
    printf '%s %s %s\n' "${line:-__STATS__ 000 0 0}" "$rc" "$body"
}
export -f one
export HTTP_FRONT HTTPS_FRONT SOCKS TIMEOUT

# --- the app's own counters (Prometheus text format) -----------------------
metrics() { curl -s --max-time 5 "$ADMIN/api/metrics?format=text" 2>/dev/null; }
metric() { metrics | awk -v k="$1" '$1==k {print $2}' | head -1; }
health_field() { curl -s --max-time 5 "$ADMIN/health" 2>/dev/null | tr -d '{}"' | tr ',' '\n' | awk -F: -v k="$1" '{gsub(/ /,"",$1); gsub(/ /,"",$2); if ($1==k) print $2}'; }

echo "stress: front=$FRONT url=$URL conc=$CONC requests=$REQUESTS (success>=$SUCCESS_PCT% p99<=${P99_MS}ms)"
m_served0=$(metric served_ok_total);   m_served0=${m_served0:-0}
m_dfail0=$(metric dial_failures_total); m_dfail0=${m_dfail0:-0}
m_evict0=$(metric evictions_total);     m_evict0=${m_evict0:-0}
m_block0=$(metric block_pages_total);   m_block0=${m_block0:-0}
m_sfail0=$(metric serve_failures_total); m_sfail0=${m_sfail0:-0}
m_reqs0=$(metric requests_total);        m_reqs0=${m_reqs0:-0}
m_checks0=$(metric checks_total);        m_checks0=${m_checks0:-0}
g_before=$(health_field goroutines);     g_before=${g_before:-0}
start=$(date +%s.%N)

seq "$REQUESTS" | xargs -P "$CONC" -n1 -I{} \
    bash -c 'one "$1" "$2"' _stress_ "$URL" "$FRONT" > "$TMP/results"

end=$(date +%s.%N)
elapsed=$(awk -v a="$start" -v b="$end" 'BEGIN{printf "%.3f", b-a}')

m_served1=$(metric served_ok_total);   m_served1=${m_served1:-0}
m_dfail1=$(metric dial_failures_total); m_dfail1=${m_dfail1:-0}
m_evict1=$(metric evictions_total);     m_evict1=${m_evict1:-0}
m_block1=$(metric block_pages_total);   m_block1=${m_block1:-0}
m_sfail1=$(metric serve_failures_total); m_sfail1=${m_sfail1:-0}
m_reqs1=$(metric requests_total);        m_reqs1=${m_reqs1:-0}
m_checks1=$(metric checks_total);        m_checks1=${m_checks0}

# --- aggregate --------------------------------------------------------------
awk -v success_pct="$SUCCESS_PCT" -v p99_ms="$P99_MS" -v elapsed="$elapsed" '
{
    code=$2; ms=$3; rc=$4
    n++
    if (code >= 200 && code < 400 && rc == 0) ok++
    else { bad++; why[code]++ ; if (rc != 0) why["curl_exit_" rc]++ }
    lat[n] = ms
    total_ms += ms
    if (ms > max) max = ms
    if ($5 ~ /^([0-9]{1,3}\.){3}[0-9]{1,3}$/) ips[$5] = 1
}
END {
    asort(lat)
    p50 = lat[int(n*0.50)+1]; p90 = lat[int(n*0.90)+1]; p99 = lat[int(n*0.99)+1]
    rate = n / elapsed
    printf "requests      : %d in %ss (%.1f req/s)\n", n, elapsed, rate
    printf "success       : %d/%d (%.1f%%)\n", ok+0, n, (ok+0)*100/n
    printf "latency ms    : avg %.0f  p50 %.0f  p90 %.0f  p99 %.0f  max %.0f\n", total_ms/n, p50, p90, p99, max
    d = 0; for (i in ips) d++
    printf "exit IPs      : %d distinct%s\n", d, (d ? " (" : " (")
    printf "failures      : "
    for (k in why) printf "%s=%d ", k, why[k]
    print ""
    okpct = (ok+0)*100/n
    if (okpct < success_pct) { print "VERDICT FAIL  : success rate below " success_pct "%"; exit 1 }
    if (p99 > p99_ms)         { print "VERDICT FAIL  : p99 latency above " p99_ms "ms"; exit 1 }
    if (d < 2 && n >= 20)     { print "VERDICT WARN  : only one exit IP under load" }
    print "VERDICT PASS"
}' "$TMP/results" | tee "$TMP/report"
grep -q '^VERDICT FAIL' "$TMP/report" && rc=1 || rc=0

echo
echo "-- app counters for the same window --"
delta() { awk -v a="$1" -v b="$2" 'BEGIN{printf "%d", (b>a ? b-a : 0)}'; }
printf '  served_ok      +%s\n' "$(delta "$m_served0" "$m_served1")"
printf '  dial_failures  +%s\n' "$(delta "$m_dfail0" "$m_dfail1")"
printf '  serve_failures +%s\n' "$(delta "$m_sfail0" "$m_sfail1")"
printf '  evictions      +%s\n' "$(delta "$m_evict0" "$m_evict1")"
printf '  block_pages    +%s\n' "$(delta "$m_block0" "$m_block1")"
printf '  checks (pool)  +%s\n' "$(delta "$m_checks0" "$m_checks1")"
app_reqs=$(delta "$m_reqs0" "$m_reqs1")
app_served=$(delta "$m_served0" "$m_served1")
app_dfail=$(delta "$m_dfail0" "$m_dfail1")
if [ "$app_reqs" -gt 0 ]; then
    printf '  internal error share: %.1f%% of client requests hit a dial failure\n' \
        "$(awk -v d="$app_dfail" -v r="$app_reqs" 'BEGIN{printf "%.1f", d*100/r}')"
fi

# --- leak check: the process must give the goroutines back -------------------
sleep "$SETTLE"
g_after=$(health_field goroutines); g_after=${g_after:-0}
printf '  goroutines    : %s -> %s after %ss settle\n' "$g_before" "$g_after" "$SETTLE"
if [ "$g_before" -gt 0 ] && [ "$g_after" -gt $((g_before + CONC)) ]; then
    echo "  WARNING: goroutine count grew by more than the concurrency; possible leak"
    rc=1
fi

q_live=$(health_field queue_live); q_proven=$(health_field queue_proven)
printf '  queue         : live=%s proven=%s\n' "$q_live" "$q_proven"

echo
exit $rc
