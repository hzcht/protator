#!/usr/bin/env bash
# servertest/check.sh - proxy smoke test against the running instance.
#
# Feeds every line of urls.txt through the local front-ends, checks the response
# against the expectation, and prints diagnostics: status, latency, which front
# answered, how many distinct exit IPs the rotating pool produced, and whether
# the upstream leaked our own address.
#
# Exit codes: 0 = all passed, 1 = at least one failure, 2 = front-end unreachable.
set -u

HTTP_FRONT="${HTTP_FRONT:-http://127.0.0.1:8888}"
HTTPS_FRONT="${HTTPS_FRONT:-https://127.0.0.1:8443}"
SOCKS="${SOCKS:-127.0.0.1:1080}"
ADMIN="${ADMIN:-http://127.0.0.1:9090}"
URLS_FILE="${URLS_FILE:-$(dirname "$0")/urls.txt}"
RUNS="${RUNS:-8}"
TIMEOUT="${TIMEOUT:-25}"
FRONTS="${FRONTS:-http https socks5}"

pass=0; warn=0; fail=0; slow=0; rows=""

# verdict name detail ms
record() {
    case "$1" in
        PASS) pass=$((pass+1)) ;;
        WARN) warn=$((warn+1)) ;;
        *)    fail=$((fail+1)) ;;
    esac
    if [ "${4:-0}" -ge 5000 ]; then slow=$((slow+1)); fi
    printf '[%-4s] %-52s %6s ms  %s\n' "$1" "$2" "${4:-0}" "$3"
    rows="$rows$1|$2|$3\n"
}

# fetch FRONT URL -> echoes "code<TAB>ms<TAB>body" (body on one line)
fetch() {
    local front="$1" url="$2"
    local args=(-s -o "$TMP/body" -w '%{http_code} %{time_total}'
                --max-time "$TIMEOUT" --connect-timeout 10)
    case "$front" in
        http)   args+=(-x "$HTTP_FRONT") ;;
        https)  args+=(-k -x "$HTTPS_FRONT") ;;
        socks5) args+=(-k --socks5-hostname "$SOCKS") ;;
        direct) args+=(--noproxy '*') ;;
    esac
    local out
    out=$(curl "${args[@]}" "$url" 2>/dev/null)
    local rc=$?
    local code="${out%% *}" ms=""
    ms=$(awk -v s="${out#* }" 'BEGIN{printf "%d", s*1000}')
    if [ -z "$code" ] || [ "$code" = "$out" ]; then code="000"; ms="0"; fi
    printf '%s\t%s\t%s\t%s' "$code" "$ms" "$rc" "$(tr -d '\r\n' < "$TMP/body" | cut -c1-4000)"
}

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

echo "servertest: fronts http=$HTTP_FRONT https=$HTTPS_FRONT socks5=$SOCKS"
echo

# --- 0. where do we sit from here? ---
IFS=$'\t' read -r dcode dms drc dbody <<EOF
$(fetch direct "https://api.ipify.org")
EOF
my_ip=$(printf '%s' "$dbody" | grep -oE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' | head -1)
if [ "$dcode" != "200" ] || [ -z "$my_ip" ]; then
    echo "cannot reach the internet directly ($dcode); leak checks will be skipped." >&2
    my_ip=""
else
    echo "our own address (direct): $my_ip"
fi

# --- 1. every URL in urls.txt, over each front ---
for front in $FRONTS; do
    echo
    echo "-- front: $front --"
    while IFS= read -r line; do
        case "$line" in ''|\#*) continue ;; esac
        url=$(printf '%s' "$line" | cut -d'|' -f1)
        kind=$(printf '%s' "$line" | cut -d'|' -f2 | tr -d ' ')
        want=$(printf '%s' "$line" | cut -d'|' -f3- | sed 's/^ *//;s/ *$//')
        name="$front ${url#http*://}"
        IFS=$'\t' read -r code ms rc body <<EOF
$(fetch "$front" "$url")
EOF
        if [ "$rc" -ne 0 ] && [ "$code" = "000" ]; then
            record FAIL "$name" "curl exit $rc (dial/tunnel failed)" "$ms"
            continue
        fi
        ok=0; why="status $code"
        lower=$(printf '%s' "$body" | tr 'A-Z' 'a-z')
        case "$kind" in
            status)   [ "$code" = "$want" ] && ok=1; why="status $code, want $want" ;;
            contains) printf '%s' "$lower" | grep -qiF "$(printf '%s' "$want" | tr 'A-Z' 'a-z')" && ok=1
                      why="contains '$want': $([ $ok -eq 1 ] && echo yes || echo no)" ;;
            regex)    printf '%s' "$body" | grep -qE "$want" && ok=1; why="matches /$want/: $([ $ok -eq 1 ] && echo yes || echo no)" ;;
            ip)       printf '%s' "$body" | grep -qE '^([0-9]{1,3}\.){3}[0-9]{1,3}$' && ok=1; why="body '$body'" ;;
            ipjson)   printf '%s' "$body" | grep -qE '"ip"[[:space:]]*:[[:space:]]*"([0-9]{1,3}\.){3}[0-9]{1,3}"' && ok=1
                      why="ip field: $([ $ok -eq 1 ] && echo yes || echo no)" ;;
            nonempty) [ -n "$body" ] && ok=1; why="${#body} bytes" ;;
            noleak)
                if [ -z "$my_ip" ]; then record WARN "$name" "leak check skipped (no direct IP)" "$ms"; continue; fi
                printf '%s' "$body" | grep -qF "$my_ip" || ok=1
                why=$([ $ok -eq 1 ] && echo "our IP not present" || echo "OUR IP $my_ip LEAKED in the response") ;;
        esac
        if [ $ok -eq 1 ]; then
            record PASS "$name" "$why" "$ms"
        else
            record FAIL "$name" "$why; body starts: $(printf '%s' "$body" | cut -c1-80)" "$ms"
        fi
    done < "$URLS_FILE"
done

# --- 2. rotation ---
echo
echo "-- rotation ($RUNS samples of api.ipify.org) --"
seen=""
lat_total=0; lat_n=0; lat_max=0
i=0
while [ $i -lt "$RUNS" ]; do
    IFS=$'\t' read -r code ms rc body <<EOF
$(fetch http "https://api.ipify.org")
EOF
    if [ "$code" = "200" ] && printf '%s' "$body" | grep -qE '^([0-9]{1,3}\.){3}[0-9]{1,3}$'; then
        case "$seen" in *"$body"*) ;; *) seen="$seen $body" ;; esac
        lat_total=$((lat_total + ms)); lat_n=$((lat_n + 1))
        [ "$ms" -gt "$lat_max" ] && lat_max=$ms
    fi
    i=$((i + 1))
done
distinct=$(printf '%s' "$seen" | wc -w)
if [ "$distinct" -ge 2 ]; then
    record PASS "rotation" "$distinct distinct exit IPs:$seen"
elif [ "$distinct" -eq 1 ]; then
    record WARN "rotation" "only one exit IP$seen: the pool may be exhausted or pins are sticky"
else
    record FAIL "rotation" "no exit IP returned in $RUNS samples"
fi
[ "$lat_n" -gt 0 ] && echo "       exit latency: avg $((lat_total / lat_n)) ms, max $lat_max ms"

# --- 3. front-end rules ---
echo
echo "-- rules (config: waste_hosts / block_connect) --"
IFS=$'\t' read -r code ms rc body <<EOF
$(fetch http "https://analytics.google.com/")
EOF
if [ "$body" = "Waste" ] || printf '%s' "$body" | grep -q '^Waste'; then
    record PASS "waste_hosts" "short-circuited with 'Waste'"
else
    record WARN "waste_hosts" "expected 'Waste', got status $code body '$(printf '%s' "$body" | cut -c1-40)'"
fi
IFS=$'\t' read -r code ms rc body <<EOF
$(fetch http "https://google.com:443")
EOF
if [ "$rc" -ne 0 ] || [ "$code" -ge 400 ]; then
    record PASS "block_connect" "google.*:443 rejected (curl exit $rc, status $code)"
else
    record WARN "block_connect" "expected a reject, got status $code"
fi

# --- 4. the app's own verdict about itself ---
echo
echo "-- app health ($ADMIN) --"
if command -v curl >/dev/null && health=$(curl -s --max-time 5 "$ADMIN/health" 2>/dev/null) && [ -n "$health" ]; then
    printf '%s\n' "$health" | tr '{,' '\n\n' | grep -E 'queue_|pool_|served_ok_total|dial_failures_total|collector_stale|revalidate_stale|worker_restarts' | sed 's/^/       /'
else
    echo "       admin API not reachable at $ADMIN"
fi

# --- summary ---
echo
echo "servertest: $pass passed, $warn warnings, $fail failed, $slow slow (>=5s)"
if [ $fail -gt 0 ]; then
    echo "failed tests:"
    printf "$rows" | grep '^FAIL|' | sed 's/^FAIL|/  - /; s/|/: /'
    exit 1
fi
exit 0
