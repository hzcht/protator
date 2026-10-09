# servertest: does our proxy actually serve?

Runs the URL list in `urls.txt` through the three front-ends and reports
PASS/FAIL/WARN per endpoint, plus diagnostic info an operator needs:

- per-endpoint latency and HTTP status,
- which front served it (HTTP CONNECT / HTTPS / SOCKS5),
- **rotation** - how many distinct exit IPs the pool gave for N requests to an
  echo endpoint (a rotating forward proxy must give more than one),
- **leak check** - the body must not contain our own direct IP,
- **rule checks** - the config's `waste_hosts` short-circuit and
  `block_connect` rejection must still work.

## Usage

```powershell
# defaults: http=127.0.0.1:8888 https=127.0.0.1:8443 socks5=127.0.0.1:1080
powershell -File servertest/check.ps1

# custom front-ends, more rotation samples, only HTTPS
powershell -File servertest/check.ps1 -HttpFront http://10.0.0.5:8888 `
    -HttpsFront https://127.0.0.1:8443 -Socks 127.0.0.1:1080 -Runs 12
```

```bash
chmod +x servertest/check.sh
./servertest/check.sh                       # defaults
./servertest/check.sh -r 12 -f https        # 12 rotation samples, HTTPS only
```

Exit code is 0 when every test passed, 1 when any failed, 2 when the front-end
is unreachable (so a CI job or a supervisor can tell "broken" from "not
running").

`curl` is the only dependency (ships with Windows 10+ and every Linux).

### Two curl flags that are easy to get wrong

- **HTTPS proxy**: `-k` only relaxes verification of the *target*. The proxy's
  own self-signed certificate needs `--proxy-insecure`. Without it every request
  through the HTTPS front fails with `SEC_E_UNTRUSTED_ROOT` (curl exit 52/56) —
  the scripts pass both.
- **HTTPS proxy support at all** requires curl >= 7.52. On a box with an older
  curl, the `https` front is untestable: use the `http` front or SOCKS5.
  (`curl --version` tells you; PowerShell 5.1 users note that `curl` alone is an
  alias for `Invoke-WebRequest`, so run `curl.exe` or the scripts.)
