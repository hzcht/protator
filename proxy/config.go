package proxy

import (
	"fmt"
	"log"
	"time"

	"github.com/BurntSushi/toml"
)

// Duration is a TOML-friendly duration ("10s", "2m30s").
type Duration struct {
	time.Duration
}

func (d *Duration) UnmarshalTOML(v interface{}) error {
	s, ok := v.(string)
	if !ok {
		return fmt.Errorf("duration must be a string like \"10s\", got %T", v)
	}
	dd, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	d.Duration = dd
	return nil
}

func (d Duration) MarshalText() ([]byte, error) {
	return []byte(d.Duration.String()), nil
}

// ServerConfig controls the local HTTP forward proxy.
type ServerConfig struct {
	Listen          string   `toml:"listen"`
	ListenHTTPS     string   `toml:"listen_https"`
	TLSCertFile     string   `toml:"tls_cert_file"`
	TLSKeyFile      string   `toml:"tls_key_file"`
	ReadTimeout     Duration `toml:"read_timeout"`
	WriteTimeout    Duration `toml:"write_timeout"`
	IdleTimeout     Duration `toml:"idle_timeout"`
	KeepAlives      bool     `toml:"keep_alives"`
	Verbose         bool     `toml:"verbose"`
	MaxProxies      int      `toml:"max_proxies"`
	BlockConnect    []string `toml:"block_connect"`
	WasteHosts      []string `toml:"waste_hosts"`
	BlockURLSuffix  []string `toml:"block_url_suffixes"`
	DialTimeout     Duration `toml:"dial_timeout"`
	TLSHandshake    Duration `toml:"tls_handshake_timeout"`
	ResponseHeader  Duration `toml:"response_header_timeout"`
	MaxIdleConns    int      `toml:"max_idle_conns"`
	IdleConnTimeout Duration `toml:"idle_conn_timeout"`
	// Serving-path resilience: every client request gets a freshly picked
	// proxy; on dial failure it is retried with a different one.
	ServeRetries  int `toml:"serve_retries"`
	ServeMaxFails int `toml:"serve_max_fails"`
	PickProbes    int `toml:"pick_probes"`
	// How recent a proof of life must be for an entry to count as proven when
	// picking an upstream. PickFreshWindow must outlast
	// storage.revalidate_interval: between two revalidation passes the warm
	// tier is what the picker has to aim at, and a shorter window leaves it
	// serving the unverified bulk of the queue.
	PickServeWindow Duration `toml:"pick_serve_window"`
	PickFreshWindow Duration `toml:"pick_fresh_window"`
	// Maximum wall-clock budget for a single client request across all
	// failover attempts (0 = unbounded, rely on parent deadlines).
	ServeTotalTimeout Duration `toml:"serve_total_timeout"`
	// CONNECT-tunnel supervision: after the upstream answers "200 Connection
	// established" we wait up to this long for the far target's first byte.
	// If the client is sending data while the tunnel stays silent, the proxy
	// is charged as a serving failure and the tunnel is transparently
	// re-established through a different proxy (early client bytes up to
	// serve_connect_replay_max are replayed). 0 disables supervision (plain
	// pass-through, the old behavior).
	ServeConnectProbe Duration `toml:"serve_connect_probe"`
	// First-response-byte supervision for plain HTTP: after the upstream answers
	// the dial, the far side must produce the first response byte within this
	// window or the attempt is abandoned and the request is retried through a
	// different proxy. Same failure class as ServeConnectProbe, which covers
	// CONNECT tunnels; without it a blackholed proxy burns the whole
	// response_header_timeout before failover. 0 disables.
	ServeResponseProbe Duration `toml:"serve_response_probe"`
	// Enable the interstitial/block-page detector: a 200 text/html response
	// with a small body matching known blocker markers is treated as "no
	// content" and re-requested through another proxy.
	ServeBlockDetect   bool `toml:"serve_block_detect"`
	ServeBlockMaxBytes int  `toml:"serve_block_max_bytes"`
	// Session stickiness. ConnKey pins the upstream proxy per client TCP
	// connection (recommended); SessionKey (from the client-supplied
	// "X-Sticky-Session" header, stripped before forwarding) pins across
	// connections. A pinned proxy that fails is remapped to a fresh pick.
	ServePinTTL Duration `toml:"serve_pin_ttl"`
	ServePinMax int      `toml:"serve_pin_max"`
	// Graceful shutdown: after SIGINT/SIGTERM, in-flight requests get up to
	// this long to finish before the process exits.
	ShutdownTimeout Duration `toml:"shutdown_timeout"`
	// Admin/health endpoint (JSON metrics + /ready), empty = disabled.
	// Listening on 127.0.0.1 (or "localhost:port") recommended; the port
	// carries no proxy traffic and no auth by default.
	//
	// admin_token, when set, is required on every request but /health and
	// /ready, either as "Authorization: Bearer <token>" or as a ?token= query
	// parameter. It exists for the case admin_listen leaves the loopback
	// interface: the page edits sites.txt and can drop proxies from the queue,
	// so an unauthenticated listener on a routable address is a remote kill
	// switch. Empty token + non-loopback address is a loud startup warning,
	// not a refusal — firewalled deployments are legitimate.
	AdminListen string `toml:"admin_listen"`
	AdminToken  string `toml:"admin_token"`
}

// Socks5Config controls the local SOCKS5 forward proxy.
type Socks5Config struct {
	Enabled     bool     `toml:"enabled"`
	Listen      string   `toml:"listen"`
	DialTimeout Duration `toml:"dial_timeout"`
	IdleTimeout Duration `toml:"idle_timeout"`
}

// CheckerConfig controls proxy validation.
type CheckerConfig struct {
	SelfIPURLs   []string `toml:"self_ip_urls"`
	TestsFile    string   `toml:"tests_file"`
	Workers      int      `toml:"workers"`
	ChannelSize  int      `toml:"channel_size"`
	ConnectT     Duration `toml:"connect_timeout"`
	TCPTimeout   Duration `toml:"tcp_timeout"`
	TLSHandshake Duration `toml:"tls_handshake_timeout"`
	ResponseT    Duration `toml:"response_timeout"`
	TotalT       Duration `toml:"total_timeout"`
	ProbeOrder   []string `toml:"probe_order"`
	// Header-echo endpoints used to detect proxies that forward the client
	// IP in X-Forwarded-For/Via headers (transparent-leak detection).
	// Empty = stage skipped. Leak verdicts are only trusted when the echo
	// endpoint actually responded; service errors never fail a proxy.
	LeakProbeURLs []string `toml:"leak_probe_urls"`
	// RequireStableExit re-probes the winning self-IP URL and rejects
	// proxies whose exit IP differs between the two probes (rotators).
	RequireStableExit bool `toml:"require_stable_exit"`
	// E2EProbe opens a tunnel through the exact serving dial path
	// (dialProxy) to the first self-IP URL before accepting a proxy.
	E2EProbe bool `toml:"e2e_probe"`
	// GeoIPDBPath is the path to a MaxMind GeoIP2-City.mmdb file.
	// If set, the checker will look up the country and ASN for each
	// validated proxy's exit IP and attach it to the proxy for admin display.
	GeoIPDBPath string `toml:"geoip_db_path"`
}

// CollectorConfig controls proxy list collection.
type CollectorConfig struct {
	SitesFile    string   `toml:"sites_file"`
	RegexFile    string   `toml:"regex_file"`
	FetchWorkers int      `toml:"fetch_workers"`
	FetchRetries int      `toml:"fetch_retries"`
	HTTPTimeout  Duration `toml:"http_timeout"`
	PageTimeout  Duration `toml:"page_timeout"`
	UseBrowser   bool     `toml:"use_browser"`
	BrowserHead  bool     `toml:"browser_headless"`
	CycleSleep   Duration `toml:"cycle_sleep"`
	SiteLogDir   string   `toml:"site_log_dir"`
	// Failing sites are reduced to cheap direct attempts for this long
	// after this many consecutive failures.
	SiteCooldown Duration `toml:"site_cooldown"`
	SiteMaxFails int      `toml:"site_max_fails"`
	// Persisted-candidate re-probing: every PoolRetryInterval the pool
	// re-emits up to PoolRetryBatch candidates (oldest first) for another
	// validation pass. Dead-at-probe-time proxies often come up later.
	PoolRetryBatch    int      `toml:"pool_retry_batch"`
	PoolRetryInterval Duration `toml:"pool_retry_interval"`
	// Cap the number of candidates emitted per site per cycle (0 = no cap).
	// Huge auto-generated lists (100k+ entries) otherwise monopolize the
	// pipeline and starve fresh sites; a per-site sample keeps every source's
	// share fair while the pool_retry loop re-visits the rest.
	MaxCandidatesPerSite int `toml:"max_candidates_per_site"`
	// Cap the number of sources fetched per cycle (0 = the whole list). The
	// list is fetched in registry priority order (live output first), so a cap
	// simply spends each cycle on the most productive sources; the rest follow
	// as soon as the leader's cooldown/yield drops off.
	MaxSitesPerCycle int `toml:"max_sites_per_cycle"`
	// Cap on the persisted candidate pool (found-but-not-yet-validated
	// proxies). The pool re-probe loop re-emits pool_retry_batch every
	// pool_retry_interval, but the checker can only churn a few candidates per
	// second, so an unbounded pool grows without limit — 391k entries and
	// counting on the author's machine. Once full, new candidates are dropped,
	// which is the right behaviour: a candidate the checker has no capacity
	// for is not worth keeping.
	MaxCandidates int `toml:"max_candidates"`
}

// StorageConfig controls queue persistence.
type StorageConfig struct {
	QueueFile          string   `toml:"queue_file"`
	GoodFile           string   `toml:"good_file"`
	SaveInterval       Duration `toml:"save_interval"`
	RevalidateInterval Duration `toml:"revalidate_interval"`
	RevalidateWorkers  int      `toml:"revalidate_workers"`
	MaxBytes           int64    `toml:"max_bytes"`
	// Passive telemetry: proxies that specifically served a client dial more
	// recently than this are skipped by the periodic revalidation (real time
	// serving success is fresher proof of life than an old validation stamp).
	RevalidateFreshServers Duration `toml:"revalidate_fresh_servers"`
	// Cap on the number of proxies re-checked per periodic pass (0 = no cap).
	// The queue can hold 50k+ entries and a full sweep rarely converges inside
	// one revalidate_interval; a per-pass budget (oldest first) keeps the
	// freshness rotation always making progress instead of chasing a tail
	// that grows faster than it shrinks.
	RevalidateMaxPerPass int `toml:"revalidate_max_per_pass"`
	// Rate limit for feeding the seeded queue back into the validation
	// pipeline at startup (seeds per second, 0 = 200). Without it a 65k seed
	// dump floods the candidate channel and starves the collector's fresh
	// candidates and the pool re-probe loop.
	RevalidateSeedRate int `toml:"revalidate_seed_rate"`
	// Cap on how many seeded proxies are fed back into validation at startup
	// (0 = 5000). The periodic revalidation pass churns the rest; feeding all
	// 65k at once — even rate-limited — keeps the checker busy with dead seeds
	// for hours while fresh candidates wait.
	RevalidateSeedMax int `toml:"revalidate_seed_max"`
	// Path of the persisted candidate pool (found-but-not-yet-validated
	// proxies that are re-probed on later cycles; see collector.pool_*).
	CandidatesFile string `toml:"candidates_file"`
	// Debug output: a small rolling window of freshly validated proxies
	// (every entry passed the full checker incl. the e2e serving-path probe),
	// written as one URL per line. Point a browser directly at one of these to
	// prove whether a failure lives in the serving logic or in the pool itself.
	DebugProxiesFile string `toml:"debug_proxies_file"`
	DebugProxiesMax  int    `toml:"debug_proxies_max"`
}

// LoggingConfig controls log verbosity and per-category file logging.
type LoggingConfig struct {
	Level string `toml:"level"`
	// Dir holds per-category log files (collector.log, checker.log,
	// serve.log, system.log). Empty = files disabled, stderr only.
	Dir string `toml:"dir"`
	// Every category file is rotated once it reaches MaxBytes; the newest
	// file is <dir>/<cat>.log and rotated generations are <cat>.log.1..Keep
	// (.1 oldest... keep it simple: .1 is the most recent rotated one).
	MaxBytes int64 `toml:"max_bytes"`
	Keep     int   `toml:"keep"`
}

// Config is the root application configuration.
type Config struct {
	Server    ServerConfig    `toml:"server"`
	Socks5    Socks5Config    `toml:"socks5"`
	Checker   CheckerConfig   `toml:"checker"`
	Collector CollectorConfig `toml:"collector"`
	Storage   StorageConfig   `toml:"storage"`
	Logging   LoggingConfig   `toml:"logging"`

	// path is where this config was loaded from. It is not a config field: it
	// is the answer to "which file is this instance running", which the admin
	// page shows next to the effective values, and which -check exists to
	// validate.
	path string
}

// Path returns the config file this instance was loaded from.
func (c *Config) Path() string { return c.path }

func validSchema(s string) bool {
	switch s {
	case "http", "https", "socks4", "socks5", "vless":
		return true
	}
	return false
}

// LoadConfig reads and validates a TOML config file.
func LoadConfig(path string) (*Config, error) {
	cfg := &Config{path: path}
	if _, err := toml.DecodeFile(path, cfg); err != nil {
		return nil, fmt.Errorf("decode config %s: %w", path, err)
	}
	if err := cfg.fillDefaults(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// fillDefaults applies sane defaults for missing fields and validates values.
func (c *Config) fillDefaults() error {
	if c.Server.Listen == "" {
		c.Server.Listen = "0.0.0.0:8888"
	}
	if c.Server.ListenHTTPS == "" {
		c.Server.ListenHTTPS = "0.0.0.0:8443"
	}
	if c.Server.MaxProxies <= 0 {
		c.Server.MaxProxies = 2000000
	}
	if c.Server.DialTimeout.Duration <= 0 {
		c.Server.DialTimeout = Duration{time.Second * 5}
	}
	if c.Server.TLSHandshake.Duration <= 0 {
		c.Server.TLSHandshake = Duration{time.Second * 8}
	}
	if c.Server.ResponseHeader.Duration <= 0 {
		c.Server.ResponseHeader = Duration{time.Second * 10}
	}
	if c.Server.MaxIdleConns <= 0 {
		c.Server.MaxIdleConns = 128
	}
	if c.Server.IdleConnTimeout.Duration <= 0 {
		c.Server.IdleConnTimeout = Duration{time.Second * 90}
	}
	if c.Server.WriteTimeout.Duration <= 0 {
		c.Server.WriteTimeout = Duration{time.Second * 60}
	}
	if c.Server.IdleTimeout.Duration <= 0 {
		c.Server.IdleTimeout = Duration{time.Second * 90}
	}
	if c.Server.ServeRetries < 1 {
		c.Server.ServeRetries = 3
	}
	if c.Server.ServeMaxFails < 1 {
		c.Server.ServeMaxFails = 3
	}
	if c.Server.PickProbes < 1 {
		c.Server.PickProbes = 8
	}
	if c.Server.PickServeWindow.Duration <= 0 {
		c.Server.PickServeWindow = Duration{defaultPickServeWindow}
	}
	if c.Server.PickFreshWindow.Duration <= 0 {
		c.Server.PickFreshWindow = Duration{defaultPickFreshWindow}
	}
	// A fresh window shorter than the revalidation interval guarantees the
	// picker runs out of proven entries between passes and falls back to the
	// unverified bulk. Warn rather than silently override: the operator may
	// have a reason (a very fast revalidation loop), but it is the single
	// setting that most quietly destroys serving stability.
	if f, r := c.Server.PickFreshWindow.Duration, c.Storage.RevalidateInterval.Duration; r > 0 && f < r {
		log.Printf("config: pick_fresh_window (%s) is shorter than revalidate_interval (%s); "+
			"between revalidation passes the picker will have no proven proxies to choose from",
			f, r)
	}
	if c.Server.ServeTotalTimeout.Duration <= 0 {
		c.Server.ServeTotalTimeout = Duration{time.Second * 25}
	}
	if c.Server.ServeConnectProbe.Duration <= 0 {
		c.Server.ServeConnectProbe = Duration{time.Second * 3}
	}
	if c.Server.ServeResponseProbe.Duration <= 0 {
		c.Server.ServeResponseProbe = Duration{time.Second * 3}
	}
	if c.Server.ServeBlockMaxBytes <= 0 {
		c.Server.ServeBlockMaxBytes = 16384
	}
	if c.Server.ServePinTTL.Duration <= 0 {
		c.Server.ServePinTTL = Duration{time.Minute * 10}
	}
	if c.Server.ServePinMax <= 0 {
		c.Server.ServePinMax = 100000
	}
	if c.Server.ShutdownTimeout.Duration <= 0 {
		c.Server.ShutdownTimeout = Duration{time.Second * 10}
	}

	if c.Socks5.DialTimeout.Duration <= 0 {
		c.Socks5.DialTimeout = Duration{time.Second * 12}
	}
	if c.Socks5.IdleTimeout.Duration <= 0 {
		c.Socks5.IdleTimeout = Duration{time.Minute * 5}
	}

	if len(c.Checker.SelfIPURLs) == 0 {
		return fmt.Errorf("checker.self_ip_urls must not be empty")
	}
	if c.Checker.Workers <= 0 {
		c.Checker.Workers = 300
	}
	if c.Checker.ChannelSize <= 0 {
		c.Checker.ChannelSize = 10000
	}
	if c.Checker.ConnectT.Duration <= 0 {
		c.Checker.ConnectT = Duration{time.Second * 10}
	}
	if c.Checker.TCPTimeout.Duration <= 0 {
		c.Checker.TCPTimeout = Duration{time.Second * 4}
	}
	if c.Checker.TLSHandshake.Duration <= 0 {
		c.Checker.TLSHandshake = Duration{time.Second * 10}
	}
	if c.Checker.ResponseT.Duration <= 0 {
		c.Checker.ResponseT = Duration{time.Second * 20}
	}
	if c.Checker.TotalT.Duration <= 0 {
		c.Checker.TotalT = Duration{time.Second * 30}
	}
	if len(c.Checker.ProbeOrder) == 0 {
		c.Checker.ProbeOrder = []string{"http", "socks5", "socks4", "https"}
	}
	for _, s := range c.Checker.ProbeOrder {
		if !validSchema(s) {
			return fmt.Errorf("checker.probe_order contains unknown scheme %q", s)
		}
	}

	if c.Collector.SitesFile == "" {
		c.Collector.SitesFile = "config/sites.txt"
	}
	if c.Collector.RegexFile == "" {
		c.Collector.RegexFile = "config/regexp.txt"
	}
	if c.Collector.FetchWorkers <= 0 {
		c.Collector.FetchWorkers = 4
	}
	if c.Collector.FetchRetries <= 0 {
		c.Collector.FetchRetries = 3
	}
	if c.Collector.HTTPTimeout.Duration <= 0 {
		c.Collector.HTTPTimeout = Duration{time.Second * 45}
	}
	if c.Collector.PageTimeout.Duration <= 0 {
		c.Collector.PageTimeout = Duration{time.Second * 30}
	}
	if c.Collector.CycleSleep.Duration <= 0 {
		c.Collector.CycleSleep = Duration{time.Minute * 25}
	}
	if c.Collector.SiteCooldown.Duration <= 0 {
		c.Collector.SiteCooldown = Duration{time.Minute * 30}
	}
	if c.Collector.SiteMaxFails <= 0 {
		c.Collector.SiteMaxFails = 3
	}
	if c.Collector.PoolRetryBatch <= 0 {
		c.Collector.PoolRetryBatch = 20000
	}
	if c.Collector.PoolRetryInterval.Duration <= 0 {
		c.Collector.PoolRetryInterval = Duration{time.Minute * 3}
	}
	if c.Collector.MaxCandidatesPerSite < 0 {
		c.Collector.MaxCandidatesPerSite = 0
	}
	if c.Collector.MaxSitesPerCycle < 0 {
		c.Collector.MaxSitesPerCycle = 0
	}
	if c.Storage.RevalidateSeedRate < 0 {
		c.Storage.RevalidateSeedRate = 200
	}
	if c.Storage.RevalidateSeedMax < 0 {
		c.Storage.RevalidateSeedMax = 5000
	}
	if c.Collector.MaxCandidates <= 0 {
		c.Collector.MaxCandidates = 200000
	}

	if c.Storage.QueueFile == "" {
		c.Storage.QueueFile = "data/proxy.lst"
	}
	if c.Storage.SaveInterval.Duration <= 0 {
		c.Storage.SaveInterval = Duration{time.Minute}
	}
	if c.Storage.RevalidateInterval.Duration <= 0 {
		c.Storage.RevalidateInterval = Duration{time.Minute * 15}
	}
	if c.Storage.RevalidateWorkers <= 0 {
		c.Storage.RevalidateWorkers = 100
	}
	if c.Storage.RevalidateFreshServers.Duration <= 0 {
		c.Storage.RevalidateFreshServers = Duration{time.Minute * 10}
	}
	if c.Storage.CandidatesFile == "" {
		c.Storage.CandidatesFile = "data/candidates.lst"
	}
	if c.Storage.DebugProxiesMax <= 0 {
		c.Storage.DebugProxiesMax = 50
	}
	if c.Storage.MaxBytes <= 0 {
		c.Storage.MaxBytes = 256 << 20
	}

	if c.Logging.Dir == "" {
		c.Logging.Dir = "data/logs"
	}
	if c.Logging.MaxBytes <= 0 {
		c.Logging.MaxBytes = 32 << 20
	}
	if c.Logging.Keep < 1 {
		c.Logging.Keep = 5
	}
	return nil
}

// ContentTest is a check that must succeed through every validated proxy.
type ContentTest struct {
	Name        string   `toml:"name"`
	URL         string   `toml:"url"`
	MustContain []string `toml:"must_contain"`
}

// TestsConfig is the special config holding test server URLs and templates
// of the expected answer.
type TestsConfig struct {
	Tests []ContentTest `toml:"tests"`
}

// LoadTests reads the content-test config from disk.
func LoadTests(path string) ([]ContentTest, error) {
	tc := &TestsConfig{}
	if _, err := toml.DecodeFile(path, tc); err != nil {
		return nil, fmt.Errorf("decode tests %s: %w", path, err)
	}
	if len(tc.Tests) == 0 {
		return nil, fmt.Errorf("tests file %s contains no [[tests]] entries", path)
	}
	return tc.Tests, nil
}
