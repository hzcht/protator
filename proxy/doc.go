// Package proxy is the whole engine behind the protator binary: it collects
// proxy addresses from list pages, validates them, keeps the ones that work in
// a live queue, and dials upstream through them on behalf of the three local
// fronts (HTTP, HTTPS, SOCKS5).
//
// The pieces, in the order a proxy moves through them:
//
//   - collector.go (+ collect_fetch.go) scrapes config/sites.txt. Everything
//     about one HTTP request — transport reuse, block-page classification,
//     retry hints — lives in collect_fetch.go.
//   - extract.go and its extract_*.go siblings turn a page body into
//     Candidates: universal shapes first, then the per-site patterns in
//     config/regexp.txt, share links, spys' XOR-encoded ports and base64.
//   - pipeline.go runs the validation workers, checker.go (+ checker_probe.go)
//     makes the accept/reject decision and records the evidence.
//   - bucket.go is the live queue with its curated hot tail; pick.go chooses
//     which entry serves a dial; pool.go persists candidates that failed or
//     have not been tried yet.
//   - upstream.go (the forward dialer, failover and passive feedback),
//     dial.go (per-protocol handshakes) and transport.go (the serving-path
//     round tripper) sit between a client connection and an upstream proxy.
//   - revalidate.go / poolloop.go keep the queue honest over time.
//
// Contracts a change in this package has to respect are summarised in AGENTS.md
// ("Conventions & pitfalls") and docs/ARCHITECTURE.md. The ones that are easy to
// break silently — and are therefore pinned by tests — are the extractor's gate
// contract (a gate may only skip a pass that provably cannot match), the
// anchored-path equivalence with regexp.FindAll, the lock order freshMu -> mu in
// Bucket, and "no mutex on Proxy" (its health fields are atomics, read on every
// dial).
package proxy
