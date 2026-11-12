// Package main wires the pieces of the proxy package into a running service:
// the collector, the checker workers, the live queue, the three forward-proxy
// listeners and the admin surface.
//
// Files are split by concern rather than by layer, and the split is load
// bearing: proxy.go is wiring only, loops.go owns the periodic housekeeping,
// servers.go owns the listeners and the goproxy construction, admin*.go owns
// the operator surface (routes split into a testable function), workers.go
// supervises the checker goroutines, and logfiles.go/logging.go own log
// routing.
//
// Everything here runs on the process's behalf: a bare goroutine started
// without proxy.RecoverPanic turns any panic into an exit that skips main's
// deferred queue save. See AGENTS.md for the full invariant list.
package main
