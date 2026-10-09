package proxy

import (
	"log"
	"net"
	"runtime/debug"
)

// RecoverPanic converts a panic into a logged event and keeps the process
// alive. Every goroutine that a client can reach must defer it at its top:
// net/http recovers inside its own connection goroutines, but the bare `go
// func` goroutines this program spawns (SOCKS5 session handling, the admin
// WebSocket writer, the tunnel pipes, the checker's parallel sub-probes) do
// not, so one bad input there takes every listener, every in-flight request
// and the unsaved queue with it.
//
// The client gets a dropped connection instead of the whole service.
func RecoverPanic(what string) {
	r := recover()
	if r == nil {
		return
	}
	Stats.RecoverPanics.Add(1)
	log.Printf("%s: panic recovered: %v\n%s", what, r, debug.Stack())
}

// probeResult is the shape every parallel checker sub-probe reports back on.
//
// The send has to happen exactly once per goroutine: the collectors read a
// fixed number of results, so a goroutine that panicked before sending — even
// with the panic recovered — would leave its peers blocked on a receive that
// never comes. GuardedSend keeps that invariant.
type probeResult struct {
	ip          net.IP
	leaked      bool
	viaConnect  bool
	transparent bool
	err         error
	url         string
}

// GuardedSend delivers one probe result, recovering a panic on the way.
//
// Use it as the last statement of a parallel sub-probe:
//
//	go func(u string) {
//	    defer RecoverPanic("checker: leak probe " + u)
//	    ...
//	    GuardedSend(ch, probeResult{leaked: true})
//	}(u)
//
// A panic after a successful send is harmless: the result is already counted
// and the deferred recover only logs.
func GuardedSend[T any](ch chan<- T, v T) {
	defer RecoverPanic("probe send")
	ch <- v
}
