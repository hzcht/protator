// Package util holds a legacy two-function helper.
//
// Deprecated: nothing in the current tree imports it. The global math/rand seed
// it needs was made unnecessary by Go 1.20, and the proxy package has its own
// random, so this exists only as a stub. Do not grow it.
package util

import (
	"math/rand"
	"time"
)

func init() {
	rand.Seed(time.Now().Unix())
}

// RandInt returns a random int in [min, max). It panics when max <= min, the
// same contract as rand.Intn.
//
// Deprecated: use math/rand/v2 directly; see the package comment.
func RandInt(min int, max int) int {
	return min + rand.Intn(max-min)
}
