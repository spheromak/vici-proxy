package proxy

// Simple Backoff implementation
// Mostly inspired from the old advent of code

import (
	"math/rand"
	"time"
)

var (
	// defaultBackOff is the list of backoff intervals in miliseconds
	DefaultBackOff = BackOffPolicy{[]int{0, 10, 10, 100, 100, 500, 500, 3000, 3000, 5000, 5000, 7000, 7000}}
)

type BackOffPolicy struct {
	MiliSec []int
}

// Duration gets the nth timeout/backoff duration and splays it a bit
func (b BackOffPolicy) Duration(n int) time.Duration {
	if n >= len(b.MiliSec) {
		n = len(b.MiliSec) - 1
	}

	return time.Duration(jitter(b.MiliSec[n])) * time.Millisecond
}

func jitter(millis int) int {
	if millis == 0 {
		return 0
	}
	return millis/2 + rand.Intn(millis)
}
