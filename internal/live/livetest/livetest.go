// Package livetest holds test helpers for the live hub.
package livetest

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/nhridoy/shetu-server/internal/live"
)

// UseHub swaps live.Default for a fresh hub for one test.
func UseHub(t testing.TB) *live.Hub {
	t.Helper()
	prev := live.Default
	live.Default = live.NewHub()
	t.Cleanup(func() { live.Default = prev })
	return live.Default
}

// Received returns the signals a test stream got within a short wait, and whether it closed.
func Received(ch <-chan string) (kinds []string, closed bool) {
	deadline := time.After(50 * time.Millisecond)
	for {
		select {
		case k, ok := <-ch:
			if !ok {
				return kinds, true
			}
			kinds = append(kinds, k)
		case <-deadline:
			return kinds, false
		}
	}
}

// Listen subscribes a test stream for user and device; it's removed when the test ends.
func Listen(t testing.TB, h *live.Hub, user uuid.UUID, device string) <-chan string {
	t.Helper()
	ch, cancel := h.Subscribe(user, device)
	t.Cleanup(cancel)
	return ch
}
