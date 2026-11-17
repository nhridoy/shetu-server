package live

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func recv(t *testing.T, ch <-chan string) (string, bool) {
	t.Helper()
	select {
	case k, ok := <-ch:
		return k, ok
	case <-time.After(time.Second):
		t.Fatal("nothing received")
		return "", false
	}
}

func nothing(t *testing.T, ch <-chan string) {
	t.Helper()
	select {
	case k, ok := <-ch:
		t.Fatalf("unexpected %q (open=%v)", k, ok)
	case <-time.After(30 * time.Millisecond):
	}
}

func TestHub_PublishReachesUserExceptDevice(t *testing.T) {
	h := NewHub()
	u, other := uuid.New(), uuid.New()
	a, cancelA := h.Subscribe(u, "dev-a")
	defer cancelA()
	b, cancelB := h.Subscribe(u, "dev-b")
	defer cancelB()
	o, cancelO := h.Subscribe(other, "dev-o")
	defer cancelO()
	h.Publish([]uuid.UUID{u}, KindChanged, "dev-a")
	if k, _ := recv(t, b); k != KindChanged {
		t.Fatalf("dev-b got %q", k)
	}
	nothing(t, a)
	nothing(t, o)
}

func TestHub_PublishDeviceClosesThatStream(t *testing.T) {
	h := NewHub()
	u := uuid.New()
	a, cancelA := h.Subscribe(u, "dev-a")
	defer cancelA()
	b, cancelB := h.Subscribe(u, "dev-b")
	defer cancelB()
	h.PublishDevice(u, "dev-a", KindDeviceRevoked)
	if k, ok := recv(t, a); k != KindDeviceRevoked || !ok {
		t.Fatalf("dev-a got %q %v", k, ok)
	}
	if _, ok := recv(t, a); ok {
		t.Fatal("dev-a stream should be closed")
	}
	nothing(t, b)
}

func TestHub_FullSubscriberNeverBlocks(t *testing.T) {
	h := NewHub()
	u := uuid.New()
	_, cancel := h.Subscribe(u, "slow")
	defer cancel()
	done := make(chan struct{})
	go func() {
		for i := 0; i < 1000; i++ {
			h.Publish([]uuid.UUID{u}, KindChanged, "")
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("publishing blocked on a full subscriber")
	}
}

func TestHub_CloseUser(t *testing.T) {
	h := NewHub()
	u := uuid.New()
	a, cancelA := h.Subscribe(u, "dev-a")
	defer cancelA()
	b, cancelB := h.Subscribe(u, "dev-b")
	defer cancelB()
	h.CloseUser(u)
	if _, ok := recv(t, a); ok {
		t.Fatal("dev-a open")
	}
	if _, ok := recv(t, b); ok {
		t.Fatal("dev-b open")
	}
	cancelA() // cancelling after a close is safe
}

func TestHub_LimitClosesOldest(t *testing.T) {
	h := NewHub()
	u := uuid.New()
	first, cancel := h.Subscribe(u, "dev-0")
	defer cancel()
	for i := 1; i <= maxStreamsPerUser; i++ {
		_, c := h.Subscribe(u, "dev")
		defer c()
	}
	if _, ok := recv(t, first); ok {
		t.Fatal("oldest stream should be closed past the limit")
	}
}
