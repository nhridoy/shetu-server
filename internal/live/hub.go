// Package live tells open Shetu apps, over a Server-Sent Events stream, that something
// happened ("sync now", "this device was signed out", "account changed"). Signals carry no
// data; the apps fetch everything through the normal sync.
package live

import (
	"sync"

	"github.com/google/uuid"
)

const (
	KindChanged        = "changed"
	KindDeviceRevoked  = "device_revoked"
	KindAccountChanged = "account_changed"

	maxStreamsPerUser = 10
	streamBuffer      = 8
)

type subscriber struct {
	device string
	ch     chan string
	closed bool
}

// Hub tracks open streams in memory. Shetu runs as one process; a server behind several
// copies only delivers to streams held by the copy that published.
type Hub struct {
	mu   sync.Mutex
	subs map[uuid.UUID][]*subscriber
}

// Default is the process-wide hub; tests swap it.
var Default = NewHub()

func NewHub() *Hub { return &Hub{subs: map[uuid.UUID][]*subscriber{}} }

// Subscribe opens a stream for the user's device. The channel closes when the stream is ended
// by the hub; cancel removes it (safe to call more than once).
func (h *Hub) Subscribe(userID uuid.UUID, deviceID string) (<-chan string, func()) {
	s := &subscriber{device: deviceID, ch: make(chan string, streamBuffer)}
	h.mu.Lock()
	list := append(h.subs[userID], s)
	if len(list) > maxStreamsPerUser {
		h.closeLocked(list[0])
		list = list[1:]
	}
	h.subs[userID] = list
	h.mu.Unlock()
	return s.ch, func() {
		h.mu.Lock()
		defer h.mu.Unlock()
		h.closeLocked(s)
		list := h.subs[userID]
		for i, x := range list {
			if x == s {
				h.subs[userID] = append(list[:i:i], list[i+1:]...)
				break
			}
		}
		if len(h.subs[userID]) == 0 {
			delete(h.subs, userID)
		}
	}
}

func (h *Hub) closeLocked(s *subscriber) {
	if !s.closed {
		s.closed = true
		close(s.ch)
	}
}

// send never blocks: a full stream drops the signal (the app's safety sync covers it).
func send(s *subscriber, kind string) {
	if s.closed {
		return
	}
	select {
	case s.ch <- kind:
	default:
	}
}

// Publish signals every stream of these users, except exceptDevice's.
func (h *Hub) Publish(userIDs []uuid.UUID, kind string, exceptDevice string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, u := range userIDs {
		for _, s := range h.subs[u] {
			if exceptDevice == "" || s.device != exceptDevice {
				send(s, kind)
			}
		}
	}
}

// PublishDevice signals one device's streams, then ends them.
func (h *Hub) PublishDevice(userID uuid.UUID, deviceID, kind string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, s := range h.subs[userID] {
		if s.device == deviceID {
			send(s, kind)
			h.closeLocked(s)
		}
	}
}

// CloseUser ends every stream of the user.
func (h *Hub) CloseUser(userID uuid.UUID) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, s := range h.subs[userID] {
		h.closeLocked(s)
	}
}
