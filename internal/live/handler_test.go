package live

import (
	"bufio"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// liveServer serves HandleLive as user u on device dev, with a token expiring at exp.
func liveServer(t *testing.T, u uuid.UUID, dev string, exp time.Time) *httptest.Server {
	t.Helper()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/live", func(c *gin.Context) {
		c.Set("user_id", u)
		c.Set("device_id", dev)
		c.Set("token_exp", exp)
		c.Next()
	}, HandleLive())
	srv := httptest.NewServer(r)
	t.Cleanup(srv.Close)
	return srv
}

func useHub(t *testing.T) *Hub {
	t.Helper()
	prev := Default
	Default = NewHub()
	t.Cleanup(func() { Default = prev })
	return Default
}

// lines reads the stream line by line into a channel; it closes when the stream ends.
func lines(t *testing.T, url string) (*http.Response, <-chan string) {
	t.Helper()
	res, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { res.Body.Close() })
	out := make(chan string, 64)
	go func() {
		defer close(out)
		sc := bufio.NewScanner(res.Body)
		for sc.Scan() {
			out <- sc.Text()
		}
	}()
	return res, out
}

func waitLine(t *testing.T, ch <-chan string, want string) {
	t.Helper()
	deadline := time.After(2 * time.Second)
	for {
		select {
		case l, ok := <-ch:
			if !ok {
				t.Fatalf("stream ended before %q", want)
			}
			if l == want {
				return
			}
		case <-deadline:
			t.Fatalf("no %q", want)
		}
	}
}

func TestLive_StreamHeadersReadyAndSignal(t *testing.T) {
	h := useHub(t)
	u := uuid.New()
	srv := liveServer(t, u, "dev-a", time.Now().Add(time.Hour))
	res, ch := lines(t, srv.URL+"/live")
	if ct := res.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/event-stream") ||
		res.Header.Get("Cache-Control") != "no-cache" || res.Header.Get("X-Accel-Buffering") != "no" {
		t.Fatalf("headers: %v", res.Header)
	}
	waitLine(t, ch, "event: ready")
	h.Publish([]uuid.UUID{u}, KindChanged, "")
	waitLine(t, ch, "event: changed")
	waitLine(t, ch, "data: {}")
}

func TestLive_Ping(t *testing.T) {
	useHub(t)
	prev := pingEvery
	pingEvery = 20 * time.Millisecond
	t.Cleanup(func() { pingEvery = prev })
	srv := liveServer(t, uuid.New(), "dev-a", time.Now().Add(time.Hour))
	_, ch := lines(t, srv.URL+"/live")
	waitLine(t, ch, ": ping")
}

func TestLive_ClosesAtTokenExpiry(t *testing.T) {
	useHub(t)
	srv := liveServer(t, uuid.New(), "dev-a", time.Now().Add(300*time.Millisecond))
	_, ch := lines(t, srv.URL+"/live")
	waitLine(t, ch, "event: ready")
	select {
	case <-time.After(2 * time.Second):
		t.Fatal("stream outlived its token")
	case <-func() chan struct{} {
		done := make(chan struct{})
		go func() {
			for range ch {
			}
			close(done)
		}()
		return done
	}():
	}
}

func TestLive_DeviceRevokedEndsStream(t *testing.T) {
	h := useHub(t)
	u := uuid.New()
	srv := liveServer(t, u, "dev-a", time.Now().Add(time.Hour))
	_, ch := lines(t, srv.URL+"/live")
	waitLine(t, ch, "event: ready")
	h.PublishDevice(u, "dev-a", KindDeviceRevoked)
	waitLine(t, ch, "event: device_revoked")
	for range ch {
	}
}

// stuckWriter is a client that stopped reading: writes block until the write deadline passes.
type stuckWriter struct {
	header   http.Header
	deadline chan time.Time
}

func (w *stuckWriter) Header() http.Header { return w.header }
func (w *stuckWriter) WriteHeader(int)     {}
func (w *stuckWriter) Flush()              {}
func (w *stuckWriter) Write(b []byte) (int, error) {
	d := <-w.deadline
	time.Sleep(time.Until(d))
	return 0, errors.New("write deadline exceeded")
}
func (w *stuckWriter) SetWriteDeadline(d time.Time) error {
	select {
	case w.deadline <- d:
	default:
	}
	return nil
}

func TestLive_StuckClientDoesNotHoldTheHandler(t *testing.T) {
	useHub(t)
	prev := writeTimeout
	writeTimeout = 50 * time.Millisecond
	t.Cleanup(func() { writeTimeout = prev })
	gin.SetMode(gin.TestMode)
	w := &stuckWriter{header: http.Header{}, deadline: make(chan time.Time, 1)}
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/live", nil)
	c.Set("user_id", uuid.New())
	c.Set("token_exp", time.Now().Add(time.Hour))
	done := make(chan struct{})
	go func() {
		HandleLive()(c)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("a client that stopped reading kept the handler alive")
	}
}

func TestLive_IdleStreamOutlivesTheWriteTimeout(t *testing.T) {
	useHub(t)
	prevW, prevP := writeTimeout, pingEvery
	writeTimeout, pingEvery = 50*time.Millisecond, 200*time.Millisecond
	t.Cleanup(func() { writeTimeout, pingEvery = prevW, prevP })
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/live", func(c *gin.Context) {
		c.Set("user_id", uuid.New())
		c.Set("token_exp", time.Now().Add(time.Hour))
		c.Next()
	}, HandleLive())
	// HTTP/2, where an expired write deadline resets the stream rather than waiting.
	srv := httptest.NewUnstartedServer(r)
	srv.EnableHTTP2 = true
	srv.StartTLS()
	t.Cleanup(srv.Close)
	res, err := srv.Client().Get(srv.URL + "/live")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.ProtoMajor != 2 {
		t.Fatalf("want HTTP/2, got %s", res.Proto)
	}
	sc := bufio.NewScanner(res.Body)
	pings := 0
	deadline := time.After(2 * time.Second)
	got := make(chan string)
	go func() {
		for sc.Scan() {
			got <- sc.Text()
		}
		close(got)
	}()
	for pings < 2 {
		select {
		case l, ok := <-got:
			if !ok {
				t.Fatalf("stream ended after %d pings (idle longer than the write timeout)", pings)
			}
			if l == ": ping" {
				pings++
			}
		case <-deadline:
			t.Fatalf("only %d pings", pings)
		}
	}
}

// flushFails is a connection whose flush fails (the client went away).
type flushFails struct{ header http.Header }

func (w *flushFails) Header() http.Header         { return w.header }
func (w *flushFails) WriteHeader(int)             {}
func (w *flushFails) Write(b []byte) (int, error) { return len(b), nil }
func (w *flushFails) Flush()                      {}
func (w *flushFails) FlushError() error           { return errors.New("connection reset") }

func TestLive_FailedFlushEndsTheStream(t *testing.T) {
	useHub(t)
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(&flushFails{header: http.Header{}})
	c.Request = httptest.NewRequest(http.MethodGet, "/live", nil)
	c.Set("user_id", uuid.New())
	c.Set("token_exp", time.Now().Add(time.Hour))
	done := make(chan struct{})
	go func() {
		HandleLive()(c)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("a failed flush must end the stream")
	}
}
