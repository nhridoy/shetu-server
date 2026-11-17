package live

import (
	"bufio"
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
