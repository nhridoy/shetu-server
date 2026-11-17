package live

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// pingEvery keeps proxies and the app's read-idle timer from treating a quiet stream as dead.
var pingEvery = 25 * time.Second

// writeTimeout bounds each write: an app that stops reading can't hold the handler (and its
// connection) past it.
var writeTimeout = 10 * time.Second

// HandleLive streams signals to the signed-in device until its access token expires, the
// hub ends the stream, or the app disconnects. It runs behind the JWT middleware, which sets
// user_id, device_id and token_exp.
func HandleLive() gin.HandlerFunc {
	return func(c *gin.Context) {
		userID := c.MustGet("user_id").(uuid.UUID)
		ch, cancel := Default.Subscribe(userID, c.GetString("device_id"))
		defer cancel()

		h := c.Writer.Header()
		h.Set("Content-Type", "text/event-stream")
		h.Set("Cache-Control", "no-cache")
		h.Set("X-Accel-Buffering", "no")
		c.Status(http.StatusOK)
		exp := c.GetTime("token_exp")
		rc := http.NewResponseController(c.Writer)
		write := func(s string) bool {
			// Each write gets its own deadline (never past the token's expiry), so a stalled
			// client ends the stream instead of blocking it.
			deadline := time.Now().Add(writeTimeout)
			if exp.Before(deadline) {
				deadline = exp
			}
			_ = rc.SetWriteDeadline(deadline)
			if _, err := c.Writer.WriteString(s); err != nil {
				return false
			}
			return rc.Flush() == nil
		}
		if !write("event: ready\ndata: {}\n\n") {
			return
		}

		// A signed-out or expired session must not keep listening: end with the token.
		expiry := time.NewTimer(time.Until(exp))
		defer expiry.Stop()
		ping := time.NewTicker(pingEvery)
		defer ping.Stop()
		for {
			select {
			case <-c.Request.Context().Done():
				return
			case <-expiry.C:
				return
			case kind, ok := <-ch:
				if !ok || !write("event: "+kind+"\ndata: {}\n\n") {
					return
				}
			case <-ping.C:
				if !write(": ping\n\n") {
					return
				}
			}
		}
	}
}
