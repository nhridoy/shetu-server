package live

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// pingEvery keeps proxies and the app's read-idle timer from treating a quiet stream as dead.
var pingEvery = 25 * time.Second

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
		write := func(s string) bool {
			if _, err := c.Writer.WriteString(s); err != nil {
				return false
			}
			c.Writer.Flush()
			return true
		}
		if !write("event: ready\ndata: {}\n\n") {
			return
		}

		// A signed-out or expired session must not keep listening: end with the token.
		expiry := time.NewTimer(time.Until(c.GetTime("token_exp")))
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
