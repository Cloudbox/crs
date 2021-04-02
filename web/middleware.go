package web

import (
	"github.com/dustin/go-humanize"
	"github.com/gin-gonic/gin"
	"strings"
	"time"
)

func (c *Client) Logger() gin.HandlerFunc {
	return func(g *gin.Context) {
		// log request
		rl := c.log.With().
			Str("ip", g.ClientIP()).
			Str("uri", g.Request.RequestURI).
			Logger()

		rl.Debug().Msg("Request received")

		// handle request
		t := time.Now()
		g.Next()
		l := time.Since(t)

		// log errors
		switch {
		case len(g.Errors) > 0:
			errors := make([]error, 0)
			for _, err := range g.Errors {
				errors = append(errors, err.Err)
			}

			rl.Error().
				Errs("errors", errors).
				Int("status", g.Writer.Status()).
				Str("duration", l.String()).
				Msg("Request failed")
			return

		case g.Writer.Status() >= 400 && g.Writer.Status() <= 599:
			rl.Error().
				Int("status", g.Writer.Status()).
				Str("duration", l.String()).
				Msg("Request failed")
			return
		}

		// log outcome
		rl.Info().
			Str("size", humanize.IBytes(uint64(g.Writer.Size()))).
			Int("status", g.Writer.Status()).
			Str("duration", l.String()).
			Msg("Request processed")
	}
}

func (c Client) WithErrorResponse(next func(*gin.Context)) gin.HandlerFunc {
	return func(g *gin.Context) {
		// call handler
		next(g)

		// error response
		if len(g.Errors) > 0 {
			errors := make([]string, 0)
			for _, err := range g.Errors {
				errors = append(errors, err.Error())
			}

			g.JSON(g.Writer.Status(), &fileResponse{
				Message: strings.Join(errors, ", "),
				Error:   true,
			})
		}
	}
}
