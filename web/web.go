package web

import (
	"github.com/Cloudbox/crs/logger"
	"github.com/dustin/go-humanize"
	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog"
	"strings"
	"time"
)

type Client struct {
	uploadDirectory string
	maxFileSize     int64
	allowedFiles    []string

	log zerolog.Logger
}

type Config struct {
	MaxFileSize  int64    `yaml:"max_file_size"`
	AllowedFiles []string `yaml:"allowed_files"`
}

type fileRequest struct {
	Hash     string `uri:"hash" binding:"required"`
	Filename string `uri:"filename" binding:"required"`

	Directory string
	Filepath  string
}

type fileResponse struct {
	Message string `json:"msg,omitempty"`
	Error   bool   `json:"error"`
}

func New(c *Config, uploadDirectory string) *Client {
	return &Client{
		uploadDirectory: uploadDirectory,
		maxFileSize:     c.MaxFileSize,
		allowedFiles:    c.AllowedFiles,

		log: logger.New(""),
	}
}

func (c *Client) SetHandlers(r *gin.Engine) {
	// core
	r.GET("/load/:hash/:filename", c.WithErrorResponse(c.Load))
	r.GET("/save/:hash/:filename", c.WithErrorResponse(c.Save))
}

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
