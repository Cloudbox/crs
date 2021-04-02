package web

import (
	"errors"
	"github.com/Cloudbox/crs/logger"
	"github.com/dustin/go-humanize"
	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog"
	"io"
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
	r.POST("/save/:hash/:filename", c.WithErrorResponse(c.WithRequestSizeLimit(c.Save, c.maxFileSize*1024)))
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

type maxBytesReader struct {
	ctx        *gin.Context
	rdr        io.ReadCloser
	remaining  int64
	wasAborted bool
	sawEOF     bool
}

func (mbr *maxBytesReader) tooLarge() (n int, err error) {
	n, err = 0, errors.New("request body too large")

	if !mbr.wasAborted {
		mbr.wasAborted = true
		mbr.ctx.Header("connection", "close")
	}
	return
}

func (mbr *maxBytesReader) Read(p []byte) (n int, err error) {
	toRead := mbr.remaining
	if mbr.remaining == 0 {
		if mbr.sawEOF {
			return mbr.tooLarge()
		}
		// The underlying io.Reader may not return (0, io.EOF)
		// at EOF if the requested size is 0, so read 1 byte
		// instead. The io.Reader docs are a bit ambiguous
		// about the return value of Read when 0 bytes are
		// requested, and {bytes,strings}.Reader gets it wrong
		// too (it returns (0, nil) even at EOF).
		toRead = 1
	}
	if int64(len(p)) > toRead {
		p = p[:toRead]
	}
	n, err = mbr.rdr.Read(p)
	if err == io.EOF {
		mbr.sawEOF = true
	}
	if mbr.remaining == 0 {
		// If we had zero bytes to read remaining (but hadn't seen EOF)
		// and we get a byte here, that means we went over our limit.
		if n > 0 {
			return mbr.tooLarge()
		}
		return 0, err
	}
	mbr.remaining -= int64(n)
	if mbr.remaining < 0 {
		mbr.remaining = 0
	}
	return
}

func (mbr *maxBytesReader) Close() error {
	return mbr.rdr.Close()
}

func (c Client) WithRequestSizeLimit(next func(*gin.Context), limit int64) gin.HandlerFunc {
	return func(g *gin.Context) {
		// set body reader
		g.Request.Body = &maxBytesReader{
			ctx:        g,
			rdr:        g.Request.Body,
			remaining:  limit,
			wasAborted: false,
			sawEOF:     false,
		}

		// call handler
		next(g)
	}
}
