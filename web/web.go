package web

import (
	"github.com/Cloudbox/crs/logger"
	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog"
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
	r.POST("/save/:hash/:filename", c.WithErrorResponse(c.Save))
}
