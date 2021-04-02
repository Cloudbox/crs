package web

import (
	"fmt"
	"github.com/Cloudbox/crs/util"
	"github.com/gin-gonic/gin"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

func (c *Client) Load(g *gin.Context) {
	// parse query
	b := new(fileRequest)
	if err := g.ShouldBindUri(b); err != nil {
		g.AbortWithError(http.StatusBadRequest, fmt.Errorf("bind uri: %w", err))
		return
	}

	b.Hash = filepath.Base(b.Hash)
	b.Filename = filepath.Base(strings.ToLower(b.Filename))
	b.Directory = filepath.Join(c.uploadDirectory, b.Hash)
	b.Filepath = filepath.Join(b.Directory, b.Filename)

	// validate request
	if !util.StringListContains(c.allowedFiles, b.Filename) {
		g.AbortWithError(http.StatusBadRequest, fmt.Errorf("file unsupported: %v", b.Filename))
		return
	}

	// validate file
	if _, err := os.Stat(b.Filepath); err != nil {
		if os.IsNotExist(err) {
			g.AbortWithError(http.StatusNotFound, fmt.Errorf("file not found: %v", b.Filename))
			return
		}

		g.AbortWithError(http.StatusInternalServerError, fmt.Errorf("file stat: %w", err))
		return
	}

	// return file
	g.File(b.Filepath)
}
