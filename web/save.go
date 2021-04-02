package web

import (
	"errors"
	"fmt"
	"github.com/Cloudbox/crs/util"
	"github.com/gin-gonic/gin"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

func (c *Client) Save(g *gin.Context) {
	// parse query
	b := new(struct {
		fileRequest
		ContentLength int64 `header:"content-length"" binding:"required"`
	})

	if err := g.ShouldBindUri(b); err != nil {
		g.AbortWithError(http.StatusBadRequest, fmt.Errorf("bind uri: %w", err))
		return
	}

	if err := g.ShouldBindHeader(b); err != nil {
		g.AbortWithError(http.StatusBadRequest, fmt.Errorf("bind header: %w", err))
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

	if b.ContentLength > (c.maxFileSize*1024)+100 {
		g.AbortWithError(http.StatusRequestEntityTooLarge, errors.New("file validate: request body too large"))
		return
	}

	// validate directory
	_, err := os.Stat(b.Directory)
	switch {
	case err != nil && os.IsNotExist(err):
		if err := os.MkdirAll(b.Directory, os.ModePerm); err != nil {
			g.AbortWithError(http.StatusInternalServerError, fmt.Errorf("directory make: %w", err))
			return
		}
	case err != nil:
		g.AbortWithError(http.StatusInternalServerError, fmt.Errorf("directory stat: %w", err))
		return
	}

	// receive file
	g.Request.Body = http.MaxBytesReader(g.Writer, g.Request.Body, c.maxFileSize*1024)
	file, err := g.FormFile("file")
	if err != nil {
		g.AbortWithError(http.StatusBadRequest, fmt.Errorf("file receive: %w", err))
		return
	}

	// save file
	if err = g.SaveUploadedFile(file, b.Filepath); err != nil {
		g.AbortWithError(http.StatusRequestEntityTooLarge, fmt.Errorf("file save: %w", err))
		return
	}

	g.JSON(http.StatusOK, &fileResponse{
		Message: fmt.Sprintf("Saved %v", b.Filename),
		Error:   false,
	})
}
