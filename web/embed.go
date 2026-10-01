package web

import (
	"embed"
	"io/fs"
)

//go:embed static/*
var staticEmbed embed.FS

// GetStaticFS returns the embedded sub-filesystem pointing to static/
func GetStaticFS() fs.FS {
	sub, err := fs.Sub(staticEmbed, "static")
	if err != nil {
		panic(err)
	}
	return sub
}
