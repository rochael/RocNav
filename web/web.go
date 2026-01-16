package web

import (
	"embed"
	"io/fs"
)

//go:embed frontend/dist/*
var distFS embed.FS

// GetDistFS 返回构建好的前端静态文件系统（根目录已定位到 dist）
func GetDistFS() (fs.FS, error) {
	// 去掉 frontend/dist 前缀，让访问路径直接从 dist 内部开始
	return fs.Sub(distFS, "frontend/dist")
}
