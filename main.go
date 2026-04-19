package main

import (
	"embed"
	"os"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
	"github.com/wailsapp/wails/v2/pkg/options/windows"

	"data-recovery/internal/logging"
)

//go:embed all:frontend/dist
var assets embed.FS

func main() {
	bootLogger := logging.L().With("component", "boot")

	relaunched, err := ensureAdminPrivileges()
	if err != nil {
		bootLogger.Error("无法获取管理员权限", "err", err)
		os.Exit(1)
	}
	if relaunched {
		return
	}

	app := NewApp()

	err = wails.Run(&options.App{
		Title:     "数据恢复大师",
		Width:     1280,
		Height:    800,
		MinWidth:  960,
		MinHeight: 640,
		AssetServer: &assetserver.Options{
			Assets: assets,
		},
		BackgroundColour: &options.RGBA{R: 244, G: 239, B: 231, A: 1},
		OnStartup:        app.startup,
		OnShutdown:       app.shutdown,
		Bind: []interface{}{
			app,
		},
		Windows: &windows.Options{
			WebviewIsTransparent: false,
			WindowIsTranslucent:  false,
		},
	})
	if err != nil {
		bootLogger.Error("Wails 启动失败", "err", err)
		os.Exit(1)
	}
}
