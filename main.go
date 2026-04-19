package main

import (
	"embed"
	"os"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
	"github.com/wailsapp/wails/v2/pkg/options/windows"

	"data-recovery/internal/logging"
	"data-recovery/internal/updater"
)

//go:embed all:frontend/dist
var assets embed.FS

func main() {
	bootLogger := logging.L().With("component", "boot")

	// 检测"自动更新 helper 模式"：由主程序 fork 自己时带上 --apply-update，
	// 本模式不启动 Wails UI，只负责替换 exe 然后启动新版。
	if updater.IsApplyMode(os.Args) {
		parentPID, oldExe, newExe := updater.ParseApplyArgs(os.Args)
		bootLogger.Info("进入更新 helper 模式",
			"parent_pid", parentPID, "old_exe", oldExe, "new_exe", newExe)
		if err := updater.RunApplyHelper(parentPID, oldExe, newExe); err != nil {
			bootLogger.Error("更新 helper 执行失败", "err", err)
			os.Exit(1)
		}
		return
	}

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
