// Package appcore 是 DataRecoveryMaster 的核心 App 实现。
//
// 之前所有 App 方法和 Wails 配置都堆在 root 的 package main。v2.8.47 重构：
//   - App 结构 + 100+ IPC 方法 + admin 提权 / wails 装配全部搬到 appcore
//   - root main.go 退化成几十行的 thin bootloader（embed assets + 调 appcore.Run）
//   - 测试紧邻代码而不再被困在 package main
//
// 调用方（main.go）只需要：
//
//	//go:embed all:frontend/dist
//	var assets embed.FS
//	func main() { os.Exit(appcore.Run(assets)) }
package appcore

import (
	"context"
	"embed"
	"os"
	"path/filepath"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
	"github.com/wailsapp/wails/v2/pkg/options/windows"

	"data-recovery/internal/logging"
	"data-recovery/internal/updater"
)

// Run 启动整个应用 —— 含 updater apply mode 检测 / 管理员提权 / 静默更新 /
// Wails 主循环。返回 process exit code（0 = 成功）。
//
// assets 来自 root main.go 的 //go:embed all:frontend/dist —— 因为 embed
// 路径相对于源文件，必须在 root 声明。其它一切搬到本包。
func Run(assets embed.FS) int {
	// 优先把日志切到"用户配置目录/logs/"下，方便诊断包导出时一并带上
	if cfgDir, err := os.UserConfigDir(); err == nil {
		_ = logging.EnableFileLogging(filepath.Join(cfgDir, "data-recovery", "logs"))
	}
	defer logging.Close()

	bootLogger := logging.L().With("component", "boot")

	// 检测"自动更新 helper 模式"：由主程序 fork 自己时带上 --apply-update，
	// 本模式不启动 Wails UI，只负责替换 exe 然后启动新版。
	if updater.IsApplyMode(os.Args) {
		parentPID, oldExe, newExe := updater.ParseApplyArgs(os.Args)
		bootLogger.Info("进入更新 helper 模式",
			"parent_pid", parentPID, "old_exe", oldExe, "new_exe", newExe)
		if err := updater.RunApplyHelper(parentPID, oldExe, newExe); err != nil {
			bootLogger.Error("更新 helper 执行失败", "err", err)
			return 1
		}
		return 0
	}

	relaunched, err := ensureAdminPrivileges()
	if err != nil {
		bootLogger.Error("无法获取管理员权限", "err", err)
		return 1
	}
	if relaunched {
		return 0
	}

	// 静默自动更新：检测到上次下载好的 pending 新版本，spawn helper 替换 exe，
	// 本进程立即退出让 helper 接管（再以新版 exe 重启应用）
	if ApplyPendingUpdateOnStartup() {
		bootLogger.Info("静默更新已派发 helper，当前进程退出让新版替换")
		return 0
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
		// v2.8.16: 关闭按钮二次确认 —— 防止扫描跑到一半被误关
		OnBeforeClose: app.onBeforeClose,
		Bind: []interface{}{
			app,
		},
		Windows: &windows.Options{
			WebviewIsTransparent: false,
			WindowIsTranslucent:  false,
		},
		// 启用 OS 级文件拖拽：用户把磁盘镜像 / .img / .raw 拖到窗口任意位置即可触发扫描。
		DragAndDrop: &options.DragAndDrop{
			EnableFileDrop:     true,
			DisableWebViewDrop: false,
		},
		OnDomReady: func(ctx context.Context) {
			app.bindFileDrop(ctx)
		},
	})
	if err != nil {
		bootLogger.Error("Wails 启动失败", "err", err)
		return 1
	}
	return 0
}
