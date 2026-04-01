package main

import (
	"context"
	"fmt"
	"log"
	"os/exec"
	"runtime"
	"sync"

	wailsRuntime "github.com/wailsapp/wails/v2/pkg/runtime"

	"data-recovery/internal/disk"
	"data-recovery/internal/recovery"
	"data-recovery/internal/types"
)

// App 是 Wails 绑定的核心结构体，作为前端和后端之间的桥梁。
// 它负责暴露方法供前端 JS 调用，并通过 Wails runtime events 向前端推送实时进度。
type App struct {
	ctx    context.Context
	engine *recovery.Engine
	mu     sync.Mutex
}

// NewApp 创建一个新的 App 实例
func NewApp() *App {
	return &App{}
}

// startup 是 Wails 的 startup hook，在应用启动时调用
func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
	a.engine = recovery.NewEngine()
	log.Println("应用启动完成，恢复引擎已初始化")
}

// shutdown 是 Wails 的 shutdown hook，在应用关闭时调用
func (a *App) shutdown(ctx context.Context) {
	log.Println("应用正在关闭，清理资源...")
	if a.engine != nil {
		a.engine.Shutdown()
	}
	log.Println("资源清理完成")
}

// GetDrives 获取系统中所有可用的驱动器列表
func (a *App) GetDrives() ([]*types.DriveInfo, error) {
	log.Println("正在获取驱动器列表...")
	drives, err := disk.ListDrives()
	if err != nil {
		log.Printf("获取驱动器列表失败: %v", err)
		return nil, fmt.Errorf("获取驱动器列表失败: %w", err)
	}

	// 为每个驱动器填充人类可读的大小字符串
	for _, d := range drives {
		d.SizeHuman = types.FormatSize(d.Size)
	}

	log.Printf("发现 %d 个驱动器", len(drives))
	return drives, nil
}

// StartScan 开始扫描指定驱动器
// drivePath: 驱动器路径（如 \\.\PhysicalDrive0）
// mode: 扫描模式（quick / deep / full），为空时默认使用 full
func (a *App) StartScan(drivePath string, mode string) error {
	a.mu.Lock()
	if a.engine.IsScanning() {
		a.mu.Unlock()
		return fmt.Errorf("已有扫描任务正在执行，请先停止当前扫描")
	}
	a.mu.Unlock()

	if mode == "" {
		mode = string(types.ScanFull)
	}

	log.Printf("开始扫描驱动器: %s, 模式: %s", drivePath, mode)

	// 定义进度回调
	callbacks := recovery.ScanCallbacks{
		// 扫描进度回调，向前端推送进度信息
		OnProgress: func(p types.ScanProgress) {
			wailsRuntime.EventsEmit(a.ctx, "scan:progress", p)
		},
		// 发现文件回调，向前端推送新发现的文件
		OnFileFound: func(f *types.RecoveredFile) {
			wailsRuntime.EventsEmit(a.ctx, "scan:fileFound", f)
		},
	}

	// 在新的 goroutine 中执行扫描，避免阻塞前端
	go func() {
		result, err := a.engine.Scan(drivePath, types.ScanMode(mode), callbacks)
		if err != nil {
			log.Printf("扫描出错: %v", err)
			wailsRuntime.EventsEmit(a.ctx, "scan:error", err.Error())
			return
		}
		log.Printf("扫描完成，共发现 %d 个可恢复文件", len(result.Files))
		wailsRuntime.EventsEmit(a.ctx, "scan:completed", result)
	}()

	return nil
}

// StopScan 停止当前正在执行的扫描任务
func (a *App) StopScan() {
	log.Println("正在停止扫描...")
	a.engine.Stop()
}

// GetScanResults 获取当前扫描结果
func (a *App) GetScanResults() *types.ScanResult {
	return a.engine.Results()
}

// StartRecovery 开始恢复指定的文件
// fileIDs: 要恢复的文件 ID 列表
// outputDir: 恢复文件的输出目录
func (a *App) StartRecovery(fileIDs []string, outputDir string) error {
	if len(fileIDs) == 0 {
		return fmt.Errorf("未选择任何文件进行恢复")
	}
	if outputDir == "" {
		return fmt.Errorf("未指定输出目录")
	}
	if err := a.engine.ValidateRecoveryTarget(outputDir); err != nil {
		return err
	}

	log.Printf("开始恢复 %d 个文件到目录: %s", len(fileIDs), outputDir)

	// 定义恢复进度回调
	callbacks := recovery.RecoverCallbacks{
		OnProgress: func(p types.RecoveryProgress) {
			wailsRuntime.EventsEmit(a.ctx, "recovery:progress", p)
		},
	}

	// 在新的 goroutine 中执行恢复，避免阻塞前端
	go func() {
		result, err := a.engine.Recover(fileIDs, outputDir, callbacks)
		if err != nil {
			log.Printf("恢复出错: %v", err)
			wailsRuntime.EventsEmit(a.ctx, "recovery:error", err.Error())
			return
		}
		log.Printf("恢复完成，成功: %d, 失败: %d", result.Succeeded, result.Failed)
		wailsRuntime.EventsEmit(a.ctx, "recovery:completed", result)
	}()

	return nil
}

// StopRecovery 停止当前正在执行的恢复任务
func (a *App) StopRecovery() {
	log.Println("正在停止恢复...")
	a.engine.StopRecovery()
}

// SelectOutputDir 打开目录选择对话框，让用户选择恢复文件的输出目录
func (a *App) SelectOutputDir() (string, error) {
	dir, err := wailsRuntime.OpenDirectoryDialog(a.ctx, wailsRuntime.OpenDialogOptions{
		Title: "选择恢复文件保存位置",
	})
	if err != nil {
		log.Printf("打开目录选择对话框失败: %v", err)
		return "", fmt.Errorf("打开目录选择对话框失败: %w", err)
	}
	return dir, nil
}

// IsAdmin 检查当前程序是否以管理员权限运行
// Windows 平台使用 golang.org/x/sys/windows 检测；其他平台检查 euid 是否为 0
func (a *App) IsAdmin() bool {
	if runtime.GOOS == "windows" {
		return isWindowsAdmin()
	}
	return isUnixRoot()
}

// OpenFolder 使用系统默认文件管理器打开指定文件夹
func (a *App) OpenFolder(path string) error {
	log.Printf("打开文件夹: %s", path)

	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("explorer", path)
	case "darwin":
		cmd = exec.Command("open", path)
	case "linux":
		cmd = exec.Command("xdg-open", path)
	default:
		return fmt.Errorf("不支持的操作系统: %s", runtime.GOOS)
	}

	if err := cmd.Start(); err != nil {
		log.Printf("打开文件夹失败: %v", err)
		return fmt.Errorf("打开文件夹失败: %w", err)
	}

	return nil
}
