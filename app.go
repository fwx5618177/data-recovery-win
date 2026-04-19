package main

import (
	"context"
	"fmt"
	"os/exec"
	"runtime"
	"sync"
	"time"

	wailsRuntime "github.com/wailsapp/wails/v2/pkg/runtime"

	"data-recovery/internal/disk"
	"data-recovery/internal/logging"
	"data-recovery/internal/recovery"
	"data-recovery/internal/session"
	"data-recovery/internal/types"
)

var appLogger = logging.L().With("component", "app")

// App 是 Wails 绑定的核心结构体，作为前端和后端之间的桥梁。
// 它负责暴露方法供前端 JS 调用，并通过 Wails runtime events 向前端推送实时进度。
type App struct {
	ctx    context.Context
	engine *recovery.Engine
	store  *session.Store

	mu sync.Mutex

	// 当前扫描上下文（供会话持久化使用）
	currentDrive types.DriveInfo
	currentMode  string

	// 扫描过程中最新一次进度/累积文件，用于周期性持久化
	scanSnapshotMu sync.Mutex
	scanProgress   types.ScanProgress
	scanFiles      []*types.RecoveredFile
	scanActive     bool
}

// NewApp 创建一个新的 App 实例
func NewApp() *App {
	return &App{}
}

// startup 是 Wails 的 startup hook，在应用启动时调用
func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
	a.engine = recovery.NewEngine()

	store, err := session.NewStore()
	if err != nil {
		appLogger.Warn("会话存储初始化失败（会话恢复将被禁用）", "err", err)
	} else {
		a.store = store
		appLogger.Info("会话存储就绪", "path", store.Path())
	}

	appLogger.Info("应用启动完成")
}

// shutdown 是 Wails 的 shutdown hook，在应用关闭时调用
func (a *App) shutdown(ctx context.Context) {
	appLogger.Info("应用关闭中")

	// 如果扫描正在进行，最后再存一次，丢失窗口降到秒级
	a.flushSessionIfActive()

	if a.engine != nil {
		a.engine.Shutdown()
	}
	appLogger.Info("资源清理完成")
}

// ============================================================
// 基础查询
// ============================================================

// GetDrives 获取系统中所有可用的驱动器列表
func (a *App) GetDrives() ([]*types.DriveInfo, error) {
	appLogger.Info("获取驱动器列表")
	drives, err := disk.ListDrives()
	if err != nil {
		appLogger.Warn("获取驱动器列表失败", "err", err)
		return nil, fmt.Errorf("获取驱动器列表失败: %w", err)
	}

	for _, d := range drives {
		d.SizeHuman = types.FormatSize(d.Size)
	}

	appLogger.Info("驱动器枚举完成", "count", len(drives))
	return drives, nil
}

// GetFreeSpace 查询任意路径所在卷的剩余空间。
// 用于前端在用户选定输出目录后提示"够不够装下恢复结果"。
func (a *App) GetFreeSpace(path string) (disk.FreeSpace, error) {
	if path == "" {
		return disk.FreeSpace{}, fmt.Errorf("路径为空")
	}
	fs, err := disk.GetFreeSpace(path)
	if err != nil {
		appLogger.Warn("查询剩余空间失败", "path", path, "err", err)
		return disk.FreeSpace{}, err
	}
	return fs, nil
}

// IsAdmin 检查当前程序是否以管理员权限运行
func (a *App) IsAdmin() bool {
	if runtime.GOOS == "windows" {
		return isWindowsAdmin()
	}
	return isUnixRoot()
}

// Platform 返回当前运行平台，用于前端显示对应的提权指引。
func (a *App) Platform() string {
	return runtime.GOOS
}

// ============================================================
// 扫描
// ============================================================

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

	// 记录上下文
	a.mu.Lock()
	a.currentDrive = types.DriveInfo{Path: drivePath}
	a.currentMode = mode
	a.mu.Unlock()

	a.scanSnapshotMu.Lock()
	a.scanProgress = types.ScanProgress{}
	a.scanFiles = nil
	a.scanActive = true
	a.scanSnapshotMu.Unlock()

	appLogger.Info("开始扫描", "drive", drivePath, "mode", mode)

	// 定义进度回调：同步更新本地快照以便持久化
	callbacks := recovery.ScanCallbacks{
		OnProgress: func(p types.ScanProgress) {
			a.scanSnapshotMu.Lock()
			a.scanProgress = p
			a.scanSnapshotMu.Unlock()
			wailsRuntime.EventsEmit(a.ctx, "scan:progress", p)
		},
		OnFileFound: func(f *types.RecoveredFile) {
			a.scanSnapshotMu.Lock()
			a.scanFiles = append(a.scanFiles, f)
			a.scanSnapshotMu.Unlock()
			wailsRuntime.EventsEmit(a.ctx, "scan:fileFound", f)
		},
	}

	// 在后台启动扫描，同时起会话持久化协程
	stopPersist := make(chan struct{})
	go a.persistLoop(stopPersist)

	go func() {
		result, err := a.engine.Scan(drivePath, types.ScanMode(mode), callbacks)
		close(stopPersist)

		a.scanSnapshotMu.Lock()
		a.scanActive = false
		a.scanSnapshotMu.Unlock()

		if err != nil {
			appLogger.Warn("扫描出错", "err", err)
			wailsRuntime.EventsEmit(a.ctx, "scan:error", err.Error())
			return
		}
		appLogger.Info("扫描结果已发送", "files", len(result.Files))

		// 扫描完成后也存一次快照（completed = true），用户下次打开可以看到上次的结果
		a.saveSnapshot(true)

		wailsRuntime.EventsEmit(a.ctx, "scan:completed", result)
	}()

	return nil
}

// StopScan 停止当前正在执行的扫描任务
func (a *App) StopScan() {
	appLogger.Info("正在停止扫描")
	a.engine.Stop()
}

// GetScanResults 获取当前扫描结果
func (a *App) GetScanResults() *types.ScanResult {
	return a.engine.Results()
}

// ============================================================
// 恢复
// ============================================================

// ValidateOutputDir 允许前端在用户选目录后立即做校验，不必等到真正点"开始恢复"。
// 返回空字符串表示可用；非空即为错误提示（同盘/权限不足等）。
func (a *App) ValidateOutputDir(outputDir string) string {
	if err := a.engine.ValidateRecoveryTarget(outputDir); err != nil {
		return err.Error()
	}
	return ""
}

// StartRecovery 开始恢复指定的文件
// fileIDs: 要恢复的文件 ID 列表
// outputDir: 恢复文件的输出目录
func (a *App) StartRecovery(fileIDs []string, outputDir string) error {
	return a.StartRecoveryEx(fileIDs, outputDir, false)
}

// StartRecoveryEx 是 StartRecovery 的扩展版本，多一个 allowSameDisk 参数。
// allowSameDisk=true 时跳过"恢复目录不能与源盘同一块物理磁盘"的安全检查——
// 仅当用户在前端明确勾选"我已了解风险（可能覆盖源数据）"后才应传 true。
func (a *App) StartRecoveryEx(fileIDs []string, outputDir string, allowSameDisk bool) error {
	if len(fileIDs) == 0 {
		return fmt.Errorf("未选择任何文件进行恢复")
	}
	if outputDir == "" {
		return fmt.Errorf("未指定输出目录")
	}
	if !allowSameDisk {
		if err := a.engine.ValidateRecoveryTarget(outputDir); err != nil {
			return err
		}
	}

	appLogger.Info("开始恢复",
		"files", len(fileIDs),
		"output_dir", outputDir,
		"allow_same_disk", allowSameDisk,
	)

	callbacks := recovery.RecoverCallbacks{
		OnProgress: func(p types.RecoveryProgress) {
			wailsRuntime.EventsEmit(a.ctx, "recovery:progress", p)
		},
	}

	opts := recovery.RecoverOptions{AllowSameDisk: allowSameDisk}

	go func() {
		result, err := a.engine.RecoverWithOptions(fileIDs, outputDir, opts, callbacks)
		if err != nil {
			appLogger.Warn("恢复出错", "err", err)
			wailsRuntime.EventsEmit(a.ctx, "recovery:error", err.Error())
			return
		}
		appLogger.Info("恢复结果已发送", "success", result.Succeeded, "failed", result.Failed)
		wailsRuntime.EventsEmit(a.ctx, "recovery:completed", result)
	}()

	return nil
}

// RetryFailedRecovery 基于上一次恢复记录，只对失败/跳过的文件重试。
// outputDir 通常沿用上次，但允许调用方换到别的盘。
func (a *App) RetryFailedRecovery(outputDir string) error {
	ids := a.engine.FailedRecoveryFileIDs()
	if len(ids) == 0 {
		return fmt.Errorf("没有失败或跳过的文件可重试")
	}
	return a.StartRecovery(ids, outputDir)
}

// GetLastRecoveryRecords 给前端展示上一次的每文件结果。
func (a *App) GetLastRecoveryRecords() []*recovery.FileRecoveryRecord {
	return a.engine.GetLastRecoveryResult()
}

// ExportRecoveryReport 把最近一次恢复的每文件记录导出成 CSV。
// 返回实际落地的绝对路径。
func (a *App) ExportRecoveryReport(outputDir string) (string, error) {
	records := a.engine.GetLastRecoveryResult()
	if len(records) == 0 {
		return "", fmt.Errorf("尚未有恢复记录可导出")
	}
	path, err := recovery.ExportReportCSV(records, outputDir)
	if err != nil {
		return "", err
	}
	appLogger.Info("恢复报告已导出", "path", path)
	return path, nil
}

// StopRecovery 停止当前正在执行的恢复任务
func (a *App) StopRecovery() {
	appLogger.Info("正在停止恢复")
	a.engine.StopRecovery()
}

// ============================================================
// 会话恢复
// ============================================================

// LoadLastSession 返回上次未完成的扫描快照，供前端提示"是否恢复上次扫描结果"。
// 没有会话或解析失败时返回 (nil, nil)。
func (a *App) LoadLastSession() (*session.Snapshot, error) {
	if a.store == nil {
		return nil, nil
	}
	return a.store.Load()
}

// DiscardSession 清除上次的会话（用户选"不恢复"时调用）。
func (a *App) DiscardSession() error {
	if a.store == nil {
		return nil
	}
	return a.store.Clear()
}

// persistLoop 扫描进行中每 5 秒保存一次快照；扫描结束由 caller close(stop) 退出。
func (a *App) persistLoop(stop <-chan struct{}) {
	if a.store == nil {
		return
	}
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()

	for {
		select {
		case <-stop:
			return
		case <-t.C:
			a.saveSnapshot(false)
		}
	}
}

// saveSnapshot 用当前状态覆盖会话文件。
// completed 为 true 表示扫描已完整结束（用户下次可选择直接恢复而不是续跑）。
func (a *App) saveSnapshot(completed bool) {
	if a.store == nil {
		return
	}

	a.scanSnapshotMu.Lock()
	progress := a.scanProgress
	filesCopy := make([]*types.RecoveredFile, len(a.scanFiles))
	copy(filesCopy, a.scanFiles)
	a.scanSnapshotMu.Unlock()

	a.mu.Lock()
	drive := a.currentDrive
	mode := a.currentMode
	a.mu.Unlock()

	snap := session.Snapshot{
		DrivePath:  drive.Path,
		DriveLabel: drive.Name,
		Mode:       mode,
		Progress:   progress,
		Files:      filesCopy,
		Completed:  completed,
	}
	if err := a.store.Save(snap); err != nil {
		appLogger.Warn("保存会话快照失败", "err", err)
	}
}

// flushSessionIfActive 在关机时兜底写一次。
func (a *App) flushSessionIfActive() {
	a.scanSnapshotMu.Lock()
	active := a.scanActive
	a.scanSnapshotMu.Unlock()
	if active {
		a.saveSnapshot(false)
	}
}

// ============================================================
// UI 辅助
// ============================================================

// SelectOutputDir 打开目录选择对话框，让用户选择恢复文件的输出目录
func (a *App) SelectOutputDir() (string, error) {
	dir, err := wailsRuntime.OpenDirectoryDialog(a.ctx, wailsRuntime.OpenDialogOptions{
		Title: "选择恢复文件保存位置",
	})
	if err != nil {
		appLogger.Warn("打开目录选择对话框失败", "err", err)
		return "", fmt.Errorf("打开目录选择对话框失败: %w", err)
	}
	return dir, nil
}

// OpenFolder 使用系统默认文件管理器打开指定文件夹
func (a *App) OpenFolder(path string) error {
	appLogger.Info("打开文件夹", "path", path)

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
		appLogger.Warn("打开文件夹失败", "err", err)
		return fmt.Errorf("打开文件夹失败: %w", err)
	}

	return nil
}
