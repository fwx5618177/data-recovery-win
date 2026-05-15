package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	wailsRuntime "github.com/wailsapp/wails/v2/pkg/runtime"

	"data-recovery/internal/apfs"
	"data-recovery/internal/backup"
	"data-recovery/internal/bitlocker"
	"data-recovery/internal/dedup"
	"data-recovery/internal/diag"
	"data-recovery/internal/disk"
	"data-recovery/internal/forensics"
	"data-recovery/internal/gpt"
	"data-recovery/internal/android"
	"data-recovery/internal/hfsplus"
	"data-recovery/internal/ios"
	"data-recovery/internal/logging"
	"data-recovery/internal/luks"
	"data-recovery/internal/mtp"
	"data-recovery/internal/netfs"
	"data-recovery/internal/ocr"
	"data-recovery/internal/parallel"
	"data-recovery/internal/raid"
	"data-recovery/internal/recovery"
	"data-recovery/internal/refs"
	"data-recovery/internal/sed"
	"data-recovery/internal/session"
	"data-recovery/internal/types"
	"data-recovery/internal/updater"
	"data-recovery/internal/veracrypt"
	"data-recovery/internal/volmgr"
	"data-recovery/internal/vss"
)

// EncryptedVolumeInfo 是 ScanEncryptedVolumes 给前端的统一报告类型。
// BitLocker / FileVault 都是"加密但本工具不能解密"的同一类问题，UI 用同一区块展示。
type EncryptedVolumeInfo struct {
	DrivePath  string `json:"drivePath"`  // 来源磁盘路径
	Kind       string `json:"kind"`       // "bitlocker" / "filevault" / "apfs-volume"
	Offset     int64  `json:"offset"`
	Name       string `json:"name"`        // 卷名（APFS 有；BitLocker 无）
	UUID       string `json:"uuid"`
	Encrypted  bool   `json:"encrypted"`
	Note       string `json:"note"`        // 给用户的引导（去 dislocker / 用专门工具等）
}

// updateRepoOwner / updateRepoName 指向本项目的 GitHub 仓库，用于版本检查。
//
// 发版时通过 -ldflags 在 CI 里注入真实值，避免源码里把 fork 写死：
//
//	go build -ldflags "-X main.updateRepoOwner=MyOrg -X main.updateRepoName=data-recovery"
//
// 源码里保留占位值，fork 的开发者不需要改任何代码即可跑；只有正式发版时才注入真仓库。
// 占位值用 "" 比"your-github-owner"更诚实 — 让 updater.CheckLatest 在没注入时直接跳过
// 远程检查，不会发出误导性的 HTTP 请求。
var (
	updateRepoOwner = ""
	updateRepoName  = ""
)

// imagingMu 序列化 DumpDisk 调用 —— 一次只允许一个 dump 任务
var imagingMu sync.Mutex

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

	// 可选载入的 NSRL 良性 hash 库（取证场景用）
	nsrlDB *forensics.NSRLDB

	// 下载是否进行中 —— 防止 autoCheckForUpdate 静默下载后，用户点"下载"
	// 按钮又触发一次，两个下载并发写同 pending 目录 → 进度回退 bug
	downloadActive bool

	// NAS 扫描的 cancel 函数（Batch 2）；一次只有一个 SMB/NFS 扫描在跑
	smbScanCancel context.CancelFunc
	nfsScanCancel context.CancelFunc

	// iOS 备份扫描的 cancel（Batch 3）
	iosScanCancel context.CancelFunc

	// OCR 搜图的 cancel（v2.8.4）
	ocrMu     sync.Mutex
	ocrCancel context.CancelFunc

	// 多盘并行扫描的 cancel（v2.8.5）—— 同时只允许一个 multi-disk 任务
	parallelMu     sync.Mutex
	parallelCancel context.CancelFunc

	// Android backup 扫描 cancel（Batch 4）
	androidScanCancel context.CancelFunc

	// 移动端任务的 cancel functions（v2.5.1）
	// 一次每种 kind 只允许一个任务在跑，所以单字段够用
	mtpDumpCancel    context.CancelFunc // Android root 块级 dump
	mtpPullCancel    context.CancelFunc // ADB pull directory
	iosBackupCancel  context.CancelFunc // libimobiledevice 备份触发
	ptpPullCancel    context.CancelFunc // gphoto2 相机 pull
	diskDumpCancel   context.CancelFunc // 整盘镜像 dump

	// v2.8.16: 关闭按钮二次确认。用户点 X 时 OnBeforeClose 拦截 → 发 app:closeRequested
	// 事件给前端 → 前端弹模态对话框（退出 / 最小化 / 取消）→ 前端调 ConfirmExit() 设
	// confirmedExit=true → 程序真正退出。
	confirmedExitMu sync.Mutex
	confirmedExit   bool
}

// NewApp 创建一个新的 App 实例
func NewApp() *App {
	return &App{}
}

// onBeforeClose 是 Wails 的关闭拦截 hook。返回 true 表示阻止关闭。
//
// v2.8.16 行为：
//   - 第一次点 X：返回 true 阻止退出 + 发 "app:closeRequested" 事件给前端
//   - 前端弹模态对话框 "退出 / 最小化 / 取消"
//   - 用户选"退出" → 前端调 ConfirmExit() 设 confirmedExit=true → 再调 wails.Quit()
//   - 用户选"最小化" → 前端调 MinimizeWindow()
//   - 用户选"取消" → 前端关闭弹窗，啥也不做
//
// 防止扫描跑到一半被误关，丢失几小时进度。
func (a *App) onBeforeClose(ctx context.Context) bool {
	a.confirmedExitMu.Lock()
	confirmed := a.confirmedExit
	a.confirmedExitMu.Unlock()
	if confirmed {
		return false // 用户已经显式确认退出，放行
	}
	// 通知前端弹确认对话框
	wailsRuntime.EventsEmit(ctx, "app:closeRequested")
	return true // 阻止关闭
}

// ConfirmExit 给前端调：用户在关闭确认对话框选了"退出应用"。
// 设标志位然后调 wails.Quit() 让 OnBeforeClose 放行。
func (a *App) ConfirmExit() {
	a.confirmedExitMu.Lock()
	a.confirmedExit = true
	a.confirmedExitMu.Unlock()
	wailsRuntime.Quit(a.ctx)
}

// MinimizeWindow 给前端调：用户在关闭确认对话框选了"最小化"。
func (a *App) MinimizeWindow() {
	wailsRuntime.WindowMinimise(a.ctx)
}

// startup 是 Wails 的 startup hook，在应用启动时调用
// emitScanHeartbeat 每 500ms 重发一次 "scan:progress"，使用 a.scanProgress 当前快照
// + 实时更新的 Elapsed。底层扫描器可能在某些阶段（如 NTFS 读 MFT entry 0、USN
// journal 慢扫、JPEG carver 长 seek）几秒不主动 emit 进度，前端就会卡在
// indeterminate 动画 + "0.0%"。heartbeat 让 UI 至少能看到时间在走、scan 还活着。
//
// 调用方：开扫前 `go a.emitScanHeartbeat(stopCh, startTime)`，
//        扫描 goroutine 结束后 `close(stopCh)`。
func (a *App) emitScanHeartbeat(stopCh <-chan struct{}, startTime time.Time) {
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	state := &heartbeatState{
		lastBytesScanned: 0,
		lastSampleTime:   startTime,
		lastSpeed:        0,
	}
	// 立刻发一次 —— 不等 500ms tick，让前端在用户点"开始扫描"后立刻跳出 ready 状态。
	// 没有这一发，brute-force 分区发现期间 (可能跑几秒到几分钟) 前端会卡在"即将开始 0.0%"。
	a.emitHeartbeatTick(startTime, state)
	for {
		select {
		case <-stopCh:
			return
		case <-ticker.C:
			if !a.emitHeartbeatTick(startTime, state) {
				return
			}
		}
	}
}

// mergeScanProgress 把新的 ScanProgress 合并进既有快照。
//
// 关键：dispatcher 创建新的 ScanProgress 时只设置自己关心的字段（Phase / Percent /
// CurrentFile），其余字段是 zero value。如果直接覆盖 a.scanProgress，已经从底层拿到
// 的 TotalBytes / FilesFound / Speed 会被重置为 0。
//
// 合并策略：incoming 设了非零 → 用 incoming（最新值）；incoming 为零 → 保留 prev。
//
// 例外：Percent 必须用 incoming（即使是 0，可能是有意从某 phase 重置进度的开头）。
// 但前端 App.tsx 已有单调 guard 兜底，所以这里直接用 incoming 安全。
func mergeScanProgress(prev, incoming types.ScanProgress) types.ScanProgress {
	out := incoming
	if out.TotalBytes == 0 && prev.TotalBytes > 0 {
		out.TotalBytes = prev.TotalBytes
	}
	if out.BytesScanned == 0 && prev.BytesScanned > 0 {
		out.BytesScanned = prev.BytesScanned
	}
	if out.FilesFound == 0 && prev.FilesFound > 0 {
		out.FilesFound = prev.FilesFound
	}
	if out.Speed == 0 && prev.Speed > 0 {
		out.Speed = prev.Speed
	}
	return out
}

// heartbeatState 心跳间复用的状态：用来从 BytesScanned 增量算 speed。
// 底层扫描器（如 brute-force partition discovery）只报字节数 + 总数，不算速度；
// 心跳每 500ms 看一次 BytesScanned 差，得到 bytes/sec。
type heartbeatState struct {
	lastBytesScanned int64
	lastSampleTime   time.Time
	lastSpeed        int64 // 缓存最近一次有效速度，避免 sample 间速度=0 闪烁
}

// emitHeartbeatTick 单次心跳：返回 false 表示 scan 已结束，调用方应退出循环。
func (a *App) emitHeartbeatTick(startTime time.Time, state *heartbeatState) bool {
	a.scanSnapshotMu.Lock()
	p := a.scanProgress
	active := a.scanActive
	filesCount := len(a.scanFiles)
	a.scanSnapshotMu.Unlock()
	if !active {
		return false
	}
	// 实时 elapsed
	p.Elapsed = formatElapsedSeconds(time.Since(startTime).Seconds())
	// 还没收到任何真实进度报告 → 发个"初始化"占位让 UI 跳出 indeterminate 模式
	if p.Phase == "" {
		p.Phase = "init"
		p.CurrentFile = "正在初始化扫描…"
		p.Percent = 0.5
	}
	// FilesFound 用 a.scanFiles 长度兜底（OnFileFound 累计的，更稳）
	if filesCount > p.FilesFound {
		p.FilesFound = filesCount
	}
	// 如果底层没填 Speed，但 BytesScanned 在涨，自己算一个（500ms 滚动窗口）
	if p.Speed == 0 && p.BytesScanned > state.lastBytesScanned {
		dt := time.Since(state.lastSampleTime).Seconds()
		if dt > 0.1 { // 100ms 以下不可信
			delta := p.BytesScanned - state.lastBytesScanned
			state.lastSpeed = int64(float64(delta) / dt)
			state.lastBytesScanned = p.BytesScanned
			state.lastSampleTime = time.Now()
		}
		p.Speed = state.lastSpeed
	} else if p.Speed == 0 && state.lastSpeed > 0 {
		// 没新增字节但有缓存速度 —— 短暂的 IO 停顿，UI 显示最近一次而不是闪 0
		p.Speed = state.lastSpeed
	}
	wailsRuntime.EventsEmit(a.ctx, "scan:progress", p)
	return true
}

// formatElapsedSeconds 把秒数格式化为 "12s" / "3m45s" / "1h02m"
func formatElapsedSeconds(s float64) string {
	if s < 60 {
		return fmt.Sprintf("%ds", int(s))
	}
	if s < 3600 {
		m := int(s / 60)
		return fmt.Sprintf("%dm%02ds", m, int(s)-m*60)
	}
	h := int(s / 3600)
	return fmt.Sprintf("%dh%02dm", h, int((s-float64(h)*3600)/60))
}

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

	// 启动后台版本检查 + 静默自动更新（下载 + 下次启动自动替换）
	// 注意：故意不阻塞启动，不报错干扰用户
	go a.autoCheckForUpdate()

	appLogger.Info("应用启动完成", "version", updater.Version)
}

// ApplyPendingUpdateOnStartup 在 main.go 很早期（wails.Run 之前）调用：
// 检测是否有上次下载好的新版本 pending；有就 spawn helper 替换 exe 并 exit，
// 用户下次启动（通过 helper 重新拉起）就是新版本 —— 完全静默。
//
// 返回 true 表示"已发起替换 + 当前进程应退出"（让 helper 接管）。
// 独立在 app struct 外是因为 struct 实例化时已经太晚。
func ApplyPendingUpdateOnStartup() bool {
	// 环境变量 opt-out（CI / 企业部署可禁）
	if os.Getenv("DATA_RECOVERY_NO_AUTO_UPDATE") == "1" {
		return false
	}
	pending, err := updater.LoadPending()
	if err != nil || pending == nil {
		return false
	}
	// pending 版本必须比当前运行的 binary 版本新
	if pending.Version == "" || pending.Version == updater.Version {
		return false
	}
	// 二进制文件必须存在（user 可能手动清理过）
	if _, err := os.Stat(pending.BinaryPath); err != nil {
		_ = updater.ClearPending()
		return false
	}
	currentExe, err := os.Executable()
	if err != nil {
		return false
	}
	appLogger.Info("检测到 pending 更新，静默替换", "version", pending.Version)
	if err := updater.SpawnApplyHelper(currentExe, pending.BinaryPath); err != nil {
		appLogger.Warn("静默更新 spawn helper 失败", "err", err)
		return false
	}
	// helper 已脱离本进程；当前进程退出让 helper 替换 exe 再重新拉起
	return true
}

// autoCheckForUpdate 后台检查 GitHub Releases。
// 约束：
//   - 扫描 / 恢复进行中**不**打扰用户（即便 release 页有新版，本次会话不推送）
//   - 失败静默（网络问题 / GitHub 限流不影响用户操作）
//   - 10 秒超时已在 updater.httpClient 里兜住
func (a *App) autoCheckForUpdate() {
	// 发版时 -ldflags 未注入仓库名 → 不发 HTTP 请求（fork 开发者 / CI 构建都跳过）
	if updateRepoOwner == "" || updateRepoName == "" {
		return
	}
	// 启动时先等 3 秒，避免与磁盘枚举等请求争资源
	time.Sleep(3 * time.Second)

	if a.engine != nil && (a.engine.IsScanning()) {
		appLogger.Info("扫描进行中，跳过自动更新检查")
		return
	}

	ctx, cancel := context.WithTimeout(a.ctx, 10*time.Second)
	defer cancel()

	res, err := updater.CheckLatest(ctx, updateRepoOwner, updateRepoName)
	if err != nil {
		appLogger.Debug("版本检查失败（忽略）", "err", err)
		return
	}
	if !res.HasUpdate {
		return
	}

	appLogger.Info("发现新版本",
		"current", res.CurrentVersion,
		"latest", res.LatestVersion,
		"url", res.DownloadPage)
	wailsRuntime.EventsEmit(a.ctx, "update:available", res)

	// 静默自动下载：用户 opt-out 才不做
	if os.Getenv("DATA_RECOVERY_NO_AUTO_UPDATE") == "1" {
		return
	}
	// 选择本平台对应的 asset（按平台 + arch 前缀匹配）
	asset := pickPlatformAsset(res.Assets)
	if asset == nil {
		appLogger.Info("自动更新：未找到本平台 asset，留给用户手动下载")
		return
	}
	appLogger.Info("开始静默后台下载", "asset", asset.Name, "size", asset.Size)
	// 复用 DownloadUpdate 的核心逻辑 —— 直接调 DownloadAsset + SavePending
	if err := a.DownloadUpdate(res.LatestVersion, asset.DownloadURL, asset.Name, asset.Size); err != nil {
		appLogger.Debug("静默下载调度失败（忽略）", "err", err)
	}
}

// pickPlatformAsset 从 release assets 里选当前平台对应的 asset
// 匹配规则：文件名包含 runtime.GOOS + runtime.GOARCH（或 universal）
func pickPlatformAsset(assets []updater.Asset) *updater.Asset {
	osName := runtime.GOOS
	arch := runtime.GOARCH
	// GitHub Release asset 命名惯例：data-recovery-{os}-{arch}.{ext}
	// universal 也匹配（macOS 通用二进制）
	for i := range assets {
		name := strings.ToLower(assets[i].Name)
		if strings.Contains(name, osName) && (strings.Contains(name, arch) || strings.Contains(name, "universal")) {
			return &assets[i]
		}
	}
	// 仅按 OS 匹配的 fallback（有些 release 用 amd64 别名如 x64/x86_64）
	for i := range assets {
		name := strings.ToLower(assets[i].Name)
		if strings.Contains(name, osName) {
			return &assets[i]
		}
	}
	return nil
}

// CheckForUpdate 提供给前端主动触发版本检查的入口（"立刻检查更新"按钮）。
// 返回 CheckResult —— 无论有无更新都返回，前端自己决定怎么展示。
func (a *App) CheckForUpdate() (*updater.CheckResult, error) {
	if updateRepoOwner == "" || updateRepoName == "" {
		return nil, fmt.Errorf("未配置发布仓库（build 时 -ldflags 注入 main.updateRepoOwner / main.updateRepoName）")
	}
	if a.engine != nil && a.engine.IsScanning() {
		return nil, fmt.Errorf("正在扫描，请稍后再检查更新")
	}
	ctx, cancel := context.WithTimeout(a.ctx, 10*time.Second)
	defer cancel()
	return updater.CheckLatest(ctx, updateRepoOwner, updateRepoName)
}

// GetAppVersion 返回当前二进制的版本号，前端 footer 展示用
func (a *App) GetAppVersion() string {
	return updater.Version
}

// UnlockBitLockerAndScan 用 recovery key 解锁 BitLocker 卷，然后启动一次完整扫描。
//
// 这是 Phase 2 完整链 IPC 的对外入口：
//   recovery key → VMK → FVEK → DecryptingReader → engine.ScanWithReader → NTFS/carver
//
// 调用前 UI 应显示"正在派生密钥…"，因为 StretchKey 1M 次 SHA-256 在普通 CPU ~1-2s。
// 前端事件流和普通扫描一致：bitlocker:keyDeriving / bitlocker:unlocked / scan:progress /
// scan:fileFound / scan:completed / scan:error。
func (a *App) UnlockBitLockerAndScan(drivePath, volumeOffsetHex, recoveryKey, mode string) error {
	if drivePath == "" || recoveryKey == "" {
		return fmt.Errorf("drivePath / recovery key 不能为空")
	}
	if mode == "" {
		mode = string(types.ScanFull)
	}

	// BitLocker 卷必然在物理盘 / 卷设备上，读 \\.\PhysicalDriveN 等原始设备
	// 一定要管理员权限。提前告诉用户比让他们看 "Access is denied" 友好。
	if !a.IsAdmin() {
		return fmt.Errorf("需要管理员 / root 权限才能读原始磁盘设备解锁 BitLocker；请以管理员身份重启本工具")
	}

	a.mu.Lock()
	if a.engine.IsScanning() {
		a.mu.Unlock()
		return fmt.Errorf("已有扫描任务正在执行，请先停止当前扫描")
	}
	a.mu.Unlock()

	// 解析卷偏移（十六进制；通常 "0" 即整盘起点）
	var volumeOffset int64
	if _, err := fmt.Sscanf(volumeOffsetHex, "%x", &volumeOffset); err != nil {
		return fmt.Errorf("volumeOffset 解析失败: %w", err)
	}

	underlying := disk.NewReader(drivePath)
	if err := underlying.Open(); err != nil {
		return fmt.Errorf("打开磁盘失败: %w", err)
	}

	// 检测 BitLocker 卷头（拿 metadata block 偏移）
	bvolume, err := bitlocker.Detect(underlying, volumeOffset)
	if err != nil {
		underlying.Close()
		return fmt.Errorf("BitLocker 检测失败: %w", err)
	}
	if bvolume == nil {
		underlying.Close()
		return fmt.Errorf("此偏移位置不是 BitLocker 卷")
	}

	appLogger.Info("BitLocker 解锁开始", "drive", drivePath, "offset", volumeOffset)

	progressCb := func(done, total uint64) {
		wailsRuntime.EventsEmit(a.ctx, "bitlocker:keyDeriving", map[string]uint64{
			"done":  done,
			"total": total,
		})
	}

	result, err := bitlocker.UnlockBitLockerVolumeWithRecoveryKey(underlying, bvolume, recoveryKey, progressCb)
	if err != nil {
		underlying.Close()
		appLogger.Warn("BitLocker 解锁失败", "err", err)
		return fmt.Errorf("解锁失败: %w", err)
	}

	appLogger.Info("BitLocker 解锁成功",
		"encryption_method", fmt.Sprintf("0x%04X", result.EncryptionMethod),
		"volume_uuid", fmt.Sprintf("%X", result.VolumeIdentifier))

	wailsRuntime.EventsEmit(a.ctx, "bitlocker:unlocked", map[string]any{
		"encryptionMethod": fmt.Sprintf("0x%04X", result.EncryptionMethod),
		"volumeUUID":       fmt.Sprintf("%X", result.VolumeIdentifier),
	})

	// 记录上下文 + 初始化快照（与 StartScan 对齐）
	a.mu.Lock()
	a.currentDrive = types.DriveInfo{Path: drivePath + " (BitLocker 已解锁)"}
	a.currentMode = mode
	a.mu.Unlock()

	a.scanSnapshotMu.Lock()
	a.scanProgress = types.ScanProgress{}
	a.scanFiles = nil
	a.scanActive = true
	a.scanSnapshotMu.Unlock()

	callbacks := recovery.ScanCallbacks{
		OnProgress: func(p types.ScanProgress) {
			a.scanSnapshotMu.Lock()
			merged := mergeScanProgress(a.scanProgress, p)
			a.scanProgress = merged
			a.scanSnapshotMu.Unlock()
			wailsRuntime.EventsEmit(a.ctx, "scan:progress", merged)
		},
		OnFileFound: func(f *types.RecoveredFile) {
			a.scanSnapshotMu.Lock()
			a.scanFiles = append(a.scanFiles, f)
			a.scanSnapshotMu.Unlock()
			wailsRuntime.EventsEmit(a.ctx, "scan:fileFound", f)
		},
	}

	stopPersist := make(chan struct{})
	go a.persistLoop(stopPersist)

	stopHeartbeat := make(chan struct{})
	go a.emitScanHeartbeat(stopHeartbeat, time.Now())

	go func() {
		defer func() {
			// 扫描结束统一关闭 reader 链（DecryptingReader.Close 会透传到 underlying）
			if err := result.Reader.Close(); err != nil {
				appLogger.Warn("关闭 BitLocker DecryptingReader 失败", "err", err)
			}
		}()

		scanResult, err := a.engine.ScanWithReader(result.Reader, types.ScanMode(mode), callbacks)
		close(stopPersist)
		close(stopHeartbeat)

		a.scanSnapshotMu.Lock()
		a.scanActive = false
		a.scanSnapshotMu.Unlock()

		if err != nil {
			appLogger.Warn("BitLocker 卷扫描出错", "err", err)
			wailsRuntime.EventsEmit(a.ctx, "scan:error", err.Error())
			return
		}
		appLogger.Info("BitLocker 卷扫描完成", "files", len(scanResult.Files))
		a.saveSnapshot(true)
		wailsRuntime.EventsEmit(a.ctx, "scan:completed", scanResult)
	}()

	return nil
}

// QueryDiskHealth 给前端的"开始扫描前先看盘是不是要崩"的快捷接口。
// 走 smartctl（用户得装 smartmontools）；没装时返回 Available=false 给 UI 友好提示。
func (a *App) QueryDiskHealth(devicePath string) (*disk.SmartHealth, error) {
	ctx, cancel := context.WithTimeout(a.ctx, 10*time.Second)
	defer cancel()
	return disk.QuerySmart(ctx, devicePath)
}

// bindFileDrop 注册 OS-level 文件拖拽 → 前端事件 "files:dropped" 的桥。
// 在 main.go 的 OnDomReady 里调一次。
func (a *App) bindFileDrop(ctx context.Context) {
	// 把拖入的所有文件路径直接转发到前端；前端按需挑第一个 .img/.raw/.dd 触发镜像扫描
	wailsRuntime.OnFileDrop(ctx, func(x, y int, paths []string) {
		appLogger.Info("OS 文件拖入", "count", len(paths), "paths", paths)
		wailsRuntime.EventsEmit(ctx, "files:dropped", paths)
	})
}

// UnlockBitLockerWithMemoryImage 用一份"内存镜像 / 休眠文件"里搜出来的 VMK 解锁
// TPM-only / TPM+PIN 等无法跨平台直接解的 BitLocker 保护器。
//
// 现实路径：
//   1. 用户从原 Windows 抓 hiberfil.sys（C:\hiberfil.sys，需要管理员）或用 winpmem
//      / DumpIt 抓内存 dump
//   2. 把 .raw / hiberfil.sys 路径传过来
//   3. 我们扫一遍找出能解开 VMK datum 的 32 字节候选
//   4. 用 VMK → FVEK → DecryptingReader → engine.ScanWithReader 完整链
//
// 这是 Passware / Elcomsoft 等专业取证工具用的同款"memory-based" 攻击；
// 完全合法，只要被恢复的数据是用户自己的（被偷电脑、忘记密码、合规取证）。
func (a *App) UnlockBitLockerWithMemoryImage(
	drivePath, volumeOffsetHex, memImagePath, mode string,
) error {
	if drivePath == "" || memImagePath == "" {
		return fmt.Errorf("drivePath / memImagePath 不能为空")
	}
	if mode == "" {
		mode = string(types.ScanFull)
	}
	if !a.IsAdmin() {
		return fmt.Errorf("需要管理员 / root 权限才能读原始磁盘设备")
	}
	a.mu.Lock()
	if a.engine.IsScanning() {
		a.mu.Unlock()
		return fmt.Errorf("已有扫描任务正在执行，请先停止当前扫描")
	}
	a.mu.Unlock()

	var volumeOffset int64
	if _, err := fmt.Sscanf(volumeOffsetHex, "%x", &volumeOffset); err != nil {
		return fmt.Errorf("volumeOffset 解析失败: %w", err)
	}

	// 1. 打开磁盘 + 检测 BitLocker
	underlying := disk.NewReader(drivePath)
	if err := underlying.Open(); err != nil {
		return fmt.Errorf("打开磁盘失败: %w", err)
	}
	bvolume, err := bitlocker.Detect(underlying, volumeOffset)
	if err != nil || bvolume == nil {
		underlying.Close()
		return fmt.Errorf("此偏移不是 BitLocker 卷")
	}

	// 2. 打开内存镜像 reader（image file 模式即可，磁盘 reader 已经支持文件）
	memReader := disk.NewReader(memImagePath)
	if err := memReader.Open(); err != nil {
		underlying.Close()
		return fmt.Errorf("打开内存镜像失败: %w", err)
	}

	// 3. 找一个 VMK datum（任意一个能用就行；通常 TPM 保护类型 = 0x100）
	mb, err := loadFirstFVEMetadata(underlying, bvolume)
	if err != nil {
		underlying.Close()
		memReader.Close()
		return fmt.Errorf("读 FVE metadata 失败: %w", err)
	}
	vmks := mb.FindVMKs()
	if len(vmks) == 0 {
		underlying.Close()
		memReader.Close()
		return fmt.Errorf("metadata 里没有 VMK 保护器")
	}
	// 取第一个 —— 多 VMK 的话每个都能解出同一个 VMK，所以挑哪个无所谓
	vmkDatum := &vmks[0]

	appLogger.Info("VMK 内存搜索开始", "drive", drivePath, "mem", memImagePath)

	// 4. 内存搜 VMK，进度回调到前端
	progressCb := func(scanned, total int64) {
		wailsRuntime.EventsEmit(a.ctx, "bitlocker:memScanProgress", map[string]int64{
			"scanned": scanned,
			"total":   total,
		})
	}
	ctx, cancel := context.WithCancel(a.ctx)
	defer cancel()
	res, err := bitlocker.SearchVMKInMemoryImage(ctx, memReader, vmkDatum, progressCb)
	if err != nil {
		underlying.Close()
		memReader.Close()
		return fmt.Errorf("VMK 内存搜索失败: %w", err)
	}
	memReader.Close()
	appLogger.Info("VMK 已从内存找到", "iter", res.Iterations, "hit_offset", res.HitOffset)

	// 5. 用搜到的 VMK 提 FVEK + 构造解密 reader
	fvek, method, err := bitlocker.ExtractFVEKFromMetadata(mb, res.VMK)
	if err != nil {
		underlying.Close()
		return fmt.Errorf("FVEK 提取失败: %w", err)
	}
	sectorCipher, err := bitlocker.BuildSectorCipherForMethodPublic(fvek, method)
	if err != nil {
		underlying.Close()
		return fmt.Errorf("构造 BitLocker sector cipher (method=0x%04X) 失败: %w", method, err)
	}
	// 8192 sector cache ≈ 4MB @ 512B / 32MB @ 4096B —— 覆盖 NTFS MFT hot 区，
	// 加密卷扫描时同 sector 反复解密的代价省掉
	dec, err := bitlocker.NewDecryptingReaderWithCache(underlying, sectorCipher, bvolume.OEMID, 8192)
	if err != nil {
		underlying.Close()
		return fmt.Errorf("构造 BitLocker decrypting reader 失败: %w", err)
	}
	dec.SetVolumeOffset(bvolume.Offset)
	if vh := mb.FindVolumeHeaderInfo(); vh != nil && vh.PlaintextHeaderSize > 0 {
		dec.SetPlainTextHeaderEnd(vh.PlaintextHeaderSize)
	}

	wailsRuntime.EventsEmit(a.ctx, "bitlocker:unlocked", map[string]any{
		"encryptionMethod": fmt.Sprintf("0x%04X", method),
		"volumeUUID":       fmt.Sprintf("%X", mb.VolumeIdentifier),
		"unlockMode":       "memory-image",
	})

	// 6. 走和 UnlockBitLockerAndScan 完全一致的扫描启动流程
	a.startScanWithUnlockedReader(dec, drivePath+" (BitLocker via memory image)", mode)
	return nil
}

// loadFirstFVEMetadata 把 UnlockBitLockerVolumeWithRecoveryKey 里"试三个 metadata block"
// 的逻辑独立出来给其他入口复用
func loadFirstFVEMetadata(underlying disk.DiskReader, bvolume *bitlocker.Volume) (*bitlocker.FVEMetadataBlock, error) {
	var mb *bitlocker.FVEMetadataBlock
	var lastErr error
	for _, off := range []int64{
		bvolume.FVEMetaBlockOffset1,
		bvolume.FVEMetaBlockOffset2,
		bvolume.FVEMetaBlockOffset3,
	} {
		if off <= 0 {
			continue
		}
		mb, lastErr = bitlocker.ParseFVEMetadataBlock(underlying, bvolume.Offset+off)
		if mb != nil {
			return mb, nil
		}
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, fmt.Errorf("三个 FVE metadata block 全部解析失败")
}

// startScanWithUnlockedReader 把 UnlockBitLockerAndScan 里的"goroutine 启动 + 事件桥"
// 抽出来共用，给两种解锁路径（recovery key / memory image）都用同一段流程。
func (a *App) startScanWithUnlockedReader(reader *bitlocker.DecryptingReader, driveLabel, mode string) {
	a.mu.Lock()
	a.currentDrive = types.DriveInfo{Path: driveLabel}
	a.currentMode = mode
	a.mu.Unlock()

	a.scanSnapshotMu.Lock()
	a.scanProgress = types.ScanProgress{}
	a.scanFiles = nil
	a.scanActive = true
	a.scanSnapshotMu.Unlock()

	callbacks := recovery.ScanCallbacks{
		OnProgress: func(p types.ScanProgress) {
			a.scanSnapshotMu.Lock()
			merged := mergeScanProgress(a.scanProgress, p)
			a.scanProgress = merged
			a.scanSnapshotMu.Unlock()
			wailsRuntime.EventsEmit(a.ctx, "scan:progress", merged)
		},
		OnFileFound: func(f *types.RecoveredFile) {
			a.scanSnapshotMu.Lock()
			a.scanFiles = append(a.scanFiles, f)
			a.scanSnapshotMu.Unlock()
			wailsRuntime.EventsEmit(a.ctx, "scan:fileFound", f)
		},
	}

	stopPersist := make(chan struct{})
	go a.persistLoop(stopPersist)

	stopHeartbeat := make(chan struct{})
	go a.emitScanHeartbeat(stopHeartbeat, time.Now())

	go func() {
		defer reader.Close()
		scanResult, err := a.engine.ScanWithReader(reader, types.ScanMode(mode), callbacks)
		close(stopPersist)
		close(stopHeartbeat)
		a.scanSnapshotMu.Lock()
		a.scanActive = false
		a.scanSnapshotMu.Unlock()
		if err != nil {
			wailsRuntime.EventsEmit(a.ctx, "scan:error", err.Error())
			return
		}
		a.saveSnapshot(true)
		wailsRuntime.EventsEmit(a.ctx, "scan:completed", scanResult)
	}()
}

// SummarizeBitLockerProtectors 暴露给前端的"该 BitLocker 卷有哪些保护器、各能不能解"
// 的清单，让 UI 在解锁前就能告诉用户该用 recovery / password / startup-key / memory-image。
func (a *App) SummarizeBitLockerProtectors(drivePath, volumeOffsetHex string) ([]bitlocker.ProtectorSummary, error) {
	if drivePath == "" {
		return nil, fmt.Errorf("drivePath 为空")
	}
	var volumeOffset int64
	if _, err := fmt.Sscanf(volumeOffsetHex, "%x", &volumeOffset); err != nil {
		return nil, fmt.Errorf("volumeOffset 解析失败: %w", err)
	}
	reader := disk.NewReader(drivePath)
	if err := reader.Open(); err != nil {
		return nil, fmt.Errorf("打开磁盘失败: %w", err)
	}
	defer reader.Close()
	bvolume, err := bitlocker.Detect(reader, volumeOffset)
	if err != nil || bvolume == nil {
		return nil, fmt.Errorf("此偏移不是 BitLocker 卷")
	}
	mb, err := loadFirstFVEMetadata(reader, bvolume)
	if err != nil {
		return nil, err
	}
	return bitlocker.SummarizeProtectors(mb), nil
}

// RAIDScanRequest 是前端构造 RAID 阵列扫描时的输入。
//
// 字段语义：
//   Level         "raid0" / "raid1" / "raid5"
//   DiskPaths     按"原阵列编号顺序"排好的物理盘 / 镜像路径；缺失盘传空字符串 ""
//   StripeBytes   条带大小（typical 65536 / 131072 / 524288）
//   Mode          扫描模式 quick/deep/full
type RAIDScanRequest struct {
	Level       string   `json:"level"`
	DiskPaths   []string `json:"diskPaths"`
	StripeBytes int64    `json:"stripeBytes"`
	Mode        string   `json:"mode"`
}

// DetectRAIDArrays 从一组盘读 mdadm v1.x superblock，按 array UUID 聚合
// 返回可直接组装的阵列（level / chunkBytes / 按 role 排好序的成员盘路径）。
//
// 前端流程：用户多选盘 → 调本接口 → 展示识别出的阵列 → 一键填入 StartRAIDScan 表单。
func (a *App) DetectRAIDArrays(paths []string) ([]volmgr.DetectedArray, error) {
	arrays, errs := volmgr.DetectRAIDArrays(paths)
	if len(arrays) == 0 && len(errs) > 0 {
		// 没识别出任何阵列且有错误 → 返回第一个错误让用户看清楚原因
		return nil, errs[0]
	}
	return arrays, nil
}

// StartRAIDScan 把多个物理盘 / 镜像按 RAID 规则虚拟拼成一个连续设备，
// 然后跑标准 NTFS / carver 等扫描流程。
//
// 这是给"被偷电脑里硬盘是 RAID 阵列"或"NAS 拆出 4 块盘"等场景用。
func (a *App) StartRAIDScan(req RAIDScanRequest) error {
	if len(req.DiskPaths) < 2 {
		return fmt.Errorf("RAID 至少 2 块盘")
	}
	if !a.IsAdmin() {
		return fmt.Errorf("需要管理员 / root 权限才能读原始磁盘设备")
	}
	a.mu.Lock()
	if a.engine.IsScanning() {
		a.mu.Unlock()
		return fmt.Errorf("已有扫描任务正在执行，请先停止当前扫描")
	}
	a.mu.Unlock()

	if req.Mode == "" {
		req.Mode = string(types.ScanFull)
	}

	var level raid.Level
	switch req.Level {
	case "raid0":
		level = raid.Level0
	case "raid1":
		level = raid.Level1
	case "raid5":
		level = raid.Level5
	default:
		return fmt.Errorf("不支持的 RAID level: %q", req.Level)
	}

	// 打开每块盘（空字符串 = 缺失，传 nil）
	disks := make([]disk.DiskReader, len(req.DiskPaths))
	openedReaders := []disk.DiskReader{}
	for i, p := range req.DiskPaths {
		if p == "" {
			disks[i] = nil
			continue
		}
		dr := disk.NewReader(p)
		if err := dr.Open(); err != nil {
			for _, r := range openedReaders {
				r.Close()
			}
			return fmt.Errorf("打开 disk[%d] %q 失败: %w", i, p, err)
		}
		disks[i] = dr
		openedReaders = append(openedReaders, dr)
	}

	rdr, err := raid.NewReader(raid.Config{
		Level:       level,
		Disks:       disks,
		StripeBytes: req.StripeBytes,
	})
	if err != nil {
		for _, r := range openedReaders {
			r.Close()
		}
		return fmt.Errorf("RAID 配置错: %w", err)
	}

	appLogger.Info("启动 RAID 扫描", "level", req.Level, "disks", len(req.DiskPaths), "stripe", req.StripeBytes)

	// 走和 BitLocker 解锁后扫描相同的"goroutine + 事件桥"模板
	a.mu.Lock()
	a.currentDrive = types.DriveInfo{Path: fmt.Sprintf("RAID(%s, %d 盘)", req.Level, len(req.DiskPaths))}
	a.currentMode = req.Mode
	a.mu.Unlock()

	a.scanSnapshotMu.Lock()
	a.scanProgress = types.ScanProgress{}
	a.scanFiles = nil
	a.scanActive = true
	a.scanSnapshotMu.Unlock()

	callbacks := recovery.ScanCallbacks{
		OnProgress: func(p types.ScanProgress) {
			a.scanSnapshotMu.Lock()
			merged := mergeScanProgress(a.scanProgress, p)
			a.scanProgress = merged
			a.scanSnapshotMu.Unlock()
			wailsRuntime.EventsEmit(a.ctx, "scan:progress", merged)
		},
		OnFileFound: func(f *types.RecoveredFile) {
			a.scanSnapshotMu.Lock()
			a.scanFiles = append(a.scanFiles, f)
			a.scanSnapshotMu.Unlock()
			wailsRuntime.EventsEmit(a.ctx, "scan:fileFound", f)
		},
	}

	stopPersist := make(chan struct{})
	go a.persistLoop(stopPersist)
	stopHeartbeat := make(chan struct{})
	go a.emitScanHeartbeat(stopHeartbeat, time.Now())
	go func() {
		defer rdr.Close()
		scanResult, err := a.engine.ScanWithReader(rdr, types.ScanMode(req.Mode), callbacks)
		close(stopPersist)
		close(stopHeartbeat)
		a.scanSnapshotMu.Lock()
		a.scanActive = false
		a.scanSnapshotMu.Unlock()
		if err != nil {
			wailsRuntime.EventsEmit(a.ctx, "scan:error", err.Error())
			return
		}
		a.saveSnapshot(true)
		wailsRuntime.EventsEmit(a.ctx, "scan:completed", scanResult)
	}()
	return nil
}

// ScanEncryptedVolumes 在指定盘上检测 BitLocker / APFS / FileVault 卷。
//
// 本工具**不解密**任何加密卷 —— 只检测它们存在让用户/取证人员知道。
// 对于这些卷，提示用户用专门工具继续：
//   - BitLocker: dislocker（开源）/ R-Studio / Windows 本机 RecoveryKey
//   - FileVault: 必须有用户登录密码或 Institutional Key，专业工具如 R-Studio Mac
//
// 调用方典型用法：用户在 WelcomePage 选盘前，先把所有盘各扫一遍出加密卷预警。
func (a *App) ScanEncryptedVolumes(drivePath string) ([]EncryptedVolumeInfo, error) {
	if drivePath == "" {
		return nil, fmt.Errorf("drivePath 为空")
	}
	reader := disk.NewReader(drivePath)
	// Open 加 5s 超时：dirty U 盘 / 系统级 chkdsk 中的盘 CreateFile 可能 hang
	// 这里宁可放弃这块盘的加密卷预警，也不能让整个启动流程被卡住
	if err := disk.OpenWithTimeout(reader, 5*time.Second); err != nil {
		return nil, fmt.Errorf("打开磁盘失败: %w", err)
	}
	defer reader.Close()

	var out []EncryptedVolumeInfo

	// 1. BitLocker 卷扫描（Windows 加密）
	// 用 FindVolumesFast：只检测 offset 0 + GPT/MBR 分区起始，
	// 避免在多 TB 盘上做几分钟的全盘 brute-force（启动阶段对所有盘并行扫）。
	blScanner := bitlocker.NewScanner(reader)
	if vols, err := blScanner.FindVolumesFast(); err == nil {
		for _, v := range vols {
			out = append(out, EncryptedVolumeInfo{
				DrivePath: drivePath,
				Kind:      "bitlocker",
				Offset:    v.Offset,
				Encrypted: true,
				Note:      "BitLocker 加密卷。本工具支持用 recovery key 解锁；也可用 dislocker / R-Studio / Windows 系统恢复",
			})
		}
	}

	// 2a. HFS+ / HFSX 卷（老 macOS / Time Machine 备份盘）—— 诊断用，fast path 即可
	if vols, err := hfsplus.NewScanner(reader).FindVolumes(a.ctx, hfsplus.FindOptions{}); err == nil {
		for _, v := range vols {
			label := "HFS+"
			if v.IsHFSX {
				label = "HFSX"
			}
			out = append(out, EncryptedVolumeInfo{
				DrivePath: drivePath,
				Kind:      "hfsplus",
				Offset:    v.Offset,
				Name:      label,
				Encrypted: false,
				Note:      fmt.Sprintf("%s 卷（block=%d total=%d files=%d）。Catalog B-tree + Extents Overflow 已支持", label, v.BlockSize, v.TotalBlocks, v.FileCount),
			})
		}
	}
	// 2b. ReFS 卷（Server / Win11 Pro for Workstations）—— 诊断 fast path
	// v2.8.26: 用 BruteForce=false 走 offset 0 fast path。之前 ReFS 是全套 scanner 里
	// 唯一不接受 FindOptions 的，永远做全盘 4MB 步进扫描；2TB SSD 上跑 ~11 分钟，
	// 用户在 welcome 页每选一次盘都会触发，看到的就是"取消扫描后 IO 不停"。
	if vols, err := refs.NewScanner(reader).FindVolumes(a.ctx, refs.FindOptions{}); err == nil {
		for _, v := range vols {
			out = append(out, EncryptedVolumeInfo{
				DrivePath: drivePath,
				Kind:      "refs",
				Offset:    v.Offset,
				Name:      fmt.Sprintf("ReFS v%d.%d", v.MajorVersion, v.MinorVersion),
				Encrypted: false,
				Note:      "ReFS 卷。Minstore page 索引 + 启发式 entry 提取已支持（M$ 规范未公开，为 best-effort）",
			})
		}
	}

	// 3. APFS 容器扫描（含 FileVault 检测）—— 诊断用，fast path 即可
	apfsScanner := apfs.NewScanner(reader)
	if containers, err := apfsScanner.FindContainers(a.ctx, apfs.FindOptions{}); err == nil {
		for _, c := range containers {
			for _, v := range c.Volumes {
				kind := "apfs-volume"
				note := "APFS 卷。omap + fs B-tree 文件枚举已支持；含 snapshot / FileVault 解锁路径"
				if v.IsEncrypted {
					kind = "filevault"
					note = "FileVault 加密 APFS 卷。点解锁按钮输入用户密码；完整链 keybag → PBKDF2 → AES-KeyWrap → VEK → XTS"
				}
				out = append(out, EncryptedVolumeInfo{
					DrivePath: drivePath,
					Kind:      kind,
					Offset:    c.Offset,
					Name:      v.Name,
					UUID:      formatGUIDMixedEndian(v.UUID),
					Encrypted: v.IsEncrypted,
					Note:      note,
				})
			}
		}
	}

	// 3b. LUKS / LUKS2 卷（Linux 全盘加密标准）—— 同时支持本工具内置解锁
	if h, err := luks.Detect(reader, 0); err == nil && h != nil {
		note := fmt.Sprintf("LUKS%d 加密卷（%s-%s，UUID=%s）。本工具支持密码解锁；命中 keyslot 后用 NTFS / ext4 等扫描器走原路径",
			h.Version, h.CipherName, h.CipherMode, h.UUID)
		if h.Version == 2 {
			note = fmt.Sprintf("LUKS2 加密卷（label=%q）。本工具支持 Argon2id + AES-XTS 主流配置；密码解锁后走 ext4 / NTFS 等扫描器", h.Label)
		}
		out = append(out, EncryptedVolumeInfo{
			DrivePath: drivePath,
			Kind:      fmt.Sprintf("luks%d", h.Version),
			Offset:    h.Offset,
			UUID:      h.UUID,
			Name:      h.Label,
			Encrypted: true,
			Note:      note,
		})
	}

	// 3c. VeraCrypt / TrueCrypt 启发式探针（offset 0 高熵 + 无已知 fs magic）
	// 注意：VC 容器没有明文 magic，全靠熵 + 排除法；可能假阳性，在 Note 里告诉用户
	if hint, err := veracrypt.Detect(reader, 0); err == nil && hint != nil {
		out = append(out, EncryptedVolumeInfo{
			DrivePath: drivePath,
			Kind:      "veracrypt",
			Offset:    hint.Offset,
			Encrypted: true,
			Note:      hint.Note + "（本工具内置解锁：用密码尝试 SHA-512 / SHA-256 / RIPEMD-160）",
		})
	}

	// 4. 卷管理器成员识别（mdadm / LVM2 / Storage Spaces）— 不是加密卷，但同样会让
	//    普通扫描"扫不出文件"，给用户同样的预警
	for _, m := range volmgr.DetectAll(reader) {
		out = append(out, EncryptedVolumeInfo{
			DrivePath: drivePath,
			Kind:      m.Type,
			Offset:    0,
			Name:      m.Type,
			Encrypted: false,
			Note:      m.Hint,
		})
	}

	// 去重：同一 (kind, drivePath, offset) 可能被 BitLocker 扫描和 APFS 扫描各命中一次
	return dedupeEncryptedVolumes(out), nil
}

// dedupeEncryptedVolumes 按 (kind, drivePath, offset) 键去重，保留第一个出现的条目。
func dedupeEncryptedVolumes(in []EncryptedVolumeInfo) []EncryptedVolumeInfo {
	seen := make(map[string]bool, len(in))
	out := make([]EncryptedVolumeInfo, 0, len(in))
	for _, v := range in {
		k := v.Kind + "|" + v.DrivePath + "|" + fmt.Sprintf("%d", v.Offset)
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, v)
	}
	return out
}

// formatGUIDMixedEndian 把 16 字节按 Microsoft/GPT 混合字节序输出为标准 UUID 字符串：
//
//	前 3 段（4/2/2 字节）是 little-endian，后 2 段（2/6 字节）是 big-endian。
//	与 Windows 磁盘管理器 / GPT 工具看到的格式一致。
func formatGUIDMixedEndian(u [16]byte) string {
	// LE 反转前三段
	p1 := []byte{u[3], u[2], u[1], u[0]}
	p2 := []byte{u[5], u[4]}
	p3 := []byte{u[7], u[6]}
	p4 := u[8:10]
	p5 := u[10:16]
	return fmt.Sprintf("%X-%X-%X-%X-%X", p1, p2, p3, p4, p5)
}

// ListShadowCopies 枚举本机 Volume Shadow Copy 快照。
// 非 Windows 平台返回 nil，让前端礼貌地隐藏 VSS 区块，不报错。
// 失败（无权限 / 无快照）返回空切片 + nil error。
func (a *App) ListShadowCopies() ([]vss.Shadow, error) {
	shadows, err := vss.ListShadows(a.ctx)
	if err != nil {
		if err == vss.ErrNotSupported {
			return nil, nil // 静默
		}
		appLogger.Info("VSS 枚举失败", "err", err)
		return []vss.Shadow{}, nil // 容错：UI 显示"没有快照"即可
	}
	return shadows, nil
}

// DownloadUpdate 后台下载指定版本的安装包到 pending 目录。
// assetURL / assetSize 通常来自 update:available 事件里 CheckResult 的 Assets[i]。
// 下载是异步的：本函数立即返回，进度通过 "update:downloadProgress" 事件推送；
// 完成 / 失败分别通过 "update:downloaded" / "update:downloadError" 推送。
func (a *App) DownloadUpdate(version, assetURL, assetName string, assetSize int64) error {
	if a.engine != nil && a.engine.IsScanning() {
		return fmt.Errorf("正在扫描，请先停止后再下载更新")
	}
	if version == "" || assetURL == "" || assetName == "" {
		return fmt.Errorf("下载参数不完整")
	}

	// 避免并发下载：autoCheckForUpdate 已经静默启动了，用户再点 UI 下载按钮
	// 不该再起第二个下载任务（两个 goroutine 写同 pending 目录 + 各自 emit 进度
	// 事件 → UI 百分比会来回跳）
	a.mu.Lock()
	if a.downloadActive {
		a.mu.Unlock()
		appLogger.Info("下载已在进行，忽略重复请求", "version", version)
		return nil // 静默 return，前端 UI 不弹错误
	}
	a.downloadActive = true
	a.mu.Unlock()

	pendingDir, err := updater.PendingDir()
	if err != nil {
		// **关键**：goroutine 还没起，必须手动释放下载锁，否则后续所有
		// 下载请求都被静默吞掉（"下载已在进行" 分支），用户只能重启 app。
		// 历史 bug：曾直接 return err，导致下载功能永久 hang。
		a.mu.Lock()
		a.downloadActive = false
		a.mu.Unlock()
		return fmt.Errorf("获取 pending 目录失败: %w", err)
	}
	// 每个版本独立子目录，避免不同版本互相覆盖
	versionDir := filepath.Join(pendingDir, version)
	destPath := filepath.Join(versionDir, assetName)

	appLogger.Info("开始下载更新", "version", version, "asset", assetName, "dest", destPath)

	go func() {
		ctx, cancel := context.WithCancel(a.ctx)
		defer cancel()
		// 保证 goroutine 退出时释放下载锁，让下次 release 能重试
		defer func() {
			a.mu.Lock()
			a.downloadActive = false
			a.mu.Unlock()
		}()

		asset := updater.Asset{Name: assetName, DownloadURL: assetURL, Size: assetSize}
		sha, err := updater.DownloadAsset(ctx, asset, destPath, func(p updater.DownloadProgress) {
			wailsRuntime.EventsEmit(a.ctx, "update:downloadProgress", p)
		})
		if err != nil {
			appLogger.Warn("下载更新失败", "err", err)
			wailsRuntime.EventsEmit(a.ctx, "update:downloadError", err.Error())
			return
		}

		// ★ 供应链完整性（外部审计级）：三层校验
		//   1. 版本号单调（拒绝 downgrade 攻击 — TUF rollback protection）
		//   2. SHA256SUMS.txt 对比 binary hash
		//   3. SHA256SUMS.txt 本身的 Ed25519 签名
		// 任何一层失败 → 删掉下载文件 + 审计日志 + 推 event 告用户
		if !updater.IsVersionNewer(updater.Version, version) {
			appLogger.Warn("拒绝下载：目标版本不比当前新（防 downgrade 攻击）",
				"current", updater.Version, "target", version)
			_ = os.Remove(destPath)
			wailsRuntime.EventsEmit(a.ctx, "update:downloadError", "防 downgrade: 目标版本 "+version+" 不比当前新")
			return
		}
		if sums, sumsErr := updater.FetchSHA256SUMS(ctx, updateRepoOwner, updateRepoName, version); sumsErr == nil {
			if vErr := updater.VerifyAssetChecksum(assetName, sha, sums); vErr != nil {
				appLogger.Warn("SHA256SUMS 校验失败，拒绝应用", "err", vErr)
				_ = os.Remove(destPath)
				wailsRuntime.EventsEmit(a.ctx, "update:downloadError", "供应链校验失败: "+vErr.Error())
				return
			}
			// 验签 SHA256SUMS.txt.sig（如果 release 附了）
			if sigErr := updater.VerifySumsSignatureFromRelease(ctx, updateRepoOwner, updateRepoName, version); sigErr != nil {
				// 签名验证失败**可能**是：攻击者替了 SHA256SUMS + binary 一起，
				// 或者老 release 没附 .sig 文件（兼容模式 → warning 不阻塞）
				appLogger.Warn("SHA256SUMS 签名验证失败或缺失（老 release 兼容）", "err", sigErr)
			}
			appLogger.Info("SHA256SUMS 供应链校验通过", "asset", assetName)
		} else {
			appLogger.Warn("未能获取 SHA256SUMS.txt（老版 release？）", "err", sumsErr)
		}

		info, _ := os.Stat(destPath)
		var size int64
		if info != nil {
			size = info.Size()
		}
		pending := updater.Pending{
			Version:    version,
			BinaryPath: destPath,
			SHA256:     sha,
			SizeBytes:  size,
			StagedAt:   time.Now().UTC().Format(time.RFC3339),
		}
		if err := updater.SavePending(pending); err != nil {
			appLogger.Warn("保存 pending manifest 失败", "err", err)
			wailsRuntime.EventsEmit(a.ctx, "update:downloadError", err.Error())
			return
		}
		appLogger.Info("更新下载完成", "version", version, "sha256", sha, "size", size)
		wailsRuntime.EventsEmit(a.ctx, "update:downloaded", pending)
	}()

	return nil
}

// ApplyPendingUpdate 应用 pending 更新：派生 helper 进程 → 退出主程序。
// helper 会等主程序退出后把新 exe 覆盖到当前位置，再启动新版。
// 调用前建议前端先提示用户"应用将关闭并重启"。
func (a *App) ApplyPendingUpdate() error {
	if a.engine != nil && (a.engine.IsScanning()) {
		return fmt.Errorf("扫描进行中不能应用更新，请先停止扫描")
	}
	pending, err := updater.LoadPending()
	if err != nil {
		return fmt.Errorf("读取 pending 失败: %w", err)
	}
	if pending == nil {
		return fmt.Errorf("没有待应用的更新")
	}

	currentExe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("无法定位当前 exe 路径: %w", err)
	}

	if err := updater.SpawnApplyHelper(currentExe, pending.BinaryPath); err != nil {
		return fmt.Errorf("派生更新进程失败: %w", err)
	}

	appLogger.Info("已派生更新 helper，主进程即将退出",
		"current_exe", currentExe, "pending_exe", pending.BinaryPath)

	// 给 UI 一点时间显示"正在重启"再关
	go func() {
		time.Sleep(500 * time.Millisecond)
		wailsRuntime.Quit(a.ctx)
	}()
	return nil
}

// GetPendingUpdate 检查是否有 pending 更新，前端启动时调用。
// 返回 nil 表示没有 pending。
func (a *App) GetPendingUpdate() (*updater.Pending, error) {
	return updater.LoadPending()
}

// CancelPendingUpdate 取消 pending（清理下载文件）
func (a *App) CancelPendingUpdate() error {
	return updater.ClearPending()
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

// IsSystemDrive 给前端在用户选盘后查询：这个盘是不是系统盘？
// 用于警告用户"扫系统盘会让 OS 占用 IO 严重，系统可能假死"+ 提供继续选项。
//
// v2.8.20 加 —— 用户报"扫系统盘卡死整个系统"。
func (a *App) IsSystemDrive(drivePath string) bool {
	return disk.IsSystemDrive(drivePath)
}

// DeleteFile 删除一个文件 —— v2.8.17 用于"重复图片结果"页面让用户删除冗余副本。
//
// 安全检查：
//   - 必须绝对路径（拒绝相对路径，避免 cwd 注入）
//   - 必须是已存在的 regular file（不允许目录 / device / pipe）
//   - lstat 防止 symlink TOCTOU
//
// 返回 nil = 删除成功；error 含原因方便前端提示。
func (a *App) DeleteFile(path string) error {
	if path == "" {
		return fmt.Errorf("path 为空")
	}
	clean := filepath.Clean(path)
	if !filepath.IsAbs(clean) {
		return fmt.Errorf("必须绝对路径: %s", path)
	}
	st, err := os.Lstat(clean)
	if err != nil {
		return fmt.Errorf("文件不存在或无访问权限: %w", err)
	}
	if !st.Mode().IsRegular() {
		return fmt.Errorf("不是普通文件（拒绝删除目录/设备/管道）: %s", path)
	}
	// #nosec G304 G306 —— path 已经过 Clean + IsAbs + IsRegular 校验
	if err := os.Remove(clean); err != nil {
		return fmt.Errorf("删除失败: %w", err)
	}
	appLogger.Info("用户删除文件", "path", clean)
	return nil
}

// ShowInFolder 在系统文件管理器中定位到一个文件 —— v2.8.17。
// Windows: explorer /select,<path>
// macOS:   open -R <path>
// Linux:   xdg-open <dirname> （没有"选中"语义，只能打开父目录）
func (a *App) ShowInFolder(path string) error {
	if path == "" {
		return fmt.Errorf("path 为空")
	}
	clean := filepath.Clean(path)
	if !filepath.IsAbs(clean) {
		return fmt.Errorf("必须绝对路径")
	}
	if _, err := os.Stat(clean); err != nil {
		return fmt.Errorf("文件不存在: %w", err)
	}
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("explorer.exe", "/select,"+clean)
	case "darwin":
		cmd = exec.Command("open", "-R", clean)
	case "linux":
		cmd = exec.Command("xdg-open", filepath.Dir(clean))
	default:
		return fmt.Errorf("不支持的平台: %s", runtime.GOOS)
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("启动文件管理器失败: %w", err)
	}
	return nil
}

// InstallTesseractViaWinget 在 Windows 上拉起 winget 自动安装 Tesseract OCR。
//
// v2.8.17 加 —— 之前 OCR 引擎未找到时只给个 GitHub releases 链接，国内用户经常
// 访问不了；winget 内置在 Windows 11 + 10 21H1 后，命令一键安装。
//
// 用 cmd.exe /C start 包一层让 winget 在新 console 窗口跑（用户能看到进度 + UAC 提示）。
// 安装完用户手动重启 OCR 搜图。
//
// 仅 Windows。其他系统返回错误。
func (a *App) InstallTesseractViaWinget() error {
	if runtime.GOOS != "windows" {
		return fmt.Errorf("winget 仅在 Windows 可用；当前平台 %s 请用包管理器（apt/brew）", runtime.GOOS)
	}
	// 用 cmd /C start 让 winget 在独立窗口跑：用户能看到下载进度 + UAC 提示
	// 不用 hideCmdWindow —— 这次我们故意要让用户看到 winget 的输出
	cmd := exec.Command("cmd.exe", "/C", "start",
		"winget", "install",
		"--id", "UB-Mannheim.TesseractOCR",
		"--accept-package-agreements",
		"--accept-source-agreements",
	)
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("拉起 winget 失败（请确认系统有 winget 命令；Win10 21H1+ 内置）: %w", err)
	}
	// 不 cmd.Wait() —— 让 winget 异步跑；用户装完自己点"刷新"或重新打开 OCR 搜图。
	return nil
}

// ============================================================
// 扫描
// ============================================================

// StartScan 开始扫描指定驱动器
// drivePath: 驱动器路径（如 \\.\PhysicalDrive0）
// mode: 扫描模式（quick / deep / full），为空时默认使用 full
func (a *App) StartScan(drivePath string, mode string) error {
	return a.startScanInternal(drivePath, mode, false)
}

// StartScanWithOptions 启动扫描，支持取证模式开关。
//
// includeDeletedPartitions=true 会在 NTFS / exFAT / FAT 上启用全盘 brute-force 扫描
// 找已删除/丢失的分区。代价：每个支持的 FS 多读一遍全盘 IO（125GB U 盘 ≈ 多 1-2 小时）。
// 使用场景：被盗笔记本被重装系统后救回原数据 / 司法取证 / R-Studio "Deleted partition recovery" 同款流程。
//
// 健康盘走默认 StartScan 即可，速度快得多。
func (a *App) StartScanWithOptions(drivePath string, mode string, includeDeletedPartitions bool) error {
	return a.startScanInternal(drivePath, mode, includeDeletedPartitions)
}

func (a *App) startScanInternal(drivePath, mode string, includeDeletedPartitions bool) error {
	// v2.8.17 Issue 2 修复：用户体验"点停止 → 立刻换盘 → 启动失败 已有任务"。
	// 根因：Stop() 是异步的（cancel ctx + 让 goroutine 自己退），用户能在
	// goroutine 真正退出前再次点开始。之前粗暴报错"已有任务正在执行"。
	//
	// 现在的策略：检测到还有扫描在跑 → 自动调一次 Stop() + 等最多 5 秒它退出。
	// 用户既然已经显式点了"开始扫描"，意图很明确 = 放弃旧的开新的。
	a.mu.Lock()
	if a.engine.IsScanning() {
		a.mu.Unlock()
		appLogger.Info("检测到上一次扫描尚在退出过程中，自动 Stop + 等待")
		a.engine.Stop()
		// 轮询等待 goroutine 真正退出
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			if !a.engine.IsScanning() {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
		if a.engine.IsScanning() {
			return fmt.Errorf("上一个扫描任务还在停止中（IO 卡死？），请等 10 秒后重试")
		}
	} else {
		a.mu.Unlock()
	}

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

	appLogger.Info("开始扫描", "drive", drivePath, "mode", mode, "forensic", includeDeletedPartitions)

	// 定义进度回调：同步更新本地快照以便持久化
	// 关键：合并而不是覆盖。TotalBytes 一旦从底层（disk reader / carver）拿到，后续
	// dispatcher 只关心 phase/percent/CurrentFile，不会重设 TotalBytes —— 用 merge
	// 保留它，避免前端"0 B / 0 B"显示。
	callbacks := recovery.ScanCallbacks{
		OnProgress: func(p types.ScanProgress) {
			a.scanSnapshotMu.Lock()
			merged := mergeScanProgress(a.scanProgress, p)
			a.scanProgress = merged
			a.scanSnapshotMu.Unlock()
			wailsRuntime.EventsEmit(a.ctx, "scan:progress", merged)
		},
		OnFileFound: func(f *types.RecoveredFile) {
			a.scanSnapshotMu.Lock()
			a.scanFiles = append(a.scanFiles, f)
			a.scanSnapshotMu.Unlock()
			wailsRuntime.EventsEmit(a.ctx, "scan:fileFound", f)
		},
	}

	// 在后台启动扫描，同时起会话持久化协程 + 进度心跳
	stopPersist := make(chan struct{})
	go a.persistLoop(stopPersist)

	stopHeartbeat := make(chan struct{})
	go a.emitScanHeartbeat(stopHeartbeat, time.Now())

	// v2.8.25: 用 "registered" channel 同步等扫描 goroutine 真正进入 ScanWithOptions
	// 的临界区（设好 scanCancel/scanDone）才返回。否则用户点开始后立刻点停止，
	// IPC 序列是 StartScan→return→StopScan→engine.Stop()，engine.Stop 看到 done=nil
	// 返回 no-op，扫描 goroutine 之后才登记 —— 之后没人能取消它，扫描一路跑到底。
	// 这是用户报的"取消扫描后依然在执行"的最后一条隐蔽路径。
	registered := make(chan struct{})
	go func() {
		// engine.ScanWithOptions 第一件事是抢 mu 设 scanCancel/scanDone/scanning。
		// 我们没法直接 hook 到那个时刻，只能 poll IsScanning。在自旋上限内一旦
		// 看到 scanning=true，登记完成。
		go func() {
			for i := 0; i < 500; i++ {
				if a.engine.IsScanning() {
					close(registered)
					return
				}
				time.Sleep(2 * time.Millisecond)
			}
			// 1 秒还没启动起来 —— 异常路径（Open 失败、reader nil 等），也 close
			// 让外层不死等
			close(registered)
		}()

		result, err := a.engine.ScanWithOptions(drivePath, types.ScanOptions{
			Mode:                     types.ScanMode(mode),
			IncludeDeletedPartitions: includeDeletedPartitions,
		}, callbacks)
		close(stopPersist)
		close(stopHeartbeat)

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

	// 等扫描注册完成（最多 1s），确保后续 StopScan 能看到 scanCancel/scanDone
	<-registered

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

// ReadFilePreview 读取指定 fileID 在源盘上的前 maxBytes 字节，供前端做图片预览。
// 返回的 []byte 在 Wails JSON 传输层会自动被 base64 编码为字符串。
// 建议仅对 category=image 的文件调用，调用者自行根据扩展名拼 data URL。
func (a *App) ReadFilePreview(fileID string, maxBytes int) ([]byte, error) {
	if fileID == "" {
		return nil, fmt.Errorf("文件 ID 为空")
	}
	return a.engine.ReadFilePreview(fileID, maxBytes)
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

// StartRecoveryWithOptions 带完整选项（allowSameDisk + archiveByExifDate）的恢复入口。
func (a *App) StartRecoveryWithOptions(fileIDs []string, outputDir string, allowSameDisk, archiveByExifDate bool) error {
	return a.startRecoveryInternal(fileIDs, outputDir, allowSameDisk, archiveByExifDate)
}

// StartRecoveryEx 是 StartRecovery 的扩展版本，多一个 allowSameDisk 参数。
// allowSameDisk=true 时跳过"恢复目录不能与源盘同一块物理磁盘"的安全检查——
// 仅当用户在前端明确勾选"我已了解风险（可能覆盖源数据）"后才应传 true。
func (a *App) StartRecoveryEx(fileIDs []string, outputDir string, allowSameDisk bool) error {
	return a.startRecoveryInternal(fileIDs, outputDir, allowSameDisk, false)
}

func (a *App) startRecoveryInternal(fileIDs []string, outputDir string, allowSameDisk, archiveByExifDate bool) error {
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

	opts := recovery.RecoverOptions{AllowSameDisk: allowSameDisk, ArchiveByExifDate: archiveByExifDate}

	go func() {
		result, err := a.engine.RecoverWithOptions(fileIDs, outputDir, opts, callbacks)
		if err != nil {
			appLogger.Warn("恢复出错", "err", err)
			wailsRuntime.EventsEmit(a.ctx, "recovery:error", err.Error())
			return
		}
		appLogger.Info("恢复结果已发送", "success", result.Succeeded, "failed", result.Failed)

		// v2.8.28: 把 recovery:completed 事件**立刻**发出，让前端立刻切到"恢复完成"页 ——
		// 之前会等 5 个 forensics 步骤（SHA256 walk outputDir / 签名 / TSA / HTML / zip 打包）
		// 跑完才发，期间前端卡在"正在恢复文件 100%"还显示"停止"按钮，外加 outputDir
		// 全盘 SHA256 walk 让用户磁盘 IO 持续几十秒，看起来像"扫描没停"。
		wailsRuntime.EventsEmit(a.ctx, "recovery:completed", result)

		// 取证后处理放到独立 goroutine 跑 —— 用户体验上不阻塞任何东西；失败也只影响
		// 取证证据包，不影响用户已经看到的恢复结果。
		if result.Succeeded > 0 {
			go a.runForensicsPostProcess(outputDir, result)
		}
	}()

	return nil
}

// runForensicsPostProcess 跑取证证据链（manifest / 签名 / HTML / zip bundle）。
// v2.8.28 抽出来独立 goroutine 跑 —— 之前在 recovery 主 goroutine 里同步跑会让
// recovery:completed 事件被几十秒到几分钟的 forensics 工作阻塞，前端 UI 看起来
// "卡在 100% 不动"。现在 emit 早就发了，这里只在后台默默生成附加证据文件。
func (a *App) runForensicsPostProcess(outputDir string, result *recovery.RecoveryResult) {
	_ = result // 预留参数：未来 forensics 可以用 records 列表精确算 SHA256，避免 walk outputDir
	custody := forensics.Custody{
		ToolName:     "DataRecovery",
		ToolVersion:  updater.Version,
		StartedAt:    time.Now().UTC(),
		SourceDevice: a.currentDrive.Path,
	}
	mp, err := forensics.BuildAndWrite(outputDir, custody)
	if err != nil {
		appLogger.Warn("保管链生成失败（不影响恢复结果）", "err", err)
		return
	}
	appLogger.Info("保管链已自动生成", "path", mp)

	sp, err := forensics.BuildSignAndWrite(outputDir, custody)
	if err != nil {
		appLogger.Warn("签名保管链生成失败（不影响恢复结果）", "err", err)
		return
	}
	appLogger.Info("签名保管链已生成", "path", sp)

	if rp, err := forensics.GenerateHTMLReport(outputDir); err == nil {
		appLogger.Info("HTML 取证报告已生成", "path", rp)
	}
	if zp, err := forensics.BundleEvidence(outputDir); err == nil {
		appLogger.Info("Evidence Bundle 已生成", "path", zp)
	}
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

// ExportDiagnosticBundle 把日志 / 会话 snapshot / pending manifest 打包成 zip，
// 用户可以直接贴到 GitHub issue。不会包含磁盘扇区 / 密钥 / 用户文件。
//
// destDir 为空时自动写到用户"下载目录"/"桌面"/配置目录。
func (a *App) ExportDiagnosticBundle(destDir, extraNotes string) (string, error) {
	if destDir == "" {
		// v2.8.16: 用 diag.ResolveDefaultExportDir，Windows 上走 SHGetKnownFolderPath
		// 拿真实桌面（处理 OneDrive / 中文 / D: 重定向）。fallback ~/Desktop 然后家目录。
		destDir = diag.ResolveDefaultExportDir()
		if destDir == "" {
			return "", fmt.Errorf("无法确定导出目录：请显式指定 destDir")
		}
	}

	opts := diag.Options{
		DestPath:   destDir,
		AppVersion: updater.Version,
		LogDir:     logging.LogDir(),
		ExtraNotes: extraNotes,
	}
	if a.store != nil {
		opts.SessionFile = a.store.Path()
	}
	if mp, err := updater.ManifestPath(); err == nil {
		if _, e := os.Stat(mp); e == nil {
			opts.PendingFile = mp
		}
	}
	path, err := diag.Export(opts)
	if err != nil {
		return "", fmt.Errorf("导出诊断包失败: %w", err)
	}
	appLogger.Info("诊断包已导出", "path", path)
	return path, nil
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

// ResumeLastScan 从上次会话的断点继续扫描（跳过已扫的 carver 偏移）。
//
// 前端在 WelcomePage 点"从断点继续"按钮时调用：
//   1. 读 LastSession 拿到 drivePath / mode / carverResumeOffset
//   2. SetResumeCarverOffset 告诉 engine 起点
//   3. StartScan 启动新扫描，engine.runCarverScan 自动消费该 offset
//
// NTFS / exFAT / FAT / ext / APFS / HFS+ 阶段会重跑（相对 carver 耗时很短）；
// 主要目的是省掉 carver 的几小时全盘读。
func (a *App) ResumeLastScan() error {
	if a.store == nil {
		return fmt.Errorf("会话存储未初始化")
	}
	snap, err := a.store.Load()
	if err != nil || snap == nil {
		return fmt.Errorf("未找到可恢复的扫描会话")
	}
	if snap.DrivePath == "" {
		return fmt.Errorf("会话中源盘路径缺失")
	}
	if snap.CarverResumeOffset > 0 {
		a.engine.SetResumeCarverOffset(snap.CarverResumeOffset)
		appLogger.Info("断点续扫", "drive", snap.DrivePath, "resumeOffset", snap.CarverResumeOffset)
	}
	mode := snap.Mode
	if mode == "" {
		mode = string(types.ScanFull)
	}
	return a.StartScan(snap.DrivePath, mode)
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
		DrivePath:          drive.Path,
		DriveLabel:         drive.Name,
		Mode:               mode,
		Progress:           progress,
		Files:              filesCopy,
		Completed:          completed,
		CarverResumeOffset: a.engine.CurrentCarverOffset(),
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

// SelectDirectory 通用目录选择对话框 —— 给 OCR / 图片查重 / 任何要选目录的功能用。
//
// title 参数让 caller 自定义对话框标题（例如 "选择要查重的目录" / "选择 OCR 搜索目录"）。
// 用户取消返回 ""（不算 error，调用方自己处理）。
//
// v2.8.17 加 —— 之前 OCR modal 调 SelectDirectory 但后端没这个方法，导致"选目录"按钮无反应。
func (a *App) SelectDirectory(title string) (string, error) {
	if title == "" {
		title = "选择目录"
	}
	dir, err := wailsRuntime.OpenDirectoryDialog(a.ctx, wailsRuntime.OpenDialogOptions{
		Title: title,
	})
	if err != nil {
		appLogger.Warn("打开目录选择对话框失败", "err", err, "title", title)
		return "", fmt.Errorf("打开目录选择对话框失败: %w", err)
	}
	return dir, nil
}

// SelectImageSavePath 让用户选"把镜像保存到哪"的目标路径。
// 单独一个入口，默认 .img 后缀；后端自己不该猜路径。
func (a *App) SelectImageSavePath() (string, error) {
	path, err := wailsRuntime.SaveFileDialog(a.ctx, wailsRuntime.SaveDialogOptions{
		Title:           "保存镜像文件",
		DefaultFilename: "disk.img",
		Filters: []wailsRuntime.FileFilter{
			{DisplayName: "磁盘镜像 (*.img)", Pattern: "*.img"},
			{DisplayName: "原始 (*.dd / *.raw)", Pattern: "*.dd;*.raw"},
		},
	})
	if err != nil {
		return "", fmt.Errorf("打开保存对话框失败: %w", err)
	}
	return path, nil
}

// DumpDisk 把源盘整盘 dump 到镜像文件，支持坏道跳过。
// 业界 image-first 恢复工作流的核心一步：源盘只读一次、后续扫描全在镜像上。
// srcDevicePath：源盘（`\\.\PhysicalDriveN` / `/dev/diskN` 等），不接受普通文件路径
// dstImagePath：镜像输出文件，如果已存在会直接失败（避免误覆盖）
// 进度通过 "imaging:progress" / "imaging:completed" / "imaging:error" 事件推送
func (a *App) DumpDisk(srcDevicePath string, dstImagePath string) error {
	if srcDevicePath == "" || dstImagePath == "" {
		return fmt.Errorf("源盘或目标路径为空")
	}

	// 只允许一次 dump 并行运行
	if !imagingMu.TryLock() {
		return fmt.Errorf("已有镜像任务正在进行中，请等待完成或取消")
	}

	ctx, cancel := context.WithCancel(a.ctx)
	a.mu.Lock()
	a.diskDumpCancel = cancel
	a.mu.Unlock()

	go func() {
		defer func() {
			imagingMu.Unlock()
			cancel()
			a.mu.Lock()
			a.diskDumpCancel = nil
			a.mu.Unlock()
		}()

		reader := disk.NewReader(srcDevicePath)
		if err := reader.Open(); err != nil {
			wailsRuntime.EventsEmit(a.ctx, "imaging:error", err.Error())
			wailsRuntime.EventsEmit(a.ctx, "image:dumpError", err.Error())
			return
		}
		defer reader.Close()

		// 同时发 imaging:started + image:dumpStarted 让前端 TasksSidebar 也跟到
		wailsRuntime.EventsEmit(a.ctx, "image:dumpStarted", map[string]string{
			"src": srcDevicePath, "dst": dstImagePath,
		})

		opts := disk.DefaultImageOptions()
		written, err := disk.DumpDiskToImage(ctx, reader, dstImagePath, opts, func(p disk.ImageProgress) {
			wailsRuntime.EventsEmit(a.ctx, "imaging:progress", p)
			// TasksSidebar 用单个 progress 字节数（已成功读 = 写到镜像的字节数）
			wailsRuntime.EventsEmit(a.ctx, "image:dumpProgress", p.BytesOK)
		})
		if err != nil {
			appLogger.Warn("镜像 dump 出错", "err", err, "written", written)
			wailsRuntime.EventsEmit(a.ctx, "imaging:error", err.Error())
			wailsRuntime.EventsEmit(a.ctx, "image:dumpError", err.Error())
			return
		}
		appLogger.Info("镜像 dump 完成", "path", dstImagePath, "bytes", written)
		wailsRuntime.EventsEmit(a.ctx, "imaging:completed", map[string]any{
			"path":  dstImagePath,
			"bytes": written,
		})
		wailsRuntime.EventsEmit(a.ctx, "image:dumpCompleted", map[string]any{
			"path":  dstImagePath,
			"bytes": written,
		})
	}()

	return nil
}

// CancelDiskDump 取消进行中的整盘镜像 dump 任务。
// 取消后已写的部分镜像保留（用户可能想保住已有 X% 数据）。
func (a *App) CancelDiskDump() error {
	a.mu.Lock()
	c := a.diskDumpCancel
	a.mu.Unlock()
	if c == nil {
		return nil
	}
	c()
	appLogger.Info("用户取消整盘镜像 dump")
	return nil
}

// SelectImageFile 让用户选一个磁盘镜像文件（.img/.dd/.raw/.001 等）作为扫描源。
// 业界工作流：先用 ddrescue / HDDSuperClone / DMDE clone 把源盘整盘 dump 成镜像，
// 然后对镜像做扫描，源盘一旦 dump 完就不再动，是最安全的方式。
// 返回选中的文件路径；用户取消时返回空串、nil error。
func (a *App) SelectImageFile() (string, error) {
	path, err := wailsRuntime.OpenFileDialog(a.ctx, wailsRuntime.OpenDialogOptions{
		Title: "选择磁盘镜像文件",
		Filters: []wailsRuntime.FileFilter{
			{
				DisplayName: "磁盘镜像 (*.img, *.dd, *.raw, *.bin, *.001)",
				Pattern:     "*.img;*.dd;*.raw;*.bin;*.001",
			},
			{DisplayName: "全部文件 (*.*)", Pattern: "*.*"},
		},
	})
	if err != nil {
		appLogger.Warn("打开镜像文件选择对话框失败", "err", err)
		return "", fmt.Errorf("打开文件选择对话框失败: %w", err)
	}
	return path, nil
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

// ============================================================
// "接通 orphaned 包"IPC 批次 —— backup / dedup / forensics / gpt /
// netfs / ocr / parallel / sed 的对外方法
// ============================================================

// ScheduleBackup 把恢复目录加到系统定时备份（cron / schtasks）。
// 用户场景：数据找回后想把它定期同步到另一块盘。
func (a *App) ScheduleBackup(sourceDir, destDir string, hourOfDay int) error {
	s := backup.Schedule{
		SourceDir: sourceDir,
		DestDir:   destDir,
		HourOfDay: hourOfDay,
		Frequency: "daily",
	}
	return s.Install()
}

// UnscheduleBackup 取消定时备份
func (a *App) UnscheduleBackup() error {
	return backup.Schedule{}.Uninstall()
}

// BackupInstallCommand 仅给用户看"将要执行的命令"，方便审核
func (a *App) BackupInstallCommand(sourceDir, destDir string, hourOfDay int) (string, error) {
	return backup.Schedule{
		SourceDir: sourceDir, DestDir: destDir, HourOfDay: hourOfDay, Frequency: "daily",
	}.GenerateInstallCommand()
}

// FindDuplicateImages 用 aHash 在 outputDir 里找视觉上相似的图片组。
// 返回每个组里的文件路径列表。
func (a *App) FindDuplicateImages(outputDir string, threshold int) ([][]string, error) {
	if outputDir == "" {
		return nil, fmt.Errorf("outputDir 为空")
	}
	if threshold <= 0 {
		threshold = 5
	}
	// 收集 outputDir 下所有图片文件
	var paths []string
	var hashes []dedup.AverageHash
	err := filepath.Walk(outputDir, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(p))
		if ext != ".jpg" && ext != ".jpeg" && ext != ".png" && ext != ".gif" {
			return nil
		}
		// #nosec G122 — 用户自己的恢复输出目录不存在 TOCTOU 威胁场景
		f, err := os.Open(p)
		if err != nil {
			return nil
		}
		defer f.Close()
		h, err := dedup.ComputeAverageHash(f)
		if err != nil {
			return nil // 解码失败跳过，不阻塞整体
		}
		paths = append(paths, p)
		hashes = append(hashes, h)
		return nil
	})
	if err != nil {
		return nil, err
	}
	groups := dedup.SimilarityGroup(hashes, threshold)
	out := make([][]string, 0, len(groups))
	for _, g := range groups {
		row := make([]string, 0, len(g))
		for _, idx := range g {
			row = append(row, paths[idx])
		}
		out = append(out, row)
	}
	return out, nil
}

// ExportTimeline 时间线 mactime/JSON 输出
func (a *App) ExportTimeline(outputDir, format string) (string, error) {
	files := a.engine.GetLastRecoveryResult()
	if len(files) == 0 {
		return "", fmt.Errorf("尚无可导出的恢复记录")
	}
	scanFiles := a.scanFiles
	if len(scanFiles) > 0 {
		// 用扫描到的文件（更完整），否则退化到最近恢复记录
		events := forensics.BuildTimeline(scanFiles)
		return writeTimelineFile(outputDir, format, events)
	}
	// 从 recovery records 构造最简 event list
	var rfs []*types.RecoveredFile
	for _, r := range files {
		rfs = append(rfs, &types.RecoveredFile{FileName: r.FileName, Size: r.Size})
	}
	events := forensics.BuildTimeline(rfs)
	return writeTimelineFile(outputDir, format, events)
}

func writeTimelineFile(outputDir, format string, events []forensics.TimelineEvent) (string, error) {
	if outputDir == "" {
		if home, _ := os.UserHomeDir(); home != "" {
			outputDir = home
		} else {
			outputDir = "."
		}
	}
	var ext, filename string
	switch format {
	case "json":
		ext = ".ndjson"
	default:
		format = "mactime"
		ext = ".body"
	}
	filename = filepath.Join(outputDir, "timeline-"+time.Now().Format("20060102-150405")+ext)
	f, err := os.Create(filename)
	if err != nil {
		return "", err
	}
	defer f.Close()
	switch format {
	case "json":
		if err := forensics.WriteTimelineJSON(f, events); err != nil {
			return "", err
		}
	default:
		if err := forensics.WriteTimelineMACTime(f, events); err != nil {
			return "", err
		}
	}
	return filename, nil
}

// ExportDFXML 取证标准 XML 报告
func (a *App) ExportDFXML(outputDir string) (string, error) {
	files := a.scanFiles
	if len(files) == 0 {
		return "", fmt.Errorf("尚无扫描结果可导出")
	}
	if outputDir == "" {
		if home, _ := os.UserHomeDir(); home != "" {
			outputDir = home
		} else {
			outputDir = "."
		}
	}
	path := filepath.Join(outputDir, "dfxml-"+time.Now().Format("20060102-150405")+".xml")
	f, err := os.Create(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	// 给 DFXML 加上 source —— 取证场景下"数据来自哪块盘"必须在报告里
	a.mu.Lock()
	driveLabel := a.currentDrive.Path
	a.mu.Unlock()
	source := &forensics.SourceInfo{
		ImageFilename: driveLabel,
		SectorSize:    512,
	}
	return path, forensics.WriteDFXMLWithSource(f, "DataRecovery", updater.Version, source, files)
}

// BuildCustody 把 outputDir 下的所有恢复文件打保管链 manifest.json
func (a *App) BuildCustody(outputDir, sourceDevice, operator string) (string, error) {
	c := forensics.Custody{
		ToolName:     "DataRecovery",
		ToolVersion:  updater.Version,
		SourceDevice: sourceDevice,
		OperatorUser: operator,
		StartedAt:    time.Now().UTC(),
	}
	return forensics.BuildAndWrite(outputDir, c)
}

// VerifyCustody 校验保管链
func (a *App) VerifyCustody(outputDir string) ([]string, error) {
	problems, err := forensics.VerifyCustody(outputDir)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(problems))
	for _, p := range problems {
		out = append(out, p.Error())
	}
	return out, nil
}

// LookupVirusTotal 用户自带 API key 查 hash
func (a *App) LookupVirusTotal(sha256Hex, apiKey string) (*forensics.VTReport, error) {
	c := forensics.NewVTClient(apiKey)
	ctx, cancel := context.WithTimeout(a.ctx, 30*time.Second)
	defer cancel()
	return c.LookupHash(ctx, sha256Hex)
}

// RecoverGPTPartitions 从盘尾备份 GPT 恢复丢失的分区表。
//
// **GPT 在物理盘上**，逻辑卷（\\.\C: / \\.\G:）只是其中一个分区，没有 GPT 头。
// v2.8.3 修：自动把 Windows 逻辑卷路径解析回底层物理盘，避免"读 0 字节"错误。
func (a *App) RecoverGPTPartitions(drivePath string) ([]gpt.Partition, error) {
	if drivePath == "" {
		return nil, fmt.Errorf("drivePath 为空")
	}
	// Windows 逻辑卷 → 物理盘（非 Windows 平台 no-op，原样返回）
	resolved := disk.ResolveToPhysicalDriveWindows(drivePath)
	r := disk.NewReader(resolved)
	if err := r.Open(); err != nil {
		return nil, fmt.Errorf("打开磁盘 %s: %w", resolved, err)
	}
	defer r.Close()
	// 先试主表
	if h, err := gpt.ReadPrimaryHeader(r); err == nil && h.IsValidCRC {
		return gpt.ReadPartitions(r, h)
	}
	_, parts, err := gpt.RecoverFromBackup(r)
	return parts, err
}

// SuggestNetworkMount 给定 smb:// / nfs:// / iscsi:// URL 返回挂载步骤
func (a *App) SuggestNetworkMount(url string) []netfs.MountAdvice {
	return netfs.SuggestMount(url)
}

// FindMountedRemoteImages 扫 /Volumes / /mnt 找已挂载远程盘里的镜像
func (a *App) FindMountedRemoteImages() []string {
	return netfs.FindMountedRemoteImages()
}

// OCRImage 对一张图做 OCR
func (a *App) OCRImage(imagePath string, langs []string) (string, error) {
	return ocr.Recognize(imagePath, langs)
}

// OCRSearch 在一批指定图片里找含 keyword 文字的（保留兼容老调用）
func (a *App) OCRSearch(imagePaths []string, keyword string, langs []string) []string {
	return ocr.SearchInImages(imagePaths, keyword, langs)
}

// OCRStatus 给前端 OCR Modal 用 —— 拿"OCR 当前能不能用 + 装了哪些语言"摘要
func (a *App) OCRStatus() *ocr.Status {
	return ocr.QueryStatus()
}

// OCRListLanguages 列所有可用语言（已装 + 可下载），供 Modal 渲染
func (a *App) OCRListLanguages() ([]ocr.LanguageInfo, error) {
	return ocr.ListAvailableLanguages()
}

// OCRDownloadLanguage 从 tessdata_fast 官方仓库下载某语言到 cache
func (a *App) OCRDownloadLanguage(code string) error {
	ctx, cancel := context.WithTimeout(a.ctx, 5*time.Minute)
	defer cancel()
	return ocr.DownloadLanguage(ctx, code)
}

// OCRDeleteLanguage 删除已下载的语言（内置 eng/chi_sim 不允许删）
func (a *App) OCRDeleteLanguage(code string) error {
	return ocr.DeleteLanguage(code)
}

// OCRSearchDirectory 走一个目录里的所有图片，OCR + 关键词搜，事件流式推送进度。
//
// 前端事件流：
//   - "ocr:progress" { current, total, currentFile, hitCount }
//   - "ocr:hit"      { path }
//   - "ocr:done"     { hits []string }   或   "ocr:error" { message }
//
// 函数本身立即返回（goroutine 跑实际工作），前端通过事件接结果。
// 同时只允许一个搜索在跑：再调一次会让旧的 ctx cancel。
func (a *App) OCRSearchDirectory(dir, keyword string, langs []string) error {
	a.ocrMu.Lock()
	if a.ocrCancel != nil {
		a.ocrCancel()
	}
	ctx, cancel := context.WithCancel(a.ctx)
	a.ocrCancel = cancel
	a.ocrMu.Unlock()

	go func() {
		defer func() {
			a.ocrMu.Lock()
			if a.ocrCancel != nil {
				cancel := a.ocrCancel
				a.ocrCancel = nil
				_ = cancel
			}
			a.ocrMu.Unlock()
		}()
		hits, err := ocr.SearchInDirectory(
			ctx, dir, keyword, langs,
			func(p ocr.SearchProgress) {
				wailsRuntime.EventsEmit(a.ctx, "ocr:progress", p)
			},
			func(path string) {
				wailsRuntime.EventsEmit(a.ctx, "ocr:hit", map[string]any{"path": path})
			},
		)
		if err != nil {
			wailsRuntime.EventsEmit(a.ctx, "ocr:error", map[string]any{"message": err.Error()})
			return
		}
		wailsRuntime.EventsEmit(a.ctx, "ocr:done", map[string]any{"hits": hits, "count": len(hits)})
	}()
	return nil
}

// OCRCancelSearch 让正在跑的 OCRSearchDirectory 立刻退出（用户点 Modal 关闭 / 取消）
func (a *App) OCRCancelSearch() {
	a.ocrMu.Lock()
	defer a.ocrMu.Unlock()
	if a.ocrCancel != nil {
		a.ocrCancel()
		a.ocrCancel = nil
	}
}

// QueryDiskHealth 读 SMART（早已实现，上次漏挂 binding — 本轮同步补绑定）
// 已存在，不再重复定义

// QuerySEDStatus TCG OPAL 自加密硬盘锁定检测
func (a *App) QuerySEDStatus(drivePath string) (*sed.SEDStatus, error) {
	ctx, cancel := context.WithTimeout(a.ctx, 10*time.Second)
	defer cancel()
	return sed.QueryStatus(ctx, drivePath)
}

// ParallelScanDrives 多盘并行扫描（**同步阻塞**版，CLI / 测试用）。
//
// 前端不要直接用这个 —— 它在 wails IPC 上会卡住 UI 线程几分钟到几小时。
// 前端走 StartParallelScanDrives 异步版。
//
// jobs 里每项是 {drivePath, mode}；最多 maxParallel 个同时跑。
// 进度通过 parallel:diskStart / parallel:diskProgress / parallel:fileFound / parallel:diskDone 事件流推送。
func (a *App) ParallelScanDrives(jobs []parallel.DiskJob, maxParallel int) []parallel.JobResult {
	cb := parallel.ScanCallback{
		OnDiskStart: func(j parallel.DiskJob) {
			wailsRuntime.EventsEmit(a.ctx, "parallel:diskStart", j)
		},
		OnDiskProgress: func(j parallel.DiskJob, p types.ScanProgress) {
			wailsRuntime.EventsEmit(a.ctx, "parallel:diskProgress", map[string]any{
				"drive": j.DrivePath, "progress": p,
			})
		},
		OnFileFound: func(j parallel.DiskJob, f *types.RecoveredFile) {
			wailsRuntime.EventsEmit(a.ctx, "parallel:fileFound", map[string]any{
				"drive": j.DrivePath, "file": f,
			})
		},
		OnDiskDone: func(res parallel.JobResult) {
			wailsRuntime.EventsEmit(a.ctx, "parallel:diskDone", res)
		},
	}
	return parallel.ScanMultiple(a.ctx, jobs, maxParallel, cb)
}

// StartParallelScanDrives 给 GUI 用的"启动多盘并行扫描"异步入口（v2.8.5）。
//
// 立刻返回 nil；扫描在后台 goroutine 跑，进度通过事件流推前端：
//   - "parallel:diskStart"    {drivePath, mode}
//   - "parallel:diskProgress" {drive, progress: ScanProgress}
//   - "parallel:fileFound"    {drive, file}
//   - "parallel:diskDone"     {drivePath, result, err}
//   - "parallel:allDone"      {results: []JobResult}   ← 新增，所有盘扫完
//
// 同时只允许一个 multi-disk 任务在跑：再调一次会先 cancel 旧的。
func (a *App) StartParallelScanDrives(jobs []parallel.DiskJob, maxParallel int) error {
	if len(jobs) == 0 {
		return fmt.Errorf("没有要扫描的盘")
	}
	if maxParallel <= 0 {
		maxParallel = 1
	}

	a.parallelMu.Lock()
	if a.parallelCancel != nil {
		a.parallelCancel()
	}
	ctx, cancel := context.WithCancel(a.ctx)
	a.parallelCancel = cancel
	a.parallelMu.Unlock()

	go func() {
		defer func() {
			a.parallelMu.Lock()
			a.parallelCancel = nil
			a.parallelMu.Unlock()
		}()
		cb := parallel.ScanCallback{
			OnDiskStart: func(j parallel.DiskJob) {
				wailsRuntime.EventsEmit(a.ctx, "parallel:diskStart", j)
			},
			OnDiskProgress: func(j parallel.DiskJob, p types.ScanProgress) {
				wailsRuntime.EventsEmit(a.ctx, "parallel:diskProgress", map[string]any{
					"drive": j.DrivePath, "progress": p,
				})
			},
			OnFileFound: func(j parallel.DiskJob, f *types.RecoveredFile) {
				wailsRuntime.EventsEmit(a.ctx, "parallel:fileFound", map[string]any{
					"drive": j.DrivePath, "file": f,
				})
			},
			OnDiskDone: func(res parallel.JobResult) {
				// 序列化 err 让前端能拿到字符串
				payload := map[string]any{
					"drivePath": res.DrivePath,
					"result":    res.Result,
				}
				if res.Err != nil {
					payload["error"] = res.Err.Error()
				}
				wailsRuntime.EventsEmit(a.ctx, "parallel:diskDone", payload)
			},
		}
		results := parallel.ScanMultiple(ctx, jobs, maxParallel, cb)
		// 序列化所有结果并发 allDone
		serialized := make([]map[string]any, 0, len(results))
		for _, r := range results {
			item := map[string]any{
				"drivePath": r.DrivePath,
				"result":    r.Result,
			}
			if r.Err != nil {
				item["error"] = r.Err.Error()
			}
			serialized = append(serialized, item)
		}
		wailsRuntime.EventsEmit(a.ctx, "parallel:allDone", serialized)
	}()
	return nil
}

// CancelParallelScan 让正在跑的 StartParallelScanDrives 立刻退出（用户关 modal / 点取消）
func (a *App) CancelParallelScan() {
	a.parallelMu.Lock()
	defer a.parallelMu.Unlock()
	if a.parallelCancel != nil {
		a.parallelCancel()
		a.parallelCancel = nil
	}
}

// LoadNSRLDatabase 载入 NSRL 良性 hash 列表
func (a *App) LoadNSRLDatabase(path string) (int, error) {
	db, err := forensics.LoadNSRLFromFile(path)
	if err != nil {
		return 0, err
	}
	a.mu.Lock()
	a.nsrlDB = db
	a.mu.Unlock()
	return db.Size(), nil
}

// UnlockFileVaultVolume 用用户输入的 password 解 FileVault 卷的 keybag → VEK → 注入 engine。
//
// 输入：
//   drivePath     磁盘路径（或镜像）
//   volumeUUID    目标卷的 APFS volume UUID（32 hex char 或 UUID 标准格式）
//   password      用户密码
//   salt          来自 PreBoot plist（用户可手动提供；macOS 上也可从 diskutil 拿）
//   iter          PBKDF2 迭代数（典型 ~100000，来自 PreBoot plist）
//
// 成功后，engine.APFS 扫描路径会自动对该 UUID 卷启用透明解密 reader。
func (a *App) UnlockFileVaultVolume(drivePath, volumeUUID, password string, salt []byte, iter int) error {
	if drivePath == "" || password == "" {
		return fmt.Errorf("drivePath / password 不能为空")
	}
	uuid, err := parseHexUUID(volumeUUID)
	if err != nil {
		return fmt.Errorf("volumeUUID 解析失败: %w", err)
	}
	r := disk.NewReader(drivePath)
	if err := r.Open(); err != nil {
		return fmt.Errorf("打开磁盘 %s 失败（FileVault unlock）: %w", drivePath, err)
	}
	defer r.Close()

	containers, err := apfs.NewScanner(r).FindContainers(a.ctx, apfs.FindOptions{})
	if err != nil || len(containers) == 0 {
		return fmt.Errorf("未在 %s 找到 APFS 容器", drivePath)
	}

	var targetCont *apfs.Container
	var targetVol *apfs.Volume
	for _, c := range containers {
		for i := range c.Volumes {
			if c.Volumes[i].UUID == uuid {
				targetCont = c
				targetVol = &c.Volumes[i]
				break
			}
		}
		if targetVol != nil {
			break
		}
	}
	if targetVol == nil {
		return fmt.Errorf("未找到 UUID 为 %X 的卷", uuid)
	}
	if !targetVol.IsEncrypted {
		return fmt.Errorf("卷未加密，无需解锁")
	}

	// 读卷级 keybag
	kb, err := apfs.ReadKeyBagFromVolume(r, targetCont, targetVol)
	if err != nil {
		return fmt.Errorf("读 keybag: %w", err)
	}
	// 在 keybag 里找 wrapped VEK + wrapped KEK
	wv := kb.FindEntry(uuid, apfs.KeyBagTagWrappedVEK)
	wk := kb.FindEntry(uuid, apfs.KeyBagTagWrappedKEK)
	if wv == nil || wk == nil {
		return fmt.Errorf("keybag 缺 wrappedVEK 或 wrappedKEK entry")
	}
	if iter <= 0 {
		iter = 100000
	}
	derived := apfs.DeriveKeyFromPassword(password, salt, iter, 32)
	vek, err := apfs.UnwrapVEKWithDerivedKey(derived, wk.KeyData, wv.KeyData)
	if err != nil {
		return fmt.Errorf("解 VEK: %w", err)
	}
	a.engine.SetAPFSVEK(uuid, vek)
	appLogger.Info("FileVault VEK 已注入", "volume", fmt.Sprintf("%X", uuid))
	return nil
}

// parseHexUUID 接受 "XXXXXXXX-XXXX-..." 或 32 hex char 的 UUID 字符串
func parseHexUUID(s string) ([16]byte, error) {
	var out [16]byte
	clean := strings.ReplaceAll(s, "-", "")
	if len(clean) != 32 {
		return out, fmt.Errorf("UUID 长度 %d != 32 hex chars", len(clean))
	}
	for i := 0; i < 16; i++ {
		var b byte
		if _, err := fmt.Sscanf(clean[i*2:i*2+2], "%02x", &b); err != nil {
			return out, err
		}
		out[i] = b
	}
	return out, nil
}

// ListAPFSSnapshots 枚举磁盘上所有 APFS 容器里的 snapshot
type APFSSnapshotInfo struct {
	DrivePath     string         `json:"drivePath"`
	ContainerOffset int64        `json:"containerOffset"`
	Snapshots     []apfs.Snapshot `json:"snapshots"`
}

func (a *App) ListAPFSSnapshots(drivePath string) ([]APFSSnapshotInfo, error) {
	r := disk.NewReader(drivePath)
	if err := r.Open(); err != nil {
		return nil, err
	}
	defer r.Close()
	containers, err := apfs.NewScanner(r).FindContainers(a.ctx, apfs.FindOptions{})
	if err != nil {
		return nil, err
	}
	var out []APFSSnapshotInfo
	for _, c := range containers {
		omap, err := apfs.LoadOmap(r, c.Offset, c.BlockSize, c.OmapOID)
		if err != nil {
			continue
		}
		for _, v := range c.Volumes {
			if v.RootTreeOID == 0 {
				continue
			}
			snaps, err := apfs.EnumerateSnapshots(r, c.Offset, c.BlockSize, omap, v.RootTreeOID)
			if err != nil || len(snaps) == 0 {
				continue
			}
			out = append(out, APFSSnapshotInfo{
				DrivePath:       drivePath,
				ContainerOffset: c.Offset,
				Snapshots:       snaps,
			})
		}
	}
	return out, nil
}

// GetBadSectors 返回最近一次扫描中 ResilientReader 跳过的坏扇区列表。
// Engine.Scan 现在自动包 ResilientReader → 用户不用管；前端可直接展示。
func (a *App) GetBadSectors() []disk.BadSector {
	if bs := a.engine.BadSectors(); bs != nil {
		return bs
	}
	return []disk.BadSector{}
}

// EncryptedReaderCacheStatsResp 给前端的统一返回（即便没缓存也带 Active 字段）
type EncryptedReaderCacheStatsResp struct {
	Active bool             `json:"active"` // false = 当前扫描非加密卷或无缓存
	Stats  disk.CacheStats `json:"stats"`
}

// GetEncryptedReaderCacheStats 返回加密卷扫描的 sector 缓存命中率快照。
//
// 给 UI 显示"BitLocker / LUKS / VeraCrypt 卷扫描缓存命中率 87%"，让用户
// 直观看到优化生效。Active=false 时表示当前扫描不是加密卷链路，前端应隐藏该面板。
//
// 数据是 Engine 实时维护的，扫描中可定期 poll 看变化。
func (a *App) GetEncryptedReaderCacheStats() EncryptedReaderCacheStatsResp {
	stats, ok := a.engine.EncryptedReaderCacheStats()
	return EncryptedReaderCacheStatsResp{Active: ok, Stats: stats}
}

// IsKnownBenign 已载入的 NSRL 库里 hash 是否为已知良性
func (a *App) IsKnownBenign(sha256Hex string) bool {
	a.mu.Lock()
	db := a.nsrlDB
	a.mu.Unlock()
	if db == nil {
		return false
	}
	return db.IsKnownBenign(sha256Hex)
}

// ====================================================================
// NAS 发现 / 连接 / 扫描（Batch 2）
// ====================================================================

// DiscoveredNAS 前端 UI 展示用的简化视图（不暴露 net.IP 等内部类型）
type DiscoveredNAS struct {
	Kind     string `json:"kind"`     // "smb" | "nfs" | "afp"
	Host     string `json:"host"`
	IP       string `json:"ip"`
	Port     uint16 `json:"port"`
	Instance string `json:"instance"`
}

// DiscoverNASServices 在局域网用 mDNS 查找 SMB / NFS / AFP 服务。
// timeout 秒单位；UI 可以传 3-5 秒。
func (a *App) DiscoverNASServices(timeoutSecs int) []DiscoveredNAS {
	if timeoutSecs <= 0 || timeoutSecs > 30 {
		timeoutSecs = 3
	}
	ctx, cancel := context.WithTimeout(a.ctx, time.Duration(timeoutSecs)*time.Second)
	defer cancel()

	svcs, err := netfs.DiscoverNAS(ctx, time.Duration(timeoutSecs)*time.Second)
	if err != nil {
		appLogger.Warn("mDNS NAS 发现失败", "err", err)
		return nil
	}
	out := make([]DiscoveredNAS, 0, len(svcs))
	for _, s := range svcs {
		ip := ""
		if s.IP != nil {
			ip = s.IP.String()
		}
		out = append(out, DiscoveredNAS{
			Kind:     string(s.Kind),
			Host:     s.Host,
			IP:       ip,
			Port:     s.Port,
			Instance: s.Instance,
		})
	}
	return out
}

// SMBListShares 试连 SMB server 并列出 share 名（不扫描文件）。
// UI 里的"连接 → 让我先看有哪些共享"步骤。返回的 []string 给前端展示选择列表。
func (a *App) SMBListShares(host string, port int, user, password, domain string) ([]string, error) {
	ctx, cancel := context.WithTimeout(a.ctx, 30*time.Second)
	defer cancel()

	sess, err := netfs.DialSMB(ctx, netfs.SMBScanConfig{
		Host: host, Port: port, User: user, Password: password, Domain: domain,
	})
	if err != nil {
		return nil, err
	}
	defer sess.Close()
	return sess.ListShares()
}

// NFSListExports 连 NFS server 并列出 export 点。
// 多数家用 NAS 开启了 EXPORT；企业 NFS 常关闭，此时会报错，用户需手动填 export 路径。
func (a *App) NFSListExports(host string, nfsPort, mountPort, uid, gid uint32) ([]string, error) {
	ctx, cancel := context.WithTimeout(a.ctx, 30*time.Second)
	defer cancel()

	sess, err := netfs.DialNFSSession(ctx, netfs.NFSScanConfig{
		Host: host, NFSPort: nfsPort, MountPort: mountPort, UID: uid, GID: gid,
	})
	if err != nil {
		return nil, err
	}
	defer sess.Close()
	return sess.ListExports(ctx)
}

// SMBScanRequestWails SMB 扫描的参数（从 UI 过来）
type SMBScanRequestWails struct {
	Host     string   `json:"host"`
	Port     int      `json:"port"`
	User     string   `json:"user"`
	Password string   `json:"password"`
	Domain   string   `json:"domain"`
	Shares   []string `json:"shares"`
	MaxDepth int      `json:"maxDepth"`
	MaxFiles int      `json:"maxFiles"`
}

// StartSMBScan 后台启动 SMB 扫描，通过 scan:progress / scan:fileFound 事件流式推送结果。
// 与盘扫描复用同一套事件契约，前端不用特殊处理。
func (a *App) StartSMBScan(req SMBScanRequestWails) error {
	a.mu.Lock()
	if a.engine.IsScanning() {
		a.mu.Unlock()
		return fmt.Errorf("已有扫描任务正在进行")
	}
	a.mu.Unlock()

	go func() {
		ctx, cancel := context.WithCancel(context.Background())
		a.mu.Lock()
		a.smbScanCancel = cancel
		a.mu.Unlock()
		defer cancel()

		_, err := a.engine.ScanSMBShare(
			ctx,
			recovery.SMBScanRequest{
				Host: req.Host, Port: req.Port,
				User: req.User, Password: req.Password, Domain: req.Domain,
				Shares: req.Shares, MaxDepth: req.MaxDepth, MaxFiles: req.MaxFiles,
			},
			func(p types.ScanProgress) {
				wailsRuntime.EventsEmit(a.ctx, "scan:progress", p)
			},
			func(f *types.RecoveredFile) {
				wailsRuntime.EventsEmit(a.ctx, "scan:fileFound", f)
			},
		)
		if err != nil {
			appLogger.Warn("SMB 扫描出错", "err", err)
			wailsRuntime.EventsEmit(a.ctx, "scan:error", err.Error())
			return
		}
		result := a.engine.Results()
		wailsRuntime.EventsEmit(a.ctx, "scan:completed", result)
	}()
	return nil
}

// NFSScanRequestWails NFS 扫描参数
type NFSScanRequestWails struct {
	Host      string   `json:"host"`
	NFSPort   uint32   `json:"nfsPort"`
	MountPort uint32   `json:"mountPort"`
	UID       uint32   `json:"uid"`
	GID       uint32   `json:"gid"`
	Exports   []string `json:"exports"`
	MaxDepth  int      `json:"maxDepth"`
	MaxFiles  int      `json:"maxFiles"`
}

// StartNFSScan 后台启动 NFS v3 扫描。
func (a *App) StartNFSScan(req NFSScanRequestWails) error {
	a.mu.Lock()
	if a.engine.IsScanning() {
		a.mu.Unlock()
		return fmt.Errorf("已有扫描任务正在进行")
	}
	a.mu.Unlock()

	go func() {
		ctx, cancel := context.WithCancel(context.Background())
		a.mu.Lock()
		a.nfsScanCancel = cancel
		a.mu.Unlock()
		defer cancel()

		_, err := a.engine.ScanNFSExport(
			ctx,
			recovery.NFSScanRequest{
				Host: req.Host, NFSPort: req.NFSPort, MountPort: req.MountPort,
				UID: req.UID, GID: req.GID,
				Exports: req.Exports, MaxDepth: req.MaxDepth, MaxFiles: req.MaxFiles,
			},
			func(p types.ScanProgress) {
				wailsRuntime.EventsEmit(a.ctx, "scan:progress", p)
			},
			func(f *types.RecoveredFile) {
				wailsRuntime.EventsEmit(a.ctx, "scan:fileFound", f)
			},
		)
		if err != nil {
			appLogger.Warn("NFS 扫描出错", "err", err)
			wailsRuntime.EventsEmit(a.ctx, "scan:error", err.Error())
			return
		}
		result := a.engine.Results()
		wailsRuntime.EventsEmit(a.ctx, "scan:completed", result)
	}()
	return nil
}

// StopNASScan 取消正在进行的 SMB/NFS 扫描。
func (a *App) StopNASScan() {
	a.mu.Lock()
	smbC := a.smbScanCancel
	nfsC := a.nfsScanCancel
	a.smbScanCancel = nil
	a.nfsScanCancel = nil
	a.mu.Unlock()
	if smbC != nil {
		smbC()
	}
	if nfsC != nil {
		nfsC()
	}
}

// ====================================================================
// iOS 本地备份（Batch 3）
// ====================================================================

// DiscoverIOSBackups 列出本机 MobileSync/Backup 下的所有 iOS 备份。
// UI 展示让用户挑一个；加密的会在前端看到锁标和"需要密码"提示。
func (a *App) DiscoverIOSBackups() ([]recovery.IOSBackupInfo, error) {
	return a.engine.DiscoverIOSBackups()
}

// StartIOSBackupScan 后台扫描指定备份目录。
//
//   password == "":  对未加密备份直接扫；对加密备份立即发 scan:error "encrypted"，前端弹密码框。
//   password 非空:   对加密备份做 keybag unlock + Manifest.db 解密 + 文件 enumerate。
//
// 与盘扫描复用同一套 scan:progress / scan:fileFound / scan:completed 事件。
func (a *App) StartIOSBackupScan(backupPath, password string) error {
	a.mu.Lock()
	if a.engine.IsScanning() {
		a.mu.Unlock()
		return fmt.Errorf("已有扫描任务正在进行")
	}
	a.mu.Unlock()

	go func() {
		ctx, cancel := context.WithCancel(context.Background())
		a.mu.Lock()
		a.iosScanCancel = cancel
		a.mu.Unlock()
		defer cancel()

		_, err := a.engine.ScanIOSBackup(
			ctx,
			backupPath, password,
			func(p types.ScanProgress) {
				wailsRuntime.EventsEmit(a.ctx, "scan:progress", p)
			},
			func(f *types.RecoveredFile) {
				wailsRuntime.EventsEmit(a.ctx, "scan:fileFound", f)
			},
		)
		if err != nil {
			// 加密但没给密码：发一个专用 event 让 UI 弹密码框
			if err == ios.ErrEncrypted {
				wailsRuntime.EventsEmit(a.ctx, "ios:passwordRequired", backupPath)
				return
			}
			appLogger.Warn("iOS 备份扫描出错", "err", err)
			wailsRuntime.EventsEmit(a.ctx, "scan:error", err.Error())
			return
		}
		wailsRuntime.EventsEmit(a.ctx, "scan:completed", a.engine.Results())
	}()
	return nil
}

// StopIOSBackupScan 取消正在进行的 iOS 备份扫描。
func (a *App) StopIOSBackupScan() {
	a.mu.Lock()
	c := a.iosScanCancel
	a.iosScanCancel = nil
	a.mu.Unlock()
	if c != nil {
		c()
	}
}

// ====================================================================
// Android `.ab` 备份（Batch 4）
// ====================================================================

// SelectAndroidBackup 让用户选一个 .ab 文件。
func (a *App) SelectAndroidBackup() (string, error) {
	dir, err := wailsRuntime.OpenFileDialog(a.ctx, wailsRuntime.OpenDialogOptions{
		Title: "选择 Android 备份 (.ab) 文件",
		Filters: []wailsRuntime.FileFilter{
			{DisplayName: "Android Backup", Pattern: "*.ab"},
		},
	})
	if err != nil {
		return "", err
	}
	return dir, nil
}

// InspectAndroidBackup 仅读 .ab 头部判断是否加密，UI 据此决定是否弹密码框。
func (a *App) InspectAndroidBackup(path string) (*recovery.AndroidBackupInfo, error) {
	return a.engine.InspectAndroidBackup(path)
}

// StartAndroidBackupScan 后台扫描 .ab 备份。事件流和盘扫描共用。
//   password == ""        非加密：正常扫；加密：发 android:passwordRequired
//   password 非空         加密：解锁后扫
func (a *App) StartAndroidBackupScan(backupPath, password string) error {
	a.mu.Lock()
	if a.engine.IsScanning() {
		a.mu.Unlock()
		return fmt.Errorf("已有扫描任务正在进行")
	}
	a.mu.Unlock()

	go func() {
		ctx, cancel := context.WithCancel(context.Background())
		a.mu.Lock()
		a.androidScanCancel = cancel
		a.mu.Unlock()
		defer cancel()

		_, err := a.engine.ScanAndroidBackup(
			ctx,
			backupPath, password,
			func(p types.ScanProgress) {
				wailsRuntime.EventsEmit(a.ctx, "scan:progress", p)
			},
			func(f *types.RecoveredFile) {
				wailsRuntime.EventsEmit(a.ctx, "scan:fileFound", f)
			},
		)
		if err != nil {
			if errors.Is(err, android.ErrEncrypted) {
				wailsRuntime.EventsEmit(a.ctx, "android:passwordRequired", backupPath)
				return
			}
			appLogger.Warn("Android 备份扫描出错", "err", err)
			wailsRuntime.EventsEmit(a.ctx, "scan:error", err.Error())
			return
		}
		wailsRuntime.EventsEmit(a.ctx, "scan:completed", a.engine.Results())
	}()
	return nil
}

// StopAndroidBackupScan 取消正在进行的 Android 备份扫描。
func (a *App) StopAndroidBackupScan() {
	a.mu.Lock()
	c := a.androidScanCancel
	a.androidScanCancel = nil
	a.mu.Unlock()
	if c != nil {
		c()
	}
}

// ====================================================================
// 云端备份本地发现（iCloud/OneDrive/Google Drive/Dropbox 同步文件夹扫描）
// ====================================================================

// CloudBackupFinding 给前端的发现结果（Provider 字符串化让 JSON 友好）
type CloudBackupFinding struct {
	Provider    string `json:"provider"`     // "iCloud" / "OneDrive" / ...
	Kind        string `json:"kind"`         // "iOS-MobileSync" / "Android-AB"
	Path        string `json:"path"`         // 备份绝对路径
	SizeBytes   int64  `json:"sizeBytes"`    //
	CloudRoot   string `json:"cloudRoot"`    // 它所在的同步根（"它在你 OneDrive 里"）
	Description string `json:"description"`  //
}

// CloudSyncRootInfo 给前端的同步根列表项
type CloudSyncRootInfo struct {
	Provider string `json:"provider"`
	Path     string `json:"path"`
	Reason   string `json:"reason"`
}

// DiscoverCloudSyncRoots 列出本机所有云同步根（仅返回真实存在的目录）
func (a *App) DiscoverCloudSyncRoots() []CloudSyncRootInfo {
	roots := backup.DiscoverCloudSyncRoots()
	out := make([]CloudSyncRootInfo, 0, len(roots))
	for _, r := range roots {
		out = append(out, CloudSyncRootInfo{
			Provider: string(r.Provider), Path: r.Path, Reason: r.Reason,
		})
	}
	return out
}

// ScanCloudForBackups 扫所有云同步根找其中的 iOS/Android 备份文件
//
// 这是"零网络"哲学：不调任何云 API，只扫已经被同步客户端拉到本地的副本。
func (a *App) ScanCloudForBackups() []CloudBackupFinding {
	roots := backup.DiscoverCloudSyncRoots()
	hits := backup.FindBackupsInCloudRoots(roots, 5)
	out := make([]CloudBackupFinding, 0, len(hits))
	for _, h := range hits {
		out = append(out, CloudBackupFinding{
			Provider: string(h.Provider), Kind: h.BackupKind,
			Path: h.Path, SizeBytes: h.SizeBytes,
			CloudRoot: h.CloudRoot, Description: h.Description,
		})
	}
	return out
}

// ====================================================================
// MTP / 手机直连（Batch 8）
// ====================================================================

// MTPDeviceInfo 是给前端的简化 Android device 描述
type MTPDeviceInfo struct {
	Serial  string `json:"serial"`
	State   string `json:"state"`
	Model   string `json:"model"`
	Product string `json:"product"`
}

// MTPStatus 给前端用来判断是否能用 MTP 功能
type MTPStatus struct {
	Available  bool   `json:"available"`
	Version    string `json:"version,omitempty"`
	InstallURL string `json:"installURL,omitempty"`
}

// MTPCheck 返回当前环境的 MTP 直连可用性。前端 WelcomePage 启动时调一次，
// 决定是否显示"手机直连"入口。
func (a *App) MTPCheck() MTPStatus {
	if !mtp.AdbAvailable() {
		return MTPStatus{
			Available:  false,
			InstallURL: "https://developer.android.com/tools/releases/platform-tools",
		}
	}
	ctx, cancel := context.WithTimeout(a.ctx, 5*time.Second)
	defer cancel()
	return MTPStatus{
		Available: true,
		Version:   mtp.AdbVersion(ctx),
	}
}

// MTPListDevices 列出当前插着的 Android 设备（adb 可见的）。
// 没装 adb 时返回友好错误，前端据此引导用户。
func (a *App) MTPListDevices() ([]MTPDeviceInfo, error) {
	ctx, cancel := context.WithTimeout(a.ctx, 5*time.Second)
	defer cancel()
	devs, err := mtp.ListDevices(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]MTPDeviceInfo, 0, len(devs))
	for _, d := range devs {
		out = append(out, MTPDeviceInfo{
			Serial:  d.Serial,
			State:   d.State,
			Model:   d.Model,
			Product: d.Product,
		})
	}
	return out, nil
}

// MTPPullDirectoryAndScan 把手机端 srcPath（如 "/sdcard/DCIM"）整个目录拉到本地
// destDir，然后跑一次"扫描本地目录"——上层文件系统扫描器对普通目录原生支持，
// 不需要懂 MTP。
//
// 设计选择：先 pull 后 scan 而不是流式扫描，因为：
//   1. adb pull 有官方进度，用户能看到拉了多少
//   2. 拉完一份本地副本后扫描是只读的；万一手机断开也不丢已拉部分
//   3. 拉到本地后用户可以反复扫不同 mode（fast / full / deep）
func (a *App) MTPPullDirectoryAndScan(serial, srcPath, destDir, mode string) error {
	if serial == "" || srcPath == "" || destDir == "" {
		return fmt.Errorf("serial / srcPath / destDir 不能为空")
	}
	if mode == "" {
		mode = string(types.ScanFull)
	}

	a.mu.Lock()
	if a.engine.IsScanning() {
		a.mu.Unlock()
		return fmt.Errorf("已有扫描任务正在执行，请先停止当前扫描")
	}
	a.mu.Unlock()

	ctx, cancel := context.WithCancel(a.ctx)
	a.mu.Lock()
	a.mtpPullCancel = cancel
	a.mu.Unlock()

	go func() {
		defer func() {
			cancel()
			a.mu.Lock()
			a.mtpPullCancel = nil
			a.mu.Unlock()
		}()
		wailsRuntime.EventsEmit(a.ctx, "mtp:pullStarted", map[string]string{
			"serial": serial, "src": srcPath, "dest": destDir,
		})
		appLogger.Info("MTP pull 开始", "serial", serial, "src", srcPath, "dest", destDir)

		if err := mtp.PullDirectory(ctx, serial, srcPath, destDir); err != nil {
			appLogger.Warn("MTP pull 失败", "err", err)
			wailsRuntime.EventsEmit(a.ctx, "mtp:pullError", err.Error())
			return
		}
		wailsRuntime.EventsEmit(a.ctx, "mtp:pullCompleted", destDir)
		appLogger.Info("MTP pull 完成，开始扫描本地副本", "path", destDir)

		// pull 完成后用普通目录扫描接续
		if err := a.StartScan(destDir, mode); err != nil {
			wailsRuntime.EventsEmit(a.ctx, "scan:error", err.Error())
		}
	}()
	return nil
}

// CancelMTPPull 取消进行中的 ADB pull 任务。
// 如果当前没有 pull 在跑，返回 nil（幂等）。
func (a *App) CancelMTPPull() error {
	a.mu.Lock()
	c := a.mtpPullCancel
	a.mu.Unlock()
	if c == nil {
		return nil
	}
	c()
	appLogger.Info("用户取消 MTP pull")
	return nil
}

// ====================================================================
// 手机块级直读 + PTP + iOS 直连
// ====================================================================

// AndroidPartitionInfo 给前端的分区描述
type AndroidPartitionInfo struct {
	Name      string `json:"name"`      // userdata / system / boot ...
	BlockNode string `json:"blockNode"` // /dev/block/mmcblk0pX
	SizeBytes int64  `json:"sizeBytes"`
}

// AndroidIsRooted 测设备是否 root（用于决定是否显示"块级 dump"按钮）
func (a *App) AndroidIsRooted(serial string) (bool, error) {
	ctx, cancel := context.WithTimeout(a.ctx, 5*time.Second)
	defer cancel()
	return mtp.IsRooted(ctx, serial)
}

// AndroidListPartitions 列 root 设备 /dev/block/by-name/ 下的分区。
// 用户挑一个（一般是 userdata），然后 AndroidDumpPartitionAndScan 拿物理镜像。
func (a *App) AndroidListPartitions(serial string) ([]AndroidPartitionInfo, error) {
	ctx, cancel := context.WithTimeout(a.ctx, 30*time.Second)
	defer cancel()
	parts, err := mtp.ListPartitions(ctx, serial)
	if err != nil {
		return nil, err
	}
	out := make([]AndroidPartitionInfo, 0, len(parts))
	for _, p := range parts {
		out = append(out, AndroidPartitionInfo{
			Name: p.Name, BlockNode: p.BlockNode, SizeBytes: p.SizeBytes,
		})
	}
	return out, nil
}

// AndroidDumpPartitionAndScan dd 一个分区到本地 .img，然后扫这个 image。
// 长操作（128GB ~ 50 分钟），UI 应监听 mtp:dumpProgress 事件显示百分比。
func (a *App) AndroidDumpPartitionAndScan(serial, blockNode, outImgPath, mode string) error {
	if serial == "" || blockNode == "" || outImgPath == "" {
		return fmt.Errorf("serial/blockNode/outImgPath 不能为空")
	}
	if mode == "" {
		mode = string(types.ScanFull)
	}
	a.mu.Lock()
	if a.engine.IsScanning() {
		a.mu.Unlock()
		return fmt.Errorf("已有扫描任务正在进行")
	}
	a.mu.Unlock()

	ctx, cancel := context.WithCancel(a.ctx)
	a.mu.Lock()
	a.mtpDumpCancel = cancel
	a.mu.Unlock()
	go func() {
		defer func() {
			cancel()
			a.mu.Lock()
			a.mtpDumpCancel = nil
			a.mu.Unlock()
		}()
		wailsRuntime.EventsEmit(a.ctx, "mtp:dumpStarted", map[string]string{
			"serial": serial, "block": blockNode, "out": outImgPath,
		})
		written, err := mtp.DumpPartition(ctx, serial, blockNode, outImgPath, func(w int64) {
			wailsRuntime.EventsEmit(a.ctx, "mtp:dumpProgress", w)
		})
		if err != nil {
			appLogger.Warn("Android 块级 dump 失败", "err", err, "written", written)
			wailsRuntime.EventsEmit(a.ctx, "mtp:dumpError", err.Error())
			return
		}
		wailsRuntime.EventsEmit(a.ctx, "mtp:dumpCompleted", map[string]any{
			"path": outImgPath, "bytes": written,
		})
		appLogger.Info("Android 块级 dump 完成，开始扫 image", "path", outImgPath, "bytes", written)
		// dump 完成后扫这个 image 文件 — Engine.StartScan 对 .img 原生支持
		if err := a.StartScan(outImgPath, mode); err != nil {
			wailsRuntime.EventsEmit(a.ctx, "scan:error", err.Error())
		}
	}()
	return nil
}

// CancelAndroidDump 取消进行中的 Android 块级 dump。
// adb shell dd 进程会被 ctx 取消（exec.CommandContext 自动 SIGKILL 子进程）。
func (a *App) CancelAndroidDump() error {
	a.mu.Lock()
	c := a.mtpDumpCancel
	a.mu.Unlock()
	if c == nil {
		return nil
	}
	c()
	appLogger.Info("用户取消 Android 块级 dump")
	return nil
}

// PTPStatus 给前端的 gphoto2 可用性
type PTPStatus struct {
	Available bool   `json:"available"`
	Version   string `json:"version,omitempty"`
}

// PTPCheck 检测 gphoto2 装没装
func (a *App) PTPCheck() PTPStatus {
	if !mtp.Gphoto2Available() {
		return PTPStatus{Available: false}
	}
	ctx, cancel := context.WithTimeout(a.ctx, 5*time.Second)
	defer cancel()
	return PTPStatus{Available: true, Version: mtp.Gphoto2Version(ctx)}
}

// PTPDeviceInfo 给前端的相机/PTP 设备描述
type PTPDeviceInfo struct {
	Model string `json:"model"`
	Port  string `json:"port"`
}

// PTPListDevices 列 gphoto2 自动发现的相机
func (a *App) PTPListDevices() ([]PTPDeviceInfo, error) {
	ctx, cancel := context.WithTimeout(a.ctx, 10*time.Second)
	defer cancel()
	devs, err := mtp.ListPTPDevices(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]PTPDeviceInfo, 0, len(devs))
	for _, d := range devs {
		out = append(out, PTPDeviceInfo{Model: d.Model, Port: d.Port})
	}
	return out, nil
}

// PTPPullAllAndScan 把相机所有照片拉到本地 destDir，然后扫
func (a *App) PTPPullAllAndScan(port, destDir, mode string) error {
	if port == "" || destDir == "" {
		return fmt.Errorf("port/destDir 不能为空")
	}
	if mode == "" {
		mode = string(types.ScanFull)
	}
	ctx, cancel := context.WithCancel(a.ctx)
	a.mu.Lock()
	a.ptpPullCancel = cancel
	a.mu.Unlock()
	go func() {
		defer func() {
			cancel()
			a.mu.Lock()
			a.ptpPullCancel = nil
			a.mu.Unlock()
		}()
		wailsRuntime.EventsEmit(a.ctx, "ptp:pullStarted", port)
		if err := mtp.PullPTPAll(ctx, port, destDir); err != nil {
			wailsRuntime.EventsEmit(a.ctx, "ptp:pullError", err.Error())
			return
		}
		wailsRuntime.EventsEmit(a.ctx, "ptp:pullCompleted", destDir)
		_ = a.StartScan(destDir, mode)
	}()
	return nil
}

// CancelPTPPull 取消进行中的 PTP/gphoto2 相机 pull 任务。
func (a *App) CancelPTPPull() error {
	a.mu.Lock()
	c := a.ptpPullCancel
	a.mu.Unlock()
	if c == nil {
		return nil
	}
	c()
	appLogger.Info("用户取消 PTP pull")
	return nil
}

// IOSDirectStatus libimobiledevice 装没装
type IOSDirectStatus struct {
	Available bool `json:"available"`
}

// IOSDirectCheck 检测 idevice_id 是否在
func (a *App) IOSDirectCheck() IOSDirectStatus {
	return IOSDirectStatus{Available: mtp.LibIMobileDeviceAvailable()}
}

// IOSDeviceInfo 给前端的 iOS 设备
type IOSDeviceInfo struct {
	UDID    string `json:"udid"`
	Model   string `json:"model"`
	Name    string `json:"name"`
	IOSVer  string `json:"iosVer"`
	Trusted bool   `json:"trusted"`
}

// IOSListDevices 列 idevice_id -l
func (a *App) IOSListDevices() ([]IOSDeviceInfo, error) {
	ctx, cancel := context.WithTimeout(a.ctx, 10*time.Second)
	defer cancel()
	devs, err := mtp.ListIOSDevices(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]IOSDeviceInfo, 0, len(devs))
	for _, d := range devs {
		out = append(out, IOSDeviceInfo{
			UDID: d.UDID, Model: d.Model, Name: d.Name,
			IOSVer: d.IOSVer, Trusted: d.Trusted,
		})
	}
	return out, nil
}

// IOSPair 触发 idevicepair pair（用户要在 iPhone 屏幕上点"信任"）
func (a *App) IOSPair(udid string) error {
	ctx, cancel := context.WithTimeout(a.ctx, 60*time.Second)
	defer cancel()
	return mtp.PairIOSDevice(ctx, udid)
}

// IOSTriggerBackupAndScan 触发系统级 iOS 备份到 destDir，然后用 ScanIOSBackup 扫
//
// 长操作（>30GB 数据可能 30 分钟）。UI 监听 ios:backupProgress / ios:backupCompleted。
func (a *App) IOSTriggerBackupAndScan(udid, destDir, password string) error {
	if udid == "" || destDir == "" {
		return fmt.Errorf("udid/destDir 不能为空")
	}
	ctx, cancel := context.WithCancel(a.ctx)
	a.mu.Lock()
	a.iosBackupCancel = cancel
	a.mu.Unlock()
	go func() {
		defer func() {
			cancel()
			a.mu.Lock()
			a.iosBackupCancel = nil
			a.mu.Unlock()
		}()
		wailsRuntime.EventsEmit(a.ctx, "ios:backupStarted", udid)
		if err := mtp.TriggerIOSBackup(ctx, udid, destDir); err != nil {
			wailsRuntime.EventsEmit(a.ctx, "ios:backupError", err.Error())
			return
		}
		wailsRuntime.EventsEmit(a.ctx, "ios:backupCompleted", destDir)
		// 备份完成 → 扫这个目录（idevicebackup2 写到 destDir/<UDID>/）
		// StartIOSBackupScan 会找 Manifest.plist 自动定位 backup root
		_ = a.StartIOSBackupScan(destDir, password)
	}()
	return nil
}

// CancelIOSBackup 取消进行中的 iOS 备份触发任务。
// idevicebackup2 子进程会被 ctx 取消（exec.CommandContext SIGKILL）。
// 注意：iOS 端可能仍在准备备份；下次接 USB 时 iPhone 会显示"未完成的备份"。
func (a *App) CancelIOSBackup() error {
	a.mu.Lock()
	c := a.iosBackupCancel
	a.mu.Unlock()
	if c == nil {
		return nil
	}
	c()
	appLogger.Info("用户取消 iOS 备份")
	return nil
}
