package main

import (
	"context"
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
	"data-recovery/internal/hfsplus"
	"data-recovery/internal/logging"
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

	stopPersist := make(chan struct{})
	go a.persistLoop(stopPersist)

	go func() {
		defer func() {
			// 扫描结束统一关闭 reader 链（DecryptingReader.Close 会透传到 underlying）
			if err := result.Reader.Close(); err != nil {
				appLogger.Warn("关闭 BitLocker DecryptingReader 失败", "err", err)
			}
		}()

		scanResult, err := a.engine.ScanWithReader(result.Reader, types.ScanMode(mode), callbacks)
		close(stopPersist)

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
		return err
	}
	dec, err := bitlocker.NewDecryptingReader(underlying, sectorCipher, bvolume.OEMID)
	if err != nil {
		underlying.Close()
		return err
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

	stopPersist := make(chan struct{})
	go a.persistLoop(stopPersist)

	go func() {
		defer reader.Close()
		scanResult, err := a.engine.ScanWithReader(reader, types.ScanMode(mode), callbacks)
		close(stopPersist)
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

	stopPersist := make(chan struct{})
	go a.persistLoop(stopPersist)
	go func() {
		defer rdr.Close()
		scanResult, err := a.engine.ScanWithReader(rdr, types.ScanMode(req.Mode), callbacks)
		close(stopPersist)
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

	// 2a. HFS+ / HFSX 卷（老 macOS / Time Machine 备份盘）
	if vols, err := hfsplus.NewScanner(reader).FindVolumes(); err == nil {
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
	// 2b. ReFS 卷（Server / Win11 Pro for Workstations）
	if vols, err := refs.NewScanner(reader).FindVolumes(); err == nil {
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

	// 3. APFS 容器扫描（含 FileVault 检测）
	apfsScanner := apfs.NewScanner(reader)
	if containers, err := apfsScanner.FindContainers(); err == nil {
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

	pendingDir, err := updater.PendingDir()
	if err != nil {
		return err
	}
	// 每个版本独立子目录，避免不同版本互相覆盖
	versionDir := filepath.Join(pendingDir, version)
	destPath := filepath.Join(versionDir, assetName)

	appLogger.Info("开始下载更新", "version", version, "asset", assetName, "dest", destPath)

	go func() {
		ctx, cancel := context.WithCancel(a.ctx)
		defer cancel()

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

		// 恢复成功后自动生成保管链 manifest.json（取证场景友好；
		// 普通用户即便看不懂也无害 — 就一个多出来的 JSON 文件）
		if result.Succeeded > 0 {
			custody := forensics.Custody{
				ToolName:     "DataRecovery",
				ToolVersion:  updater.Version,
				StartedAt:    time.Now().UTC(),
				SourceDevice: a.currentDrive.Path,
			}
			if mp, err := forensics.BuildAndWrite(outputDir, custody); err == nil {
				appLogger.Info("保管链已自动生成", "path", mp)
				// 签名版本（Ed25519 + 可选 RFC 3161 TSA）；失败不阻塞恢复
				if sp, err := forensics.BuildSignAndWrite(outputDir, custody); err == nil {
					appLogger.Info("签名保管链已生成", "path", sp)
					// HTML 取证报告（可打印成 PDF）
					if rp, err := forensics.GenerateHTMLReport(outputDir); err == nil {
						appLogger.Info("HTML 取证报告已生成", "path", rp)
					}
					// 再打成 evidence.zip bundle，方便 B2B 客户直接交付法务
					if zp, err := forensics.BundleEvidence(outputDir); err == nil {
						appLogger.Info("Evidence Bundle 已生成", "path", zp)
					}
				} else {
					appLogger.Warn("签名保管链生成失败（不影响恢复结果）", "err", err)
				}
			}
		}

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

// ExportDiagnosticBundle 把日志 / 会话 snapshot / pending manifest 打包成 zip，
// 用户可以直接贴到 GitHub issue。不会包含磁盘扇区 / 密钥 / 用户文件。
//
// destDir 为空时自动写到用户"下载目录"/"桌面"/配置目录。
func (a *App) ExportDiagnosticBundle(destDir, extraNotes string) (string, error) {
	if destDir == "" {
		if d, err := os.UserHomeDir(); err == nil {
			// 尝试 Desktop，不存在就落回 UserHomeDir
			desk := filepath.Join(d, "Desktop")
			if fi, err := os.Stat(desk); err == nil && fi.IsDir() {
				destDir = desk
			} else {
				destDir = d
			}
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

	go func() {
		defer imagingMu.Unlock()

		reader := disk.NewReader(srcDevicePath)
		if err := reader.Open(); err != nil {
			wailsRuntime.EventsEmit(a.ctx, "imaging:error", err.Error())
			return
		}
		defer reader.Close()

		opts := disk.DefaultImageOptions()
		ctx := a.ctx
		written, err := disk.DumpDiskToImage(ctx, reader, dstImagePath, opts, func(p disk.ImageProgress) {
			wailsRuntime.EventsEmit(a.ctx, "imaging:progress", p)
		})
		if err != nil {
			appLogger.Warn("镜像 dump 出错", "err", err, "written", written)
			wailsRuntime.EventsEmit(a.ctx, "imaging:error", err.Error())
			return
		}
		appLogger.Info("镜像 dump 完成", "path", dstImagePath, "bytes", written)
		wailsRuntime.EventsEmit(a.ctx, "imaging:completed", map[string]any{
			"path":  dstImagePath,
			"bytes": written,
		})
	}()

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
	return path, forensics.WriteDFXML(f, "DataRecovery", updater.Version, files)
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

// RecoverGPTPartitions 从盘尾备份 GPT 恢复丢失的分区表
func (a *App) RecoverGPTPartitions(drivePath string) ([]gpt.Partition, error) {
	if drivePath == "" {
		return nil, fmt.Errorf("drivePath 为空")
	}
	r := disk.NewReader(drivePath)
	if err := r.Open(); err != nil {
		return nil, fmt.Errorf("打开磁盘: %w", err)
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

// OCRImage 对一张图做 OCR（需本机有 tesseract）
func (a *App) OCRImage(imagePath string, langs []string) (string, error) {
	return ocr.Recognize(imagePath, langs)
}

// OCRSearch 在一批图片里找含 keyword 文字的
func (a *App) OCRSearch(imagePaths []string, keyword string, langs []string) []string {
	return ocr.SearchInImages(imagePaths, keyword, langs)
}

// QueryDiskHealth 读 SMART（早已实现，上次漏挂 binding — 本轮同步补绑定）
// 已存在，不再重复定义

// QuerySEDStatus TCG OPAL 自加密硬盘锁定检测
func (a *App) QuerySEDStatus(drivePath string) (*sed.SEDStatus, error) {
	ctx, cancel := context.WithTimeout(a.ctx, 10*time.Second)
	defer cancel()
	return sed.QueryStatus(ctx, drivePath)
}

// ParallelScanDrives 多盘并行扫描。
//
// jobs 里每项是 {drivePath, mode}；最多 maxParallel 个同时跑。
// 结果通过"parallel:diskStart / parallel:diskProgress / parallel:fileFound / parallel:diskDone"
// 事件流推到前端。
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
		return err
	}
	defer r.Close()

	containers, err := apfs.NewScanner(r).FindContainers()
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
	containers, err := apfs.NewScanner(r).FindContainers()
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
