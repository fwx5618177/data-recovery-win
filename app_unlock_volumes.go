package main

// ============================================================================
// LUKS / VeraCrypt / TrueCrypt 卷解锁的 Wails IPC 入口
//
// 与 BitLocker 路径并列；所有 unlock-and-scan 方法共享统一的事件流：
//   <prefix>:keyDeriving / <prefix>:unlocked / <prefix>:wrongPassword
//   scan:progress / scan:fileFound / scan:completed / scan:error
//
// 这个文件从 app.go 拆出，专门承接 Batch 5 (LUKS) + Batch 6 (VeraCrypt) 的
// IPC 入口，让 app.go 主体回到"app 生命周期 + 历史 BitLocker / FileVault"的
// 集中度。BitLocker / FileVault 因为接口签名比较复杂、共享 startScanWithUnlockedReader
// 等辅助函数，留在 app.go 不动；待未来另一波清理时再统一搬。
// ============================================================================

import (
	"errors"
	"fmt"

	wailsRuntime "github.com/wailsapp/wails/v2/pkg/runtime"

	"data-recovery/internal/disk"
	"data-recovery/internal/luks"
	"data-recovery/internal/recovery"
	"data-recovery/internal/types"
	"data-recovery/internal/veracrypt"
)

// ====================================================================
// VeraCrypt / TrueCrypt 卷解锁（Batch 6）
// ====================================================================
//
// 完整链：用户密码 → PBKDF2-{SHA-512/256/RIPEMD-160} → 解 448B encrypted header →
// CRC 校验通过 → master_key → DecryptedReader → engine.ScanWithReader → 文件系统扫描
//
// 性能：每个 (algo, isVC) 组合 ~1-3s（500K iter SHA-512 在主流 CPU 上）；
// 最坏 6 次枚举 ≈ 10-20 秒。前端通过 vc:trying 事件展示进度。

// UnlockVeraCryptAndScan 用密码尝试解锁 VC/TC 容器（PIM=0），命中后跑完整扫描。
//
// drivePath 可以是原始磁盘 / 镜像文件；
// volumeOffsetHex 是容器在原始介质上的字节起点（hex），整盘容器传 "0"。
func (a *App) UnlockVeraCryptAndScan(drivePath, volumeOffsetHex, password, mode string) error {
	return a.UnlockVeraCryptAndScanWithPIM(drivePath, volumeOffsetHex, password, 0, mode)
}

// UnlockVeraCryptSystemEncryptionAndScan 解锁 VeraCrypt **系统加密**卷
// （Windows 全盘加密 boot 盘）后扫描。
//
// 与容器路径区别：卷头在 offset 31744 而非 0；KDF 走 IterationsForPIMSystem
// （SHA 系列固定 200000；RIPEMD = pim*2048）；boot loader 区 [0, 31744) 透传。
func (a *App) UnlockVeraCryptSystemEncryptionAndScan(drivePath, volumeOffsetHex, password string, pim int, mode string) error {
	return a.unlockVCWithFunc("system", drivePath, volumeOffsetHex, password, pim, mode,
		veracrypt.OpenAndUnlockSystemEncryption)
}

// UnlockVeraCryptAutoAndScan 自动尝试两种 layout（容器 → 系统加密），
// 任一成功即扫描。给前端"我也不知道是什么 VC 卷"的一键路径。
//
// 性能：先试容器（占 95% 用户场景）失败后再试系统加密；最坏情况双倍 KDF 等待。
// 想避开这个开销，知道是哪种 layout 时直接调对应专属方法。
func (a *App) UnlockVeraCryptAutoAndScan(drivePath, volumeOffsetHex, password string, pim int, mode string) error {
	return a.unlockVCWithFunc("auto", drivePath, volumeOffsetHex, password, pim, mode,
		veracrypt.OpenAndUnlockAuto)
}

// vcUnlockFunc 是三种 VC unlock 路径的统一签名（容器 / 系统 / auto）。
type vcUnlockFunc func(reader disk.DiskReader, volStart int64, password string, pim int, progress veracrypt.UnlockProgress) (*veracrypt.UnlockedVolume, error)

// UnlockVeraCryptAndScanWithPIM 同 UnlockVeraCryptAndScan 但允许指定 PIM。
//
// PIM (Personal Iterations Multiplier) 是 VeraCrypt 高级用户在创建容器时可
// 指定的 KDF 强化系数：
//
//	pim == 0 → 走默认 iter（500K SHA-512 / 655K RIPEMD-160）
//	pim > 0  → iter = 15000 + 1000*pim (SHA-512/256) 或 327661 + 2048*pim (RIPEMD-160)
//
// 用 PIM 创建的卷必须用同一 PIM 解开 —— PIM 错跟密码错都返回 ErrWrongPassword。
func (a *App) UnlockVeraCryptAndScanWithPIM(drivePath, volumeOffsetHex, password string, pim int, mode string) error {
	return a.unlockVCWithFunc("container", drivePath, volumeOffsetHex, password, pim, mode,
		veracrypt.OpenAndUnlockWithPIM)
}

// unlockVCWithFunc 是三种 VC 入口共享的核心实现 —— 拿走 unlock 函数 + label，
// 其它 wails 事件 / 扫描调度全部一致。kind 用于日志和事件 payload 区分。
func (a *App) unlockVCWithFunc(kind, drivePath, volumeOffsetHex, password string, pim int, mode string, unlockFn vcUnlockFunc) error {
	if drivePath == "" || password == "" {
		return fmt.Errorf("drivePath / password 不能为空")
	}
	if pim < 0 {
		return fmt.Errorf("PIM 必须 >= 0, got %d", pim)
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

	var volumeOffset int64
	if volumeOffsetHex != "" {
		if _, err := fmt.Sscanf(volumeOffsetHex, "%x", &volumeOffset); err != nil {
			return fmt.Errorf("volumeOffset 解析失败: %w", err)
		}
	}

	underlying := disk.NewReader(drivePath)
	if err := underlying.Open(); err != nil {
		return fmt.Errorf("打开磁盘失败: %w", err)
	}

	appLogger.Info("VC 解锁开始", "kind", kind, "drive", drivePath, "offset", volumeOffset, "pim", pim)

	progressCb := func(tried, total int, currentAlgo string) {
		wailsRuntime.EventsEmit(a.ctx, "vc:trying", map[string]any{
			"tried":   tried,
			"total":   total,
			"current": currentAlgo,
			"pim":     pim,
			"kind":    kind, // "container" / "system" / "auto"
		})
	}

	uv, err := unlockFn(underlying, volumeOffset, password, pim, progressCb)
	if err != nil {
		underlying.Close()
		appLogger.Warn("VC 解锁失败", "err", err)
		if errors.Is(err, veracrypt.ErrWrongPassword) {
			wailsRuntime.EventsEmit(a.ctx, "vc:wrongPassword", drivePath)
		}
		return fmt.Errorf("解锁失败: %w", err)
	}

	appLogger.Info("VC 解锁成功",
		"isTrueCrypt", uv.IsTrueCrypt,
		"hash", uv.HashAlgorithm,
		"cipher", uv.Cipher,
		"payloadOffset", uv.Header.PayloadOffset,
		"payloadSize", uv.Header.PayloadSize)

	wailsRuntime.EventsEmit(a.ctx, "vc:unlocked", map[string]any{
		"isTrueCrypt":   uv.IsTrueCrypt,
		"hash":          uv.HashAlgorithm,
		"cipher":        uv.Cipher,
		"payloadOffset": uv.Header.PayloadOffset,
		"payloadSize":   uv.Header.PayloadSize,
	})

	containerLabel := "VeraCrypt"
	if uv.IsTrueCrypt {
		containerLabel = "TrueCrypt"
	}
	a.mu.Lock()
	a.currentDrive = types.DriveInfo{Path: fmt.Sprintf("%s (%s 已解锁)", drivePath, containerLabel)}
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
			_ = uv.Reader.Close()
			if err := underlying.Close(); err != nil {
				appLogger.Warn("关闭 VC underlying reader 失败", "err", err)
			}
			_ = uv.Close()
		}()

		scanResult, err := a.engine.ScanWithReader(uv.Reader, types.ScanMode(mode), callbacks)
		close(stopPersist)
		a.scanSnapshotMu.Lock()
		a.scanActive = false
		a.scanSnapshotMu.Unlock()

		if err != nil {
			appLogger.Warn("VC 卷扫描出错", "err", err)
			wailsRuntime.EventsEmit(a.ctx, "scan:error", err.Error())
			return
		}
		appLogger.Info("VC 卷扫描完成", "files", len(scanResult.Files))
		a.saveSnapshot(true)
		wailsRuntime.EventsEmit(a.ctx, "scan:completed", scanResult)
	}()

	return nil
}

// ====================================================================
// LUKS 卷解锁（Batch 5）
// ====================================================================
//
// 完整链：用户密码 → LUKS1/LUKS2 keyslot 解 → master_key → DecryptedReader →
// engine.ScanWithReader → 普通文件系统扫描器（NTFS / ext4 / APFS / 等）
//
// 与 BitLocker 路径完全平行；前端事件流：
//   luks:keyDeriving / luks:unlocked / scan:progress / scan:fileFound /
//   scan:completed / scan:error
//
// 性能：LUKS1 PBKDF2 ~1-3s；LUKS2 Argon2id（默认 t=4, m=1GB）~2-5s。
// 这里没暴露 KDF 进度（cryptsetup 也没有；KDF 是 atomic 操作）；UI 上用 spinner
// + "正在派生密钥…" 文案即可，不需要进度条。

// UnlockLUKSAndScan 用密码解锁 LUKS1/LUKS2 卷，然后跑一次完整扫描。
//
// volumeOffsetHex 是 LUKS 卷在原始磁盘上的字节起点（hex），整盘 LUKS 时传 "0"。
// password 任何 keyslot 能解开都成功；密码错时返回 ErrWrongPassword 类错误。
//
// 调用前 UI 应先 ScanEncryptedVolumes 拿到候选 LUKS 卷的偏移列表。
func (a *App) UnlockLUKSAndScan(drivePath, volumeOffsetHex, password, mode string) error {
	if drivePath == "" || password == "" {
		return fmt.Errorf("drivePath / password 不能为空")
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

	var volumeOffset int64
	if volumeOffsetHex != "" {
		if _, err := fmt.Sscanf(volumeOffsetHex, "%x", &volumeOffset); err != nil {
			return fmt.Errorf("volumeOffset 解析失败: %w", err)
		}
	}

	// 原始设备路径必然是平台 reader（需要管理员）；普通文件路径（.img / .raw）
	// 走 imageFileReader 不需要管理员
	underlying := disk.NewReader(drivePath)
	if err := underlying.Open(); err != nil {
		return fmt.Errorf("打开磁盘失败: %w", err)
	}

	appLogger.Info("LUKS 解锁开始", "drive", drivePath, "offset", volumeOffset)

	// 跨 keyslot 进度回调 → luks:keyDeriving 事件流
	progressCb := func(stage string, tried, total int, info string) {
		wailsRuntime.EventsEmit(a.ctx, "luks:keyDeriving", map[string]any{
			"drivePath": drivePath,
			"offset":    volumeOffset,
			"stage":     stage,
			"tried":     tried,
			"total":     total,
			"info":      info,
		})
	}

	uv, err := luks.OpenAndUnlockWithProgress(underlying, volumeOffset, password, progressCb)
	if err != nil {
		underlying.Close()
		appLogger.Warn("LUKS 解锁失败", "err", err)
		// 区分错密码与其它错误，前端可以据此提示"再试一次"还是"换工具"
		if errors.Is(err, luks.ErrWrongPassword) {
			wailsRuntime.EventsEmit(a.ctx, "luks:wrongPassword", drivePath)
		}
		return fmt.Errorf("解锁失败: %w", err)
	}

	appLogger.Info("LUKS 解锁成功",
		"version", uv.Version,
		"slot", uv.SlotID,
		"cipher", uv.Cipher,
		"payloadOffset", uv.PayloadOffset,
		"payloadSize", uv.PayloadSize)

	wailsRuntime.EventsEmit(a.ctx, "luks:unlocked", map[string]any{
		"version":       uv.Version,
		"slotId":        uv.SlotID,
		"cipher":        uv.Cipher,
		"payloadOffset": uv.PayloadOffset,
		"payloadSize":   uv.PayloadSize,
	})

	a.mu.Lock()
	a.currentDrive = types.DriveInfo{Path: fmt.Sprintf("%s (LUKS%d 已解锁)", drivePath, uv.Version)}
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
			// 1) 关闭虚拟解密 reader（no-op 但语义一致）
			//    2) 关闭真正的底层磁盘 reader
			//    3) 把 master_key 从内存抹掉
			_ = uv.Reader.Close()
			if err := underlying.Close(); err != nil {
				appLogger.Warn("关闭 LUKS underlying reader 失败", "err", err)
			}
			_ = uv.Close()
		}()

		scanResult, err := a.engine.ScanWithReader(uv.Reader, types.ScanMode(mode), callbacks)
		close(stopPersist)

		a.scanSnapshotMu.Lock()
		a.scanActive = false
		a.scanSnapshotMu.Unlock()

		if err != nil {
			appLogger.Warn("LUKS 卷扫描出错", "err", err)
			wailsRuntime.EventsEmit(a.ctx, "scan:error", err.Error())
			return
		}
		appLogger.Info("LUKS 卷扫描完成", "files", len(scanResult.Files))
		a.saveSnapshot(true)
		wailsRuntime.EventsEmit(a.ctx, "scan:completed", scanResult)
	}()

	return nil
}
