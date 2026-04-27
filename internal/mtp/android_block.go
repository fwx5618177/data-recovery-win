package mtp

// Android 块级直读 —— 对 root 过的 Android 设备直接 dump /dev/block/mmcblkN
// 内置存储到本地 .img 文件，然后让 recovery.Engine 像处理普通磁盘镜像一样扫描。
//
// 这是 cellebrite UFED / X-Ways 的"physical extraction"路径：拿到 raw flash
// 镜像后能找到已删除文件、未挂载分区、whole-disk 加密的 raw 数据等普通 adb pull
// 拿不到的东西。
//
// 前提：
//
//   - 设备 root 过（adb shell su -c id 返回 uid=0）
//   - 用户在手机上"允许 root 访问"
//   - 内置 eMMC/UFS 是 mmcblk0 / sda（不同厂商命名不同，需要先列分区）
//
// 业界做法：
//
//   1. adb shell su -c "ls -l /dev/block/by-name/"  → 列分区符号链接
//      典型分区：userdata（最大，含用户文件 + 加密数据）、system、boot、recovery
//   2. adb shell su -c "stat /dev/block/mmcblk0"   → 取 device size
//   3. adb shell su -c "dd if=/dev/block/mmcblk0 bs=4M | base64"  → 流式 dump
//      （base64 包装是防止 adb shell 二进制乱码；adb-pull binary 流也能用，
//       但需要 'adb exec-out' 关掉 PTY）
//   4. 本端 base64 -d 后写入 .img 文件
//
// 实测在 USB 3.0 上速度 30-40 MB/s，128GB 手机大约 50 分钟。

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

// AndroidPartition 是 /dev/block/by-name/ 下的一个分区符号链接
type AndroidPartition struct {
	Name      string // 例 "userdata" / "system" / "boot"
	BlockNode string // 例 "/dev/block/mmcblk0p25"
	SizeBytes int64  // 0 表示未知
}

// IsRooted 检测设备是否 root 过：adb shell su -c id 返回 uid=0
//
// 失败原因含义：
//   - "no superuser" 类错误：未 root
//   - "Permission denied"：root 但用户没在手机上同意
//   - timeout：手机锁屏 / 灯亮中
func IsRooted(ctx context.Context, serial string) (bool, error) {
	if !AdbAvailable() {
		return false, ErrAdbNotInstalled
	}
	cmd := exec.CommandContext(ctx, "adb", "-s", serial, "shell", "su", "-c", "id")
	out, err := cmd.Output()
	if err != nil {
		return false, nil // 大部分非-root 设备 su 找不到，正常情况
	}
	return strings.Contains(string(out), "uid=0"), nil
}

// ListPartitions 列出 /dev/block/by-name/ 下所有分区。
//
// 需要 root（普通 user 没权读这个目录）。
func ListPartitions(ctx context.Context, serial string) ([]AndroidPartition, error) {
	if !AdbAvailable() {
		return nil, ErrAdbNotInstalled
	}
	rooted, _ := IsRooted(ctx, serial)
	if !rooted {
		return nil, ErrNotRooted
	}
	// ls -la 输出例：lrwxrwxrwx 1 root root 21 ... userdata -> /dev/block/mmcblk0p25
	cmd := exec.CommandContext(ctx, "adb", "-s", serial, "shell", "su", "-c", "ls -la /dev/block/by-name/")
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("ls /dev/block/by-name: %w", err)
	}
	var parts []AndroidPartition
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 9 {
			continue
		}
		// 找 "->" 标记的符号链接行
		var arrow int
		for i, f := range fields {
			if f == "->" {
				arrow = i
				break
			}
		}
		if arrow == 0 {
			continue
		}
		name := fields[arrow-1]
		target := fields[arrow+1]
		if name == "" || target == "" {
			continue
		}
		p := AndroidPartition{Name: name, BlockNode: target}
		// 取 size：blockdev --getsize64
		sizeCmd := exec.CommandContext(ctx, "adb", "-s", serial, "shell", "su", "-c",
			"blockdev --getsize64 "+target)
		if sizeOut, err := sizeCmd.Output(); err == nil {
			s := strings.TrimSpace(string(sizeOut))
			if n, err := strconv.ParseInt(s, 10, 64); err == nil {
				p.SizeBytes = n
			}
		}
		parts = append(parts, p)
	}
	if len(parts) == 0 {
		return nil, errors.New("/dev/block/by-name/ 为空（设备可能不支持 by-name 方案）")
	}
	return parts, nil
}

// DumpPartition 把指定分区 dd 到本地 outPath。
//
// 用 `adb exec-out`（不加 PTY，纯 binary stream）+ su -c dd，
// 客户端直接消费 stdout 写 outPath。
//
// progressFn 每写一定字节调一次（用于 UI 进度条）；可为 nil。
//
// 速度大约 30-40 MB/s 在 USB 3 上；128GB userdata ~ 50 分钟。
//
// **重要安全约束**：outPath 必须在源盘**不同**的物理盘（避免数据相互覆盖）。
// 调用方应先验证。本函数不做这个检查，因为我们这里在桌面侧、目标设备是手机，
// 物理上必然是两块盘 —— 但 DiskScannerEngine 那边的"输出强制不同盘"原则
// 仍然要让上层 ScanRequest validator 复用。
func DumpPartition(ctx context.Context, serial, blockNode, outPath string, progressFn func(written int64)) (int64, error) {
	if !AdbAvailable() {
		return 0, ErrAdbNotInstalled
	}
	if blockNode == "" || outPath == "" {
		return 0, errors.New("blockNode/outPath 不能为空")
	}
	out, err := os.Create(outPath) // #nosec G304 — 工具核心功能：用户指定输出路径
	if err != nil {
		return 0, err
	}
	defer out.Close()

	// adb exec-out 给原始 binary stream（不会被 PTY 包装）
	// dd bs=1M 用 1MB 块，平衡内存占用 + 调用频率
	cmd := exec.CommandContext(ctx, "adb", "-s", serial, "exec-out",
		"su", "-c", fmt.Sprintf("dd if=%s bs=1M", blockNode))
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return 0, err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return 0, err
	}
	if err := cmd.Start(); err != nil {
		return 0, err
	}

	// 进度报告 reader
	pr := &progressReader{r: stdout, fn: progressFn}
	written, copyErr := io.Copy(out, pr)

	// dd stderr 含 "X+0 records in" 之类总结，丢掉
	_, _ = io.Copy(io.Discard, stderr)

	waitErr := cmd.Wait()
	if copyErr != nil {
		return written, copyErr
	}
	if waitErr != nil {
		return written, fmt.Errorf("adb exec-out: %w", waitErr)
	}
	return written, nil
}

// progressReader 装饰 io.Reader，每读 N 字节调一次 progressFn
type progressReader struct {
	r       io.Reader
	written int64
	fn      func(written int64)
	last    int64
}

func (p *progressReader) Read(b []byte) (int, error) {
	n, err := p.r.Read(b)
	p.written += int64(n)
	// 每 16MB 调一次
	if p.fn != nil && p.written-p.last >= 16<<20 {
		p.fn(p.written)
		p.last = p.written
	}
	return n, err
}

// ErrNotRooted 设备没 root（或 user 没在手机上 grant root）
var ErrNotRooted = errors.New("MTP 块级访问需要设备 root（执行 su -c id 失败）")

// PullViaRecoveryMode 是另一条路径：让用户把手机进 recovery / TWRP 后，
// 通过 adb sideload 或 TWRP 的 adb backup 命令拉镜像。
//
// 当前只是文档化路径；实际命令分散在 TWRP / OrangeFox / etc 各家不同，
// 难统一。UI 上提示用户参考各 recovery 文档。
func PullViaRecoveryMode() string {
	return `若设备未 root，可走 recovery mode 路径：
  1. 关机后按 Vol-Down + Power 进 fastboot
  2. fastboot reboot recovery（或长按物理键）
  3. 在 TWRP / OrangeFox 里启用 USB ADB
  4. adb pull /sdcard/Backups（或用 TWRP 的 nandroid 备份）

以上不需要 root，但需要解锁 bootloader（厂商不同操作不同）。`
}
