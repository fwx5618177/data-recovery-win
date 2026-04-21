// Package sed 检测 Self-Encrypting Drive (SED) — TCG OPAL / Enterprise / Pyrite。
//
// **SED 的关键事实**：硬件加密在控制器里完成，**对操作系统完全透明** —— 系统发起 ATA/NVMe
// 读，控制器在内部解密返回明文。所以从 OS 视角"看不出"盘是 SED。
//
// 我们能识别的特征：
//   - 通过 hdparm / sedutil-cli / nvme-cli 查询盘的 TCG SP（Security Provider）状态
//   - SED Lock 状态盘读 ATA 命令时只能读到 PBA 区（Pre-Boot Authentication 镜像）
//
// 本工具不直接发 ATA 命令（需要 OS-specific raw block ioctl + admin）；
// 提供"调 sedutil-cli 拿状态"的封装。没装 sedutil-cli 时返回友好提示。
//
// 用户场景：企业 SSD 多数支持 SED 但默认未启用；启用后必须先输入密码解锁才能读数据，
// 本工具识别到 SED 锁定就提示用户"用 sedutil 解锁后再扫"。
package sed

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// SEDStatus 是 sedutil-cli --query 的解析结果摘要
type SEDStatus struct {
	Available    bool   // sedutil-cli 装了没
	IsSED        bool   // 盘支持 TCG (Opal / Enterprise / Pyrite)
	Locked       bool   // 当前是否锁定（需要密码解锁）
	LockingEnabled bool // 启用了 locking SP（用户配过密码）
	OPALVersion  string // "1.0" / "2.0" / ""
	Note         string
}

// QueryStatus 调 sedutil-cli 拿状态
func QueryStatus(ctx context.Context, devicePath string) (*SEDStatus, error) {
	bin := findSedutilCLI()
	if bin == "" {
		return &SEDStatus{
			Available: false,
			Note:      "未安装 sedutil-cli。装 https://github.com/Drive-Trust-Alliance/sedutil 后可查 SED 状态。",
		}, nil
	}
	subCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(subCtx, bin, "--query", devicePath).Output()
	if err != nil {
		return &SEDStatus{Available: false, Note: fmt.Sprintf("sedutil 调用失败: %v", err)}, nil
	}
	return parseSedutilOutput(string(out)), nil
}

func findSedutilCLI() string {
	for _, name := range []string{"sedutil-cli", "sedutil-cli.exe"} {
		if p, err := exec.LookPath(name); err == nil {
			return p
		}
	}
	return ""
}

func parseSedutilOutput(text string) *SEDStatus {
	s := &SEDStatus{Available: true}
	for _, line := range strings.Split(text, "\n") {
		l := strings.ToLower(strings.TrimSpace(line))
		switch {
		case strings.Contains(l, "opal"):
			s.IsSED = true
			if strings.Contains(l, "2.") {
				s.OPALVersion = "2.0"
			} else if strings.Contains(l, "1.") {
				s.OPALVersion = "1.0"
			}
		case strings.HasPrefix(l, "lockingenabled"):
			s.LockingEnabled = strings.Contains(l, "y")
		case strings.HasPrefix(l, "locked"):
			s.Locked = strings.Contains(l, "y")
		}
	}
	switch {
	case s.Locked:
		s.Note = "⚠️ SED 已锁定。用 sedutil-cli --setLockingRange 0 RW <password> 解锁后再扫。"
	case s.LockingEnabled:
		s.Note = "✅ SED 已启用且当前未锁定（数据明文可读）。"
	case s.IsSED:
		s.Note = "ℹ️ 盘支持 SED 但用户未启用 locking。"
	default:
		s.Note = "盘不支持 TCG SED 或未识别。"
	}
	return s
}
