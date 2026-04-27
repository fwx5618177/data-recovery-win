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

// SEDStatus 是 sedutil-cli --query 的解析结果摘要。
//
// **v2.8.3 修**：之前的字段无 JSON tag，Wails 序列化用 PascalCase（Locked / Note），
// 前端用 camelCase（locked / note）读 → undefined → toast 显示 "SED: locked=undefined"。
// 现在统一加 JSON tag。
type SEDStatus struct {
	Available      bool   `json:"available"`      // 数据是否拿到
	IsSED          bool   `json:"isSED"`          // 盘支持 TCG (Opal / Enterprise / Pyrite)
	Locked         bool   `json:"locked"`         // 当前是否锁定（需要密码解锁）
	LockingEnabled bool   `json:"lockingEnabled"` // 启用了 locking SP（用户配过密码）
	OPALVersion    string `json:"opalVersion"`    // "1.0" / "2.0" / ""
	Note           string `json:"note"`           // 给用户友好的话
	Source         string `json:"source"`         // "sedutil" / "unavailable"
}

// QueryStatus 查 SED 状态。优先走 sedutil-cli（如装了）；没装就返回 Available=false
// + 带可执行指引的 Note，前端用 toast.warning 显示即可，不再"locked=undefined"。
func QueryStatus(ctx context.Context, devicePath string) (*SEDStatus, error) {
	bin := findSedutilCLI()
	if bin == "" {
		return &SEDStatus{
			Available: false,
			Source:    "unavailable",
			Note: "TCG OPAL 自加密硬盘检测需要 sedutil-cli（独立工具）。" +
				"普通用户的盘 99% 不是 SED，跳过此步对扫描无影响。" +
				"企业 SSD 想检测：装 https://github.com/Drive-Trust-Alliance/sedutil 后再点。",
		}, nil
	}
	subCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(subCtx, bin, "--query", devicePath).Output()
	if err != nil {
		return &SEDStatus{
			Available: false,
			Source:    "unavailable",
			Note:      fmt.Sprintf("sedutil 调用失败: %v", err),
		}, nil
	}
	s := parseSedutilOutput(string(out))
	s.Source = "sedutil"
	return s, nil
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
		s.Note = "SED 已锁定。用 sedutil-cli --setLockingRange 0 RW <password> 解锁后再扫。"
	case s.LockingEnabled:
		s.Note = "SED 已启用且当前未锁定（数据明文可读）。"
	case s.IsSED:
		s.Note = "盘支持 SED 但用户未启用 locking。"
	default:
		s.Note = "盘不支持 TCG SED 或未识别。"
	}
	return s
}
