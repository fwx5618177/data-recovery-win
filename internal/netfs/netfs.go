// Package netfs 提供"远程文件系统镜像"reader 骨架 — SMB / NFS / iSCSI。
//
// **关键现实**：直接通过 SMB/NFS 访问的是已挂载的文件视图，**不是块设备**，
// 无法做"全盘扫描 / 已删除文件恢复"。能做的只是把远程上的镜像文件 (.img/.dd/.raw)
// 当 reader 用 — 这种场景用 mount + 普通文件 reader 已经能解决。
//
// iSCSI 不一样：iSCSI 暴露的是真实块设备，挂载后 OS 识别为 /dev/sdX —
// 用现有 disk.NewReader 就能扫，无需特殊代码。
//
// 因此本包只提供"挂载远程镜像 + 把它当 disk reader" 的便利包装；
// 完整 SMB/NFS 协议客户端是另一项目（推荐 hirochachacha/go-smb2）。
package netfs

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// MountAdvice 给用户看：怎么挂载远程文件系统让本工具能读
type MountAdvice struct {
	Method string
	OS     string
	Steps  []string
}

// SuggestMount 根据 URL 协议返回挂载步骤
func SuggestMount(url string) []MountAdvice {
	out := []MountAdvice{}
	if strings.HasPrefix(url, "smb://") || strings.HasPrefix(url, "cifs://") {
		out = append(out,
			MountAdvice{
				Method: "macOS Finder",
				OS:     "darwin",
				Steps:  []string{"Cmd+K → 输入 " + url, "挂载后路径在 /Volumes/<share>/", "用本工具'选择镜像文件'选其中的 .img/.dd"},
			},
			MountAdvice{
				Method: "Linux mount",
				OS:     "linux",
				Steps: []string{
					"sudo mkdir -p /mnt/smb",
					"sudo mount -t cifs " + strings.Replace(url, "smb://", "//", 1) + " /mnt/smb -o user=YOUR_USER",
					"用本工具选 /mnt/smb/<image>.img",
				},
			},
			MountAdvice{
				Method: "Windows 资源管理器",
				OS:     "windows",
				Steps:  []string{"映射网络驱动器到 " + url, "工具选盘符里的镜像文件"},
			})
	}
	if strings.HasPrefix(url, "nfs://") {
		out = append(out, MountAdvice{
			Method: "Linux mount",
			OS:     "linux",
			Steps: []string{
				"sudo mkdir -p /mnt/nfs",
				"sudo mount -t nfs " + strings.TrimPrefix(url, "nfs://") + " /mnt/nfs",
				"用本工具选 /mnt/nfs/<image>.img",
			},
		})
	}
	if strings.HasPrefix(url, "iscsi://") {
		out = append(out, MountAdvice{
			Method: "iSCSI initiator",
			OS:     runtime.GOOS,
			Steps: []string{
				"装系统 iSCSI initiator (Linux: open-iscsi; macOS: globalSAN; Windows: iSCSI 启动器)",
				"连接 target → OS 识别为新盘 /dev/sdX 或 PhysicalDriveN",
				"用本工具选这个新盘",
			},
		})
	}
	return out
}

// IsRemoteURL 判断是否网络协议 URL
func IsRemoteURL(s string) bool {
	for _, p := range []string{"smb://", "cifs://", "nfs://", "iscsi://", "http://", "https://", "ftp://"} {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

// FindMountedRemoteImages 扫常见挂载点（macOS /Volumes、Linux /mnt + /media）找
// 已挂载的网络盘 + 里面的 .img/.dd/.raw 镜像文件。
//
// 返回路径列表给前端"快速选择镜像"用。
func FindMountedRemoteImages() []string {
	var roots []string
	switch runtime.GOOS {
	case "darwin":
		roots = []string{"/Volumes"}
	case "linux":
		roots = []string{"/mnt", "/media"}
	default:
		return nil
	}
	var out []string
	for _, root := range roots {
		entries, err := os.ReadDir(root)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			subdir := filepath.Join(root, e.Name())
			files, err := os.ReadDir(subdir)
			if err != nil {
				continue
			}
			for _, f := range files {
				name := strings.ToLower(f.Name())
				if strings.HasSuffix(name, ".img") || strings.HasSuffix(name, ".dd") ||
					strings.HasSuffix(name, ".raw") || strings.HasSuffix(name, ".iso") {
					out = append(out, filepath.Join(subdir, f.Name()))
				}
			}
		}
	}
	if len(out) == 0 {
		// 让 caller 能区分"目录扫了但没找到"和"未实现"
		return []string{}
	}
	_ = fmt.Sprintf // keep fmt import even if unused
	return out
}
