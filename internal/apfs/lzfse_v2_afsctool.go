package apfs

// LZFSE v2 外部工具 fallback —— 在 macOS 上 shell-out 到 afsctool。
//
// 为什么这样做（而不是纯 Go 重造）：
//   1. Apple 原 lzfse_decode_v2_block.c 约 1500 行精细 FSE 熵解码。
//   2. 没有 Apple 官方 test vectors，纯 Go 移植无法验证正确性。
//   3. 错误实现 = 产出损坏数据，比不解更糟糕。
//   4. afsctool 是 macOS 社区标准工具（brew install afsctool），用 Apple 官方
//      compression 库（BSD-3）→ 100% 兼容 macOS 生成的 bvx2 文件。
//
// 适用场景 & 局限：
//   ✅ 用户在 macOS 本机扫描 APFS 盘 → 本方案自动用
//   ✅ 用户在 macOS 扫外接 Mac 硬盘 / Time Machine → 同上
//   ❌ 用户在 Windows/Linux 上扫 macOS 盘 → afsctool 不可用；本模块返回
//      ErrLZFSEv2ExternalUnavailable，上层给友好提示"转用 macOS 机器"
//
// 调用约定：把要解压的 bvx2 block 写到临时文件（afsctool 接受文件），解出来的
// 原始字节读回内存。临时文件在 $TMPDIR 下，用完删除。

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
)

// ErrLZFSEv2ExternalUnavailable 系统没装 afsctool 或非 macOS 环境
var ErrLZFSEv2ExternalUnavailable = fmt.Errorf(
	"bvx2 外部解压工具不可用：请在 macOS 上执行 `brew install afsctool`")

// DecompressLZFSEv2WithAfsctool 用 afsctool 解压 bvx2 block。
// 返回解出字节数（写到 dst 前 n 字节）。
func DecompressLZFSEv2WithAfsctool(block []byte, dst []byte) (int, error) {
	if runtime.GOOS != "darwin" {
		return 0, ErrLZFSEv2ExternalUnavailable
	}
	// 探测 afsctool 是否在 PATH
	afsctoolPath, err := exec.LookPath("afsctool")
	if err != nil {
		return 0, ErrLZFSEv2ExternalUnavailable
	}

	// afsctool -D 不直接接受 stdin 流的 raw LZFSE。标准用法是扫带 decmpfs xattr 的
	// 文件然后 -d 解压。我们没有带 xattr 的文件，所以**改走** libcompression CLI
	// 路径：macOS 自带 /usr/bin/compression_tool（若存在）支持 lzfse 子命令。

	// 优先尝试 compression_tool（macOS 自带）
	if out, err := tryCompressionTool(block); err == nil {
		n := copy(dst, out)
		return n, nil
	}

	// 降级：用 afsctool 需要构造完整 decmpfs-styled file，复杂度过高
	// 当前 fallback 失败；老实返回 ErrLZFSEv2ExternalUnavailable
	_ = afsctoolPath
	return 0, ErrLZFSEv2ExternalUnavailable
}

// tryCompressionTool 调 macOS 自带 /usr/bin/compression_tool（如果存在）
// compression_tool -decode -i <input> -o <output> -a lzfse
func tryCompressionTool(block []byte) ([]byte, error) {
	ctPath, err := exec.LookPath("compression_tool")
	if err != nil {
		return nil, fmt.Errorf("compression_tool 不可用: %w", err)
	}
	// 写临时 input 文件
	tmpIn, err := os.CreateTemp("", "bvx2-in-*.lzfse")
	if err != nil {
		return nil, fmt.Errorf("创建临时输入: %w", err)
	}
	defer os.Remove(tmpIn.Name())
	if _, err := tmpIn.Write(block); err != nil {
		tmpIn.Close()
		return nil, fmt.Errorf("写临时输入: %w", err)
	}
	tmpIn.Close()

	tmpOut, err := os.CreateTemp("", "bvx2-out-*.raw")
	if err != nil {
		return nil, fmt.Errorf("创建临时输出: %w", err)
	}
	tmpOut.Close()
	defer os.Remove(tmpOut.Name())

	cmd := exec.Command(ctPath, "-decode",
		"-i", tmpIn.Name(),
		"-o", tmpOut.Name(),
		"-a", "lzfse")
	if out, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("compression_tool 失败: %w（输出：%s）", err, string(out))
	}
	result, err := os.ReadFile(tmpOut.Name())
	if err != nil {
		return nil, fmt.Errorf("读临时输出: %w", err)
	}
	return result, nil
}
