package recovery

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// openOutputForWrite 是 APFS / HFS+ 这类"按 extent 顺序写出"恢复路径用的简单 helper：
// 创建/截断目标文件 + 自动 mkdir 父目录。
//
// 与 SafeWriter 的差别：SafeWriter 还做"去重 / 同盘检查 / 字节级 ReadAt 拷贝"等；
// extent 路径需要的只是个 io.WriteCloser，不重复实现那一套。
func openOutputForWrite(outputPath string) (io.WriteCloser, error) {
	if outputPath == "" {
		return nil, fmt.Errorf("outputPath 为空")
	}
	if err := os.MkdirAll(filepath.Dir(outputPath), 0o755); err != nil {
		return nil, fmt.Errorf("创建输出目录失败: %w", err)
	}
	f, err := os.Create(outputPath)
	if err != nil {
		return nil, fmt.Errorf("创建输出文件失败: %w", err)
	}
	return f, nil
}
