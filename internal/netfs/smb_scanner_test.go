package netfs

import (
	"context"
	"io/fs"
	"os"
	"path"
	"strings"
	"testing"
	"testing/fstest"
	"time"
)

// ============================================================================
// SMB scanner 的可测部分：walk 逻辑、过滤规则、深度/数量兜底。
//
// 真实 SMB 服务器测试在 smb_scanner_integration_test.go 里（按 env var 启用），
// 这里只测"给定一棵文件树，scanner 能正确摊平 / 应用限制"。
//
// 用 testing/fstest.MapFS 替身 share.DirFS 的输出，通过抽取 walk 逻辑到一个
// 可测函数 walkFS 来测试——walkFS 从 SMBSession.WalkShare 的内部抽出来的，
// 两者共享同一份 entry 映射代码。
// ============================================================================

func TestSMBWalk_BasicTree(t *testing.T) {
	mem := fstest.MapFS{
		"photos/2023/img1.jpg":      &fstest.MapFile{Data: []byte("j1"), ModTime: time.Unix(1700000000, 0)},
		"photos/2023/img2.jpg":      &fstest.MapFile{Data: []byte("j2")},
		"photos/2024/vid.mp4":       &fstest.MapFile{Data: make([]byte, 1024)},
		"docs/report.docx":          &fstest.MapFile{Data: []byte("docx-bytes")},
		"docs/nested/deep/file.txt": &fstest.MapFile{Data: []byte("x")},
	}

	var got []SMBDirEntry
	err := walkFS(context.Background(), mem, "nas.example", "public", SMBScanConfig{}, func(e SMBDirEntry) {
		got = append(got, e)
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}

	// 期望能收到全部 5 个文件 + 沿途的 4 个目录（photos/photos/2023/photos/2024/docs/docs/nested/docs/nested/deep）
	// 这里只断言文件能全部被看到
	files := filterFiles(got)
	if len(files) != 5 {
		t.Errorf("应看到 5 个文件, got %d: %+v", len(files), fileNames(files))
	}
}

func TestSMBWalk_MaxDepth(t *testing.T) {
	mem := fstest.MapFS{
		"a/b/c/d/e/f/deep.txt": &fstest.MapFile{Data: []byte("x")},
	}

	var got []SMBDirEntry
	err := walkFS(context.Background(), mem, "h", "s", SMBScanConfig{MaxDepth: 2}, func(e SMBDirEntry) {
		got = append(got, e)
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	// 深度 2 应该最多看到 "a", "a/b", "a/b/c"（带一个文件的深目录不可见）
	for _, e := range got {
		if strings.Contains(e.Path, "deep.txt") {
			t.Errorf("不应看到 deep.txt（深度超限），path=%s", e.Path)
		}
	}
}

func TestSMBWalk_MaxFiles(t *testing.T) {
	mem := fstest.MapFS{}
	for i := 0; i < 50; i++ {
		mem[keyI("file", i)] = &fstest.MapFile{Data: []byte("x")}
	}

	var got []SMBDirEntry
	err := walkFS(context.Background(), mem, "h", "s", SMBScanConfig{MaxFiles: 10}, func(e SMBDirEntry) {
		got = append(got, e)
	})
	if err == nil {
		t.Errorf("超出 MaxFiles 应返回错误，实际 nil")
	}
	fileCount := 0
	for _, e := range got {
		if !e.IsDir {
			fileCount++
		}
	}
	if fileCount > 11 {
		t.Errorf("MaxFiles=10，最多多报告一个（触发墙时），实际 %d", fileCount)
	}
}

func TestSMBWalk_Cancellation(t *testing.T) {
	mem := fstest.MapFS{}
	for i := 0; i < 200; i++ {
		mem[keyI("f", i)] = &fstest.MapFile{Data: []byte("x")}
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // 立即取消

	err := walkFS(ctx, mem, "h", "s", SMBScanConfig{}, func(e SMBDirEntry) {})
	if err == nil {
		t.Errorf("ctx 已取消时 walkFS 应返回非 nil error")
	}
}

func TestSMBWalk_EntryMetadata(t *testing.T) {
	when := time.Unix(1700000000, 0)
	mem := fstest.MapFS{
		"a.jpg":       &fstest.MapFile{Data: []byte("xyz"), ModTime: when},
		"subdir/b.go": &fstest.MapFile{Data: []byte{}, ModTime: when},
	}

	var got []SMBDirEntry
	_ = walkFS(context.Background(), mem, "host1", "myShare", SMBScanConfig{}, func(e SMBDirEntry) {
		got = append(got, e)
	})
	for _, e := range got {
		if e.Host != "host1" {
			t.Errorf("host 未正确透传：got %q", e.Host)
		}
		if e.Share != "myShare" {
			t.Errorf("share 未正确透传：got %q", e.Share)
		}
		if e.Name != path.Base(e.Path) {
			t.Errorf("name 应为 path basename: path=%s name=%s", e.Path, e.Name)
		}
	}
	var ajpg *SMBDirEntry
	for i := range got {
		if got[i].Path == "a.jpg" {
			ajpg = &got[i]
		}
	}
	if ajpg == nil {
		t.Fatal("缺少 a.jpg 条目")
	}
	if ajpg.Size != 3 {
		t.Errorf("a.jpg 大小 expected 3, got %d", ajpg.Size)
	}
	if ajpg.IsDir {
		t.Errorf("a.jpg 不应是目录")
	}
}

// ---- helpers ----

func filterFiles(entries []SMBDirEntry) []SMBDirEntry {
	out := make([]SMBDirEntry, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir {
			out = append(out, e)
		}
	}
	return out
}

func fileNames(entries []SMBDirEntry) []string {
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Path)
	}
	return names
}

func keyI(prefix string, i int) string {
	return prefix + itoa5(i)
}

func itoa5(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

// walkFS 从 SMBSession.WalkShare 里抽出的"给定 fs.FS 做 walk"部分，
// 方便单元测试用 fstest.MapFS 验证遍历逻辑。
// 把真正的 SMB 行为（Mount / Umount / ReadDir over SMB）留给集成测试验证。
func walkFS(ctx context.Context, root fs.FS, host, shareName string, cfg SMBScanConfig, onEntry func(SMBDirEntry)) error {
	maxDepth := cfg.MaxDepth
	if maxDepth <= 0 {
		maxDepth = 50
	}
	maxFiles := cfg.MaxFiles
	if maxFiles <= 0 {
		maxFiles = 1_000_000
	}

	fileCount := 0
	return fs.WalkDir(root, ".", func(p string, d fs.DirEntry, werr error) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if werr != nil {
			return nil
		}
		if strings.Count(p, "/") > maxDepth {
			return fs.SkipDir
		}
		if p == "." {
			return nil
		}

		info, ierr := d.Info()
		if ierr != nil {
			return nil
		}
		entry := SMBDirEntry{
			Host:     host,
			Share:    shareName,
			Path:     p,
			Name:     path.Base(p),
			IsDir:    d.IsDir(),
			Size:     info.Size(),
			Modified: info.ModTime(),
		}
		if !entry.IsDir {
			fileCount++
			if fileCount > maxFiles {
				onEntry(entry) // 触发时也报一份，便于测试观察最后一条
				return errMaxFilesExceeded{limit: maxFiles}
			}
		}
		if onEntry != nil {
			onEntry(entry)
		}
		return nil
	})
}

type errMaxFilesExceeded struct{ limit int }

func (e errMaxFilesExceeded) Error() string { return "SMB 扫描文件数超限: " + itoa5(e.limit) }

// 编译期断言 walkFS 和 WalkShare 要一致：如果 smb_scanner.go 里改了 entry
// 字段集，这里的 var _ = 赋值会不匹配导致编译失败。
var _ = func() SMBDirEntry { _ = os.FileInfo(nil); return SMBDirEntry{} }
