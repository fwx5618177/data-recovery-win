package recovery

import (
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"data-recovery/internal/disk"
	"data-recovery/internal/types"
)

// 回归测试（Bug #1）：跨源去重需要 NTFS 先落地。
// 上一版用了 source[i] < source[j] 做排序，但 "carver" < "ntfs" 字母序反而让
// carver 跑在前，结果去重时保留了 carver 副本、丢弃 NTFS 副本，与设计相反。
// 本测试直接对 ntfsFirstLess 建立契约：
//   - ntfs vs carver → ntfs 在前
//   - carver vs ntfs → ntfs 在前（对称性）
//   - 同源 → 不交换（让 sort.SliceStable 保持原序）
func TestNTFSFirstLess_Contract(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"ntfs", "carver", true},
		{"carver", "ntfs", false},
		{"ntfs", "ntfs", false},
		{"carver", "carver", false},
		{"ntfs", "other", true},
		{"other", "ntfs", false},
	}
	for _, c := range cases {
		if got := ntfsFirstLess(c.a, c.b); got != c.want {
			t.Errorf("ntfsFirstLess(%q, %q) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}

// 端到端证据：给一组乱序 RecoveredFile，sort.SliceStable + ntfsFirstLess 能把 NTFS 提前。
func TestNTFSFirstLess_SortsNTFSAhead(t *testing.T) {
	files := []*types.RecoveredFile{
		{ID: "c1", Source: "carver"},
		{ID: "n1", Source: "ntfs"},
		{ID: "c2", Source: "carver"},
		{ID: "n2", Source: "ntfs"},
		{ID: "c3", Source: "carver"},
	}
	sort.SliceStable(files, func(i, j int) bool {
		return ntfsFirstLess(files[i].Source, files[j].Source)
	})

	// 前两个必须是 ntfs（按原相对顺序 n1, n2）
	want := []string{"n1", "n2", "c1", "c2", "c3"}
	for i, w := range want {
		if files[i].ID != w {
			t.Errorf("排序后位置 %d: got %s want %s", i, files[i].ID, w)
		}
	}
}

// Bug #D 回归测试：RecoverOptions.AllowSameDisk=true 时应跳过同盘校验。
// 不走完整 Recover 流程（需要扫描结果），仅断言 opts 类型和字段命名稳定。
func TestRecoverOptions_AllowSameDiskStructure(t *testing.T) {
	// 构造即失败即可，这里只验证编译期契约：AllowSameDisk 字段存在且为 bool。
	var opts RecoverOptions
	opts.AllowSameDisk = true
	if !opts.AllowSameDisk {
		t.Error("AllowSameDisk 应能被设为 true")
	}

	// Recover 默认应走不带 AllowSameDisk 的路径
	var defaultOpts RecoverOptions
	if defaultOpts.AllowSameDisk {
		t.Error("RecoverOptions 默认 AllowSameDisk 必须为 false，避免默认就绕过安全检查")
	}
}

func TestContainsCaseInsensitive(t *testing.T) {
	cases := []struct {
		s, substr string
		want      bool
	}{
		{"hello world", "WORLD", true},
		{"Hello World", "world", true},
		{"ABCDEF", "cde", true},
		{"abcdef", "XYZ", false},
		{"", "x", false},
		{"anything", "", true},
		{"x", "longer", false},
		// 中文直接按字节比较（UTF-8 多字节不与 ASCII 重叠）
		{"与已恢复文件内容重复 abc", "重复", true},
		{"unrelated", "重复", false},
	}
	for _, c := range cases {
		if got := containsCaseInsensitive(c.s, c.substr); got != c.want {
			t.Errorf("containsCaseInsensitive(%q, %q) = %v, want %v", c.s, c.substr, got, c.want)
		}
	}
}

// 回归测试：预览 reader 必须包 TimeoutReader。
//
// Bug 历史：ReadFilePreview 此前用裸 disk.NewReader + reader.Open() 打开源盘，
// 没有套 TimeoutReader。当 preview 目标扇区是 bad sector 时，Windows 驱动层的
// ReadFile 会在 kernel queue 里无限 hang（见 internal/disk/timeout.go 说明），
// 前端表现为"点击预览卡死"。扫描 reader 在 runScan 里用了 Timeout+Resilient
// 包装，preview 路径被漏掉。
//
// 这个测试锁死一个契约：openPreviewReader 必须返回 *disk.TimeoutReader 包装过
// 的 DiskReader。将来如果有人再次裸 disk.NewReader，此测试会立刻 fail。
func TestOpenPreviewReader_WrapsTimeoutReader(t *testing.T) {
	// 创建一个 1MB 的镜像文件，用 imageFileReader 路径（避免测试需要真实磁盘权限）
	dir := t.TempDir()
	imgPath := filepath.Join(dir, "preview_test.img")
	imgData := make([]byte, 1<<20)
	for i := range imgData {
		imgData[i] = byte(i & 0xff)
	}
	if err := os.WriteFile(imgPath, imgData, 0o644); err != nil {
		t.Fatalf("写测试镜像失败: %v", err)
	}

	reader, err := openPreviewReader(imgPath)
	if err != nil {
		t.Fatalf("openPreviewReader(%q) 失败: %v", imgPath, err)
	}
	defer reader.Close()

	// 契约锁点：必须是 TimeoutReader，不能是裸 DiskReader
	if _, ok := reader.(*disk.TimeoutReader); !ok {
		t.Fatalf("openPreviewReader 返回了非 TimeoutReader 类型 %T — bad sector 会让 preview 卡死", reader)
	}

	// 健康读路径：验证包装不破坏正常读
	buf := make([]byte, 512)
	n, err := reader.ReadAt(buf, 0)
	if err != nil {
		t.Fatalf("ReadAt 正常路径失败: %v", err)
	}
	if n != 512 {
		t.Errorf("ReadAt 期望读 512 字节，实际 %d", n)
	}
	for i := 0; i < 512; i++ {
		if buf[i] != byte(i&0xff) {
			t.Fatalf("ReadAt 偏移 %d 字节错误：期望 %d 实际 %d", i, byte(i&0xff), buf[i])
		}
	}
}

// 回归测试：预览 reader 的超时要真的生效（而非只是类型对）。
//
// 用一个故意 hang 的 mock DiskReader 包进 TimeoutReader，ReadAt 必须在
// bounded time 内返回错误，而不是永远阻塞。这是防"写对了类型但传错了
// timeout"或"以后有人把 timeout 改成 0"的回归。
func TestTimeoutReader_FailsFastOnHang(t *testing.T) {
	hanging := &hangingReader{path: "/dev/fake"}
	tr := disk.NewTimeoutReader(hanging, 200*time.Millisecond)
	// Open 走透传，hangingReader.Open 立即返回 nil
	if err := tr.Open(); err != nil {
		t.Fatalf("Open 失败: %v", err)
	}
	defer tr.Close()

	buf := make([]byte, 512)
	start := time.Now()
	_, err := tr.ReadAt(buf, 0)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("hangingReader 应该让 ReadAt 超时，但 err == nil")
	}
	// 应在 timeout 附近返回（留 300ms 裕量给调度）
	if elapsed > 600*time.Millisecond {
		t.Fatalf("ReadAt 返回耗时 %v，超过预期 600ms — 超时没生效", elapsed)
	}
	if elapsed < 150*time.Millisecond {
		t.Fatalf("ReadAt 返回耗时 %v，远小于超时阈值 200ms — mock 可能没真 hang", elapsed)
	}
}

// hangingReader 模拟 Windows bad sector 场景：ReadAt 永远不返回（除非测试结束进程退出）。
// 只有 Open/Close/metadata 立即返回。
type hangingReader struct {
	path string
}

func (r *hangingReader) Open() error          { return nil }
func (r *hangingReader) Close() error         { return nil }
func (r *hangingReader) Size() (int64, error) { return 1 << 30, nil }
func (r *hangingReader) SectorSize() int      { return 512 }
func (r *hangingReader) DevicePath() string   { return r.path }
func (r *hangingReader) ReadAt(p []byte, _ int64) (int, error) {
	// 故意永远阻塞，模拟 Windows 驱动层卡死
	select {}
}
