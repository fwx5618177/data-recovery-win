package android

// ============================================================================
// Session: Android `.ab` 备份的高层访问 API
//
// 与 ios.Session 对齐的形态：
//   DialBackup → EnumerateFiles → RecoverFile → Close
//
// .ab 是流式 tar，没有"按 ID 跳读"能力。所以策略：
//   - EnumerateFiles 只产出元数据（不缓存内容），让 UI 选择
//   - 用户选定后 RecoverFile 是"再走一遍 tar 流到目标位置"——因为流式格式
//     不支持随机访问。如果用户一次选 N 个文件，我们做一次扫描批量提取，
//     而不是 N 次扫描（参见 RecoverMany）。
//
// 这与 iOS 的"按 hash 直接定位"模型不同；Engine 会用类似的接口但内部走批量。
// ============================================================================

import (
	"archive/tar"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ABEntry 一条 .ab 里的文件元数据（来自 tar header）
type ABEntry struct {
	Name      string    // tar 路径，例如 "apps/com.android.providers.media/db/external.db"
	Size      int64
	Mode      int64
	ModTime   time.Time
	IsDir     bool
	IsSymlink bool
	Linkname  string // 仅 IsSymlink=true
}

// Backup 一个已打开的 .ab 文件（路径 + 头部 + 可选 master key）
type Backup struct {
	Path     string
	Header   *ABHeader
	MasterKey *MasterKey // 仅加密 backup 解锁后非 nil
	// 缓存元数据：第一次 EnumerateFiles 把整个 tar 头扫一遍存这里
	entries []ABEntry
	// 偏移：每个 entry 在 tar 流里的字节起点（含 header）。
	// RecoverFile 重新打开流后跳到这里读 header + body。
	tarOffsets map[string]int64 // entry name → 它的 tar header 起点
}

// IsEncrypted 是否加密（已解锁不变）
func (b *Backup) IsEncrypted() bool { return b != nil && b.Header != nil && b.Header.IsEncrypted() }

// ErrEncrypted 表示尝试操作加密 backup 但没给密码
var ErrEncrypted = errors.New("加密 .ab 备份，需要密码解密")

// DialBackup 打开 .ab，按需解密 master key。
//
// password == "":
//   - 非加密 backup → 正常返回
//   - 加密 backup → 返回 ErrEncrypted（UI 弹密码框后再调一次）
func DialBackup(_ context.Context, path, password string) (*Backup, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("打开 .ab 失败: %w", err)
	}
	defer f.Close()

	header, err := ParseHeader(f)
	if err != nil {
		return nil, err
	}

	b := &Backup{Path: path, Header: header}

	if header.IsEncrypted() {
		if password == "" {
			return nil, ErrEncrypted
		}
		mk, err := DeriveAndDecryptMasterKey(header, password)
		if err != nil {
			return nil, err
		}
		b.MasterKey = mk
	}

	return b, nil
}

// Close 释放（目前 Session 不持有打开的 fd —— 每次操作 reopen 文件，
// 简单胜过精巧；.ab 通常 ≤ 几 GB，重新走流的开销可接受）。
func (b *Backup) Close() error {
	// 清掉敏感数据
	if b != nil && b.MasterKey != nil {
		for i := range b.MasterKey.Key {
			b.MasterKey.Key[i] = 0
		}
		b.MasterKey = nil
	}
	return nil
}

// EnumerateFiles 流式扫一遍 tar，把元数据填到 b.entries，回调每个文件给上层。
// 之后调用方可以按 entry.Name 调 RecoverFile。
//
// 性能：1 GB backup ~ 5-15s（取决于 zlib 解压速度）；这是流式格式的代价。
func (b *Backup) EnumerateFiles(ctx context.Context, onEntry func(ABEntry)) error {
	rc, _, err := b.openTarReader()
	if err != nil {
		return err
	}
	defer rc.Close()

	tr := tar.NewReader(rc)
	b.entries = b.entries[:0]
	if b.tarOffsets == nil {
		b.tarOffsets = make(map[string]int64)
	}

	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("tar Next: %w", err)
		}
		entry := ABEntry{
			Name:      hdr.Name,
			Size:      hdr.Size,
			Mode:      hdr.Mode,
			ModTime:   hdr.ModTime,
			IsDir:     hdr.Typeflag == tar.TypeDir,
			IsSymlink: hdr.Typeflag == tar.TypeSymlink,
			Linkname:  hdr.Linkname,
		}
		b.entries = append(b.entries, entry)

		if onEntry != nil {
			onEntry(entry)
		}

		// archive/tar 自动 skip 没读的 body —— 我们就不读 body
	}
	return nil
}

// Entries 返回已枚举的文件列表（必须在 EnumerateFiles 之后调用）。
func (b *Backup) Entries() []ABEntry {
	return b.entries
}

// RecoverFile 把一条 entry 的内容写到 outputPath。
//
// 实现策略：reopen tar 流，读到匹配的 entry name 时把 body 写出去。
// 对一次性恢复 N 个文件，请用 RecoverMany 避免 N 倍流扫描。
func (b *Backup) RecoverFile(ctx context.Context, entryName, outputPath string) error {
	return b.RecoverMany(ctx, []recoverItem{{Name: entryName, Out: outputPath}})
}

// recoverItem 一个待恢复条目
type recoverItem struct {
	Name string
	Out  string
}

// RecoverMany 一次扫描批量恢复多个文件。
//
// 给一组 (entry name → output path)，扫一次 tar 流提取所有匹配。
// 对"用户从 5000 个文件里勾了 200 个"的批量恢复场景大幅提速。
func (b *Backup) RecoverMany(ctx context.Context, items []recoverItem) error {
	if len(items) == 0 {
		return nil
	}
	want := make(map[string]string, len(items))
	for _, it := range items {
		want[it.Name] = it.Out
	}

	rc, _, err := b.openTarReader()
	if err != nil {
		return err
	}
	defer rc.Close()

	tr := tar.NewReader(rc)
	missing := len(want)

	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("tar Next: %w", err)
		}
		out, ok := want[hdr.Name]
		if !ok {
			continue
		}
		if err := writeTarEntry(tr, hdr, out); err != nil {
			return fmt.Errorf("写入 %s 失败: %w", out, err)
		}
		missing--
		if missing == 0 {
			break
		}
	}

	if missing > 0 {
		return fmt.Errorf("有 %d 个文件未在 .ab 里找到", missing)
	}
	return nil
}

func writeTarEntry(r io.Reader, hdr *tar.Header, outPath string) error {
	if err := os.MkdirAll(filepath.Dir(outPath), 0o755); err != nil {
		return err
	}
	switch hdr.Typeflag {
	case tar.TypeReg:
		f, err := os.Create(outPath)
		if err != nil {
			return err
		}
		defer f.Close()
		if _, err := io.Copy(f, r); err != nil {
			return err
		}
		return nil
	case tar.TypeDir:
		return os.MkdirAll(outPath, 0o755)
	case tar.TypeSymlink:
		// Windows 上创建 symlink 需要管理员权限；失败时改写一个文本提示文件
		if err := os.Symlink(hdr.Linkname, outPath); err != nil {
			return os.WriteFile(outPath+".symlink.txt",
				[]byte("symlink target: "+hdr.Linkname), 0o644)
		}
		return nil
	default:
		// 其它类型（FIFO / device / char）跳过
		return nil
	}
}

// openTarReader 打开文件 + Seek 到 PayloadOffset + 返回解码后的 tar reader
func (b *Backup) openTarReader() (io.ReadCloser, *os.File, error) {
	f, err := os.Open(b.Path)
	if err != nil {
		return nil, nil, fmt.Errorf("打开 .ab 失败: %w", err)
	}
	if _, err := f.Seek(b.Header.PayloadOffset, io.SeekStart); err != nil {
		f.Close()
		return nil, nil, fmt.Errorf("seek 到 payload 起点失败: %w", err)
	}
	rc, err := OpenPayloadReader(f, b.Header, b.MasterKey)
	if err != nil {
		f.Close()
		return nil, nil, err
	}
	// 包一层 ReadCloser，关闭时同时关 f
	return &fileBackedReadCloser{rc: rc, f: f}, f, nil
}

type fileBackedReadCloser struct {
	rc io.ReadCloser
	f  *os.File
}

func (b *fileBackedReadCloser) Read(p []byte) (int, error) { return b.rc.Read(p) }
func (b *fileBackedReadCloser) Close() error {
	rcErr := b.rc.Close()
	fErr := b.f.Close()
	if rcErr != nil {
		return rcErr
	}
	return fErr
}

// AppDomainFromPath 从 tar entry 路径推断"所属 App"
//
//   apps/com.example.app/db/users.db  → "com.example.app"
//   apps/com.foo/sp/prefs.xml         → "com.foo"
//   shared/0/Pictures/IMG.jpg         → "shared(共享存储)"
func AppDomainFromPath(p string) string {
	parts := strings.Split(p, "/")
	if len(parts) >= 2 && parts[0] == "apps" {
		return parts[1]
	}
	if len(parts) >= 1 && parts[0] == "shared" {
		return "shared(共享存储)"
	}
	return "(其它)"
}
