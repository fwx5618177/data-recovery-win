package ios

// ============================================================================
// iOS 备份扫描的"会话"总控：把 bplist + keybag + Manifest.db + 文件解密串起来。
//
// 生命周期：
//   DialBackup → (可能 Unlock) → EnumerateFiles → 对每个文件 Recover → Close
//
// 设计目的：Engine 层只需要和这个 Session 打交道，不用管加密/未加密两条路径。
// ============================================================================

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
)

// Session 一次 iOS 备份扫描的完整上下文。
type Session struct {
	Backup *Backup

	// 未加密备份里 this == nil；加密解锁成功后非 nil
	classKeys map[uint32][]byte

	// 已打开的 Manifest.db 连接
	db          *sql.DB
	manifestTmp string // 加密路径下，临时明文 db 的位置（Close 时删）
}

// DialBackup 打开一份备份，准备做文件枚举。
//
//   - 未加密备份：直接打开 Manifest.db
//   - 加密备份：
//     password == ""  → 返回 ErrEncrypted，UI 应要用户输密码后再调一次
//     password 正确   → 解 keybag + 解 Manifest.db 到临时文件 + 打开
//     password 错误   → 返回带"密码错误"字样的 err
func DialBackup(ctx context.Context, backup *Backup, password string) (*Session, error) {
	if backup == nil {
		return nil, fmt.Errorf("backup 为 nil")
	}
	if !backup.IsEncrypted {
		db, err := OpenManifestDB(backup.ManifestDBPath)
		if err != nil {
			return nil, err
		}
		return &Session{Backup: backup, db: db}, nil
	}

	// 加密路径
	if password == "" {
		return nil, ErrEncrypted
	}

	manifest, err := backup.ReadManifestPlist()
	if err != nil {
		return nil, fmt.Errorf("读 Manifest.plist 失败: %w", err)
	}
	bkbBlob := manifest.GetData("BackupKeyBag")
	if len(bkbBlob) == 0 {
		return nil, fmt.Errorf("manifest.plist 里没有 BackupKeyBag（不像是加密备份？）")
	}
	kb, err := ParseKeybag(bkbBlob)
	if err != nil {
		return nil, fmt.Errorf("解析 BackupKeyBag 失败: %w", err)
	}
	classKeys, err := kb.Unlock(password)
	if err != nil {
		return nil, fmt.Errorf("解锁备份失败（密码错？）：%w", err)
	}

	// ManifestKey 字段用来解 Manifest.db 本身
	mkBlob := manifest.GetData("ManifestKey")
	if len(mkBlob) == 0 {
		return nil, fmt.Errorf("manifest.plist 里没有 ManifestKey")
	}
	mk, err := DecryptManifestKey(mkBlob, classKeys)
	if err != nil {
		return nil, err
	}

	// 解到临时文件（.tmp，Close 时删除）
	tmp, err := os.CreateTemp("", "manifest-*.db")
	if err != nil {
		return nil, fmt.Errorf("创建临时明文 Manifest.db 失败: %w", err)
	}
	tmp.Close()
	if err := DecryptManifestDBFile(backup.ManifestDBPath, tmp.Name(), mk.Key); err != nil {
		os.Remove(tmp.Name())
		return nil, err
	}

	db, err := OpenManifestDB(tmp.Name())
	if err != nil {
		os.Remove(tmp.Name())
		return nil, err
	}

	return &Session{
		Backup:      backup,
		classKeys:   classKeys,
		db:          db,
		manifestTmp: tmp.Name(),
	}, nil
}

// Close 关闭数据库连接，删除解密出的临时文件。
func (s *Session) Close() error {
	if s == nil {
		return nil
	}
	var firstErr error
	if s.db != nil {
		if err := s.db.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
		s.db = nil
	}
	if s.manifestTmp != "" {
		if err := os.Remove(s.manifestTmp); err != nil && firstErr == nil && !os.IsNotExist(err) {
			firstErr = err
		}
		s.manifestTmp = ""
	}
	// class keys 里是敏感内存，用完清零（best effort；Go 不保证）
	for k, v := range s.classKeys {
		for i := range v {
			v[i] = 0
		}
		delete(s.classKeys, k)
	}
	return firstErr
}

// IsEncrypted 当前会话是否解锁的是加密备份。
func (s *Session) IsEncrypted() bool { return s != nil && s.classKeys != nil }

// EnumerateFiles 遍历 Manifest.db，把每条 file record 回调到 onRecord。
// 完全等价于 ios.EnumerateFiles(s.db, ...)，但作为 Session 方法更易用。
func (s *Session) EnumerateFiles(ctx context.Context, onRecord func(FileRecord)) error {
	return EnumerateFiles(ctx, s.db, onRecord)
}

// RecoverFile 把一条 file record 的内容写到 outputPath。
//
// 分支：
//   - 未加密备份：直接从 <backup>/<prefix>/<fileID> 拷贝
//   - 加密备份：
//     file record 有 EncryptionKey → 走 DecryptBackupFile
//     没有           → 备份本身加密但这条文件未加密（少见；直接拷贝）
func (s *Session) RecoverFile(rec FileRecord, outputPath string) error {
	if !rec.IsFile() {
		return fmt.Errorf("不是普通文件（flags=%d）", rec.Flags)
	}
	if rec.FileID == "" {
		return fmt.Errorf("FileID 为空")
	}
	srcPath := filepath.Join(s.Backup.Root, rec.FileID[:2], rec.FileID)
	if _, err := os.Stat(srcPath); err != nil {
		return fmt.Errorf("备份里找不到 %s: %w", srcPath, err)
	}

	if err := os.MkdirAll(filepath.Dir(outputPath), 0o755); err != nil {
		return fmt.Errorf("创建输出目录失败: %w", err)
	}

	// 加密 + 有 EncryptionKey：走 CBC 解密路径
	if s.IsEncrypted() && len(rec.EncryptionKey) > 0 {
		_, err := DecryptBackupFile(srcPath, outputPath, rec, s.classKeys)
		return err
	}

	// 其它：直接拷贝（未加密备份 / 备份加密但单文件未加密）
	return copyFile(srcPath, outputPath)
}

// copyFile 简单流式拷贝
func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()

	buf := make([]byte, 256*1024)
	for {
		n, rerr := in.Read(buf)
		if n > 0 {
			if _, werr := out.Write(buf[:n]); werr != nil {
				return werr
			}
		}
		if rerr != nil {
			if rerr.Error() == "EOF" || rerr == os.ErrClosed {
				return nil
			}
			// io.EOF —— 不视为错误
			// 这里不引 io 避免多一处 import；通过 n == 0 也能判断到结尾
			if n == 0 {
				return nil
			}
			break
		}
	}
	return nil
}
