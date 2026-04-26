package luks

// ============================================================================
// OpenAndUnlock —— 一站式入口：原始磁盘 + 密码 → 已解密的 DiskReader
//
// 这是给 app.go / engine 用的"傻瓜接口"：调用方完全不需要知道 LUKS1 / LUKS2
// 区别、KDF 是 PBKDF2 还是 Argon2、cipher 是 XTS 还是 ESSIV。
//
// 调用流程：
//   underlying = disk.NewReader(drivePath); underlying.Open()
//   uv, err := luks.OpenAndUnlock(underlying, volStart, password)
//   if err != nil { ... }
//   defer uv.Close()
//   engine.ScanWithReader(uv.Reader, ScanFull, callbacks)
//
// 性能：LUKS1 PBKDF2(1M iter, sha256) ~1-3s；LUKS2 Argon2id(t=4, m=1GB) ~2-5s。
// PBKDF2 / Argon2 是 atomic primitive，没有内部迭代回调。我们提供 *跨 keyslot*
// 的进度回调（"正在尝试 keyslot 2 / 8"），让多 keyslot 的 LUKS 卷在 UI 上有
// 可观察进度；UI 可以并联一个 spinner 表达"当前这个 keyslot 在跑 KDF"。
// ============================================================================

import (
	"errors"
	"fmt"
	"io"

	"data-recovery/internal/disk"
)

// UnlockedVolume 是 OpenAndUnlock 的返回结果
type UnlockedVolume struct {
	// Reader 是"虚拟解密磁盘"，下游 NTFS / ext4 / APFS 等扫描器直接 ReadAt 即可
	Reader *DecryptedReader

	// Version: 1 表示 LUKS1，2 表示 LUKS2
	Version uint16

	// SlotID: 命中的 keyslot 标识（LUKS1 是 "0"–"7" 数字，LUKS2 是 keyslot 名）
	SlotID string

	// Cipher 是被识别出来的加密配置，给 UI 展示（"aes-xts-plain64"）
	Cipher string

	// PayloadOffset: 解密区在原始磁盘上的字节偏移（payload 起点）
	PayloadOffset int64

	// PayloadSize: 解密视图的总字节数；0 表示直到底层末尾
	PayloadSize int64

	// MasterKey: master_key 副本——只在内存中、调用 Close() 后会被清零
	// 暴露给上层只为调试/取证报告；扫描路径不需要直接用
	MasterKey []byte

	// underlying 不在结构体里直接暴露，但 Close() 时不主动关——所有权属于调用方。
}

// Close 清掉内存里的 master key（防止 dump core 后泄密）。
// 不关闭 underlying reader——所有权在调用方。
func (u *UnlockedVolume) Close() error {
	if u == nil {
		return nil
	}
	for i := range u.MasterKey {
		u.MasterKey[i] = 0
	}
	u.MasterKey = nil
	return nil
}

// UnlockProgress 是跨 keyslot 的进度回调。
//
//	stage  典型取值："header_read" / "trying_keyslot" / "verifying_digest" / "ready"
//	tried  当前已尝试的 keyslot 数（含正在跑的）
//	total  本卷 active keyslot 总数
//	info   人类可读上下文（"keyslot 2/argon2id"）
//
// 任何 stage 调用都允许 nil；UI 通常只关心 "trying_keyslot"。
type UnlockProgress func(stage string, tried, total int, info string)

// OpenAndUnlock 是高层入口：检测 LUKS 版本，按密码解锁，返回可读虚拟卷。
//
// volStart 是 LUKS 容器在 underlying 上的起始字节偏移（整盘当 LUKS 卷时传 0）。
// password 是用户输入的密码（任何 keyslot 解开都成功）。
//
// 失败原因可能是：
//   - 不是 LUKS 容器（magic 不对）
//   - 密码错（ErrWrongPassword）
//   - 不支持的 cipher / KDF（ErrUnsupportedCipher 或 deriveLUKS2KDF 报错）
//   - 底层读盘失败（IO 错）
//
// 上层应在 UI 上把这几类错误分开提示。
func OpenAndUnlock(reader disk.DiskReader, volStart int64, password string) (*UnlockedVolume, error) {
	return OpenAndUnlockWithProgress(reader, volStart, password, nil)
}

// OpenAndUnlockWithProgress 同 OpenAndUnlock，但接收一个跨 keyslot 进度回调。
// progress 为 nil 时与 OpenAndUnlock 完全等价。
func OpenAndUnlockWithProgress(reader disk.DiskReader, volStart int64, password string, progress UnlockProgress) (*UnlockedVolume, error) {
	if reader == nil {
		return nil, errors.New("OpenAndUnlock: reader 为 nil")
	}
	if password == "" {
		return nil, errors.New("OpenAndUnlock: 密码为空")
	}

	if progress != nil {
		progress("header_read", 0, 0, "读取 LUKS 头部")
	}
	// 读 16KB（够覆盖 LUKS2 binary header + JSON metadata；LUKS1 phdr 只占前 1KB）
	hdrBuf := make([]byte, 16*1024)
	n, err := reader.ReadAt(hdrBuf, volStart)
	if err != nil && err != io.EOF {
		return nil, fmt.Errorf("OpenAndUnlock: 读 LUKS header: %w", err)
	}
	if n < 1024 || !startsWith(hdrBuf, luksMagic) {
		return nil, errors.New("OpenAndUnlock: 不是 LUKS 容器（magic 不匹配）")
	}

	// 由 version 字段区分 LUKS1 vs LUKS2
	switch hdrBuf[7] { // big-endian uint16 第二字节就是低 8 位
	case 1:
		return unlockLUKS1AsVolume(reader, volStart, hdrBuf, password, progress)
	case 2:
		return unlockLUKS2AsVolume(reader, volStart, hdrBuf, password, progress)
	default:
		return nil, fmt.Errorf("OpenAndUnlock: 不支持的 LUKS 版本 %d", hdrBuf[7])
	}
}

func unlockLUKS1AsVolume(reader disk.DiskReader, volStart int64, hdrBuf []byte, password string, progress UnlockProgress) (*UnlockedVolume, error) {
	hdr, err := ParseLUKS1Header(hdrBuf[:1024])
	if err != nil {
		return nil, fmt.Errorf("LUKS1 header 解析: %w", err)
	}
	if progress != nil {
		// 统计 active keyslot 数；总共最多 8 个
		total := 0
		for _, ks := range hdr.Keyslots {
			if ks.Active {
				total++
			}
		}
		progress("trying_keyslot", 0, total, fmt.Sprintf("LUKS1 (%s-%s)", hdr.CipherName, hdr.CipherMode))
	}
	mk, slot, err := UnlockLUKS1(reader, volStart, hdr, password)
	if err != nil {
		return nil, err
	}
	if progress != nil {
		progress("ready", 1, 1, fmt.Sprintf("命中 keyslot %d", slot))
	}

	// payload 起点 = volStart + payload_offset(扇区) * 512
	payloadOff := volStart + int64(hdr.PayloadOffset)*512
	cipher, err := NewSectorCipher(hdr.CipherName, hdr.CipherMode, mk)
	if err != nil {
		return nil, fmt.Errorf("LUKS1 SectorCipher: %w", err)
	}

	// PayloadSize=0 → 走 underlying.Size() 自动算
	// CacheSectors=8192 → 4MB cache @ 512B sectors，覆盖 NTFS MFT hot 区
	dr, err := NewDecryptedReader(DecryptedReaderConfig{
		Underlying:   reader,
		Cipher:       cipher,
		PayloadOff:   payloadOff,
		DevicePath:   fmt.Sprintf("luks1-decrypted://%s", reader.DevicePath()),
		CacheSectors: 8192,
	})
	if err != nil {
		return nil, err
	}
	return &UnlockedVolume{
		Reader:        dr,
		Version:       1,
		SlotID:        fmt.Sprintf("%d", slot),
		Cipher:        fmt.Sprintf("%s-%s", hdr.CipherName, hdr.CipherMode),
		PayloadOffset: payloadOff,
		PayloadSize:   dr.payloadSize,
		MasterKey:     mk,
	}, nil
}

func unlockLUKS2AsVolume(reader disk.DiskReader, volStart int64, hdrBuf []byte, password string, progress UnlockProgress) (*UnlockedVolume, error) {
	bin, err := ParseLUKS2BinHeader(hdrBuf[:4096])
	if err != nil {
		return nil, fmt.Errorf("LUKS2 binary header: %w", err)
	}
	// JSON 区域在 4KB 起，长度由 hdr_size - 4096 给出
	jsonEnd := bin.HdrSize
	if jsonEnd > uint64(len(hdrBuf)) {
		jsonEnd = uint64(len(hdrBuf))
	}
	jsonBuf := hdrBuf[4096:jsonEnd]
	meta, err := ParseLUKS2Metadata(jsonBuf)
	if err != nil {
		return nil, fmt.Errorf("LUKS2 metadata: %w", err)
	}

	// 不强制 checksum 通过——损坏的 header 仍然可能解开
	_ = VerifyLUKS2HeaderChecksum(hdrBuf[:4096], jsonBuf, bin.CsumAlg)

	if progress != nil {
		// 数 luks2 类型的 keyslot
		total := 0
		for _, ks := range meta.Keyslots {
			if ks != nil && ks.Type == "luks2" {
				total++
			}
		}
		progress("trying_keyslot", 0, total, fmt.Sprintf("LUKS2 (%d keyslot)", total))
	}
	mk, slotID, err := UnlockLUKS2(reader, volStart, bin, meta, password)
	if err != nil {
		return nil, err
	}
	if progress != nil {
		progress("ready", 1, 1, fmt.Sprintf("命中 keyslot %s", slotID))
	}

	// 选 default segment（只支持单 segment 的"普通卷"；reencrypt 中的卷不解）
	seg := pickDefaultSegment(meta.Segments)
	if seg == nil {
		return nil, errors.New("LUKS2 metadata 无可用 segment")
	}
	payloadOff := volStart
	if seg.Offset != "" {
		var ofs int64
		if _, err := fmt.Sscanf(seg.Offset, "%d", &ofs); err == nil {
			payloadOff += ofs
		}
	}
	var payloadSize int64
	if seg.Size != "" && seg.Size != "dynamic" {
		_, _ = fmt.Sscanf(seg.Size, "%d", &payloadSize)
	}
	var ivTweak uint64
	if seg.IVTweak != "" {
		_, _ = fmt.Sscanf(seg.IVTweak, "%d", &ivTweak)
	}

	cipherName, cipherMode, err := splitEncryption(seg.Encryption)
	if err != nil {
		return nil, err
	}
	// segment.sector_size 默认 512；LUKS2 spec 也允许 4096（4K 原生盘 / NVMe AF）
	dataSectorSize := seg.SectorSize
	if dataSectorSize == 0 {
		dataSectorSize = 512
	}
	cipher, err := NewSectorCipherWithSize(cipherName, cipherMode, mk, dataSectorSize)
	if err != nil {
		return nil, fmt.Errorf("LUKS2 SectorCipher: %w", err)
	}

	dr, err := NewDecryptedReader(DecryptedReaderConfig{
		Underlying:   reader,
		Cipher:       cipher,
		PayloadOff:   payloadOff,
		PayloadSize:  payloadSize,
		IVBase:       ivTweak,
		DevicePath:   fmt.Sprintf("luks2-decrypted://%s", reader.DevicePath()),
		CacheSectors: 8192,
	})
	if err != nil {
		return nil, err
	}
	return &UnlockedVolume{
		Reader:        dr,
		Version:       2,
		SlotID:        slotID,
		Cipher:        seg.Encryption,
		PayloadOffset: payloadOff,
		PayloadSize:   dr.payloadSize,
		MasterKey:     mk,
	}, nil
}

// pickDefaultSegment 选第一个 type=="crypt" 的 segment。
// LUKS2 多 segment 用于在线 reencrypt；恢复场景几乎都是单 segment。
func pickDefaultSegment(segs map[string]*LUKS2Segment) *LUKS2Segment {
	// 先按 key "0" 优先（cryptsetup 默认 ID）
	if s, ok := segs["0"]; ok && s != nil && s.Type == "crypt" {
		return s
	}
	for _, s := range segs {
		if s != nil && s.Type == "crypt" {
			return s
		}
	}
	return nil
}
