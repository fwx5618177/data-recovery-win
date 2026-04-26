package luks

// ============================================================================
// LUKS2 on-disk format（Linux 5.x+ 默认）
//
// LUKS2 用 4KB 二进制 header + 12KB JSON metadata 区域代替 LUKS1 的固定字段。
// 默认配置：Argon2id keyslot KDF、AES-XTS-512 全卷、SHA-256 摘要。
//
// 物理布局（offset 0 起算）：
//   bin_hdr_pri   :   0..4096        二进制 header（含 metadata 起点 + size）
//   json_pri      :   bin_hdr_pri 之后到 16KB（typical：4KB header + 12KB JSON）
//   bin_hdr_sec   :   16384..20480   备份 header
//   json_sec      :   备份 JSON
//   keyslots      :   通常从 32KB 起，每 keyslot area 由 JSON.area.offset 指定
//   payload       :   由 JSON.segments[].offset 指定
//
// 二进制 header (4096 字节，big-endian)：
//   off  size  field
//   0    6     magic "LUKS\xba\xbe"
//   6    2     version (= 2)
//   8    8     hdr_size (含 JSON 区域)，典型 16384
//   16   8     seqid
//   24   48    label (字符串)
//   72   32    csum_alg ("sha256")
//   104  64    salt
//   168  40    uuid
//   208  48    subsystem
//   256  8     hdr_offset (二级备份 header 用，主 header 这里通常 = 0)
//   264  184   reserved/padding
//   448  64    csum (SHA-256 of header+JSON, header.csum 字段置 0 时算)
//   512..4096  padding
//
// JSON metadata 区域（紧跟 4096 字节 header 之后）：
//   {
//     "keyslots":  { "0": {type:"luks2", key_size, kdf:{type,salt,...}, area:{...}, ...}, ... },
//     "tokens":    {...},
//     "segments":  { "0": {type:"crypt", offset, size, iv_tweak, encryption, sector_size}, ...},
//     "digests":   { "0": {type:"pbkdf2", keyslots:[...], salt, iterations, hash, digest}, ...},
//     "config":    {json_size, keyslots_size}
//   }
//
// 解锁流程：
//   1. 解析 bin_hdr → metadata 起点 + size
//   2. 解析 JSON
//   3. 对每个 active keyslot：
//        kdf = keyslot.kdf
//        if kdf.type == "argon2id":
//            keyslot_key = Argon2id(password, salt, time=t, memory=m, threads=p)
//        elif kdf.type == "pbkdf2":
//            keyslot_key = PBKDF2(password, salt, iter, key_size, hash)
//        decrypt keyslot.area (按其 sector cipher) → AFsplit data
//        AFmerge → candidate master key
//   4. 验证：digests[].keyslots 包含此 keyslot 时，重算 PBKDF2(MK, salt, iter) == digest
// ============================================================================

import (
	// LUKS2 spec 明确允许 sha1/sha256/sha512 三种 csum hash（cryptsetup 实现集合）。
	// SHA-1 在新创建卷里不推荐，但读取老存量必须支持；纯只读取证场景 SHA-1 抗碰撞
	// 弱化不构成实际威胁（无对手能选择性伪造让我们误信"卷未被篡改"）。
	// #nosec G505 -- LUKS2 csum 兼容性，纯只读
	"crypto/sha1"

	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"strings"
)

// LUKS2BinHeader 二进制 header 解析结果
type LUKS2BinHeader struct {
	Version   uint16
	HdrSize   uint64 // 含 JSON 区域的总长（典型 16384）
	SeqID     uint64
	Label     string
	CsumAlg   string
	Salt      []byte
	UUID      string
	Subsystem string
	Csum      []byte
}

// LUKS2Metadata 是 JSON 区域的关键子集（够解锁用）
type LUKS2Metadata struct {
	Keyslots map[string]*LUKS2Keyslot `json:"keyslots"`
	Segments map[string]*LUKS2Segment `json:"segments"`
	Digests  map[string]*LUKS2Digest  `json:"digests"`
	Config   *LUKS2Config             `json:"config"`
}

// LUKS2Keyslot JSON keyslot 描述
type LUKS2Keyslot struct {
	Type     string         `json:"type"`     // "luks2"
	KeySize  int            `json:"key_size"` // master key bytes
	KDF      LUKS2KDF       `json:"kdf"`
	AF       LUKS2AF        `json:"af"`
	Area     LUKS2Area      `json:"area"`
	Priority *int           `json:"priority,omitempty"`
}

// LUKS2KDF：argon2id / argon2i / pbkdf2
type LUKS2KDF struct {
	Type       string `json:"type"`
	Salt       string `json:"salt"`        // base64
	Time       int    `json:"time"`        // argon2 t-cost
	Memory     int    `json:"memory"`      // argon2 m-cost (KB)
	CPUs       int    `json:"cpus"`        // argon2 parallelism
	Hash       string `json:"hash"`        // pbkdf2 hash
	Iterations int    `json:"iterations"`  // pbkdf2 iter
}

// LUKS2AF：AFsplit 配置
type LUKS2AF struct {
	Type    string `json:"type"`    // "luks1"
	Stripes int    `json:"stripes"` // 通常 4000
	Hash    string `json:"hash"`    // sha256
}

// LUKS2Area：keyslot 加密数据区
type LUKS2Area struct {
	Type       string `json:"type"`       // "raw"
	Offset     string `json:"offset"`     // 字节，作为字符串存（避免 JSON 64-bit 精度问题）
	Size       string `json:"size"`
	Encryption string `json:"encryption"` // 例 "aes-xts-plain64"
	KeySize    int    `json:"key_size"`   // keyslot 加密 key 长度
}

// LUKS2Segment：payload 数据段
type LUKS2Segment struct {
	Type       string `json:"type"`       // "crypt"
	Offset     string `json:"offset"`     // 字节
	Size       string `json:"size"`       // 字节 / "dynamic"
	IVTweak    string `json:"iv_tweak"`   // "0" 或一个数字
	Encryption string `json:"encryption"`
	SectorSize int    `json:"sector_size"`
}

// LUKS2Digest：master key 摘要
type LUKS2Digest struct {
	Type       string   `json:"type"`       // "pbkdf2"
	Keyslots   []string `json:"keyslots"`
	Segments   []string `json:"segments"`
	Salt       string   `json:"salt"`       // base64
	Digest     string   `json:"digest"`     // base64
	Iterations int      `json:"iterations"`
	Hash       string   `json:"hash"`
}

// LUKS2Config 容器配置
type LUKS2Config struct {
	JSONSize     string `json:"json_size"`
	KeyslotsSize string `json:"keyslots_size"`
}

// ParseLUKS2BinHeader 把 4096 字节 binary header 拆开
func ParseLUKS2BinHeader(buf []byte) (*LUKS2BinHeader, error) {
	if len(buf) < 4096 {
		return nil, fmt.Errorf("LUKS2 header buf 太短: %d", len(buf))
	}
	if !startsWith(buf, luksMagic) {
		return nil, errors.New("不是 LUKS (magic 不匹配)")
	}
	ver := binary.BigEndian.Uint16(buf[6:8])
	if ver != 2 {
		return nil, fmt.Errorf("非 LUKS2 版本: %d", ver)
	}
	h := &LUKS2BinHeader{
		Version:   2,
		HdrSize:   binary.BigEndian.Uint64(buf[8:16]),
		SeqID:     binary.BigEndian.Uint64(buf[16:24]),
		Label:     trimNul(string(buf[24:72])),
		CsumAlg:   trimNul(string(buf[72:104])),
		Salt:      append([]byte{}, buf[104:168]...),
		UUID:      trimNul(string(buf[168:208])),
		Subsystem: trimNul(string(buf[208:256])),
		Csum:      append([]byte{}, buf[448:448+64]...),
	}
	if h.HdrSize < 16384 || h.HdrSize > 4*1024*1024 {
		return nil, fmt.Errorf("hdr_size 异常: %d", h.HdrSize)
	}
	return h, nil
}

// luks2CsumHash 返回 LUKS2 header csum 用的 hash 构造器 + 输出字节数。
// 未知 hash 返回 (nil, 0)，调用方应跳过校验而不是报错。
func luks2CsumHash(name string) (func() hash.Hash, int) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "sha256":
		return sha256.New, 32
	case "sha512":
		return sha512.New, 64
	case "sha1":
		return sha1.New, 20
	}
	return nil, 0
}

// ParseLUKS2Metadata 解析 JSON 区域。
//
// 策略：JSON 区域可能末尾有大量 0 padding；我们按 NUL 截断后再 unmarshal。
// 任何字段缺失都不算错（容器可能省 keyslots 等），上层在解锁时再做完整性检查。
func ParseLUKS2Metadata(jsonBuf []byte) (*LUKS2Metadata, error) {
	// 找第一个 0x00 截断
	end := len(jsonBuf)
	for i, b := range jsonBuf {
		if b == 0 {
			end = i
			break
		}
	}
	jsonStr := jsonBuf[:end]
	if len(jsonStr) == 0 {
		return nil, errors.New("JSON 区域为空")
	}

	var meta LUKS2Metadata
	if err := json.Unmarshal(jsonStr, &meta); err != nil {
		return nil, fmt.Errorf("JSON 解析失败: %w", err)
	}
	if len(meta.Keyslots) == 0 {
		return nil, errors.New("LUKS2 metadata 没有 keyslots")
	}
	return &meta, nil
}

// VerifyLUKS2HeaderChecksum 校验 hash(bin_header_with_csum_zeroed || json_area)
//
// header.Csum 字段在计算时要置 0；这是 cryptsetup 的写入算法。
// 支持 sha256（默认）、sha512、sha1（cryptsetup 支持的全部三种 csum hash）。
// 不识别的 hash 一律返回 true（保守通过 —— 后续 unlock 路径自身仍要解 keyslot
// 才能成功，csum 失败本身不是 unlock 阻塞）。
//
// 校验失败：典型是磁盘损坏或被篡改；上层应只 log 警告，不中断 unlock 流程。
func VerifyLUKS2HeaderChecksum(binHeaderBuf, jsonBuf []byte, csumAlg string) bool {
	if len(binHeaderBuf) < 4096 {
		return false
	}
	hashFn, hashSize := luks2CsumHash(csumAlg)
	if hashFn == nil {
		return true // 未知 hash，跳过校验
	}
	// 复制并把 csum 字段（offset 448, 64 bytes）清零
	tmp := make([]byte, 4096)
	copy(tmp, binHeaderBuf[:4096])
	for i := 448; i < 448+64; i++ {
		tmp[i] = 0
	}
	h := hashFn()
	h.Write(tmp)
	h.Write(jsonBuf)
	got := h.Sum(nil)
	// 取 binHeaderBuf 里的原 csum 前 N 字节（N = hash 输出长度；剩余是 0 padding）
	want := binHeaderBuf[448 : 448+hashSize]
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}
