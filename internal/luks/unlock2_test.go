package luks

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"testing"

	"data-recovery/internal/testutil"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/pbkdf2"
)

// 端到端 LUKS2：构造一个 Argon2id keyslot + AES-XTS-plain64 area 的镜像 fixture，
// 用 UnlockLUKS2 解锁验证。

const (
	// 128 stripes × 64 mkLen = 8192 字节 = 16 个 512B 扇区——必须 sector-aligned，
	// 否则末尾不足一扇区的 AFsplit 尾巴在生产 unlock 路径里会被当成"加密 padding"
	// 解密一次，破坏 AFmerge。真实 cryptsetup 默认 stripes=4000、mkLen=64 → 256000B
	// 也是恰好 sector-aligned。
	luks2TestStripes = 128
	luks2TestMKLen   = 64

	// 测试用低 Argon2 cost（保证 < 1s 跑完）；生产真实密码典型 t=4, m=1GB, p=1
	argonTime    = 1
	argonMemory  = 4096 // KB → 4MB
	argonThreads = 1

	digestIter = 1000
)

func buildLUKS2Image(t *testing.T, password string, masterKey []byte) []byte {
	t.Helper()

	const totalSize = 256 * 1024 // 256KB 测试镜像够用

	img := make([]byte, totalSize)

	// ---- 1) 二进制 header (4096 字节) ----
	copy(img[0:6], luksMagic)
	binary.BigEndian.PutUint16(img[6:8], 2)
	binary.BigEndian.PutUint64(img[8:16], 16384) // hdr_size = 4KB header + 12KB JSON
	binary.BigEndian.PutUint64(img[16:24], 1)    // seqid
	copy(img[24:72], "test-luks2")
	copy(img[72:104], "sha256")
	// salt 64B
	for i := 0; i < 64; i++ {
		img[104+i] = byte(i)
	}
	copy(img[168:208], "abcd1234-5678-90ab-cdef-1234567890ab")
	copy(img[208:256], "test")
	// csum 暂留 0；下面计算后填回

	// ---- 2) 算 keyslot_key（Argon2id）----
	kdfSalt := bytes.Repeat([]byte{0xAB}, 32)
	keyslotKey := argon2.IDKey([]byte(password), kdfSalt, argonTime, argonMemory, argonThreads, luks2TestMKLen)

	// ---- 3) AFsplit master_key ----
	rand := make([]byte, luks2TestMKLen*(luks2TestStripes-1))
	for i := range rand {
		rand[i] = byte(i*5 + 3)
	}
	afSplit, err := AFsplit(masterKey, luks2TestStripes, rand, sha256.New)
	if err != nil {
		t.Fatal(err)
	}

	// ---- 4) 加密 afSplit (AES-XTS-plain64) ----
	encrypted := make([]byte, len(afSplit))
	copy(encrypted, afSplit)
	stripeBytes := luks2TestMKLen * luks2TestStripes
	xtsHelper, err := makeXTSCipher(keyslotKey)
	if err != nil {
		t.Fatal(err)
	}
	for off := 0; off+512 <= stripeBytes; off += 512 {
		xtsHelper.Encrypt(encrypted[off:off+512], encrypted[off:off+512], uint64(off/512))
	}

	// ---- 5) 写到 keyslot area（offset 32KB 起，cryptsetup 默认） ----
	const ksOffset = 32 * 1024
	const ksSize = 64 * 1024 // area 比 stripeBytes 大点，符合 cryptsetup 行为
	copy(img[ksOffset:ksOffset+stripeBytes], encrypted)

	// ---- 6) 算 master key digest ----
	digestSalt := bytes.Repeat([]byte{0xCD}, 32)
	mkDigest := pbkdf2.Key(masterKey, digestSalt, digestIter, 32, sha256.New)

	// ---- 7) 构造 JSON metadata ----
	meta := LUKS2Metadata{
		Keyslots: map[string]*LUKS2Keyslot{
			"0": {
				Type:    "luks2",
				KeySize: luks2TestMKLen,
				KDF: LUKS2KDF{
					Type:   "argon2id",
					Salt:   base64.StdEncoding.EncodeToString(kdfSalt),
					Time:   argonTime,
					Memory: argonMemory,
					CPUs:   argonThreads,
				},
				AF: LUKS2AF{Type: "luks1", Stripes: luks2TestStripes, Hash: "sha256"},
				Area: LUKS2Area{
					Type:       "raw",
					Offset:     fmt.Sprintf("%d", ksOffset),
					Size:       fmt.Sprintf("%d", ksSize),
					Encryption: "aes-xts-plain64",
					KeySize:    luks2TestMKLen,
				},
			},
		},
		Digests: map[string]*LUKS2Digest{
			"0": {
				Type:       "pbkdf2",
				Keyslots:   []string{"0"},
				Salt:       base64.StdEncoding.EncodeToString(digestSalt),
				Digest:     base64.StdEncoding.EncodeToString(mkDigest),
				Iterations: digestIter,
				Hash:       "sha256",
			},
		},
	}
	jsonBytes, err := json.Marshal(meta)
	if err != nil {
		t.Fatal(err)
	}
	copy(img[4096:], jsonBytes)
	// 剩余 JSON 区域已经是 0 padding（make 出来就是 0）

	// ---- 8) 算 csum 并写回 ----
	tmp := make([]byte, 4096)
	copy(tmp, img[:4096])
	for i := 448; i < 448+64; i++ {
		tmp[i] = 0
	}
	h := sha256.New()
	h.Write(tmp)
	h.Write(img[4096:16384])
	csum := h.Sum(nil)
	copy(img[448:448+32], csum)

	return img
}

func TestUnlockLUKS2_EndToEnd(t *testing.T) {
	const password = "MyLUKS2Password!"
	masterKey := make([]byte, luks2TestMKLen)
	for i := range masterKey {
		masterKey[i] = byte((i*17 + 7) & 0xFF)
	}

	img := buildLUKS2Image(t, password, masterKey)
	reader := testutil.NewMemReader(img)

	bin, err := ParseLUKS2BinHeader(img[:4096])
	if err != nil {
		t.Fatalf("解析 binary header: %v", err)
	}
	meta, err := ParseLUKS2Metadata(img[4096:16384])
	if err != nil {
		t.Fatalf("解析 metadata: %v", err)
	}

	// header checksum 应通过
	if !VerifyLUKS2HeaderChecksum(img[:4096], img[4096:16384], bin.CsumAlg) {
		t.Errorf("LUKS2 header checksum 验证失败")
	}

	mk, slotID, err := UnlockLUKS2(reader, 0, bin, meta, password)
	if err != nil {
		t.Fatalf("UnlockLUKS2: %v", err)
	}
	if slotID != "0" {
		t.Errorf("应在 keyslot 0 命中, got %s", slotID)
	}
	if !bytes.Equal(mk, masterKey) {
		t.Errorf("master key 不匹配:\n  got  %x\n  want %x", mk, masterKey)
	}
}

func TestUnlockLUKS2_WrongPassword(t *testing.T) {
	masterKey := bytes.Repeat([]byte{0x42}, luks2TestMKLen)
	img := buildLUKS2Image(t, "right", masterKey)
	reader := testutil.NewMemReader(img)
	bin, _ := ParseLUKS2BinHeader(img[:4096])
	meta, _ := ParseLUKS2Metadata(img[4096:16384])

	if _, _, err := UnlockLUKS2(reader, 0, bin, meta, "wrong"); err != ErrWrongPassword {
		t.Errorf("错密码应返回 ErrWrongPassword, got %v", err)
	}
}

func TestParseLUKS2BinHeader_RejectsLUKS1(t *testing.T) {
	// LUKS1 magic 但 version=1，应被 LUKS2 解析器拒绝
	buf := make([]byte, 4096)
	copy(buf[0:6], luksMagic)
	binary.BigEndian.PutUint16(buf[6:8], 1)
	if _, err := ParseLUKS2BinHeader(buf); err == nil {
		t.Errorf("应拒绝 LUKS1")
	}
}

func TestVerifyLUKS2HeaderChecksum_TamperedFails(t *testing.T) {
	masterKey := bytes.Repeat([]byte{0x99}, luks2TestMKLen)
	img := buildLUKS2Image(t, "any", masterKey)

	// 翻转 binary header 里某个字节
	tampered := append([]byte{}, img[:4096]...)
	tampered[100] ^= 0x01
	if VerifyLUKS2HeaderChecksum(tampered, img[4096:16384], "sha256") {
		t.Errorf("被篡改的 header 应校验失败")
	}
}

// 未知 csum hash 应被保守通过（不阻断 unlock）
func TestVerifyLUKS2HeaderChecksum_UnknownHashPassesThrough(t *testing.T) {
	masterKey := bytes.Repeat([]byte{0x77}, luks2TestMKLen)
	img := buildLUKS2Image(t, "any", masterKey)
	// "blake2b" 不是 cryptsetup 支持的 LUKS2 csum hash → 跳过校验返回 true
	if !VerifyLUKS2HeaderChecksum(img[:4096], img[4096:16384], "blake2b") {
		t.Errorf("未知 csum hash 应保守返回 true (不阻断 unlock)")
	}
}

// SHA-512 / SHA-1 csum 路径（构造一个 csum_alg=sha512 的合成 header）
func TestVerifyLUKS2HeaderChecksum_SHA512Path(t *testing.T) {
	// 用 buildLUKS2Image 拿到的 img 是 sha256；这里手工把 csum_alg 改为 sha512
	// 并重算 csum，验证 sha512 路径走通。
	masterKey := bytes.Repeat([]byte{0x55}, luks2TestMKLen)
	img := buildLUKS2Image(t, "any", masterKey)

	// csum_alg 字段在 binary header 偏移 72..104 (32B)
	hdr := append([]byte{}, img[:4096]...)
	for i := 72; i < 104; i++ {
		hdr[i] = 0
	}
	copy(hdr[72:], "sha512")
	// 重算 sha512 csum，写回 hdr[448:448+64]
	for i := 448; i < 448+64; i++ {
		hdr[i] = 0
	}
	hashFn, hashSize := luks2CsumHash("sha512")
	if hashFn == nil {
		t.Fatal("luks2CsumHash 应识别 sha512")
	}
	h := hashFn()
	h.Write(hdr)
	h.Write(img[4096:16384])
	csum := h.Sum(nil)
	copy(hdr[448:448+hashSize], csum)

	if !VerifyLUKS2HeaderChecksum(hdr, img[4096:16384], "sha512") {
		t.Errorf("SHA-512 csum 路径应校验通过")
	}
	// 篡改后应失败
	hdr[200] ^= 0x01
	if VerifyLUKS2HeaderChecksum(hdr, img[4096:16384], "sha512") {
		t.Errorf("篡改后 SHA-512 csum 应失败")
	}
}
