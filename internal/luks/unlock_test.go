package luks

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"testing"

	"data-recovery/internal/testutil"

	"golang.org/x/crypto/pbkdf2"
)

// 构造一个真实 LUKS1 镜像 fixture（按照 spec 自己拼字节），跑 UnlockLUKS1 端到端。
// 这是 LUKS1 解锁链最有价值的回归测试 —— 任何一处偏移、字节序、PBKDF2 调用错位都会让 mk 错。

const (
	testCipherName = "aes"
	testCipherMode = "xts-plain64"
	testHashSpec   = "sha256"
	testStripes    = 100 // 测试用小 stripes 加快
	testMKLen      = 64  // aes-xts 用 64B（256-bit cipher key + 256-bit tweak key）
)

// buildLUKS1Image 构造一个 1MB 的 LUKS1 镜像 fixture。
//
//   payload 区域不真填密文（我们只测 unlock 链，全卷 sector reader 留给后面）；
//   仅保证 keyslot 区域里能解出 mk 且 mk_digest 正确。
func buildLUKS1Image(t *testing.T, password string, masterKey []byte) []byte {
	t.Helper()

	const (
		ksIter      = 1000 // 测试用低轮次
		mkDigestIter = 1000
	)

	// 1) phdr (1024 字节)
	img := make([]byte, 2*1024*1024)

	copy(img[0:6], luksMagic)
	binary.BigEndian.PutUint16(img[6:8], 1)
	copy(img[8:40], testCipherName)
	copy(img[40:72], testCipherMode)
	copy(img[72:104], testHashSpec)

	// payload_offset 用 4096 sector（2MB 之后），确保 keyslot 区在头之后、payload 之前
	binary.BigEndian.PutUint32(img[104:108], 4096)
	binary.BigEndian.PutUint32(img[108:112], uint32(testMKLen))

	// 2) 算 mk_digest = PBKDF2(MK, mkSalt, mkIter, 20)
	mkSalt := bytes.Repeat([]byte{0x77}, 32)
	binary.BigEndian.PutUint32(img[164:168], mkDigestIter)
	copy(img[132:164], mkSalt)
	mkDigest := pbkdf2.Key(masterKey, mkSalt, mkDigestIter, 20, sha256.New)
	copy(img[112:132], mkDigest)

	// uuid
	copy(img[168:208], "11111111-2222-3333-4444-555555555555")

	// 3) keyslot[0]：active，PBKDF2(password, salt) → keyslot_key，加密 AFsplit(MK)
	ksSalt := bytes.Repeat([]byte{0x88}, 32)
	keyslotKey := pbkdf2.Key([]byte(password), ksSalt, ksIter, testMKLen, sha256.New)

	// AFsplit
	rand := make([]byte, testMKLen*(testStripes-1))
	for i := range rand {
		rand[i] = byte(i*13 + 7)
	}
	afSplit, err := AFsplit(masterKey, testStripes, rand, sha256.New)
	if err != nil {
		t.Fatal(err)
	}

	// 加密 afSplit（按 512B 扇区，xts-plain64）
	encrypted := make([]byte, len(afSplit))
	copy(encrypted, afSplit)
	// 注意：keyslot area 必须按 512B 对齐写入（最后不足一个扇区不加密）
	areaBytes := testMKLen * testStripes
	for off := 0; off < areaBytes; off += 512 {
		end := off + 512
		if end > areaBytes {
			break
		}
		// 加密：先复制再调 Decrypt 反向？我们这里要的是"加密"——
		// xts.Cipher 有 Encrypt 方法，但 SectorCipher 接口只暴露 Decrypt。
		// 测试场景反向跑一次：用 Decrypt 模拟 "Encrypt" 行不通（不对称）。
		// 解法：直接复用 xts.Cipher.Encrypt 内部 API。
		// 为了不暴露底层类型，这里 cheap：用 stdlib 的 AES + XTS 重新构一个。
		// → 见 helper：testEncryptSector
		testEncryptSector(t, encrypted[off:end], uint64(off/512), keyslotKey)
	}

	// 写入 keyslot[0] 元数据
	binary.BigEndian.PutUint32(img[208:212], luks1KeyslotActive)
	binary.BigEndian.PutUint32(img[212:216], ksIter)
	copy(img[216:248], ksSalt)
	// keyslot 数据区用 sector 8 起（4KB 偏移）
	const ksDataOffsetSector = 8
	binary.BigEndian.PutUint32(img[248:252], ksDataOffsetSector)
	binary.BigEndian.PutUint32(img[252:256], testStripes)

	// keyslot 数据写到 sector 8（字节 4096）
	copy(img[ksDataOffsetSector*512:], encrypted)

	// 其它 keyslot 全 0（inactive）—— 已经默认是 0

	return img
}

// testEncryptSector 是 buildLUKS1Image 用的辅助：用测试 helper 加密一个 sector
func testEncryptSector(t *testing.T, buf []byte, sectorIdx uint64, key []byte) {
	t.Helper()
	if len(buf) != 512 {
		t.Fatal("sector 必须 512B")
	}
	c, err := makeXTSCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	c.Encrypt(buf, buf, sectorIdx)
}

func TestUnlockLUKS1_EndToEnd(t *testing.T) {
	const password = "MyDiskPassword2026"
	masterKey := make([]byte, testMKLen)
	for i := range masterKey {
		masterKey[i] = byte((i*31 + 11) & 0xFF)
	}

	img := buildLUKS1Image(t, password, masterKey)
	reader := testutil.NewMemReader(img)

	hdr, err := ParseLUKS1Header(img[:1024])
	if err != nil {
		t.Fatalf("解析 header: %v", err)
	}

	mk, slot, err := UnlockLUKS1(reader, 0, hdr, password)
	if err != nil {
		t.Fatalf("UnlockLUKS1: %v", err)
	}
	if slot != 0 {
		t.Errorf("应在 keyslot 0 命中, got %d", slot)
	}
	if !bytes.Equal(mk, masterKey) {
		t.Errorf("master key 不匹配")
	}
}

func TestUnlockLUKS1_WrongPassword(t *testing.T) {
	const password = "correct"
	masterKey := bytes.Repeat([]byte{0xAB}, testMKLen)
	img := buildLUKS1Image(t, password, masterKey)
	reader := testutil.NewMemReader(img)

	hdr, _ := ParseLUKS1Header(img[:1024])
	if _, _, err := UnlockLUKS1(reader, 0, hdr, "wrong"); err != ErrWrongPassword {
		t.Errorf("错密码应返回 ErrWrongPassword, got %v", err)
	}
}

func TestUnlockLUKS1_EmptyPasswordRejected(t *testing.T) {
	masterKey := bytes.Repeat([]byte{0x55}, testMKLen)
	img := buildLUKS1Image(t, "abc", masterKey)
	reader := testutil.NewMemReader(img)
	hdr, _ := ParseLUKS1Header(img[:1024])

	if _, _, err := UnlockLUKS1(reader, 0, hdr, ""); err == nil {
		t.Errorf("空密码应被拒绝")
	}
}
