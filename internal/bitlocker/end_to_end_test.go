package bitlocker

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"testing"

	"data-recovery/internal/testutil"
)

// 端到端正向链测试：
//
//	recovery key → stretched key → encrypt fake VMK with AES-CCM
//	→ 用我们的 UnlockVMKWithRecoveryKey 反向解锁，结果必须等于原始 VMK
//
// 这是 BitLocker 解锁链最关键的"密钥派生 + AES-CCM"组合的端到端正确性证明。
func TestEndToEnd_VMKUnlock_RoundTrip(t *testing.T) {
	if testing.Short() {
		t.Skip("跳过 1M 次 stretch key（-short 模式）")
	}

	const recoveryKey = "100958-067419-080553-145618-321024-720885-000011-000022"

	// 1. 模拟 BitLocker 写入流程：派生出 stretched key
	intermediate, err := ParseRecoveryPassword(recoveryKey)
	if err != nil {
		t.Fatalf("ParseRecoveryPassword: %v", err)
	}
	var salt [16]byte
	for i := range salt {
		salt[i] = byte(0x10 + i)
	}
	stretched := StretchKey(intermediate[:], salt, nil)

	// 2. 准备一个"真实 VMK"（32 字节随机/可识别字节）
	realVMK := make([]byte, 32)
	for i := range realVMK {
		realVMK[i] = byte(0xC0 + i)
	}

	// 3. 把 realVMK 包成 KEY datum 明文：8 头 + 4 method + 32 key
	keyDatumPlaintext := make([]byte, 8+4+32)
	binary.LittleEndian.PutUint16(keyDatumPlaintext[0:2], uint16(len(keyDatumPlaintext))) // size
	binary.LittleEndian.PutUint16(keyDatumPlaintext[2:4], 0)                              // type
	binary.LittleEndian.PutUint16(keyDatumPlaintext[4:6], DatumValueKey)                  // value type
	binary.LittleEndian.PutUint16(keyDatumPlaintext[6:8], 1)                              // version
	binary.LittleEndian.PutUint32(keyDatumPlaintext[8:12], 0x4000)                        // method
	copy(keyDatumPlaintext[12:], realVMK)

	// 4. 用 stretched key + 一个 nonce 加密 KEY datum 得到 ciphertext + tag
	nonce := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x10, 0x11, 0x12, 0x13}
	ct, tag, err := EncryptAESCCM(stretched[:], nonce, keyDatumPlaintext)
	if err != nil {
		t.Fatalf("EncryptAESCCM: %v", err)
	}

	// 5. 拼出 AES_CCM_ENCRYPTED_KEY datum body：8 nonce + 4 counter + 16 tag + ct
	aesccmBody := make([]byte, 28+len(ct))
	copy(aesccmBody[0:8], nonce[0:8])
	copy(aesccmBody[8:12], nonce[8:12])
	copy(aesccmBody[12:28], tag)
	copy(aesccmBody[28:], ct)
	aesccmDatum := buildDatum(0, DatumValueAESCCMKey, aesccmBody)

	// 6. STRETCH_KEY datum body：4 method + 16 salt + 嵌套 AES_CCM datum
	stretchBody := make([]byte, 20+len(aesccmDatum))
	binary.LittleEndian.PutUint32(stretchBody[0:4], 0x2000) // method
	copy(stretchBody[4:20], salt[:])
	copy(stretchBody[20:], aesccmDatum)
	stretchDatum := buildDatum(0, DatumValueStretchKey, stretchBody)

	// 7. VMK datum body：28 字节 header + 嵌套 STRETCH_KEY datum
	vmkBody := make([]byte, 28+len(stretchDatum))
	for i := 0; i < 16; i++ {
		vmkBody[i] = byte(i + 1) // GUID
	}
	binary.LittleEndian.PutUint16(vmkBody[24:26], VMKProtectionRecoveryPwd)
	copy(vmkBody[28:], stretchDatum)
	vmkRaw := buildDatum(DatumEntryVMKInfo, DatumValueVMK, vmkBody)

	// 8. 通过 ParseDatum 重新走一遍（验证嵌套 children 自动 parse）
	d, _, err := ParseDatum(vmkRaw, 0)
	if err != nil {
		t.Fatalf("ParseDatum VMK: %v", err)
	}
	vmkDatum := &VMKDatum{
		ProtectionType: VMKProtectionRecoveryPwd,
		Datum:          d,
	}

	// 9. 调用我们的 unlock —— 应该解出与 realVMK 完全相同的密钥
	unlockedVMK, err := UnlockVMKWithRecoveryKey(recoveryKey, vmkDatum, nil)
	if err != nil {
		t.Fatalf("UnlockVMKWithRecoveryKey: %v", err)
	}
	if !bytes.Equal(unlockedVMK, realVMK) {
		t.Errorf("unlock 出来的 VMK 不匹配:\n  got  %x\n  want %x", unlockedVMK, realVMK)
	}
}

// 端到端 XTS 解密：模拟"BitLocker 卷"——按扇区加密一段已知明文，
// 再用 DecryptingReader 透明读出原始内容。
func TestEndToEnd_DecryptingReader_RoundTrip(t *testing.T) {
	const sectorSize = 512
	const sectors = 16

	// 32-byte FVEK = K1 (16) + K2 (16)
	fvek := make([]byte, 32)
	for i := range fvek {
		fvek[i] = byte(0xA0 + i)
	}

	xts, err := NewXTSCipher(fvek, sectorSize)
	if err != nil {
		t.Fatalf("NewXTSCipher: %v", err)
	}

	// 准备明文：16 个扇区，每个填上 sector_number 标记便于断言
	plaintext := make([]byte, sectors*sectorSize)
	for s := 0; s < sectors; s++ {
		for i := 0; i < sectorSize; i++ {
			plaintext[s*sectorSize+i] = byte((s*7 + i) & 0xFF)
		}
	}

	// 加密成"磁盘内容"
	encrypted := make([]byte, len(plaintext))
	for s := 0; s < sectors; s++ {
		off := s * sectorSize
		if err := xts.EncryptSector(encrypted[off:off+sectorSize], plaintext[off:off+sectorSize], uint64(s)); err != nil {
			t.Fatalf("EncryptSector %d: %v", s, err)
		}
	}

	// 包一个 mem reader 模拟磁盘
	underlying := testutil.NewMemReader(encrypted)
	dec, err := NewDecryptingReader(underlying, xts, "mem://test")
	if err != nil {
		t.Fatalf("NewDecryptingReader: %v", err)
	}

	// 各种 ReadAt 模式（对齐 / 不对齐 / 跨多个扇区 / 完整范围）
	cases := []struct {
		name   string
		offset int64
		length int
	}{
		{"sector aligned single", 0, sectorSize},
		{"sector aligned 4 sectors", 2 * sectorSize, 4 * sectorSize},
		{"misaligned start", 100, 200},
		{"misaligned cross-sector", 500, 600},
		{"all", 0, len(plaintext)},
		{"single byte at end", int64(len(plaintext)) - 1, 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := make([]byte, c.length)
			n, _ := dec.ReadAt(got, c.offset)
			expected := plaintext[c.offset : c.offset+int64(c.length)]
			if n != c.length {
				t.Errorf("读字节数错: got %d want %d", n, c.length)
			}
			if !bytes.Equal(got, expected) {
				t.Errorf("透明解密内容不匹配 (前 32 字节):\n  got  %x\n  want %x",
					got[:min(32, len(got))], expected[:min(32, len(expected))])
			}
		})
	}

	// SHA-256 整盘对比，最严格
	encryptedSHA := sha256.Sum256(encrypted)
	decryptedFull := make([]byte, len(plaintext))
	dec.ReadAt(decryptedFull, 0)
	plainSHA := sha256.Sum256(plaintext)
	gotSHA := sha256.Sum256(decryptedFull)
	if encryptedSHA == plainSHA {
		t.Fatal("加密前后 SHA 一样，加密没起作用，测试无意义")
	}
	if gotSHA != plainSHA {
		t.Errorf("透明解密整盘 SHA 不匹配:\n  got  %x\n  want %x", gotSHA, plainSHA)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// 卷从物理盘中段开始：BitLocker 卷不总是位于 disk 起点。
// 验证：SetVolumeOffset(Off) 后，ReadAt(_, 0) 实际读的是 [Off, Off+sectorSize)，
// 且 XTS 仍然用 logical sector number（0, 1, ...），否则 tweak 错位解出乱码。
func TestDecryptingReader_VolumeOffset(t *testing.T) {
	const sectorSize = 512
	const sectors = 4
	const volOff = int64(3 * sectorSize) // 卷从物理盘第 3 扇区开始

	fvek := make([]byte, 32)
	for i := range fvek {
		fvek[i] = byte(0x70 + i)
	}
	xts, err := NewXTSCipher(fvek, sectorSize)
	if err != nil {
		t.Fatalf("NewXTSCipher: %v", err)
	}

	// 卷明文（sectors × 512）
	plaintext := make([]byte, sectors*sectorSize)
	for i := range plaintext {
		plaintext[i] = byte(0xAA ^ (i & 0xFF))
	}

	// 加密（sector_num 从 0 开始；这是 volume-relative）
	encVolume := make([]byte, sectors*sectorSize)
	for s := 0; s < sectors; s++ {
		off := s * sectorSize
		if err := xts.EncryptSector(encVolume[off:off+sectorSize], plaintext[off:off+sectorSize], uint64(s)); err != nil {
			t.Fatalf("EncryptSector %d: %v", s, err)
		}
	}

	// 物理盘 = 垃圾头部（volOff 字节）+ 加密后的卷
	physical := make([]byte, int(volOff)+len(encVolume))
	for i := 0; i < int(volOff); i++ {
		physical[i] = 0xEE // 垃圾头（模拟 MBR / 前置分区）
	}
	copy(physical[int(volOff):], encVolume)

	dr, err := NewDecryptingReader(testutil.NewMemReader(physical), xts, "mem://offset-test")
	if err != nil {
		t.Fatalf("NewDecryptingReader: %v", err)
	}
	dr.SetVolumeOffset(volOff)

	// 上层视角：ReadAt(_, 0) 应该拿到 plaintext[0..]
	for s := 0; s < sectors; s++ {
		got := make([]byte, sectorSize)
		n, _ := dr.ReadAt(got, int64(s*sectorSize))
		if n != sectorSize {
			t.Fatalf("sector %d 读字节数 %d", s, n)
		}
		if !bytes.Equal(got, plaintext[s*sectorSize:(s+1)*sectorSize]) {
			t.Errorf("sector %d 解密结果不匹配 (前 16 字节):\n  got  %x\n  want %x",
				s, got[:16], plaintext[s*sectorSize:s*sectorSize+16])
		}
	}
}
