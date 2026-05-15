package bitlocker

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// Password protector round-trip：
//  1. 把 VMK 用"来自用户密码"派生的 stretched key AES-CCM 加密成 VMK datum
//  2. 走 UnlockVMKWithPassword，验证能拿回原始 VMK
func TestPasswordProtector_RoundTrip(t *testing.T) {
	if testing.Short() {
		t.Skip("跳过 1M 次 stretch key（-short 模式）")
	}

	const password = "correct horse battery staple" // 经典长密码示例

	realVMK := make([]byte, 32)
	for i := range realVMK {
		realVMK[i] = byte(0x50 + i)
	}
	var salt [16]byte
	for i := range salt {
		salt[i] = byte(0x20 + i)
	}

	intermediate := hashUserPasswordUTF16(password)
	stretched := StretchKey(intermediate, salt, nil)

	// VMK 明文 = 嵌套 KEY datum
	vmkKeyDatum := make([]byte, 8+4+32)
	binary.LittleEndian.PutUint16(vmkKeyDatum[0:2], uint16(len(vmkKeyDatum)))
	binary.LittleEndian.PutUint16(vmkKeyDatum[4:6], DatumValueKey)
	binary.LittleEndian.PutUint16(vmkKeyDatum[6:8], 1)
	binary.LittleEndian.PutUint32(vmkKeyDatum[8:12], 0x4000)
	copy(vmkKeyDatum[12:], realVMK)

	nonce := []byte{0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7, 0xE8, 0xA1, 0xA2, 0xA3, 0xA4}
	ct, tag, err := EncryptAESCCM(stretched[:], nonce, vmkKeyDatum)
	if err != nil {
		t.Fatalf("EncryptAESCCM: %v", err)
	}

	aesccmBody := make([]byte, 28+len(ct))
	copy(aesccmBody[0:8], nonce[0:8])
	copy(aesccmBody[8:12], nonce[8:12])
	copy(aesccmBody[12:28], tag)
	copy(aesccmBody[28:], ct)
	aesccmBytes := buildDatum(0, DatumValueAESCCMKey, aesccmBody)

	stretchBody := make([]byte, 20+len(aesccmBytes))
	binary.LittleEndian.PutUint32(stretchBody[0:4], 0x2000)
	copy(stretchBody[4:20], salt[:])
	copy(stretchBody[20:], aesccmBytes)
	stretchBytes := buildDatum(0, DatumValueStretchKey, stretchBody)

	vmkBody := make([]byte, 28+len(stretchBytes))
	binary.LittleEndian.PutUint16(vmkBody[24:26], VMKProtectionPassword)
	copy(vmkBody[28:], stretchBytes)
	vmkBytes := buildDatum(DatumEntryVMKInfo, DatumValueVMK, vmkBody)

	d, _, err := ParseDatum(vmkBytes, 0)
	if err != nil {
		t.Fatalf("ParseDatum: %v", err)
	}
	vmk := &VMKDatum{ProtectionType: VMKProtectionPassword, Datum: d}

	got, err := UnlockVMKWithPassword(password, vmk, nil)
	if err != nil {
		t.Fatalf("UnlockVMKWithPassword: %v", err)
	}
	if !bytes.Equal(got, realVMK) {
		t.Errorf("密码解出 VMK 不匹配: got %x want %x", got, realVMK)
	}

	// 错误密码应失败
	if _, err := UnlockVMKWithPassword("wrong password", vmk, nil); err == nil {
		t.Error("错误密码应失败但没报错")
	}
}

// SummarizeProtectors：覆盖每种 protection type 都给出合理 Hint
func TestSummarizeProtectors_AllKinds(t *testing.T) {
	for _, c := range []struct {
		pt       uint16
		wantKind string
		solvable bool
	}{
		{VMKProtectionRecoveryPwd, "recovery", true},
		{VMKProtectionPassword, "password", true},
		{VMKProtectionStartupKey, "startup-key", true},
		{VMKProtectionTPM, "tpm", false},
		{VMKProtectionTPMAndPin, "tpm-pin", false},
		{VMKProtectionClearKey, "clear", true},
		{0xFFFF, "unknown", false},
	} {
		s := classifyProtector(c.pt)
		if s.Kind != c.wantKind {
			t.Errorf("pt=0x%04X kind=%s want %s", c.pt, s.Kind, c.wantKind)
		}
		if s.Solvable != c.solvable {
			t.Errorf("pt=0x%04X solvable=%v want %v", c.pt, s.Solvable, c.solvable)
		}
		if s.Hint == "" {
			t.Errorf("pt=0x%04X 缺 hint", c.pt)
		}
	}
}

// Startup key (BEK) 端到端：
//  1. 手工合成一个最小 BEK metadata 块：EXTERNAL_KEY + 嵌套 KEY datum
//  2. 用 ParseBEKBytes 解回来 → ExternalKey
//  3. 用它 AES-CCM 加密一段 VMK，然后 UnlockVMKWithStartupKey 解回去比对
func TestStartupKey_BEKParse_And_Unlock(t *testing.T) {
	externalKey := make([]byte, 32)
	for i := range externalKey {
		externalKey[i] = byte(0xF0 + i)
	}
	var guid [16]byte
	for i := range guid {
		guid[i] = byte(0xD0 + i)
	}

	// 构造 KEY datum（嵌在 EXTERNAL_KEY 下）：4 字节 method + 32 字节 key
	keyBody := make([]byte, 4+32)
	binary.LittleEndian.PutUint32(keyBody[0:4], 0x4000)
	copy(keyBody[4:], externalKey)
	keyDatumBytes := buildDatum(0, DatumValueKey, keyBody)

	// EXTERNAL_KEY datum：28 header (16 GUID + 12 余) + 嵌套 KEY datum
	extBody := make([]byte, 28+len(keyDatumBytes))
	copy(extBody[0:16], guid[:])
	copy(extBody[28:], keyDatumBytes)
	extDatumBytes := buildDatum(0, DatumValueExternalKey, extBody)

	// FVE metadata block 头 64 字节 + EXTERNAL_KEY datum
	metaTotalSize := uint16(64 + len(extDatumBytes))
	bek := make([]byte, metaTotalSize)
	copy(bek[0:8], []byte(fveOEMID))
	binary.LittleEndian.PutUint16(bek[8:10], metaTotalSize)
	binary.LittleEndian.PutUint16(bek[10:12], 2)                   // Version
	binary.LittleEndian.PutUint16(bek[12:14], 64)                  // HeaderSize
	binary.LittleEndian.PutUint16(bek[36:38], EncryptionAESXTS128) // 任意值，BEK 其实不用
	copy(bek[64:], extDatumBytes)

	parsed, err := ParseBEKBytes(bek)
	if err != nil {
		t.Fatalf("ParseBEKBytes: %v", err)
	}
	if !bytes.Equal(parsed.ExternalKey, externalKey) {
		t.Errorf("ExternalKey 不匹配:\n  got  %x\n  want %x", parsed.ExternalKey, externalKey)
	}
	if parsed.GUID != guid {
		t.Errorf("GUID 不匹配")
	}

	// 再走一次 VMK 解锁：用 externalKey 加密一个 VMK，然后 UnlockVMKWithStartupKey 解回去
	realVMK := make([]byte, 32)
	for i := range realVMK {
		realVMK[i] = byte(i + 1)
	}
	vmkKeyDatum := make([]byte, 8+4+32)
	binary.LittleEndian.PutUint16(vmkKeyDatum[0:2], uint16(len(vmkKeyDatum)))
	binary.LittleEndian.PutUint16(vmkKeyDatum[4:6], DatumValueKey)
	binary.LittleEndian.PutUint16(vmkKeyDatum[6:8], 1)
	binary.LittleEndian.PutUint32(vmkKeyDatum[8:12], 0x4000)
	copy(vmkKeyDatum[12:], realVMK)

	nonce := []byte{0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0x11, 0x22, 0x33, 0x44}
	ct, tag, err := EncryptAESCCM(externalKey, nonce, vmkKeyDatum)
	if err != nil {
		t.Fatalf("EncryptAESCCM: %v", err)
	}
	aesccmBody := make([]byte, 28+len(ct))
	copy(aesccmBody[0:8], nonce[0:8])
	copy(aesccmBody[8:12], nonce[8:12])
	copy(aesccmBody[12:28], tag)
	copy(aesccmBody[28:], ct)
	aesccmBytes := buildDatum(0, DatumValueAESCCMKey, aesccmBody)

	vmkBody := make([]byte, 28+len(aesccmBytes))
	binary.LittleEndian.PutUint16(vmkBody[24:26], VMKProtectionStartupKey)
	copy(vmkBody[28:], aesccmBytes)
	vmkBytes := buildDatum(DatumEntryVMKInfo, DatumValueVMK, vmkBody)

	d, _, err := ParseDatum(vmkBytes, 0)
	if err != nil {
		t.Fatalf("ParseDatum VMK: %v", err)
	}
	vmk := &VMKDatum{ProtectionType: VMKProtectionStartupKey, Datum: d}

	got, err := UnlockVMKWithStartupKey(parsed.ExternalKey, vmk)
	if err != nil {
		t.Fatalf("UnlockVMKWithStartupKey: %v", err)
	}
	if !bytes.Equal(got, realVMK) {
		t.Errorf("startup key 解出 VMK 不匹配: got %x want %x", got, realVMK)
	}

	// 用错误 external key 应该失败
	bad := make([]byte, 32)
	if _, err := UnlockVMKWithStartupKey(bad, vmk); err == nil {
		t.Error("错的 external key 应失败")
	}
}
