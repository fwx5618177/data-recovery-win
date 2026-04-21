package bitlocker

import (
	"bytes"
	"context"
	"encoding/binary"
	"testing"

	"data-recovery/internal/testutil"
)

// 合成场景：内存里某处藏着真 VMK（32 字节），周围全是垃圾。
// SearchVMKInMemoryImage 应该扫到它并解出 VMK datum。
func TestSearchVMKInMemoryImage_FindsKnownVMK(t *testing.T) {
	// 1. 准备真 VMK —— 用"非自然递增"模式避免和合成 mem 内容碰撞
	realVMK := make([]byte, 32)
	for i := range realVMK {
		realVMK[i] = byte((i*131 + 0xAB) & 0xFF) // 撒列伪随机
	}

	// 2. 用 realVMK 加密一段 KEY datum 当作 VMK datum 的 AES_CCM child
	innerKeyDatum := make([]byte, 8+4+32)
	binary.LittleEndian.PutUint16(innerKeyDatum[0:2], uint16(len(innerKeyDatum)))
	binary.LittleEndian.PutUint16(innerKeyDatum[4:6], DatumValueKey)
	binary.LittleEndian.PutUint16(innerKeyDatum[6:8], 1)
	binary.LittleEndian.PutUint32(innerKeyDatum[8:12], 0x4000)
	innerVMKBody := make([]byte, 32)
	for i := range innerVMKBody {
		innerVMKBody[i] = byte(0xAA ^ i)
	}
	copy(innerKeyDatum[12:], innerVMKBody)

	nonce := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	ct, tag, err := EncryptAESCCM(realVMK, nonce, innerKeyDatum)
	if err != nil {
		t.Fatalf("EncryptAESCCM: %v", err)
	}

	aesccmBody := make([]byte, 28+len(ct))
	copy(aesccmBody[0:8], nonce[0:8])
	copy(aesccmBody[8:12], nonce[8:12])
	copy(aesccmBody[12:28], tag)
	copy(aesccmBody[28:], ct)
	aesccmDatum := buildDatum(0, DatumValueAESCCMKey, aesccmBody)

	// 3. 包成 VMK datum（TPM 保护类型）
	vmkBody := make([]byte, 28+len(aesccmDatum))
	binary.LittleEndian.PutUint16(vmkBody[24:26], VMKProtectionTPM)
	copy(vmkBody[28:], aesccmDatum)
	vmkBytes := buildDatum(DatumEntryVMKInfo, DatumValueVMK, vmkBody)
	d, _, err := ParseDatum(vmkBytes, 0)
	if err != nil {
		t.Fatalf("ParseDatum VMK: %v", err)
	}
	vmkDatum := &VMKDatum{ProtectionType: VMKProtectionTPM, Datum: d}

	// 4. 合成"内存镜像"：3MB 垃圾，在 1.5MB 偏移处藏 realVMK
	mem := make([]byte, 3*1024*1024)
	for i := range mem {
		mem[i] = byte(i & 0xFF)
	}
	hideOff := int64(1500000)
	// 对齐到 16 字节
	hideOff -= hideOff % 16
	copy(mem[hideOff:hideOff+32], realVMK)

	// 5. 跑搜索
	r := testutil.NewMemReader(mem)
	res, err := SearchVMKInMemoryImage(context.Background(), r, vmkDatum, nil)
	if err != nil {
		t.Fatalf("SearchVMKInMemoryImage: %v", err)
	}
	if res == nil {
		t.Fatal("没找到 VMK 但 err 也 nil")
	}
	if !bytes.Equal(res.VMK, realVMK) {
		t.Errorf("找到的 VMK 不对:\n  got  %x\n  want %x", res.VMK, realVMK)
	}
	if res.HitOffset != hideOff {
		t.Errorf("命中偏移 %d want %d", res.HitOffset, hideOff)
	}
}

// 内存里没藏 VMK：应返回错误而不是死循环
func TestSearchVMKInMemoryImage_NoVMKReturnsError(t *testing.T) {
	// 跟上面一样合成一个 VMK datum 但 mem 里不放真 VMK
	realVMK := make([]byte, 32)
	for i := range realVMK {
		realVMK[i] = byte(0xAA + i)
	}
	innerKeyDatum := make([]byte, 8+4+32)
	binary.LittleEndian.PutUint16(innerKeyDatum[0:2], uint16(len(innerKeyDatum)))
	binary.LittleEndian.PutUint16(innerKeyDatum[4:6], DatumValueKey)
	binary.LittleEndian.PutUint32(innerKeyDatum[8:12], 0x4000)
	nonce := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	ct, tag, _ := EncryptAESCCM(realVMK, nonce, innerKeyDatum)
	aesccmBody := make([]byte, 28+len(ct))
	copy(aesccmBody[12:28], tag)
	copy(aesccmBody[28:], ct)
	aesccmDatum := buildDatum(0, DatumValueAESCCMKey, aesccmBody)
	vmkBody := make([]byte, 28+len(aesccmDatum))
	copy(vmkBody[28:], aesccmDatum)
	vmkBytes := buildDatum(DatumEntryVMKInfo, DatumValueVMK, vmkBody)
	d, _, _ := ParseDatum(vmkBytes, 0)
	vmkDatum := &VMKDatum{ProtectionType: VMKProtectionTPM, Datum: d}

	mem := make([]byte, 256*1024) // 小一点跑得快
	for i := range mem {
		mem[i] = byte(i)
	}
	r := testutil.NewMemReader(mem)
	_, err := SearchVMKInMemoryImage(context.Background(), r, vmkDatum, nil)
	if err == nil {
		t.Error("内存里没 VMK，应返回错误")
	}
}
