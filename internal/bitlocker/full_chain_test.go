package bitlocker

import (
	"bytes"
	"encoding/binary"
	"testing"

	"data-recovery/internal/testutil"
)

// TestFullChain_RealLikeBitLockerImage 合成一张"几乎像真"的 BitLocker 布局，
// 从入口 API 的视角一路把整条解锁链路跑通：
//
//	物理磁盘 bytes
//	  └─ Detect            → 定位 BitLocker 卷 / 三个 FVE metadata block 偏移
//	      └─ UnlockBitLockerVolumeWithRecoveryKey
//	           ├─ ParseFVEMetadataBlock          解 metadata + datum 树
//	           ├─ FindRecoveryPasswordVMK        在 VMK 列表里挑 recovery 保护器
//	           ├─ UnlockVMKWithRecoveryKey       48 位 key → stretched → AES-CCM → VMK
//	           ├─ ExtractFVEKFromMetadata        VMK → AES-CCM → FVEK
//	           └─ buildXTSCipherForMethod + NewDecryptingReader
//	  └─ DecryptingReader.ReadAt   透明解密 XTS 扇区 → 原始明文
//
// 覆盖目标：任何一环（boot sector / metadata header / datum 树嵌套 / AES-CCM / XTS /
// sector offset translation）回归都会让这个测试挂掉。
//
// 该测试跑 StretchKey 1M iter（~1-2s），-short 模式跳过。
func TestFullChain_RealLikeBitLockerImage(t *testing.T) {
	if testing.Short() {
		t.Skip("跳过 1M 次 stretch key（-short 模式）")
	}

	const (
		sectorSize       = 512
		diskPrefixBytes  = int64(4096) // 卷前面有 8 扇区的"杂物"（模拟 MBR / 其它分区）
		volumeSectors    = int64(128)  // BitLocker 卷 = 128 扇区 = 64KB
		dataSectorStart  = int64(64)   // XTS 加密数据从卷内扇区 64 开始（前面给 bootsect+metadata 用）
		dataSectorsCount = int64(32)   // 32 个扇区明文
		fveBlock1Sector  = int64(32)   // FVE metadata block 在卷内扇区 32
	)

	// ---------------- 1. 固定已知 recovery key ----------------
	const recoveryKey = "100958-067419-080553-145618-321024-720885-000011-000022"
	intermediate, err := ParseRecoveryPassword(recoveryKey)
	if err != nil {
		t.Fatalf("ParseRecoveryPassword: %v", err)
	}

	// ---------------- 2. VMK / FVEK 密钥素材 ----------------
	vmk := make([]byte, 32)
	for i := range vmk {
		vmk[i] = byte(0xB0 + i)
	}
	fvek := make([]byte, 32) // XTS-128: K1(16) + K2(16)
	for i := range fvek {
		fvek[i] = byte(0x40 + i)
	}

	// ---------------- 3. STRETCH_KEY salt + stretched key ----------------
	var salt [16]byte
	for i := range salt {
		salt[i] = byte(0xE0 + i)
	}
	stretched := StretchKey(intermediate[:], salt, nil)

	// ---------------- 4. 加密 VMK (用 stretched key) ----------------
	// VMK 明文 = 嵌套 KEY datum (头 8 + method 4 + 32 vmk)
	vmkKeyDatum := make([]byte, 8+4+32)
	binary.LittleEndian.PutUint16(vmkKeyDatum[0:2], uint16(len(vmkKeyDatum)))
	binary.LittleEndian.PutUint16(vmkKeyDatum[2:4], 0)
	binary.LittleEndian.PutUint16(vmkKeyDatum[4:6], DatumValueKey)
	binary.LittleEndian.PutUint16(vmkKeyDatum[6:8], 1)
	binary.LittleEndian.PutUint32(vmkKeyDatum[8:12], 0x4000) // method
	copy(vmkKeyDatum[12:], vmk)

	vmkNonce := []byte{0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0x01, 0x02, 0x03, 0x04}
	vmkCT, vmkTag, err := EncryptAESCCM(stretched[:], vmkNonce, vmkKeyDatum)
	if err != nil {
		t.Fatalf("EncryptAESCCM(VMK): %v", err)
	}

	vmkAESCCMBody := make([]byte, 28+len(vmkCT))
	copy(vmkAESCCMBody[0:8], vmkNonce[0:8])
	copy(vmkAESCCMBody[8:12], vmkNonce[8:12])
	copy(vmkAESCCMBody[12:28], vmkTag)
	copy(vmkAESCCMBody[28:], vmkCT)
	vmkAESCCMDatum := buildDatum(0, DatumValueAESCCMKey, vmkAESCCMBody)

	// STRETCH_KEY datum: 4 method + 16 salt + 嵌套 AES_CCM datum
	stretchBody := make([]byte, 20+len(vmkAESCCMDatum))
	binary.LittleEndian.PutUint32(stretchBody[0:4], 0x2000)
	copy(stretchBody[4:20], salt[:])
	copy(stretchBody[20:], vmkAESCCMDatum)
	stretchDatum := buildDatum(0, DatumValueStretchKey, stretchBody)

	// VMK datum: 28 header + 嵌套 STRETCH_KEY datum
	vmkBody := make([]byte, 28+len(stretchDatum))
	for i := 0; i < 16; i++ {
		vmkBody[i] = byte(0x10 + i)
	}
	binary.LittleEndian.PutUint16(vmkBody[24:26], VMKProtectionRecoveryPwd)
	copy(vmkBody[28:], stretchDatum)
	vmkDatumBytes := buildDatum(DatumEntryVMKInfo, DatumValueVMK, vmkBody)

	// ---------------- 5. 加密 FVEK (用 VMK) ----------------
	// FVEK 明文 = 嵌套 KEY datum (头 8 + method=0x8004 AES-XTS-128 + 32 字节 FVEK)
	fvekKeyDatum := make([]byte, 8+4+32)
	binary.LittleEndian.PutUint16(fvekKeyDatum[0:2], uint16(len(fvekKeyDatum)))
	binary.LittleEndian.PutUint16(fvekKeyDatum[2:4], 0)
	binary.LittleEndian.PutUint16(fvekKeyDatum[4:6], DatumValueKey)
	binary.LittleEndian.PutUint16(fvekKeyDatum[6:8], 1)
	binary.LittleEndian.PutUint32(fvekKeyDatum[8:12], uint32(EncryptionAESXTS128))
	copy(fvekKeyDatum[12:], fvek)

	fvekNonce := []byte{0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0x05, 0x06, 0x07, 0x08}
	fvekCT, fvekTag, err := EncryptAESCCM(vmk, fvekNonce, fvekKeyDatum)
	if err != nil {
		t.Fatalf("EncryptAESCCM(FVEK): %v", err)
	}

	fvekAESCCMBody := make([]byte, 28+len(fvekCT))
	copy(fvekAESCCMBody[0:8], fvekNonce[0:8])
	copy(fvekAESCCMBody[8:12], fvekNonce[8:12])
	copy(fvekAESCCMBody[12:28], fvekTag)
	copy(fvekAESCCMBody[28:], fvekCT)
	fvekAESCCMDatum := buildDatum(0, DatumValueAESCCMKey, fvekAESCCMBody)

	// FVEK info datum：Type=FVEKInfo, ValueType=USE，body=4 byte role + 嵌套 AES_CCM
	// 选 USE 是因为 parser 的 hasNestedChildren 识别 USE 并递归子 datum；
	// 真实 BitLocker 的 FVEK info 通常走类似模式（type role 包着 AES_CCM）。
	fvekUseBody := make([]byte, 4+len(fvekAESCCMDatum))
	binary.LittleEndian.PutUint32(fvekUseBody[0:4], UseRoleAESCCMKey)
	copy(fvekUseBody[4:], fvekAESCCMDatum)
	fvekInfoDatum := buildDatum(DatumEntryFVEKInfo, DatumValueUse, fvekUseBody)

	// ---------------- 6. 组装 FVE metadata block ----------------
	// 头部 64 字节（offset 0 签名 "-FVE-FS-"；12=HeaderSize；36=EncryptionMethod）
	datumsArea := append([]byte{}, vmkDatumBytes...)
	datumsArea = append(datumsArea, fvekInfoDatum...)

	metaHeaderLen := uint16(64)
	metaTotalSize := uint16(int(metaHeaderLen) + len(datumsArea))
	fveMetaBytes := make([]byte, metaTotalSize)
	copy(fveMetaBytes[0:8], []byte(fveOEMID))
	binary.LittleEndian.PutUint16(fveMetaBytes[8:10], metaTotalSize)
	binary.LittleEndian.PutUint16(fveMetaBytes[10:12], 2)             // Version
	binary.LittleEndian.PutUint16(fveMetaBytes[12:14], metaHeaderLen) // HeaderSize
	binary.LittleEndian.PutUint16(fveMetaBytes[14:16], 1)             // CopyNumber
	for i := 0; i < 16; i++ {
		fveMetaBytes[16+i] = byte(0xC0 + i) // VolumeIdentifier
	}
	binary.LittleEndian.PutUint32(fveMetaBytes[32:36], 0)
	binary.LittleEndian.PutUint16(fveMetaBytes[36:38], EncryptionAESXTS128)
	copy(fveMetaBytes[metaHeaderLen:], datumsArea)

	// ---------------- 7. 组装 boot sector ----------------
	boot := make([]byte, sectorSize)
	boot[0], boot[1], boot[2] = 0xEB, 0x58, 0x90 // jump
	copy(boot[3:11], []byte(fveOEMID))
	binary.LittleEndian.PutUint16(boot[11:13], sectorSize) // BytesPerSector
	boot[13] = 8                                           // SectorsPerCluster
	binary.LittleEndian.PutUint64(boot[40:48], uint64(volumeSectors))
	// FVE metadata block 偏移（扇区单位）
	binary.LittleEndian.PutUint64(boot[176:184], uint64(fveBlock1Sector))
	binary.LittleEndian.PutUint64(boot[184:192], uint64(fveBlock1Sector)) // 三份都用同一份
	binary.LittleEndian.PutUint64(boot[192:200], uint64(fveBlock1Sector))
	boot[510], boot[511] = 0x55, 0xAA

	// ---------------- 8. 准备明文 + XTS 加密到数据扇区 ----------------
	plaintext := make([]byte, dataSectorsCount*sectorSize)
	for s := int64(0); s < dataSectorsCount; s++ {
		for i := int64(0); i < sectorSize; i++ {
			plaintext[s*sectorSize+i] = byte((s*13 + i*7) & 0xFF)
		}
	}
	xts, err := NewXTSCipher(fvek, sectorSize)
	if err != nil {
		t.Fatalf("NewXTSCipher: %v", err)
	}
	encData := make([]byte, len(plaintext))
	for s := int64(0); s < dataSectorsCount; s++ {
		off := s * sectorSize
		// 关键：sector_num 用 **卷内** 扇区号（dataSectorStart + s）
		if err := xts.EncryptSector(encData[off:off+sectorSize], plaintext[off:off+sectorSize], uint64(dataSectorStart+s)); err != nil {
			t.Fatalf("EncryptSector %d: %v", s, err)
		}
	}

	// ---------------- 9. 铺到"磁盘"字节切片 ----------------
	diskBytes := make([]byte, diskPrefixBytes+volumeSectors*sectorSize)
	for i := int64(0); i < diskPrefixBytes; i++ {
		diskBytes[i] = 0x5A // 前置区垃圾填充
	}
	// boot sector 位于磁盘偏移 diskPrefixBytes
	copy(diskBytes[diskPrefixBytes:diskPrefixBytes+sectorSize], boot)
	// FVE metadata block 位于磁盘偏移 diskPrefixBytes + fveBlock1Sector*sectorSize
	metaAbsOff := diskPrefixBytes + fveBlock1Sector*sectorSize
	copy(diskBytes[metaAbsOff:metaAbsOff+int64(metaTotalSize)], fveMetaBytes)
	// XTS 加密数据扇区
	dataAbsOff := diskPrefixBytes + dataSectorStart*sectorSize
	copy(diskBytes[dataAbsOff:dataAbsOff+int64(len(encData))], encData)

	// ---------------- 10. Detect → Unlock → ReadAt ----------------
	disk := testutil.NewMemReader(diskBytes)

	vol, err := Detect(disk, diskPrefixBytes)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if vol == nil {
		t.Fatalf("Detect 没识别出 BitLocker 卷")
	}
	if vol.Offset != diskPrefixBytes {
		t.Errorf("Detect.Offset 错: got %d want %d", vol.Offset, diskPrefixBytes)
	}
	if vol.FVEMetaBlockOffset1 != fveBlock1Sector*sectorSize {
		t.Errorf("Detect.FVEMetaBlockOffset1 错: got %d want %d",
			vol.FVEMetaBlockOffset1, fveBlock1Sector*sectorSize)
	}

	res, err := UnlockBitLockerVolumeWithRecoveryKey(disk, vol, recoveryKey, nil)
	if err != nil {
		t.Fatalf("UnlockBitLockerVolumeWithRecoveryKey: %v", err)
	}
	if res == nil || res.Reader == nil {
		t.Fatal("解锁结果为空")
	}
	if res.EncryptionMethod != EncryptionAESXTS128 {
		t.Errorf("EncryptionMethod 错: got 0x%04X want 0x%04X",
			res.EncryptionMethod, EncryptionAESXTS128)
	}

	// DecryptingReader 从"卷起点"视角读 —— 读取数据扇区应该拿到原始明文
	gotAll := make([]byte, len(plaintext))
	n, _ := res.Reader.ReadAt(gotAll, dataSectorStart*sectorSize)
	if n != len(plaintext) {
		t.Fatalf("ReadAt 字节数错: got %d want %d", n, len(plaintext))
	}
	if !bytes.Equal(gotAll, plaintext) {
		t.Errorf("整段数据区解密不匹配\n  前 32 字节 got  %x\n  前 32 字节 want %x",
			gotAll[:32], plaintext[:32])
	}

	// 验证不对齐 / 跨扇区读也 OK（ReadAt 的关键特性）
	offset := dataSectorStart*sectorSize + 100
	length := int64(sectorSize*2 + 50)
	part := make([]byte, length)
	n, _ = res.Reader.ReadAt(part, offset)
	if int64(n) != length {
		t.Fatalf("跨扇区 ReadAt 字节数错: got %d want %d", n, length)
	}
	wantPart := make([]byte, length)
	// offset = prefix + dataSectorStart*512 + 100，但 plaintext 是按 dataSectorStart 偏移的
	// 所以 plaintext 里对应段起点 = 100
	copy(wantPart, plaintext[100:100+length])
	if !bytes.Equal(part, wantPart) {
		t.Errorf("跨扇区解密不匹配\n  got  %x\n  want %x",
			part[:32], wantPart[:32])
	}
}
