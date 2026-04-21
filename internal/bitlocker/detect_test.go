package bitlocker

import (
	"encoding/binary"
	"testing"

	"data-recovery/internal/testutil"
)

func buildBitLockerBoot() []byte {
	bs := make([]byte, 512)
	bs[0], bs[1], bs[2] = 0xEB, 0x52, 0x90 // jump
	copy(bs[3:11], []byte("-FVE-FS-"))     // OEM ID
	binary.LittleEndian.PutUint16(bs[11:13], 512)
	bs[13] = 8
	binary.LittleEndian.PutUint64(bs[40:48], 1000000)

	// FVE metadata block offsets (sector 单位)
	binary.LittleEndian.PutUint64(bs[176:184], 100)
	binary.LittleEndian.PutUint64(bs[184:192], 200)
	binary.LittleEndian.PutUint64(bs[192:200], 300)

	binary.LittleEndian.PutUint16(bs[510:512], 0xAA55)
	return bs
}

func TestDetect_BitLockerVolume(t *testing.T) {
	reader := testutil.NewMemReader(buildBitLockerBoot())
	v, err := Detect(reader, 0)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if v == nil {
		t.Fatal("应识别为 BitLocker 卷")
	}
	if v.OEMID != "-FVE-FS-" {
		t.Errorf("OEMID 错: %q", v.OEMID)
	}
	if v.BytesPerSector != 512 {
		t.Errorf("BytesPerSector 错: %d", v.BytesPerSector)
	}
	if v.SectorsPerCluster != 8 {
		t.Errorf("SectorsPerCluster 错: %d", v.SectorsPerCluster)
	}
	if v.TotalSectors != 1000000 {
		t.Errorf("TotalSectors 错: %d", v.TotalSectors)
	}
	if v.FVEMetaBlockOffset1 != 100*512 {
		t.Errorf("FVEMetaBlockOffset1 错: %d", v.FVEMetaBlockOffset1)
	}
}

func TestDetect_NotBitLocker(t *testing.T) {
	bs := make([]byte, 512)
	copy(bs[3:11], []byte("NTFS    "))
	binary.LittleEndian.PutUint16(bs[510:512], 0xAA55)

	reader := testutil.NewMemReader(bs)
	v, err := Detect(reader, 0)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if v != nil {
		t.Errorf("非 BitLocker 不应被识别，得到: %+v", v)
	}
}

func TestDetect_BadBootSignature(t *testing.T) {
	bs := buildBitLockerBoot()
	bs[510] = 0x00 // 破坏 signature

	reader := testutil.NewMemReader(bs)
	v, _ := Detect(reader, 0)
	if v != nil {
		t.Error("非法 boot signature 应被拒")
	}
}

func TestScanner_FindVolumes(t *testing.T) {
	// 镜像里塞 2 个 BitLocker 卷头：在 offset 0 和 offset 4MB
	const oneMB = 1024 * 1024
	img := make([]byte, 8*oneMB)
	copy(img[0:512], buildBitLockerBoot())
	copy(img[4*oneMB:4*oneMB+512], buildBitLockerBoot())

	reader := testutil.NewMemReader(img)
	scanner := NewScanner(reader)
	vols, err := scanner.FindVolumes()
	if err != nil {
		t.Fatalf("FindVolumes: %v", err)
	}
	if len(vols) != 2 {
		t.Errorf("应找到 2 个 BitLocker 卷，实际 %d", len(vols))
	}
}
