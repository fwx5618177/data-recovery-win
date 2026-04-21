package refs

import (
	"encoding/binary"
	"testing"

	"data-recovery/internal/testutil"
)

func makeReFSBootSector(buf []byte) {
	buf[0], buf[1], buf[2] = 0xEB, 0x76, 0x90
	copy(buf[3:11], []byte(refsOEMID))
	copy(buf[16:20], []byte(refsFSSignature))
	binary.LittleEndian.PutUint16(buf[24:26], 4096)        // bytes/sector（ReFS 默认 4K）
	buf[26] = 1                                            // sectors/cluster
	binary.LittleEndian.PutUint64(buf[32:40], 1<<24)       // total sectors
	binary.LittleEndian.PutUint64(buf[40:48], 0xCAFE)      // container number
	buf[48] = 3                                            // major version
	buf[49] = 5                                            // minor version
	buf[510], buf[511] = 0x55, 0xAA
}

func TestDetect_ReFS_Roundtrip(t *testing.T) {
	disk := make([]byte, 4096)
	makeReFSBootSector(disk)
	r := testutil.NewMemReader(disk)
	v, err := Detect(r, 0)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if v == nil {
		t.Fatal("ReFS 未识别")
	}
	if v.BytesPerSector != 4096 || v.SectorsPerCluster != 1 {
		t.Errorf("基本字段错: %+v", v)
	}
	if v.TotalSectors != 1<<24 {
		t.Errorf("TotalSectors 错: %d", v.TotalSectors)
	}
	if v.MajorVersion != 3 || v.MinorVersion != 5 {
		t.Errorf("Version 错: %d.%d", v.MajorVersion, v.MinorVersion)
	}
}

func TestDetect_NotReFS_ReturnsNil(t *testing.T) {
	disk := make([]byte, 4096)
	// boot signature 有但 OEM/FS sig 无
	disk[510], disk[511] = 0x55, 0xAA
	r := testutil.NewMemReader(disk)
	if v, _ := Detect(r, 0); v != nil {
		t.Error("不是 ReFS 应返回 nil")
	}
}

func TestFindVolumes_ScansForReFS(t *testing.T) {
	const volSize = int64(8 * 1024 * 1024)
	disk := make([]byte, volSize*2)
	makeReFSBootSector(disk[0:512])
	makeReFSBootSector(disk[volSize : volSize+512])
	r := testutil.NewMemReader(disk)
	vols, err := NewScanner(r).FindVolumes()
	if err != nil {
		t.Fatalf("FindVolumes: %v", err)
	}
	if len(vols) != 2 {
		t.Fatalf("应找到 2 个 ReFS 卷, 实际 %d", len(vols))
	}
}
