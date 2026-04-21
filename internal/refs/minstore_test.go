package refs

import (
	"encoding/binary"
	"testing"

	"data-recovery/internal/testutil"
)

// 合成卷：5 个 16KB page，其中 3 个 MSB+，1 个 CHKP，1 个空白
func TestIndexMinstorePages_FindsKnownSigs(t *testing.T) {
	const pages = 5
	disk := make([]byte, pages*MinstorePageSize)

	writePage := func(idx int, magic string, lsn uint64) {
		off := int64(idx) * MinstorePageSize
		copy(disk[off:off+4], []byte(magic))
		binary.LittleEndian.PutUint64(disk[off+8:off+16], lsn)
	}
	writePage(0, "MSB+", 100)
	writePage(1, "MSB+", 250)
	writePage(2, "CHKP", 999)
	// page 3：空白
	writePage(4, "MSB+", 200)

	r := testutil.NewMemReader(disk)
	res, err := IndexMinstorePages(r, 0, int64(len(disk)))
	if err != nil {
		t.Fatalf("IndexMinstorePages: %v", err)
	}
	if len(res) != 4 {
		t.Fatalf("识别 page 数 %d want 4", len(res))
	}
	if res[0].Offset != 0 || res[0].Magic != "MSB+" || res[0].LSN != 100 {
		t.Errorf("page[0] 错: %+v", res[0])
	}
	if res[2].Magic != "CHKP" || res[2].LSN != 999 {
		t.Errorf("CHKP page 错: %+v", res[2])
	}
}

// 合成一个包含 2 个 entry 的最小 MSB+ page，验证 ParseMinstorePage 能解出 key/value。
// 由于 ReFS 无公开规范，本测试只验证 best-effort parser 在我们自己的"假定布局"下
// 行为正确（后续真实数据若发现不同 layout 再调整）。
func TestParseMinstorePage_ParsesEntries(t *testing.T) {
	const pageSize = 16384
	buf := make([]byte, pageSize)
	copy(buf[0:4], []byte("MSB+"))

	const indexHdrAt = 0x20
	const firstEntryOff = 0x100

	binary.LittleEndian.PutUint32(buf[indexHdrAt:indexHdrAt+4], firstEntryOff)
	binary.LittleEndian.PutUint32(buf[indexHdrAt+8:indexHdrAt+12], 2)

	// entry 1: size=64, key @ +16 (8 byte), val @ +24 (16 byte)
	entry1 := firstEntryOff
	binary.LittleEndian.PutUint16(buf[entry1:entry1+2], 64)
	binary.LittleEndian.PutUint16(buf[entry1+2:entry1+4], 16) // keyOff
	binary.LittleEndian.PutUint16(buf[entry1+4:entry1+6], 8)
	binary.LittleEndian.PutUint16(buf[entry1+6:entry1+8], 24) // valOff
	binary.LittleEndian.PutUint16(buf[entry1+8:entry1+10], 16)
	for i := 0; i < 8; i++ {
		buf[entry1+16+i] = byte(0xA0 + i)
	}
	for i := 0; i < 16; i++ {
		buf[entry1+24+i] = byte(0xC0 + i)
	}

	// entry 2 紧接：size=48, key @ +16 (4)，val @ +20 (8)
	entry2 := entry1 + 64
	binary.LittleEndian.PutUint16(buf[entry2:entry2+2], 48)
	binary.LittleEndian.PutUint16(buf[entry2+2:entry2+4], 16)
	binary.LittleEndian.PutUint16(buf[entry2+4:entry2+6], 4)
	binary.LittleEndian.PutUint16(buf[entry2+6:entry2+8], 20)
	binary.LittleEndian.PutUint16(buf[entry2+8:entry2+10], 8)
	for i := 0; i < 4; i++ {
		buf[entry2+16+i] = byte(0x10 + i)
	}
	for i := 0; i < 8; i++ {
		buf[entry2+20+i] = byte(0x70 + i)
	}

	entries, err := ParseMinstorePage(buf)
	if err != nil {
		t.Fatalf("ParseMinstorePage: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("entries=%d want 2", len(entries))
	}
	if len(entries[0].Key) != 8 || len(entries[0].Value) != 16 {
		t.Errorf("entry 0 size: key=%d val=%d", len(entries[0].Key), len(entries[0].Value))
	}
	if entries[0].Key[0] != 0xA0 {
		t.Errorf("entry 0 key[0]=0x%X want 0xA0", entries[0].Key[0])
	}
	if entries[1].Key[0] != 0x10 {
		t.Errorf("entry 1 key[0]=0x%X want 0x10", entries[1].Key[0])
	}
}

// 非 MSB+ page 应返回 nil
func TestParseMinstorePage_NotMSBPlus(t *testing.T) {
	buf := make([]byte, 16384)
	copy(buf[0:4], []byte("XXXX"))
	got, err := ParseMinstorePage(buf)
	if err != nil {
		t.Fatalf("err 应 nil: %v", err)
	}
	if got != nil {
		t.Error("非 MSB+ 应返回 nil")
	}
}

func TestSummarizeMinstore_AggregatesCorrectly(t *testing.T) {
	const pages = 6
	disk := make([]byte, pages*MinstorePageSize)
	for i, magic := range []string{"MSB+", "MSB+", "CHKP", "", "MSB+", "CHKP"} {
		off := int64(i) * MinstorePageSize
		if magic == "" {
			continue
		}
		copy(disk[off:off+4], []byte(magic))
		binary.LittleEndian.PutUint64(disk[off+8:off+16], uint64(100+i*10))
	}
	r := testutil.NewMemReader(disk)
	s, err := SummarizeMinstore(r, 0, int64(len(disk)))
	if err != nil {
		t.Fatalf("SummarizeMinstore: %v", err)
	}
	if s.TotalPages != 5 {
		t.Errorf("Total %d want 5", s.TotalPages)
	}
	if s.MSBPlusCount != 3 {
		t.Errorf("MSB+ count %d want 3", s.MSBPlusCount)
	}
	if s.CheckpointCnt != 2 {
		t.Errorf("CHKP count %d want 2", s.CheckpointCnt)
	}
	// 最高 LSN：i=5 是 CHKP, lsn = 100+50 = 150
	if s.HighestLSN != 150 {
		t.Errorf("HighestLSN %d want 150", s.HighestLSN)
	}
}
