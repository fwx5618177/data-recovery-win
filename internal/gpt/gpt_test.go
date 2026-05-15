package gpt

import (
	"encoding/binary"
	"hash/crc32"
	"testing"

	"data-recovery/internal/testutil"
)

// 合成一个 4MB 磁盘 + 主 GPT 头 + 1 个分区，验证 ReadPrimaryHeader + ReadPartitions
func TestReadPrimaryHeader_Basic(t *testing.T) {
	const size = int64(4 * 1024 * 1024)
	disk := make([]byte, size)
	hdr := disk[512:1024] // LBA 1
	copy(hdr[0:8], []byte(GPTSignature))
	binary.LittleEndian.PutUint32(hdr[8:12], 0x00010000)
	binary.LittleEndian.PutUint32(hdr[12:16], 92) // header size
	binary.LittleEndian.PutUint64(hdr[24:32], 1)  // my_lba
	binary.LittleEndian.PutUint64(hdr[40:48], 34)
	binary.LittleEndian.PutUint64(hdr[48:56], 8158)
	binary.LittleEndian.PutUint64(hdr[72:80], 2) // part_entry_lba
	binary.LittleEndian.PutUint32(hdr[80:84], 1) // 1 entry
	binary.LittleEndian.PutUint32(hdr[84:88], 128)
	// 计算 CRC（CRC 字段先 0）
	binary.LittleEndian.PutUint32(hdr[16:20], 0)
	c := crc32.ChecksumIEEE(hdr[0:92])
	binary.LittleEndian.PutUint32(hdr[16:20], c)

	// 分区 entry @ LBA 2
	ent := disk[1024 : 1024+128]
	for i := 0; i < 16; i++ {
		ent[i] = byte(0xA0 + i) // 非零 typeGUID
	}
	binary.LittleEndian.PutUint64(ent[32:40], 100) // start LBA
	binary.LittleEndian.PutUint64(ent[40:48], 200) // end LBA

	r := testutil.NewMemReader(disk)
	h, err := ReadPrimaryHeader(r)
	if err != nil {
		t.Fatalf("ReadPrimaryHeader: %v", err)
	}
	if !h.IsValidCRC {
		t.Error("CRC 应通过")
	}
	parts, err := ReadPartitions(r, h)
	if err != nil {
		t.Fatalf("ReadPartitions: %v", err)
	}
	if len(parts) != 1 {
		t.Fatalf("partitions=%d want 1", len(parts))
	}
	if parts[0].StartLBA != 100 || parts[0].EndLBA != 200 {
		t.Errorf("partition: %+v", parts[0])
	}
}
