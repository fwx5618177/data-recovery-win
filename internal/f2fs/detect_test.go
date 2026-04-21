package f2fs

import (
	"encoding/binary"
	"testing"

	"data-recovery/internal/testutil"
)

func TestDetect_F2FS(t *testing.T) {
	disk := make([]byte, 2048)
	binary.LittleEndian.PutUint32(disk[1024:1028], f2fsMagic)
	binary.LittleEndian.PutUint32(disk[1024+16:1024+20], 12) // log_blocksize = 12 → 4096
	r := testutil.NewMemReader(disk)
	got, err := Detect(r, 0)
	if err != nil || got == nil {
		t.Fatalf("Detect: %v %+v", err, got)
	}
	if got.BlockSize != 4096 {
		t.Errorf("BlockSize=%d", got.BlockSize)
	}
}
