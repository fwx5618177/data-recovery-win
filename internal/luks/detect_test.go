package luks

import (
	"encoding/binary"
	"testing"

	"data-recovery/internal/testutil"
)

func TestDetect_LUKS1(t *testing.T) {
	disk := make([]byte, 1024)
	copy(disk[0:6], luksMagic)
	binary.BigEndian.PutUint16(disk[6:8], 1)
	copy(disk[8:40], []byte("aes"))
	copy(disk[40:72], []byte("xts-plain64"))
	binary.BigEndian.PutUint32(disk[104:108], 8)
	copy(disk[168:208], []byte("12345678-1234-1234-1234-123456789abc"))

	r := testutil.NewMemReader(disk)
	got, err := Detect(r, 0)
	if err != nil || got == nil {
		t.Fatalf("Detect: %v %+v", err, got)
	}
	if got.Version != 1 || got.CipherName != "aes" || got.CipherMode != "xts-plain64" {
		t.Errorf("字段错: %+v", got)
	}
}

func TestDetect_LUKS2(t *testing.T) {
	disk := make([]byte, 1024)
	copy(disk[0:6], luksMagic)
	binary.BigEndian.PutUint16(disk[6:8], 2)
	copy(disk[24:72], []byte("My Encrypted Volume"))
	r := testutil.NewMemReader(disk)
	got, _ := Detect(r, 0)
	if got == nil || got.Version != 2 || got.Label != "My Encrypted Volume" {
		t.Errorf("LUKS2: %+v", got)
	}
}
