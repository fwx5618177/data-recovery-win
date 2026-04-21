package veracrypt

import (
	"crypto/rand"
	"testing"

	"data-recovery/internal/testutil"
)

func TestDetect_VeraCrypt_HighEntropy(t *testing.T) {
	disk := make([]byte, 4096)
	rand.Read(disk) // 全随机 = 高熵
	r := testutil.NewMemReader(disk)
	got, _ := Detect(r, 0)
	if got == nil {
		t.Fatal("高熵盘头应被识别为可能的 VC 容器")
	}
	if got.Confidence <= 0 {
		t.Error("Confidence 应 > 0")
	}
}

func TestDetect_NotVeraCrypt_NTFS(t *testing.T) {
	disk := make([]byte, 4096)
	copy(disk[3:11], []byte("NTFS    "))
	r := testutil.NewMemReader(disk)
	if got, _ := Detect(r, 0); got != nil {
		t.Error("NTFS 盘不应被识别为 VC")
	}
}

func TestDetect_NotVeraCrypt_LowEntropy(t *testing.T) {
	disk := make([]byte, 4096)
	for i := range disk {
		disk[i] = byte(i & 0x0F) // 低熵规律
	}
	r := testutil.NewMemReader(disk)
	if got, _ := Detect(r, 0); got != nil {
		t.Error("低熵盘不应被识别为 VC")
	}
}
