package apfs

import (
	"encoding/binary"
	"testing"

	"data-recovery/internal/testutil"
)

// 合成场景：
//   - 容器在物理盘 offset 0
//   - 块大小 4096
//   - 容器超块 NXSB 在物理 block 0
//   - keybag 在物理 block 5
//   - keybag 内容是一个最小 kb_locker（version=2, 1 entry）
//
// 期望：
//   - Detect 解出 KeyLocker = {pAddr=5, blocks=1}
//   - ReadKeyBagFromContainer 读到 block 5 → ParseKeyBag → 1 entry
func TestReadKeyBagFromContainer_EndToEnd(t *testing.T) {
	const blockSize = 4096
	disk := make([]byte, 64*blockSize)

	// === 1. 容器超块 (NXSB) ===
	nx := disk[0:blockSize]
	copy(nx[nxMagicOffset:nxMagicOffset+4], []byte("NXSB"))
	binary.LittleEndian.PutUint32(nx[nxBlockSizeOffset:nxBlockSizeOffset+4], blockSize)
	binary.LittleEndian.PutUint64(nx[nxBlockCountOffset:nxBlockCountOffset+8], 64)
	// nx_keylocker @ 0xC8: pAddr=5, blocks=1
	binary.LittleEndian.PutUint64(nx[nxKeylockerOffset:nxKeylockerOffset+8], 5)
	binary.LittleEndian.PutUint64(nx[nxKeylockerOffset+8:nxKeylockerOffset+16], 1)

	// === 2. keybag block @ block 5 ===
	kb := disk[5*blockSize : 6*blockSize]
	// obj_phys 32 字节 0
	body := kb[32:]
	binary.LittleEndian.PutUint16(body[0:2], 2) // version
	binary.LittleEndian.PutUint16(body[2:4], 1) // 1 entry
	// nbytes = 1 entry 的字节数（24 + keyData_len）
	const keyDataLen = 16
	const entryLen = 24 + keyDataLen
	binary.LittleEndian.PutUint32(body[4:8], entryLen)

	// entry @ body+0x10
	ent := body[0x10:]
	for i := 0; i < 16; i++ {
		ent[i] = byte(0xC0 + i) // UUID
	}
	binary.LittleEndian.PutUint16(ent[16:18], KeyBagTagWrappedVEK) // tag
	binary.LittleEndian.PutUint16(ent[18:20], keyDataLen)
	for i := 0; i < keyDataLen; i++ {
		ent[24+i] = byte(0xA0 + i) // keyData
	}

	r := testutil.NewMemReader(disk)
	c, err := Detect(r, 0)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if c == nil {
		t.Fatal("Detect 没识别 NXSB")
	}
	if c.KeyLocker.StartPAddr != 5 || c.KeyLocker.BlockCount != 1 {
		t.Errorf("KeyLocker 错: %+v", c.KeyLocker)
	}

	bag, err := ReadKeyBagFromContainer(r, c)
	if err != nil {
		t.Fatalf("ReadKeyBagFromContainer: %v", err)
	}
	if bag.Version != 2 {
		t.Errorf("version=%d", bag.Version)
	}
	if len(bag.Entries) != 1 {
		t.Fatalf("entries=%d", len(bag.Entries))
	}
	if bag.Entries[0].Tag != KeyBagTagWrappedVEK {
		t.Errorf("tag=0x%X", bag.Entries[0].Tag)
	}
	if bag.Entries[0].UUID[0] != 0xC0 || bag.Entries[0].UUID[15] != 0xCF {
		t.Errorf("UUID 不匹配: %X", bag.Entries[0].UUID)
	}
	if len(bag.Entries[0].KeyData) != 16 || bag.Entries[0].KeyData[0] != 0xA0 {
		t.Errorf("keyData 不匹配: %X", bag.Entries[0].KeyData)
	}
}

// 容器没启用 FileVault — KeyLocker 为零，应明确报错
func TestReadKeyBagFromContainer_NotEncrypted(t *testing.T) {
	c := &Container{KeyLocker: PRange{}}
	_, err := ReadKeyBagFromContainer(nil, c)
	if err == nil {
		t.Error("无 keybag 应报错")
	}
}

// PRange 异常长度（恶意 metadata 撑爆内存防御）
func TestReadKeyBagFromPRange_RejectsHugeRange(t *testing.T) {
	c := &Container{
		Offset:    0,
		BlockSize: 4096,
		KeyLocker: PRange{StartPAddr: 0, BlockCount: 1 << 20}, // 4GB - 应被拒
	}
	_, err := ReadKeyBagFromContainer(testutil.NewMemReader(make([]byte, 4096)), c)
	if err == nil {
		t.Error("4GB keybag 应被拒")
	}
}
