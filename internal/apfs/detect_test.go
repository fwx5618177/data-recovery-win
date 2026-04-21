package apfs

import (
	"encoding/binary"
	"testing"

	"data-recovery/internal/testutil"
)

// buildAPFSContainerSuperblock 造一个最小合法的 NXSB 容器超块
func buildAPFSContainerSuperblock(blockSize uint32, fsOIDs []uint64) []byte {
	bs := make([]byte, blockSize)
	// magic NXSB at offset 32
	copy(bs[nxMagicOffset:nxMagicOffset+4], []byte("NXSB"))
	binary.LittleEndian.PutUint32(bs[nxBlockSizeOffset:nxBlockSizeOffset+4], blockSize)
	binary.LittleEndian.PutUint64(bs[nxBlockCountOffset:nxBlockCountOffset+8], 100000)
	// UUID (任意值)
	for i := 0; i < 16; i++ {
		bs[nxUUIDOffset+i] = byte(i + 1)
	}
	// fs_oid 列表
	for i, oid := range fsOIDs {
		if i >= nxFSOIDCount {
			break
		}
		off := nxFSOIDOffset + i*8
		binary.LittleEndian.PutUint64(bs[off:off+8], oid)
	}
	return bs
}

// buildAPFSVolumeSuperblock 造一个最小合法的 APSB 卷超块
func buildAPFSVolumeSuperblock(name string, encrypted bool, blockSize uint32) []byte {
	bs := make([]byte, blockSize)
	copy(bs[32:36], []byte("APSB"))

	// fs_flags：bit 0 = unencrypted（1=未加密；0=加密）
	var flags uint64 = 0x01 // 默认未加密
	if encrypted {
		flags = 0x00
	}
	binary.LittleEndian.PutUint64(bs[264:272], flags)

	// volname
	if len(name) > 255 {
		name = name[:255]
	}
	copy(bs[704:704+len(name)], []byte(name))
	bs[704+len(name)] = 0 // NUL-terminator

	// 文件数 / 目录数
	binary.LittleEndian.PutUint64(bs[1024:1032], 1234) // file count
	binary.LittleEndian.PutUint64(bs[1032:1040], 56)   // folder count

	// UUID
	for i := 0; i < 16; i++ {
		bs[240+i] = byte(0xA0 + i)
	}
	return bs
}

func TestDetect_APFSContainer_TwoVolumes(t *testing.T) {
	const blockSize uint32 = 4096

	// 容器在 offset 0；fs_oid[0]=10, fs_oid[1]=20
	container := buildAPFSContainerSuperblock(blockSize, []uint64{10, 20})

	// 卷在 OID 10 / 20 对应物理块（朴素假设：OID == 块号）
	vol1 := buildAPFSVolumeSuperblock("Macintosh HD", false, blockSize)
	vol2 := buildAPFSVolumeSuperblock("Macintosh HD - Data", true, blockSize)

	// 拼成镜像：100 个 block 大小
	img := make([]byte, 100*int64(blockSize))
	copy(img[0:blockSize], container)
	copy(img[10*int64(blockSize):11*int64(blockSize)], vol1)
	copy(img[20*int64(blockSize):21*int64(blockSize)], vol2)

	reader := testutil.NewMemReader(img)
	c, err := Detect(reader, 0)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if c == nil {
		t.Fatal("应识别为 APFS 容器")
	}
	if c.BlockSize != blockSize {
		t.Errorf("BlockSize 错: %d", c.BlockSize)
	}
	if len(c.Volumes) != 2 {
		t.Fatalf("应找到 2 个卷，实际 %d", len(c.Volumes))
	}
	if c.Volumes[0].Name != "Macintosh HD" {
		t.Errorf("Volumes[0].Name: %q", c.Volumes[0].Name)
	}
	if c.Volumes[0].IsEncrypted {
		t.Error("Volumes[0] 不应加密")
	}
	if c.Volumes[1].Name != "Macintosh HD - Data" {
		t.Errorf("Volumes[1].Name: %q", c.Volumes[1].Name)
	}
	if !c.Volumes[1].IsEncrypted {
		t.Error("Volumes[1] 应识别为加密（FileVault）")
	}
	if c.Volumes[0].FileCount != 1234 {
		t.Errorf("FileCount 错: %d", c.Volumes[0].FileCount)
	}
}

func TestDetect_NotAPFS(t *testing.T) {
	bs := make([]byte, 4096)
	// 没有 NXSB magic
	reader := testutil.NewMemReader(bs)
	c, err := Detect(reader, 0)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if c != nil {
		t.Error("非 APFS 不应被识别")
	}
}

func TestDetect_RejectsAbsurdBlockSize(t *testing.T) {
	bs := make([]byte, 4096)
	copy(bs[nxMagicOffset:nxMagicOffset+4], []byte("NXSB"))
	binary.LittleEndian.PutUint32(bs[nxBlockSizeOffset:nxBlockSizeOffset+4], 100) // 太小
	binary.LittleEndian.PutUint64(bs[nxBlockCountOffset:nxBlockCountOffset+8], 100)

	reader := testutil.NewMemReader(bs)
	c, _ := Detect(reader, 0)
	if c != nil {
		t.Error("异常 BlockSize 应被拒")
	}
}

func TestScanner_FindContainers(t *testing.T) {
	const blockSize uint32 = 4096
	const oneMB = 1024 * 1024

	// 镜像 8MB；放两个容器
	img := make([]byte, 8*oneMB)
	c1 := buildAPFSContainerSuperblock(blockSize, []uint64{5})
	c2 := buildAPFSContainerSuperblock(blockSize, nil)
	copy(img[0:blockSize], c1)
	copy(img[4*oneMB:4*oneMB+int64(blockSize)], c2)

	reader := testutil.NewMemReader(img)
	scanner := NewScanner(reader)
	containers, err := scanner.FindContainers()
	if err != nil {
		t.Fatalf("FindContainers: %v", err)
	}
	if len(containers) != 2 {
		t.Fatalf("应找到 2 个容器，实际 %d", len(containers))
	}
}
