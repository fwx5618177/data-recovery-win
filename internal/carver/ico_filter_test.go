package carver

import (
	"bytes"
	"context"
	"encoding/binary"
	"testing"

	"data-recovery/internal/signature"
	"data-recovery/internal/testutil"
	"data-recovery/internal/types"
)

// forgeICOLike 造一段"看上去像 ICO"的数据：
// reserved=0, type=1, count=1, 单个 16 字节条目。具体字段由参数定制。
// 用来测收紧后的 detectICOSize 会把哪些非法组合拒掉。
func forgeICOLike(colorPlanes, bitCount uint16, dataOff, dataSize uint32) []byte {
	var buf bytes.Buffer
	// ICONDIR
	buf.Write([]byte{0x00, 0x00, 0x01, 0x00})          // reserved + type=1
	binary.Write(&buf, binary.LittleEndian, uint16(1)) // count
	// ICONDIRENTRY (16 bytes)
	buf.WriteByte(16) // width
	buf.WriteByte(16) // height
	buf.WriteByte(0)  // color count
	buf.WriteByte(0)  // reserved
	binary.Write(&buf, binary.LittleEndian, colorPlanes)
	binary.Write(&buf, binary.LittleEndian, bitCount)
	binary.Write(&buf, binary.LittleEndian, dataSize)
	binary.Write(&buf, binary.LittleEndian, dataOff)
	// 填充到 dataOff+dataSize 的位置以让 detectICOSize 能通过大小检查
	need := int(dataOff) + int(dataSize) - buf.Len()
	if need > 0 {
		buf.Write(make([]byte, need))
	}
	return buf.Bytes()
}

func TestDetectICOSize_RejectsInvalidBitCount(t *testing.T) {
	// bitCount=7 不在 {0,1,4,8,16,24,32} 允许集合内，应被拒
	data := forgeICOLike(1, 7, 22, 64)
	reader := testutil.NewMemReader(data)
	if got := detectICOSize(reader, 0, int64(len(data)+1024)); got != 0 {
		t.Errorf("非法 bitCount=7 的 ICO 应被拒，却返回 size=%d", got)
	}
}

func TestDetectICOSize_RejectsColorPlanesOver1(t *testing.T) {
	// colorPlanes=5 违反规范（真实 ICO 只能是 0 或 1）
	data := forgeICOLike(5, 24, 22, 64)
	reader := testutil.NewMemReader(data)
	if got := detectICOSize(reader, 0, int64(len(data)+1024)); got != 0 {
		t.Errorf("非法 colorPlanes=5 的 ICO 应被拒，却返回 size=%d", got)
	}
}

func TestDetectICOSize_RejectsDataOffsetInsideHeader(t *testing.T) {
	// dataOff=10 落在目录区(6+16=22)之前，误报特征
	data := forgeICOLike(1, 24, 10, 64)
	data = append(data, make([]byte, 128)...) // 填充
	reader := testutil.NewMemReader(data)
	if got := detectICOSize(reader, 0, int64(len(data)+1024)); got != 0 {
		t.Errorf("dataOff 落在头部区的 ICO 应被拒，却返回 size=%d", got)
	}
}

func TestDetectICOSize_RejectsAbsurdDataSize(t *testing.T) {
	// dataSize > 10MB 按误报处理（合法 ICO 基本不会这么大）
	data := forgeICOLike(1, 32, 22, 50*1024*1024)
	reader := testutil.NewMemReader(data[:1024]) // 前 1KB 足够做结构检查
	if got := detectICOSize(reader, 0, 100*1024*1024); got != 0 {
		t.Errorf("dataSize=50MB 的 ICO 应按误报拒掉，却返回 size=%d", got)
	}
}

func TestDetectICOSize_AcceptsPlausibleICO(t *testing.T) {
	// 正常 16x16 单帧 ICO：colorPlanes=1, bitCount=32, dataOff=22, dataSize=64
	data := forgeICOLike(1, 32, 22, 64)
	reader := testutil.NewMemReader(data)
	got := detectICOSize(reader, 0, int64(len(data)+1024))
	if got == 0 {
		t.Errorf("合法 ICO 不应被拒，返回 size=0")
	}
	if got != int64(22+64) {
		t.Errorf("size 计算错：got %d want %d", got, 22+64)
	}
}

// 回归测试：DefaultConfig 默认把 ico/exe/elf 从扫描集合剔除，
// 即便磁盘里塞了 ICO 头也不会被识别出来。
func TestDefaultConfig_DisablesSystemFileSignatures(t *testing.T) {
	cfg := DefaultConfig()
	want := map[string]bool{"ico": true, "exe": true, "elf": true}
	for _, ext := range cfg.DisabledExtensions {
		if !want[ext] {
			t.Errorf("意外禁用: %s", ext)
		}
		delete(want, ext)
	}
	if len(want) > 0 {
		t.Errorf("下列扩展名本应默认禁用，却未在 DisabledExtensions 中: %v", want)
	}
}

// 端到端：在磁盘里撒一堆合法 ICO magic，验证默认配置下一个都不会产出。
func TestCarverEngine_DefaultSkipsICO(t *testing.T) {
	// 构造 6 个合法最小 ICO 并平铺到磁盘上
	ico := forgeICOLike(1, 32, 22, 64)
	chunkSize := int64(1 * 1024 * 1024)
	disk := make([]byte, chunkSize*3)
	offs := []int64{1024, 5000, chunkSize + 2048, chunkSize + 50000, 2*chunkSize + 4096, 2*chunkSize + 100000}
	for _, off := range offs {
		copy(disk[off:], ico)
	}

	reader := testutil.NewMemReader(disk)
	cfg := DefaultConfig()
	cfg.ChunkSize = chunkSize
	cfg.Workers = 2
	cfg.MaxFileSize = chunkSize * 3

	engine := NewEngine(reader, signature.NewSignatureDB(), cfg)

	count := 0
	err := engine.Scan(context.Background(), 0, int64(len(disk)), nil,
		func(f *types.RecoveredFile) {
			if f.Extension == "ico" {
				count++
			}
		},
	)
	if err != nil {
		t.Fatalf("Scan 失败: %v", err)
	}
	if count != 0 {
		t.Errorf("默认配置下 ICO 应被完全跳过，实际产出 %d 个", count)
	}
}

// 允许用户显式启用 ICO：覆盖 DisabledExtensions 为空，埋的 ICO 就应该被找到
func TestCarverEngine_OptInCanEnableICO(t *testing.T) {
	ico := forgeICOLike(1, 32, 22, 64)
	disk := make([]byte, 1024*1024)
	copy(disk[2048:], ico)

	reader := testutil.NewMemReader(disk)
	cfg := DefaultConfig()
	cfg.ChunkSize = int64(len(disk))
	cfg.Workers = 2
	cfg.MaxFileSize = int64(len(disk))
	cfg.DisabledExtensions = nil // 显式放行

	engine := NewEngine(reader, signature.NewSignatureDB(), cfg)

	count := 0
	err := engine.Scan(context.Background(), 0, int64(len(disk)), nil,
		func(f *types.RecoveredFile) {
			if f.Extension == "ico" {
				count++
			}
		},
	)
	if err != nil {
		t.Fatalf("Scan 失败: %v", err)
	}
	if count == 0 {
		t.Error("用户显式启用 ICO 后应能找到埋入的文件，实际 0 个")
	}
}
