package carver

import (
	"crypto/rand"
	"testing"

	"data-recovery/internal/testutil"
)

// 高熵段（随机字节）+ 全 0 段：byteEntropy 应分别 ~8 和 0
func TestByteEntropy_Extremes(t *testing.T) {
	zeros := make([]byte, 4096) // 全 0
	if e := byteEntropy(zeros); e > 0.01 {
		t.Errorf("全 0 熵应 ≈0，得到 %.4f", e)
	}
	rand.Read(zeros) // 复用 buf 装满随机
	if e := byteEntropy(zeros); e < 7.5 {
		t.Errorf("随机字节熵应 >7.5，得到 %.4f", e)
	}
}

// 模拟"前半段随机 / 后半段全 0"的拼接 — paranoid v2 应识别熵突变
func TestParanoidV2_DetectsEntropyBreak(t *testing.T) {
	const total = 256 * 1024
	disk := make([]byte, total)
	rand.Read(disk[:total/2])
	// 后半段保持 0

	r := testutil.NewMemReader(disk)
	res := DetectFragmentationParanoid(r, 0, int64(total), "unknown")
	if !res.LikelyFragmented {
		t.Fatal("paranoid v2 应识别出熵突变")
	}
	if res.Confidence < 0.5 {
		t.Errorf("Confidence %.2f 偏低", res.Confidence)
	}
}

// PNG 中段被注入另一个 PNG 头 — 应识别
func TestParanoidV2_PNGFragmentDetected(t *testing.T) {
	const total = 256 * 1024
	disk := make([]byte, total)
	rand.Read(disk) // 随机数据模拟 IDAT 压缩流
	// 在 50% 处插入 PNG signature
	pngSig := []byte{0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A}
	copy(disk[total/2:], pngSig)

	r := testutil.NewMemReader(disk)
	res := DetectFragmentationParanoid(r, 0, int64(total), "png")
	if !res.LikelyFragmented {
		t.Fatal("应识别 PNG 中段插入了另一个 PNG 头")
	}
}

// MP4 box 链断裂检测：第一个 box 合法，第二个开始变成乱码
func TestParanoidV2_MP4BoxChainBroken(t *testing.T) {
	const total = 256 * 1024
	disk := make([]byte, total)
	// box 0：ftyp，size=32
	disk[0], disk[1], disk[2], disk[3] = 0, 0, 0, 32
	copy(disk[4:8], []byte("ftyp"))
	// box 1 起点 = 32：故意写非 ASCII 4cc 让识别失败
	disk[32], disk[33], disk[34], disk[35] = 0, 0, 0x10, 0
	disk[36], disk[37], disk[38], disk[39] = 0xFF, 0xFE, 0xFD, 0xFC

	r := testutil.NewMemReader(disk)
	res := DetectFragmentationParanoid(r, 0, int64(total), "mp4")
	if !res.LikelyFragmented {
		t.Fatal("应识别 MP4 box 链断裂")
	}
}

// 健康文件不应被误报（高熵全文件 = 像合法压缩流，无 magic 切换）
func TestParanoidV2_NoFalsePositiveOnUniformHighEntropy(t *testing.T) {
	const total = 128 * 1024
	disk := make([]byte, total)
	rand.Read(disk)

	r := testutil.NewMemReader(disk)
	res := DetectFragmentationParanoid(r, 0, int64(total), "unknown")
	if res.LikelyFragmented {
		t.Errorf("均匀高熵不应被报为碎片: %s", res.Reason)
	}
}
