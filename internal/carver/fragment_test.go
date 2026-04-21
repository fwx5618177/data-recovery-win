package carver

import (
	"bytes"
	"testing"

	"data-recovery/internal/testutil"
)

func TestDetectFragmentation_JPEG_FindsAnotherSOI(t *testing.T) {
	// 造一个 100KB 的"碎片 JPEG"：前 50KB 是熵数据，中段插入另一个 SOI
	data := make([]byte, 100*1024)
	for i := range data {
		data[i] = byte(i & 0xFF)
		// 把所有 0xFF 替换成 0xFE 避免误触发，但保留我们插入的那个
		if data[i] == 0xFF {
			data[i] = 0xFE
		}
	}
	// 在中段（offset 50KB 附近）插入 0xFF 0xD8（SOI 标记）
	data[50*1024] = 0xFF
	data[50*1024+1] = 0xD8

	reader := testutil.NewMemReader(data)
	res := DetectFragmentation(reader, 0, int64(len(data)), "jpg")
	if !res.LikelyFragmented {
		t.Error("中段含 SOI 应被识别为碎片")
	}
}

func TestDetectFragmentation_JPEG_StuffedByteNotMistaken(t *testing.T) {
	// 0xFF 0x00 是 JPEG 熵编码合法的 byte stuffing，不是 marker，**不应**误判碎片
	data := make([]byte, 100*1024)
	for i := 0; i < len(data)-1; i += 2 {
		data[i] = 0xFF
		data[i+1] = 0x00 // stuffed byte
	}
	reader := testutil.NewMemReader(data)
	res := DetectFragmentation(reader, 0, int64(len(data)), "jpg")
	if res.LikelyFragmented {
		t.Errorf("0xFF 0x00 是合法填充，不该报碎片：%s", res.Reason)
	}
}

func TestDetectFragmentation_PDF_FindsPNGMagic(t *testing.T) {
	data := make([]byte, 100*1024)
	// 中段插入 PNG signature
	pngSig := []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}
	copy(data[50*1024:], pngSig)

	reader := testutil.NewMemReader(data)
	res := DetectFragmentation(reader, 0, int64(len(data)), "pdf")
	if !res.LikelyFragmented {
		t.Error("PDF 中段含 PNG magic 应被识别为碎片")
	}
}

func TestDetectFragmentation_SmallFileSkipped(t *testing.T) {
	// 太小的文件直接跳过判断（碎片至少要跨 cluster）
	data := make([]byte, 1024)
	reader := testutil.NewMemReader(data)
	res := DetectFragmentation(reader, 0, int64(len(data)), "jpg")
	if res.LikelyFragmented {
		t.Error("文件太小不该报碎片")
	}
}

func TestDetectFragmentation_UnknownExt(t *testing.T) {
	data := make([]byte, 200*1024)
	reader := testutil.NewMemReader(data)
	res := DetectFragmentation(reader, 0, int64(len(data)), "txt")
	if res.LikelyFragmented {
		t.Error("不支持的格式不该报碎片")
	}
}

func TestIndexOf(t *testing.T) {
	cases := []struct {
		haystack, needle []byte
		want             int
	}{
		{[]byte("hello world"), []byte("world"), 6},
		{[]byte("aaaa"), []byte("aa"), 0},
		{[]byte("abc"), []byte("xyz"), -1},
		{[]byte("abc"), []byte{}, -1},
		{[]byte{}, []byte("a"), -1},
	}
	for _, c := range cases {
		got := indexOf(c.haystack, c.needle)
		if got != c.want {
			t.Errorf("indexOf(%q, %q) = %d want %d", c.haystack, c.needle, got, c.want)
		}
	}
	// 二进制搜索
	hay := []byte{0x00, 0x01, 0xFF, 0xD8, 0xFF}
	if got := indexOf(hay, []byte{0xFF, 0xD8}); got != 2 {
		t.Errorf("二进制 indexOf 错: %d", got)
	}
	_ = bytes.Equal
}
