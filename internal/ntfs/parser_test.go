package ntfs

import (
	"reflect"
	"testing"
)

func TestReadUnsignedLE(t *testing.T) {
	cases := []struct {
		name string
		data []byte
		want int64
	}{
		{"空", []byte{}, 0},
		{"1字节", []byte{0x42}, 0x42},
		{"2字节", []byte{0x34, 0x12}, 0x1234},
		{"4字节", []byte{0x78, 0x56, 0x34, 0x12}, 0x12345678},
		{"高位", []byte{0xFF, 0xFF, 0xFF, 0x7F}, 0x7FFFFFFF},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := readUnsignedLE(tc.data); got != tc.want {
				t.Errorf("readUnsignedLE(%x) = %d, want %d", tc.data, got, tc.want)
			}
		})
	}
}

func TestReadSignedLE(t *testing.T) {
	cases := []struct {
		name string
		data []byte
		want int64
	}{
		{"正数", []byte{0x05}, 5},
		{"负1", []byte{0xFF}, -1},
		{"2字节负", []byte{0x00, 0x80}, -0x8000},
		{"2字节最小正", []byte{0xFF, 0x7F}, 0x7FFF},
		{"4字节负", []byte{0x00, 0x00, 0x00, 0x80}, -0x80000000},
		{"4字节正", []byte{0xFF, 0xFF, 0xFF, 0x7F}, 0x7FFFFFFF},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := readSignedLE(tc.data); got != tc.want {
				t.Errorf("readSignedLE(%x) = %d, want %d", tc.data, got, tc.want)
			}
		})
	}
}

// parseDataRuns 编码：
// header 字节：高 4 位 = offset 字段宽度，低 4 位 = length 字段宽度
// 紧接着 length 字节（无符号）、offset 字节（有符号，相对上一运行）
// header = 0x00 代表结束。

func TestParseDataRuns_SingleRun(t *testing.T) {
	// header = 0x21: offset 2 字节, length 1 字节
	// length = 0x10 (16 clusters), offset = 0x0100 (256 clusters)
	data := []byte{0x21, 0x10, 0x00, 0x01, 0x00}
	runs, err := parseDataRuns(data)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	want := []DataRun{{ClusterOffset: 256, ClusterCount: 16}}
	if !reflect.DeepEqual(runs, want) {
		t.Errorf("got %+v, want %+v", runs, want)
	}
}

func TestParseDataRuns_MultipleRuns(t *testing.T) {
	// 两段连续 run：
	// run1: length=0x10 clusters, offset=+0x100
	// run2: length=0x08 clusters, offset=+0x50 (相对前者，绝对 = 0x100 + 0x50 = 0x150)
	data := []byte{
		0x21, 0x10, 0x00, 0x01, // run1: len=16, offset=0x100
		0x11, 0x08, 0x50, // run2: len=8, offset=+0x50
		0x00, // 结束
	}
	runs, err := parseDataRuns(data)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if len(runs) != 2 {
		t.Fatalf("期望 2 段，实际 %d", len(runs))
	}
	if runs[0].ClusterOffset != 0x100 || runs[0].ClusterCount != 16 {
		t.Errorf("run0 错: %+v", runs[0])
	}
	if runs[1].ClusterOffset != 0x150 || runs[1].ClusterCount != 8 {
		t.Errorf("run1 错: %+v", runs[1])
	}
}

func TestParseDataRuns_NegativeOffset(t *testing.T) {
	// 第二段相对偏移为负数（文件碎片化时常见）
	data := []byte{
		0x21, 0x10, 0x00, 0x02, // run1: len=16, offset=+0x200 → 0x200
		0x11, 0x08, 0xF0, // run2: len=8, offset=-0x10 → 0x200 - 0x10 = 0x1F0
		0x00,
	}
	runs, err := parseDataRuns(data)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if runs[1].ClusterOffset != 0x1F0 {
		t.Errorf("带符号偏移应累加为 0x1F0，实际 0x%X", runs[1].ClusterOffset)
	}
}

func TestParseDataRuns_SparseRun(t *testing.T) {
	// sparse run: offset 字段宽度 = 0
	// header = 0x01: offset=0 字节, length=1 字节
	// length=0x20 clusters (稀疏)
	// 后面接一个实数段，验证 sparse 后累加的 prevOffset 未被污染
	data := []byte{
		0x01, 0x20, // sparse, 长度 32
		0x21, 0x08, 0x00, 0x03, // real, 长度 8, 绝对偏移 0x300（因 sparse 不累加）
		0x00,
	}
	runs, err := parseDataRuns(data)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if len(runs) != 2 {
		t.Fatalf("期望 2 段，实际 %d", len(runs))
	}
	if !runs[0].Sparse {
		t.Errorf("run0 应为 Sparse=true")
	}
	if runs[0].ClusterCount != 32 {
		t.Errorf("稀疏段 count 错: %d", runs[0].ClusterCount)
	}
	if runs[1].Sparse {
		t.Errorf("run1 不应为 Sparse")
	}
	if runs[1].ClusterOffset != 0x300 {
		t.Errorf("稀疏段不应污染后续累加，期望 0x300，实际 0x%X", runs[1].ClusterOffset)
	}
}

func TestParseDataRuns_Terminator(t *testing.T) {
	// 首字节 0 即结束
	_, err := parseDataRuns([]byte{0x00, 0xAA})
	if err == nil {
		t.Error("空 run 列表应返回错误")
	}
}

func TestParseDataRuns_TruncatedDataIsTolerated(t *testing.T) {
	// run header 说要读 4 字节 offset，但只给 2 字节 —— 应提前终止而不 panic
	data := []byte{0x41, 0x10, 0x01, 0x02}
	_, err := parseDataRuns(data)
	if err == nil {
		t.Error("截断数据应返回错误")
	}
}

func TestDecodeUTF16LE(t *testing.T) {
	// "Hi" 的 UTF-16 LE 编码
	data := []byte{0x48, 0x00, 0x69, 0x00}
	if got := decodeUTF16LE(data); got != "Hi" {
		t.Errorf("got %q, want %q", got, "Hi")
	}
}

func TestExtensionToCategory(t *testing.T) {
	cases := map[string]string{
		"jpg":  "image",
		".PNG": "image",
		"pdf":  "document",
		"mp4":  "video",
		"mp3":  "audio",
		"zip":  "archive",
		"db":   "database",
		"xyz":  "other",
	}
	for in, want := range cases {
		got := ExtensionToCategory(in)
		if string(got) != want {
			t.Errorf("ExtensionToCategory(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestFiletimeToTime_Bounds(t *testing.T) {
	if filetimeToTime(0) != nil {
		t.Error("FILETIME=0 应返回 nil")
	}
	// 不合理的大值（对应年份 > 2100）应返回 nil
	if filetimeToTime(int64(1)<<62) != nil {
		t.Error("超出合理范围的 FILETIME 应返回 nil")
	}
	// 2020-01-01 UTC 对应的 FILETIME 约为 132223104000000000
	t2020 := filetimeToTime(132223104000000000)
	if t2020 == nil || t2020.Year() != 2020 {
		t.Errorf("FILETIME 2020 解析失败: %v", t2020)
	}
}
