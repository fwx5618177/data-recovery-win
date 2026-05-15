package carver

import (
	"archive/zip"
	"bytes"
	"testing"
)

// 构造一个合法的小 ZIP（用 archive/zip）然后截掉末尾 EOCD + CD，
// 验证 StitchFromLocalHeaders 兜底能从 LFH 重建出可用的 ZIP。
func TestZIPStitcher_LocalHeaderFallback(t *testing.T) {
	// 1) 构造合法 ZIP
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	files := map[string][]byte{
		"hello.txt":    []byte("hello world\n"),
		"sub/data.bin": bytes.Repeat([]byte{0x42}, 1024),
		"empty.txt":    []byte(""),
	}
	for name, content := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(content); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	original := buf.Bytes()

	// 2) 找 CD 起点（EOCD 在末尾 22+commentLen 字节内）— 然后截掉 CD + EOCD
	//    简单做：从倒数第 22 字节开始找 EOCD signature，读 cdOffset，截到那
	eocdSearchEnd := len(original)
	cdOff := -1
	for i := eocdSearchEnd - 22; i >= 0; i-- {
		if original[i] == 'P' && original[i+1] == 'K' && original[i+2] == 0x05 && original[i+3] == 0x06 {
			// cdOffset 在 EOCD +16
			cdOff = int(uint32(original[i+16]) | uint32(original[i+17])<<8 |
				uint32(original[i+18])<<16 | uint32(original[i+19])<<24)
			break
		}
	}
	if cdOff < 0 {
		t.Fatal("找不到 EOCD")
	}

	// 截掉 CD + EOCD（保留 LFH + data）
	truncated := original[:cdOff]

	// 3) 走兜底
	stitcher := NewZIPStitcher(&memReader{data: truncated}, 0, int64(len(truncated)))
	stitcher.MaxOutputBytes = 10 * 1024 * 1024
	res, err := stitcher.Stitch()
	if err != nil {
		t.Fatalf("Stitch (fallback): %v", err)
	}
	if res.EntriesRead != len(files) {
		t.Errorf("entries 数: got %d want %d", res.EntriesRead, len(files))
	}

	// 4) 用 archive/zip 反向解析重建出来的 ZIP，验证文件列表 + 内容
	zr, err := zip.NewReader(bytes.NewReader(res.Data), int64(len(res.Data)))
	if err != nil {
		t.Fatalf("重建后的 ZIP 不可解析: %v", err)
	}
	gotFiles := map[string][]byte{}
	for _, f := range zr.File {
		rc, err := f.Open()
		if err != nil {
			t.Errorf("打开 entry %s: %v", f.Name, err)
			continue
		}
		var b bytes.Buffer
		if _, err := b.ReadFrom(rc); err != nil {
			t.Errorf("读 entry %s: %v", f.Name, err)
		}
		rc.Close()
		gotFiles[f.Name] = b.Bytes()
	}
	for name, want := range files {
		got, ok := gotFiles[name]
		if !ok {
			t.Errorf("entry 丢失: %s", name)
			continue
		}
		if !bytes.Equal(got, want) {
			t.Errorf("entry %s 内容不一致: got %q want %q", name, got, want)
		}
	}
}

// 完全没 LFH signature 的数据应优雅失败
func TestZIPStitcher_LocalHeaderFallback_NoLFH(t *testing.T) {
	junk := bytes.Repeat([]byte{0xAA}, 1024)
	stitcher := NewZIPStitcher(&memReader{data: junk}, 0, int64(len(junk)))
	if _, err := stitcher.StitchFromLocalHeaders(); err == nil {
		t.Errorf("无 LFH 应返回 error")
	}
}

// Stitch() 在 EOCD 损坏时应自动 fallback 到 local-header 兜底
func TestZIPStitcher_AutoFallbackWhenEOCDMissing(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, _ := zw.Create("foo.txt")
	w.Write([]byte("hi"))
	zw.Close()
	original := buf.Bytes()

	// 找 cdOff 截掉
	cdOff := -1
	for i := len(original) - 22; i >= 0; i-- {
		if original[i] == 'P' && original[i+1] == 'K' && original[i+2] == 0x05 && original[i+3] == 0x06 {
			cdOff = int(uint32(original[i+16]) | uint32(original[i+17])<<8 |
				uint32(original[i+18])<<16 | uint32(original[i+19])<<24)
			break
		}
	}
	truncated := original[:cdOff]

	stitcher := NewZIPStitcher(&memReader{data: truncated}, 0, int64(len(truncated)))
	res, err := stitcher.Stitch()
	if err != nil {
		t.Fatalf("Stitch 应自动 fallback: %v", err)
	}
	if res.EntriesRead != 1 {
		t.Errorf("应恢复 1 个 entry, got %d", res.EntriesRead)
	}
}
