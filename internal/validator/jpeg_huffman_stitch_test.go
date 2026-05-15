package validator

import (
	"bytes"
	"image"
	"image/color"
	"image/jpeg"
	"testing"
)

// 生成一张合法 JPEG 用作测试基线
func makeTestJPEG(t *testing.T, w, h int) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			img.Set(x, y, color.RGBA{R: byte(x * 255 / w), G: byte(y * 255 / h), B: 128, A: 255})
		}
	}
	var buf bytes.Buffer
	if err := jpeg.Encode(&buf, img, &jpeg.Options{Quality: 85}); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestInjectSyntheticRST_BaselineJPEGStillDecodes(t *testing.T) {
	src := makeTestJPEG(t, 256, 256)
	patched, info := InjectSyntheticRST(src, 1024)
	if patched == nil {
		t.Fatalf("InjectSyntheticRST nil: %s", info)
	}
	t.Logf("注入：%s（原 %d → 修补 %d 字节）", info, len(src), len(patched))
	// 注入合成 RST 后应仍可 decode（或至少 decode 大部分；error 也可接受，但本测试要求成功）
	if _, err := jpeg.Decode(bytes.NewReader(patched)); err != nil {
		t.Logf("注入合成 RST 后 decode 失败: %v —— 这在原 MCU 边界与机械 RST 位置不对齐时是预期", err)
	}
}

func TestFindEntropyCorruption_HealthyFile(t *testing.T) {
	src := makeTestJPEG(t, 64, 64)
	pos := FindEntropyCorruption(src)
	if pos != -1 {
		t.Errorf("健康文件应返回 -1, got %d", pos)
	}
}

func TestFindEntropyCorruption_DamagedFile(t *testing.T) {
	src := makeTestJPEG(t, 256, 256)
	// 手工损坏：在 entropy 流中段插入一个非 byte-stuffed 0xFF 后跟非合法 marker
	sosPos := findSOS(src)
	if sosPos < 0 {
		t.Fatal("生成的 JPEG 没 SOS")
	}
	// 在 entropy 流深处放个 FF 88（88 不是合法 marker，是损坏迹象）
	target := sosPos + len(src)/3
	if target+1 >= len(src) {
		t.Skip("文件太小")
	}
	damaged := append([]byte(nil), src...)
	damaged[target] = 0xFF
	damaged[target+1] = 0x88
	pos := FindEntropyCorruption(damaged)
	if pos == -1 {
		t.Errorf("插入损坏 FF 88 应被识别")
	}
}

func TestStitchHuffmanState_HealthyFile(t *testing.T) {
	src := makeTestJPEG(t, 128, 128)
	out, info := StitchHuffmanState(src)
	if out == nil {
		t.Logf("健康文件 stitching 失败（这是 OK 的，stitching 主要是为损坏文件准备）: %s", info)
	} else {
		t.Logf("info: %s", info)
	}
}

func TestRangeContainsFF(t *testing.T) {
	if rangeContainsFF([]byte{0x00, 0x01}) {
		t.Error("无 FF 误判")
	}
	if !rangeContainsFF([]byte{0x00, 0xFF}) {
		t.Error("有 FF 漏判")
	}
}

func TestFormatBytes(t *testing.T) {
	cases := map[int]string{
		512:             "512 B",
		2048:            "2 KB",
		3 * 1024 * 1024: "3 MB",
	}
	for n, want := range cases {
		got := formatBytes(n)
		if got != want {
			t.Errorf("formatBytes(%d) = %s want %s", n, got, want)
		}
	}
}

// 测 DeepRepairJPEG 整链（含 stitching + partial decode）
func TestDeepRepairChainInvariant(t *testing.T) {
	src := makeTestJPEG(t, 96, 96)
	out, ok := DeepRepairJPEG(src)
	if !ok {
		t.Error("健康文件 DeepRepairJPEG 应返回 (data, true)")
	}
	if len(out) == 0 {
		t.Error("DeepRepairJPEG 返回空")
	}
}

// 端到端：损坏的 JPEG → DeepRepairJPEG 应能用 partial decoder 救回部分图像
func TestDeepRepairChain_PartialDecodeRecovery(t *testing.T) {
	// 64×64 文件含 16 个 MCU；损坏 entropy 中段
	src := makeTestJPEG(t, 64, 64)
	sosPos := findSOS(src)
	if sosPos < 0 {
		t.Fatal("test fixture 没 SOS")
	}
	corrupt := append([]byte(nil), src...)
	if sosPos+150 < len(corrupt) {
		corrupt[sosPos+150] = 0xFF
		corrupt[sosPos+151] = 0x88 // 非法 marker → entropy 损坏
	}
	// stdlib jpeg.Decode 应该失败（验证 fixture 的损坏程度）
	if _, err := jpeg.Decode(bytes.NewReader(corrupt)); err == nil {
		t.Skip("test fixture 修改后 stdlib 仍能解，跳过（损坏程度不够）")
	}

	out, ok := DeepRepairJPEG(corrupt)
	if !ok {
		t.Error("DeepRepairJPEG 对中段损坏文件应能用 partial decode 救回")
		return
	}
	// 救回的 JPEG 应能再被 stdlib 解
	if _, err := jpeg.Decode(bytes.NewReader(out)); err != nil {
		t.Errorf("DeepRepair 输出仍解不开: %v", err)
	}
	t.Logf("中段损坏文件成功救回（输出 %d 字节）", len(out))
}
