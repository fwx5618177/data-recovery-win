package carver

import (
	"bytes"
	"context"
	"sync"
	"testing"

	"data-recovery/internal/signature"
	"data-recovery/internal/testutil"
	"data-recovery/internal/types"
)

// v2.8.46 回归测试：碎片化检测从 collector 主循环里挪走后，必须保证：
//   1. fragmentationPass 在主扫描全部 onFound 回调之后才跑（不再阻塞 IO）
//   2. SetOnFragmentation 注册的回调能拿到命中文件
//   3. file.FragHint 被正确写入（即使没注册回调也要落字段）
//   4. 候选按 offset 升序处理（验证我们把"随机 seek"转成"顺序 pass"的优化）
//   5. ctx 取消时 pass 立即退出
//
// 这一组用例是为了防止后续 PR 不小心又把 DetectFragmentation 调用塞回 collector
// 主循环（v2.8.45 时被一次提交无意改回去过，结果速度退回 322KB/s）。

// buildJPEGOfSize 造一个大小约为 targetSize 字节的最小可解析 JPEG。
// 通过在 SOS 之后填充全 0x00 字节熵数据来撑大文件 —— 0x00 永远不会被
// scanJPEGEntropy 当作 marker。文件末尾正常 FFD9 EOI 收尾。
//
// 为避免 DetectFragmentation 的 64KB 中段采样把末尾的 EOI 当成"中段 EOI"
// 误报，targetSize 必须 ≥ 256KB（mid=size/2=128KB；sample=[mid,mid+64KB)
// 不会触及末尾的 EOI）。
func buildJPEGOfSize(targetSize int) []byte {
	if targetSize < 256*1024 {
		targetSize = 256 * 1024
	}
	var buf bytes.Buffer
	// SOI
	buf.Write([]byte{0xFF, 0xD8})
	// APP0：FFE0 + len(16)
	buf.Write([]byte{0xFF, 0xE0, 0x00, 0x10})
	buf.Write(make([]byte, 14))
	// SOS：FFDA + len(12)
	buf.Write([]byte{0xFF, 0xDA, 0x00, 0x0C})
	buf.Write(make([]byte, 10))
	// 熵数据：补齐到 targetSize - 2（最后留给 EOI）。
	padLen := targetSize - buf.Len() - 2
	if padLen < 0 {
		padLen = 0
	}
	buf.Write(make([]byte, padLen))
	// EOI
	buf.Write([]byte{0xFF, 0xD9})
	return buf.Bytes()
}

// newTestEngine 用同样的配置造 engine，避免每个用例 80% 是配置噪音。
func newTestEngine(t *testing.T, diskBytes []byte) *Engine {
	t.Helper()
	return NewEngine(testutil.NewMemReader(diskBytes), signature.NewSignatureDB(), Config{
		ChunkSize:   128 * 1024,
		Workers:     1,
		MaxFileSize: int64(len(diskBytes)),
	})
}

// TestFragmentationPass_DirectCall 直接调 fragmentationPass，
// 验证：候选 offset 升序排序 + FragHint 写入 + 回调只命中真正碎片的文件。
func TestFragmentationPass_DirectCall(t *testing.T) {
	const (
		jpegSize    = 320 * 1024
		offClean    = 64 * 1024
		offFragment = offClean + jpegSize + 64*1024 // 两个 JPEG 中间留隔离区
	)
	diskSize := offFragment + jpegSize + 64*1024

	disk := make([]byte, diskSize)
	jpeg := buildJPEGOfSize(jpegSize)

	// 1) clean JPEG：原样铺
	copy(disk[offClean:], jpeg)

	// 2) fragment JPEG：铺完后在中段注入一个额外的 FFD8 SOI 标记 —— 中段采样
	//    （从 size/2=160KB 处读 64KB）必然命中。
	copy(disk[offFragment:], jpeg)
	midRel := jpegSize / 2
	disk[offFragment+midRel] = 0xFF
	disk[offFragment+midRel+1] = 0xD8

	engine := newTestEngine(t, disk)

	cleanFile := &types.RecoveredFile{
		ID:        "clean",
		Source:    "carver",
		Extension: "jpg",
		Offset:    int64(offClean),
		Size:      int64(jpegSize),
	}
	fragFile := &types.RecoveredFile{
		ID:        "frag",
		Source:    "carver",
		Extension: "jpg",
		Offset:    int64(offFragment),
		Size:      int64(jpegSize),
	}

	// 注册回调，记录命中顺序
	var mu sync.Mutex
	var callbackOrder []string
	engine.SetOnFragmentation(func(f *types.RecoveredFile) {
		mu.Lock()
		callbackOrder = append(callbackOrder, f.ID)
		mu.Unlock()
	})

	// 故意以"clean 在前 + frag 在后"的顺序传入。
	// 注意：clean.Offset < frag.Offset，所以排序后 clean 仍在前，但本测试主要
	// 关心"列表会被原地排序"这一行为；下面再单独构造一个反序用例验证排序。
	candidates := []*types.RecoveredFile{cleanFile, fragFile}
	engine.fragmentationPass(context.Background(), candidates)

	// 1) frag 文件应被标记
	if fragFile.FragHint == "" {
		t.Errorf("中段含 SOI 的 JPEG 应被标记为碎片，但 FragHint 为空")
	}
	if fragFile.Confidence > 0.4 {
		t.Errorf("碎片文件 Confidence 应被压到 ≤0.4，实际 %.2f", fragFile.Confidence)
	}

	// 2) 干净文件不应被标记
	if cleanFile.FragHint != "" {
		t.Errorf("干净 JPEG 不应被标记，实际 FragHint=%q", cleanFile.FragHint)
	}

	// 3) 回调只在 frag 时触发
	mu.Lock()
	gotCallbacks := append([]string{}, callbackOrder...)
	mu.Unlock()
	if len(gotCallbacks) != 1 || gotCallbacks[0] != "frag" {
		t.Errorf("期望仅 frag 文件触发回调，实际触发顺序=%v", gotCallbacks)
	}
}

// TestFragmentationPass_SortsByOffset 单独验证：fragmentationPass 会按
// offset 升序原地排序候选切片，把"随机 seek"转成"顺序 pass"。
func TestFragmentationPass_SortsByOffset(t *testing.T) {
	const jpegSize = 320 * 1024
	// 三个文件，故意按"乱序 offset"传入
	offsets := []int64{500 * 1024, 100 * 1024, 1024 * 1024}
	diskSize := int64(offsets[2]) + jpegSize + 64*1024
	disk := make([]byte, diskSize)

	jpeg := buildJPEGOfSize(jpegSize)
	for _, off := range offsets {
		copy(disk[off:], jpeg)
	}

	engine := newTestEngine(t, disk)

	candidates := []*types.RecoveredFile{
		{ID: "mid", Extension: "jpg", Offset: offsets[0], Size: int64(jpegSize)},
		{ID: "first", Extension: "jpg", Offset: offsets[1], Size: int64(jpegSize)},
		{ID: "last", Extension: "jpg", Offset: offsets[2], Size: int64(jpegSize)},
	}
	engine.fragmentationPass(context.Background(), candidates)

	// 校验排序：candidates 应被原地按 offset 升序排列
	for i := 1; i < len(candidates); i++ {
		if candidates[i-1].Offset > candidates[i].Offset {
			t.Errorf("候选未按 offset 升序排序：[%d]=%d > [%d]=%d",
				i-1, candidates[i-1].Offset, i, candidates[i].Offset)
		}
	}
	wantOrder := []string{"first", "mid", "last"}
	for i, want := range wantOrder {
		if candidates[i].ID != want {
			t.Errorf("排序后 candidates[%d].ID = %q, 期望 %q", i, candidates[i].ID, want)
		}
	}
}

// buildPDFOfSize 造一个大小约为 targetSize 字节的最小可解析 PDF。
// detectPDFSize 只看 "%PDF" 头 + 末尾 "%%EOF"，中间随便填什么都行 ——
// 这给了我们机会在中段注入"假 JPEG magic"来稳定触发 detectPDFFragment，
// 同时不破坏 size 检测（不像 JPEG 那样会被 scanJPEGEntropy 抓到）。
func buildPDFOfSize(targetSize int) []byte {
	if targetSize < 64*1024 {
		targetSize = 64 * 1024
	}
	var buf bytes.Buffer
	buf.WriteString("%PDF-1.4\n")
	buf.WriteString("1 0 obj\n<<>>\nendobj\n")
	// 中段填充字节，等会被 caller 覆盖
	padLen := targetSize - buf.Len() - len("xref\n0 1\ntrailer <</Size 1>>\n%%EOF\n")
	if padLen < 0 {
		padLen = 0
	}
	buf.Write(make([]byte, padLen))
	buf.WriteString("xref\n0 1\ntrailer <</Size 1>>\n")
	buf.WriteString("%%EOF\n")
	return buf.Bytes()
}

// TestFragmentationPass_FiresAfterMainScan 端到端验证：所有 onFound 回调
// 都先于任何 onFragmentation 回调发生 —— 这是 v2.8.46 最关键的契约。
// 防止任何人再把碎片化检测调回 collector 主循环。
//
// 用 PDF 而不是 JPEG：JPEG 的 size 检测会扫描熵流，注入的 FFD8 会破坏 size
// 解析导致文件被丢弃；PDF size 检测只看 %PDF + %%EOF，中段可以任意注入。
func TestFragmentationPass_FiresAfterMainScan(t *testing.T) {
	const pdfSize = 256 * 1024
	disk := make([]byte, pdfSize+128*1024)
	const off = 16 * 1024
	pdf := buildPDFOfSize(pdfSize)
	copy(disk[off:], pdf)
	// 在中段注入 JPEG magic (FFD8 FFE0) —— detectPDFFragment 必命中
	mid := off + pdfSize/2
	disk[mid] = 0xFF
	disk[mid+1] = 0xD8
	disk[mid+2] = 0xFF
	disk[mid+3] = 0xE0

	engine := newTestEngine(t, disk)

	var (
		mu     sync.Mutex
		events []string
	)
	engine.SetOnFragmentation(func(f *types.RecoveredFile) {
		mu.Lock()
		events = append(events, "frag:"+f.ID)
		mu.Unlock()
	})

	err := engine.Scan(context.Background(), 0, int64(len(disk)), nil,
		func(f *types.RecoveredFile) {
			mu.Lock()
			events = append(events, "found:"+f.ID)
			mu.Unlock()
		},
	)
	if err != nil {
		t.Fatalf("Scan 失败: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(events) < 2 {
		t.Fatalf("应至少有 1 个 found + 1 个 frag，实际 events=%v", events)
	}

	// 找到第一个 frag 事件的位置
	firstFragIdx := -1
	for i, e := range events {
		if len(e) > 5 && e[:5] == "frag:" {
			firstFragIdx = i
			break
		}
	}
	if firstFragIdx < 0 {
		t.Fatalf("没有 frag 事件，无法验证顺序 —— events=%v", events)
	}

	// firstFragIdx 之前的所有事件都必须是 found:
	for i := 0; i < firstFragIdx; i++ {
		if len(events[i]) < 6 || events[i][:6] != "found:" {
			t.Errorf("第一个 frag 之前出现非 found 事件 events[%d]=%q —— v2.8.45 回归", i, events[i])
		}
	}
	// firstFragIdx 之后不应再有 found:
	for i := firstFragIdx + 1; i < len(events); i++ {
		if len(events[i]) >= 6 && events[i][:6] == "found:" {
			t.Errorf("frag 之后又出现 found 事件 events[%d]=%q —— 碎片化检测可能阻塞了 collector", i, events[i])
		}
	}
}

// TestFragmentationPass_NoCallback_StillSetsFragHint 验证不注册回调时，
// FragHint 仍写入文件结构 —— 下游 manifest / UI 主动读取需要这个字段。
func TestFragmentationPass_NoCallback_StillSetsFragHint(t *testing.T) {
	const jpegSize = 320 * 1024
	disk := make([]byte, jpegSize+128*1024)
	const off = 16 * 1024
	copy(disk[off:], buildJPEGOfSize(jpegSize))
	// 直接注入 SOI 标记 —— 这里我们不走 Scan() 而是直接调 fragmentationPass，
	// 不会触发 detectJPEGSize 的失败，所以注入 SOI 安全。
	disk[off+jpegSize/2] = 0xFF
	disk[off+jpegSize/2+1] = 0xD8

	engine := newTestEngine(t, disk)

	f := &types.RecoveredFile{
		ID:        "test",
		Extension: "jpg",
		Offset:    off,
		Size:      int64(jpegSize),
	}
	engine.fragmentationPass(context.Background(), []*types.RecoveredFile{f})

	if f.FragHint == "" {
		t.Error("未注册回调时 FragHint 也必须被写入文件结构，否则下游 manifest 拿不到")
	}
}

// TestFragmentationPass_CancellationStopsEarly 验证 ctx 取消后 pass 立即退出。
// 用户中途取消大盘扫描时，碎片化 pass 不能继续做随机 ReadAt。
func TestFragmentationPass_CancellationStopsEarly(t *testing.T) {
	const jpegSize = 320 * 1024
	disk := make([]byte, jpegSize+128*1024)
	const off = 16 * 1024
	copy(disk[off:], buildJPEGOfSize(jpegSize))
	disk[off+jpegSize/2] = 0xFF
	disk[off+jpegSize/2+1] = 0xD8

	engine := newTestEngine(t, disk)
	engine.SetOnFragmentation(func(f *types.RecoveredFile) {
		t.Errorf("取消后不应再触发回调，但收到了 %s", f.ID)
	})

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // 立即取消

	candidates := []*types.RecoveredFile{
		{ID: "a", Extension: "jpg", Offset: off, Size: int64(jpegSize)},
	}
	engine.fragmentationPass(ctx, candidates)
	// 不检查 FragHint —— 已取消时不保证；只要回调没被错误触发即可（上面 t.Errorf）
}
