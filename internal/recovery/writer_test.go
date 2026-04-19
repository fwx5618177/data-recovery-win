package recovery

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"data-recovery/internal/ntfs"
	"data-recovery/internal/testutil"
	"data-recovery/internal/types"
)

// buildDiskImage 按模板构造一个模拟磁盘：clusterSize=512，给定每个簇号对应的内容。
func buildDiskImage(clusterSize int64, clusters map[int64][]byte) []byte {
	var maxCluster int64
	for c := range clusters {
		if c > maxCluster {
			maxCluster = c
		}
	}
	total := (maxCluster + 2) * clusterSize // 多留一点空间
	buf := make([]byte, total)
	for c, data := range clusters {
		copy(buf[c*clusterSize:], data)
	}
	return buf
}

func TestWriteNTFSFile_MultipleDataRuns(t *testing.T) {
	// 场景：一个碎片化文件，3 段 run，分别位于不同位置
	const clusterSize int64 = 512

	seg1 := bytes.Repeat([]byte{0xAA}, int(clusterSize))
	seg2 := bytes.Repeat([]byte{0xBB}, int(clusterSize)*2)
	seg3 := bytes.Repeat([]byte{0xCC}, int(clusterSize))

	clusters := map[int64][]byte{
		10:  seg1,
		50:  seg2[:clusterSize],
		51:  seg2[clusterSize:],
		100: seg3,
	}
	disk := buildDiskImage(clusterSize, clusters)

	reader := testutil.NewMemReader(disk)
	boot := &ntfs.BootSector{
		BytesPerSector:    512,
		SectorsPerCluster: 1,
		ClusterSize:       clusterSize,
	}
	entry := &ntfs.MFTEntry{
		FileName: "fragmented.bin",
		FileSize: int64(len(seg1) + len(seg2) + len(seg3)),
		DataRuns: []ntfs.DataRun{
			{ClusterOffset: 10, ClusterCount: 1},
			{ClusterOffset: 50, ClusterCount: 2},
			{ClusterOffset: 100, ClusterCount: 1},
		},
	}

	outDir := t.TempDir()
	outPath := filepath.Join(outDir, "fragmented.bin")

	w := NewSafeWriter(reader, outDir)
	if err := w.WriteNTFSFile(
		&types.RecoveredFile{
			FileName: entry.FileName,
			Size:     entry.FileSize,
			Offset:   10 * clusterSize,
		},
		entry, boot, 0, outPath,
	); err != nil {
		t.Fatalf("WriteNTFSFile 失败: %v", err)
	}

	got, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("读取输出失败: %v", err)
	}

	want := append(append([]byte{}, seg1...), seg2...)
	want = append(want, seg3...)
	if !bytes.Equal(got, want) {
		t.Errorf("恢复内容与预期不符\ngot  前8字节: %x\nwant 前8字节: %x\n总长度 got=%d want=%d",
			got[:8], want[:8], len(got), len(want))
	}
}

func TestWriteNTFSFile_SparseRunWritesZeros(t *testing.T) {
	// 稀疏段必须写零，而不是读磁盘偏移 0（那里通常是引导扇区）
	const clusterSize int64 = 512

	seg1 := bytes.Repeat([]byte{0xAA}, int(clusterSize))
	seg3 := bytes.Repeat([]byte{0xCC}, int(clusterSize))
	disk := buildDiskImage(clusterSize, map[int64][]byte{
		// 偏移 0 放一段特征字节，保证如果错误地读了偏移 0，测试能发现
		0:   bytes.Repeat([]byte{0xEE}, 1024),
		10:  seg1,
		100: seg3,
	})

	reader := testutil.NewMemReader(disk)
	boot := &ntfs.BootSector{
		BytesPerSector:    512,
		SectorsPerCluster: 1,
		ClusterSize:       clusterSize,
	}
	entry := &ntfs.MFTEntry{
		FileName: "withhole.bin",
		FileSize: clusterSize * 3,
		DataRuns: []ntfs.DataRun{
			{ClusterOffset: 10, ClusterCount: 1},
			{ClusterOffset: 0, ClusterCount: 1, Sparse: true},
			{ClusterOffset: 100, ClusterCount: 1},
		},
	}

	outDir := t.TempDir()
	outPath := filepath.Join(outDir, "withhole.bin")

	w := NewSafeWriter(reader, outDir)
	if err := w.WriteNTFSFile(
		&types.RecoveredFile{FileName: entry.FileName, Size: entry.FileSize, Offset: 10 * clusterSize},
		entry, boot, 0, outPath,
	); err != nil {
		t.Fatalf("WriteNTFSFile 失败: %v", err)
	}

	got, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("读取输出失败: %v", err)
	}
	if len(got) != int(clusterSize*3) {
		t.Fatalf("输出长度错：got %d, want %d", len(got), clusterSize*3)
	}

	// 第一段全 0xAA，中间段全 0x00（稀疏），最后段全 0xCC
	for i, b := range got[:clusterSize] {
		if b != 0xAA {
			t.Errorf("第一段位置 %d 应为 0xAA, 实际 %x", i, b)
			break
		}
	}
	for i, b := range got[clusterSize : 2*clusterSize] {
		if b != 0x00 {
			t.Errorf("稀疏段位置 %d 应为 0x00, 实际 %x", i, b)
			break
		}
	}
	for i, b := range got[2*clusterSize : 3*clusterSize] {
		if b != 0xCC {
			t.Errorf("第三段位置 %d 应为 0xCC, 实际 %x", i, b)
			break
		}
	}
}

func TestWriteNTFSFile_TruncatesToFileSize(t *testing.T) {
	// 如果最后一段超出文件大小，写入应按 FileSize 截断
	const clusterSize int64 = 512
	seg1 := bytes.Repeat([]byte{0xAA}, int(clusterSize)*2) // 1024 字节
	disk := buildDiskImage(clusterSize, map[int64][]byte{10: seg1[:clusterSize], 11: seg1[clusterSize:]})

	reader := testutil.NewMemReader(disk)
	boot := &ntfs.BootSector{BytesPerSector: 512, SectorsPerCluster: 1, ClusterSize: clusterSize}
	entry := &ntfs.MFTEntry{
		FileName: "short.bin",
		FileSize: 600, // 比 2 个簇小
		DataRuns: []ntfs.DataRun{{ClusterOffset: 10, ClusterCount: 2}},
	}

	outDir := t.TempDir()
	outPath := filepath.Join(outDir, "short.bin")
	w := NewSafeWriter(reader, outDir)
	if err := w.WriteNTFSFile(
		&types.RecoveredFile{FileName: entry.FileName, Size: entry.FileSize, Offset: 10 * clusterSize},
		entry, boot, 0, outPath,
	); err != nil {
		t.Fatalf("WriteNTFSFile 失败: %v", err)
	}

	info, err := os.Stat(outPath)
	if err != nil {
		t.Fatalf("stat 失败: %v", err)
	}
	if info.Size() != 600 {
		t.Errorf("期望 600 字节，实际 %d", info.Size())
	}
}

func TestWriteNTFSFile_NoDataNoFallback(t *testing.T) {
	// 没有 DataRuns 且没有驻留数据时必须报错（而不是回退到按 Offset 的错误读取）
	reader := testutil.NewMemReader(make([]byte, 4096))
	boot := &ntfs.BootSector{BytesPerSector: 512, SectorsPerCluster: 1, ClusterSize: 512}
	entry := &ntfs.MFTEntry{FileName: "empty.bin", FileSize: 100}

	outDir := t.TempDir()
	outPath := filepath.Join(outDir, "empty.bin")
	w := NewSafeWriter(reader, outDir)
	err := w.WriteNTFSFile(
		&types.RecoveredFile{FileName: entry.FileName, Size: entry.FileSize},
		entry, boot, 0, outPath,
	)
	if err == nil {
		t.Fatal("无数据时应返回错误")
	}
}

// ==================== GenerateOutputPath ====================

func newTestWriter(t *testing.T) *SafeWriter {
	t.Helper()
	return NewSafeWriter(testutil.NewMemReader(nil), t.TempDir())
}

func TestGenerateOutputPath_NTFSUsesOriginalPath(t *testing.T) {
	w := newTestWriter(t)
	base := t.TempDir()

	file := &types.RecoveredFile{
		Source:       "ntfs",
		FileName:     "report.docx",
		Extension:    "docx",
		OriginalPath: "Users/Alice/Documents/report.docx",
	}

	got, err := w.GenerateOutputPath(file, base)
	if err != nil {
		t.Fatalf("NTFS 路径生成不应报错: %v", err)
	}

	want := filepath.Join(base, "ntfs", "Users", "Alice", "Documents", "report.docx")
	if got != want {
		t.Errorf("NTFS 输出路径错:\n  got  %s\n  want %s", got, want)
	}
}

func TestGenerateOutputPath_CarverNormalConfidence(t *testing.T) {
	w := newTestWriter(t)
	base := t.TempDir()

	file := &types.RecoveredFile{
		Source:     "carver",
		FileName:   "jpg_0x1000_000001.jpg",
		Extension:  "jpg",
		Category:   types.CategoryImage,
		IsValid:    true,
		Confidence: 0.7,
	}

	got, err := w.GenerateOutputPath(file, base)
	if err != nil {
		t.Fatalf("正常 carver 路径生成不应报错: %v", err)
	}

	want := filepath.Join(base, "carver", "images", "batch_001", "jpg_0x1000_000001.jpg")
	if got != want {
		t.Errorf("carver 正常路径错:\n  got  %s\n  want %s", got, want)
	}
}

func TestGenerateOutputPath_CarverLowConfidenceRouting(t *testing.T) {
	w := newTestWriter(t)
	base := t.TempDir()

	file := &types.RecoveredFile{
		Source:     "carver",
		FileName:   "png_0x2000_000001.png",
		Extension:  "png",
		Category:   types.CategoryImage,
		IsValid:    true,   // IsValid=true 但置信度低于阈值
		Confidence: 0.3,
	}

	got, err := w.GenerateOutputPath(file, base)
	if err != nil {
		t.Fatalf("低置信度不应阻止路径生成: %v", err)
	}

	if !strings.Contains(got, filepath.Join("carver", "_low_confidence", "images")) {
		t.Errorf("低置信度文件应进入 _low_confidence 目录，实际路径: %s", got)
	}
}

func TestGenerateOutputPath_CarverInvalidAlsoLowConfidence(t *testing.T) {
	w := newTestWriter(t)
	base := t.TempDir()

	file := &types.RecoveredFile{
		Source:     "carver",
		FileName:   "pdf_0x3000_000001.pdf",
		Extension:  "pdf",
		Category:   types.CategoryDocument,
		IsValid:    false, // IsValid=false 即使置信度 >=0.5 也应归为低置信度
		Confidence: 0.8,
	}

	got, err := w.GenerateOutputPath(file, base)
	if err != nil {
		t.Fatalf("IsValid=false 不应阻止路径生成: %v", err)
	}

	if !strings.Contains(got, "_low_confidence") {
		t.Errorf("未通过验证的文件应进入 _low_confidence 目录，实际路径: %s", got)
	}
}

func TestGenerateOutputPath_CarverEmptyExtensionErrors(t *testing.T) {
	w := newTestWriter(t)
	base := t.TempDir()

	file := &types.RecoveredFile{
		Source:     "carver",
		FileName:   "unknown_0x4000",
		Extension:  "", // 空扩展名应拒写，不再 .bin 兜底
		IsValid:    true,
		Confidence: 0.7,
	}

	got, err := w.GenerateOutputPath(file, base)
	if err == nil {
		t.Fatalf("空扩展名应返回错误，实际返回路径 %s", got)
	}
	if got != "" {
		t.Errorf("失败时应返回空路径，实际 %s", got)
	}
}

func TestGenerateOutputPath_NilFileErrors(t *testing.T) {
	w := newTestWriter(t)
	if _, err := w.GenerateOutputPath(nil, t.TempDir()); err == nil {
		t.Error("nil 文件应返回错误")
	}
}

// ==================== nextBatchNo ====================

func TestNextBatchNo_RollsOverEvery500(t *testing.T) {
	w := newTestWriter(t)

	// 前 500 次应全部返回 batch_001
	for i := 1; i <= carverBatchSize; i++ {
		got := w.nextBatchNo("normal", "images")
		if got != 1 {
			t.Fatalf("第 %d 次调用期望 batch=1，实际 %d", i, got)
		}
	}

	// 第 501 次应进入 batch_002
	if got := w.nextBatchNo("normal", "images"); got != 2 {
		t.Errorf("第 501 次期望 batch=2，实际 %d", got)
	}

	// 继续用满第二批
	for i := 2; i <= carverBatchSize; i++ {
		if got := w.nextBatchNo("normal", "images"); got != 2 {
			t.Fatalf("第二批第 %d 次期望 batch=2，实际 %d", i, got)
		}
	}

	// 第 1001 次应进入 batch_003
	if got := w.nextBatchNo("normal", "images"); got != 3 {
		t.Errorf("第 1001 次期望 batch=3，实际 %d", got)
	}
}

func TestNextBatchNo_KeysIndependent(t *testing.T) {
	w := newTestWriter(t)

	// 不同 (confBucket, category) 组合的计数器互不影响
	if got := w.nextBatchNo("normal", "images"); got != 1 {
		t.Errorf("images 首次期望 batch=1，实际 %d", got)
	}
	if got := w.nextBatchNo("normal", "documents"); got != 1 {
		t.Errorf("documents 首次期望 batch=1，实际 %d", got)
	}
	if got := w.nextBatchNo("low", "images"); got != 1 {
		t.Errorf("low/images 首次期望 batch=1，实际 %d", got)
	}
}

// ==================== verifyMagicBytes ====================

// minimalPNG: PNG 8 字节 magic + 占位数据
var pngHeader = []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}

func TestVerifyMagicBytes_MatchPasses(t *testing.T) {
	w := newTestWriter(t)
	file := &types.RecoveredFile{Source: "carver", Extension: "png"}
	if err := w.verifyMagicBytes(file, pngHeader); err != nil {
		t.Errorf("PNG magic 应匹配 png 扩展名，实际: %v", err)
	}
}

func TestVerifyMagicBytes_MismatchRejects(t *testing.T) {
	w := newTestWriter(t)
	// 声明是 png 但实际是 JPEG magic
	jpegMagic := []byte{0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46}
	file := &types.RecoveredFile{Source: "carver", Extension: "png"}
	if err := w.verifyMagicBytes(file, jpegMagic); err == nil {
		t.Error("JPEG 字节冒充 png 应被拒绝")
	}
}

func TestVerifyMagicBytes_NTFSAlwaysPasses(t *testing.T) {
	w := newTestWriter(t)
	// NTFS 来源不走 magic 校验，即使随机字节也通过
	file := &types.RecoveredFile{Source: "ntfs", Extension: "png"}
	random := []byte{0x00, 0x11, 0x22, 0x33}
	if err := w.verifyMagicBytes(file, random); err != nil {
		t.Errorf("NTFS 来源应跳过 magic 校验，实际: %v", err)
	}
}

func TestVerifyMagicBytes_UnknownExtensionPasses(t *testing.T) {
	w := newTestWriter(t)
	// docx 不在签名库（由 ZIP 容器细分得来），应直接放行
	file := &types.RecoveredFile{Source: "carver", Extension: "docx"}
	zipHead := []byte{0x50, 0x4B, 0x03, 0x04} // PK zip header
	if err := w.verifyMagicBytes(file, zipHead); err != nil {
		t.Errorf("容器子扩展名应放行，实际: %v", err)
	}
}

func TestVerifyMagicBytes_EmptyExtensionFails(t *testing.T) {
	w := newTestWriter(t)
	file := &types.RecoveredFile{Source: "carver", Extension: ""}
	if err := w.verifyMagicBytes(file, pngHeader); err == nil {
		t.Error("空扩展名应返回错误")
	}
}

func TestVerifyMagicBytes_JPEGAcceptsAllVariants(t *testing.T) {
	w := newTestWriter(t)
	// JPEG 有 5 个变体 header，全部应通过
	variants := [][]byte{
		{0xFF, 0xD8, 0xFF, 0xE0},
		{0xFF, 0xD8, 0xFF, 0xE1},
		{0xFF, 0xD8, 0xFF, 0xE8},
		{0xFF, 0xD8, 0xFF, 0xDB},
		{0xFF, 0xD8, 0xFF, 0xEE},
	}
	for i, head := range variants {
		file := &types.RecoveredFile{Source: "carver", Extension: "jpg"}
		if err := w.verifyMagicBytes(file, head); err != nil {
			t.Errorf("JPEG 变体 %d (%x) 应匹配，实际: %v", i, head, err)
		}
	}
}

// ==================== applyTimestamps ====================

func touch(t *testing.T, content []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "target.bin")
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatalf("创建测试文件失败: %v", err)
	}
	return path
}

func TestApplyTimestamps_NTFSRestoresModTime(t *testing.T) {
	path := touch(t, []byte("hello"))

	wantMTime := time.Date(2020, 1, 2, 3, 4, 5, 0, time.UTC)
	file := &types.RecoveredFile{
		Source:       "ntfs",
		ModifiedTime: &wantMTime,
	}
	applyTimestamps(path, file)

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat 失败: %v", err)
	}
	if !info.ModTime().Equal(wantMTime) {
		t.Errorf("mtime 未正确恢复:\n  got  %s\n  want %s", info.ModTime(), wantMTime)
	}
}

func TestApplyTimestamps_CarverIsNoOp(t *testing.T) {
	path := touch(t, []byte("x"))
	before, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat 失败: %v", err)
	}

	future := time.Now().Add(24 * time.Hour)
	file := &types.RecoveredFile{
		Source:       "carver",
		ModifiedTime: &future,
	}
	applyTimestamps(path, file)

	after, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat 失败: %v", err)
	}
	if !after.ModTime().Equal(before.ModTime()) {
		t.Errorf("carver 来源不应修改 mtime: before=%s after=%s",
			before.ModTime(), after.ModTime())
	}
}

func TestApplyTimestamps_NilTimesNoop(t *testing.T) {
	path := touch(t, []byte("x"))
	before, _ := os.Stat(path)

	// NTFS 但没有时间戳——不应 panic 也不应改动
	file := &types.RecoveredFile{Source: "ntfs"}
	applyTimestamps(path, file)

	after, _ := os.Stat(path)
	if !after.ModTime().Equal(before.ModTime()) {
		t.Errorf("无时间戳不应修改 mtime")
	}
}

// ==================== 集成：WriteFile 前置 magic 校验与 SHA256 回填 ====================

func TestWriteFile_RejectsMagicByteMismatch(t *testing.T) {
	// 磁盘放 JPEG 数据，但声明扩展名为 png，应被 verifyMagicBytes 拦截
	jpegBlob := append([]byte{0xFF, 0xD8, 0xFF, 0xE0}, bytes.Repeat([]byte{0x11}, 100)...)
	reader := testutil.NewMemReader(jpegBlob)

	outDir := t.TempDir()
	outPath := filepath.Join(outDir, "fake.png")
	w := NewSafeWriter(reader, outDir)

	file := &types.RecoveredFile{
		Source:    "carver",
		FileName:  "fake.png",
		Extension: "png",
		Size:      int64(len(jpegBlob)),
		Offset:    0,
	}
	err := w.WriteFile(file, outPath)
	if err == nil {
		t.Fatal("扩展名与内容不符应被拒写")
	}
	// 失败路径下不应有文件落地
	if _, statErr := os.Stat(outPath); !os.IsNotExist(statErr) {
		t.Errorf("校验失败时不应留下文件: %s", outPath)
	}
	// 也不应填充 SHA256
	if file.SHA256 != "" {
		t.Errorf("校验失败时 SHA256 不应被回填，实际 %q", file.SHA256)
	}
}

func TestWriteFile_SetsSHA256OnSuccess(t *testing.T) {
	// 完整 PNG 头 + 随机字节（先 verify 放行，再 SHA 校验）
	blob := append([]byte{}, pngHeader...)
	blob = append(blob, bytes.Repeat([]byte{0x42}, 256)...)

	reader := testutil.NewMemReader(blob)
	outDir := t.TempDir()
	outPath := filepath.Join(outDir, "ok.png")
	w := NewSafeWriter(reader, outDir)

	file := &types.RecoveredFile{
		Source:    "carver",
		FileName:  "ok.png",
		Extension: "png",
		Size:      int64(len(blob)),
		Offset:    0,
	}
	if err := w.WriteFile(file, outPath); err != nil {
		t.Fatalf("WriteFile 失败: %v", err)
	}
	if len(file.SHA256) != 64 {
		t.Errorf("SHA256 应为 64 字节 hex 字符串，实际 %q (长度 %d)", file.SHA256, len(file.SHA256))
	}
}

func TestWriteNTFSFile_SetsSHA256AndTimestamps(t *testing.T) {
	const clusterSize int64 = 512
	data := bytes.Repeat([]byte{0xAB}, int(clusterSize))
	disk := buildDiskImage(clusterSize, map[int64][]byte{10: data})

	reader := testutil.NewMemReader(disk)
	boot := &ntfs.BootSector{
		BytesPerSector: 512, SectorsPerCluster: 1, ClusterSize: clusterSize,
	}
	entry := &ntfs.MFTEntry{
		FileName: "ok.bin",
		FileSize: clusterSize,
		DataRuns: []ntfs.DataRun{{ClusterOffset: 10, ClusterCount: 1}},
	}

	wantMTime := time.Date(2019, 5, 6, 7, 8, 9, 0, time.UTC)

	outDir := t.TempDir()
	outPath := filepath.Join(outDir, "ok.bin")
	w := NewSafeWriter(reader, outDir)
	file := &types.RecoveredFile{
		Source:       "ntfs",
		FileName:     entry.FileName,
		Size:         entry.FileSize,
		Offset:       10 * clusterSize,
		ModifiedTime: &wantMTime,
	}
	if err := w.WriteNTFSFile(file, entry, boot, 0, outPath); err != nil {
		t.Fatalf("WriteNTFSFile 失败: %v", err)
	}

	if len(file.SHA256) != 64 {
		t.Errorf("NTFS 写入后应回填 SHA256，实际 %q", file.SHA256)
	}
	info, err := os.Stat(outPath)
	if err != nil {
		t.Fatalf("stat 失败: %v", err)
	}
	if !info.ModTime().Equal(wantMTime) {
		t.Errorf("NTFS mtime 未恢复:\n  got  %s\n  want %s", info.ModTime(), wantMTime)
	}
}

// 回归测试（Bug #2）：部分写入（sizeMismatch）时不应回填 SHA256 / 不应 applyTimestamps——
// 因为调用方会删掉这个不完整文件。之前版本在判断 sizeMismatch 之前就回填了，
// 会让 manifest 和 dedup 误把已删文件当"成功"。
func TestWriteNTFSFile_PartialWriteDoesNotSetSHA256OrTimestamps(t *testing.T) {
	const clusterSize int64 = 512
	data := bytes.Repeat([]byte{0xAB}, int(clusterSize))
	disk := buildDiskImage(clusterSize, map[int64][]byte{10: data})

	reader := testutil.NewMemReader(disk)
	boot := &ntfs.BootSector{BytesPerSector: 512, SectorsPerCluster: 1, ClusterSize: clusterSize}

	// FileSize 说有 2 个簇，但 DataRuns 只给 1 个簇 → totalWritten < FileSize → PartialWriteError
	entry := &ntfs.MFTEntry{
		FileName: "short.bin",
		FileSize: clusterSize * 2,
		DataRuns: []ntfs.DataRun{{ClusterOffset: 10, ClusterCount: 1}},
	}

	futureMTime := time.Date(2019, 5, 6, 7, 8, 9, 0, time.UTC)

	outDir := t.TempDir()
	outPath := filepath.Join(outDir, "short.bin")
	w := NewSafeWriter(reader, outDir)
	file := &types.RecoveredFile{
		Source:       "ntfs",
		FileName:     entry.FileName,
		Size:         entry.FileSize,
		Offset:       10 * clusterSize,
		ModifiedTime: &futureMTime,
	}
	err := w.WriteNTFSFile(file, entry, boot, 0, outPath)

	var partialErr *PartialWriteError
	if !errors.As(err, &partialErr) {
		t.Fatalf("期望 PartialWriteError，实际 %v", err)
	}
	if file.SHA256 != "" {
		t.Errorf("部分写入不应回填 SHA256，实际 %q", file.SHA256)
	}

	// 部分写入时文件仍在磁盘（上层 Recover 才会 remove），但 mtime 不应被设为 futureMTime
	if info, statErr := os.Stat(outPath); statErr == nil {
		if info.ModTime().Equal(futureMTime) {
			t.Errorf("部分写入时不应 applyTimestamps，mtime 被错误地设为 %s", info.ModTime())
		}
	}
}

// 回归测试：驻留数据路径（NTFS 小文件）也应回填 SHA256、恢复时间戳
func TestWriteNTFSFile_ResidentSetsSHA256AndTimestamps(t *testing.T) {
	reader := testutil.NewMemReader(make([]byte, 4096))
	boot := &ntfs.BootSector{BytesPerSector: 512, SectorsPerCluster: 1, ClusterSize: 512}
	entry := &ntfs.MFTEntry{
		FileName:     "tiny.txt",
		FileSize:     12,
		IsResident:   true,
		ResidentData: []byte("hello world!"),
	}

	wantMTime := time.Date(2021, 6, 7, 8, 9, 10, 0, time.UTC)
	outDir := t.TempDir()
	outPath := filepath.Join(outDir, "tiny.txt")
	w := NewSafeWriter(reader, outDir)
	file := &types.RecoveredFile{
		Source:       "ntfs",
		FileName:     entry.FileName,
		Size:         entry.FileSize,
		ModifiedTime: &wantMTime,
	}
	if err := w.WriteNTFSFile(file, entry, boot, 0, outPath); err != nil {
		t.Fatalf("驻留 NTFS 写入失败: %v", err)
	}
	if len(file.SHA256) != 64 {
		t.Errorf("驻留路径应回填 SHA256，实际 %q", file.SHA256)
	}
	info, err := os.Stat(outPath)
	if err != nil {
		t.Fatalf("stat 失败: %v", err)
	}
	if !info.ModTime().Equal(wantMTime) {
		t.Errorf("驻留路径 mtime 未恢复: got %s want %s", info.ModTime(), wantMTime)
	}
}

// 回归测试：head buffer 比 header 短时，不应误匹配——应报 magic 不符
func TestVerifyMagicBytes_UndersizedHeadRejects(t *testing.T) {
	w := newTestWriter(t)
	// PNG header 是 8 字节，只给 4 字节
	tooShort := []byte{0x89, 0x50, 0x4E, 0x47}
	file := &types.RecoveredFile{Source: "carver", Extension: "png"}
	if err := w.verifyMagicBytes(file, tooShort); err == nil {
		t.Error("head 比 header 短应被判为不匹配")
	}
}

// NTFS OriginalPath 为空时应退回 FileName，不能产生纯 ntfs/ 空目录路径
func TestGenerateOutputPath_NTFSFallsBackToFileName(t *testing.T) {
	w := newTestWriter(t)
	base := t.TempDir()

	file := &types.RecoveredFile{
		Source:       "ntfs",
		FileName:     "orphan.txt",
		Extension:    "txt",
		OriginalPath: "", // 触发 fallbackRecoveredName
	}

	got, err := w.GenerateOutputPath(file, base)
	if err != nil {
		t.Fatalf("空 OriginalPath 不应报错: %v", err)
	}
	want := filepath.Join(base, "ntfs", "orphan.txt")
	if got != want {
		t.Errorf("NTFS 回退路径错:\n  got  %s\n  want %s", got, want)
	}
}

// 连续两次写同一目录同一名字：第二次应被 resolveConflict 改名为 _1
func TestGenerateOutputPath_ConflictResolution(t *testing.T) {
	w := newTestWriter(t)
	base := t.TempDir()

	file := &types.RecoveredFile{
		Source:     "carver",
		FileName:   "jpg_0x1000_000001.jpg",
		Extension:  "jpg",
		Category:   types.CategoryImage,
		IsValid:    true,
		Confidence: 0.7,
	}

	first, err := w.GenerateOutputPath(file, base)
	if err != nil {
		t.Fatalf("第一次路径生成失败: %v", err)
	}
	// 预先占位 —— resolveConflict 以磁盘已存在为信号
	if err := os.MkdirAll(filepath.Dir(first), 0o755); err != nil {
		t.Fatalf("mkdir 失败: %v", err)
	}
	if err := os.WriteFile(first, []byte("x"), 0o644); err != nil {
		t.Fatalf("预写占位失败: %v", err)
	}

	// nextBatchNo 会再加 1，但同批次目录下相同文件名应被 resolveConflict 改名
	second, err := w.GenerateOutputPath(file, base)
	if err != nil {
		t.Fatalf("第二次路径生成失败: %v", err)
	}
	if second == first {
		t.Errorf("重名未被解决，两次路径都是 %s", first)
	}
	if !strings.Contains(filepath.Base(second), "_1") {
		t.Errorf("冲突解决应追加 _N 后缀，实际 %s", filepath.Base(second))
	}
}

