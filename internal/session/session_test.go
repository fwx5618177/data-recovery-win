package session

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"data-recovery/internal/types"
)

// mustStore 在临时目录里建一个 Store，失败直接 fatal。
// 测试都改走 NewStoreInDir（v2.8.50 新增），不再裸构造 Store 字段。
func mustStore(t *testing.T, dir string) *Store {
	t.Helper()
	s, err := NewStoreInDir(dir)
	if err != nil {
		t.Fatalf("NewStoreInDir: %v", err)
	}
	return s
}

// 关键路径正向 round-trip：所有字段保留 + Version/SavedAt 自动填充
func TestStore_SaveLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	s := mustStore(t, dir)

	snap := Snapshot{
		DrivePath:  "/dev/sda",
		DriveLabel: "测试盘",
		Mode:       "full",
		Progress: types.ScanProgress{
			Phase: "carving", Percent: 42.5, FilesFound: 1234,
		},
		Files: []*types.RecoveredFile{
			{ID: "x", FileName: "evidence.jpg", Size: 12345, OriginalPath: "/x"},
		},
		OutputDir:          "/tmp/out",
		Completed:          false,
		CarverResumeOffset: 0xDEADBEEF,
	}

	if err := s.Save(snap); err != nil {
		t.Fatalf("Save: %v", err)
	}
	loaded, err := s.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if loaded == nil {
		t.Fatal("Load 应返回快照，得到 nil")
	}
	if loaded.Version != currentVersion {
		t.Errorf("Version 应被自动填充: got %d", loaded.Version)
	}
	if loaded.SavedAt.IsZero() {
		t.Errorf("SavedAt 应被自动填充")
	}
	if loaded.DrivePath != "/dev/sda" || loaded.DriveLabel != "测试盘" {
		t.Errorf("DrivePath/Label 不一致: %+v", loaded)
	}
	if loaded.CarverResumeOffset != 0xDEADBEEF {
		t.Errorf("CarverResumeOffset 丢失: %d", loaded.CarverResumeOffset)
	}
	if len(loaded.Files) != 1 || loaded.Files[0].FileName != "evidence.jpg" {
		t.Errorf("Files 字段丢失: %+v", loaded.Files)
	}
}

// Load 不存在文件应返回 (nil, nil)，不是 error
func TestStore_LoadMissingReturnsNil(t *testing.T) {
	dir := t.TempDir()
	s := mustStore(t, dir)
	snap, err := s.Load()
	if err != nil {
		t.Errorf("Load 不存在文件应 nil error, got %v", err)
	}
	if snap != nil {
		t.Errorf("Load 不存在文件应返回 nil snap")
	}
}

// 损坏的 JSON 应被静默忽略（避免坏文件让用户启动失败）
func TestStore_LoadCorruptReturnsNil(t *testing.T) {
	dir := t.TempDir()
	s := mustStore(t, dir)
	if err := os.WriteFile(s.snapshotPath, []byte("{not valid json"), 0o600); err != nil {
		t.Fatal(err)
	}
	snap, err := s.Load()
	if err != nil {
		t.Errorf("损坏 JSON 应静默 (nil, nil), got err=%v", err)
	}
	if snap != nil {
		t.Errorf("损坏 JSON 不应返回 snap")
	}
}

// 版本不匹配（既不是 v1 也不是 currentVersion）应返回 nil
func TestStore_LoadVersionMismatch(t *testing.T) {
	dir := t.TempDir()
	s := mustStore(t, dir)
	if err := os.WriteFile(s.snapshotPath, []byte(`{"version":999,"drivePath":"x"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	snap, _ := s.Load()
	if snap != nil {
		t.Errorf("Version=999 应被拒绝, got %+v", snap)
	}
}

// v1 向后兼容：v1 数据应被读为 v2（CarverResumeOffset 默认 0）
func TestStore_LoadV1BackwardCompatible(t *testing.T) {
	dir := t.TempDir()
	s := mustStore(t, dir)
	if err := os.WriteFile(s.snapshotPath, []byte(`{"version":1,"drivePath":"/dev/old","driveLabel":"v1 disk"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	snap, err := s.Load()
	if err != nil {
		t.Fatal(err)
	}
	if snap == nil {
		t.Fatal("v1 应被接受")
	}
	if snap.DrivePath != "/dev/old" {
		t.Errorf("v1 字段丢失: %+v", snap)
	}
	if snap.CarverResumeOffset != 0 {
		t.Errorf("v1 缺失字段应默认 0")
	}
}

// Clear 删除 session 文件；文件不存在不算错误（幂等）
func TestStore_ClearIdempotent(t *testing.T) {
	dir := t.TempDir()
	s := mustStore(t, dir)

	// 先写一份
	if err := s.Save(Snapshot{DrivePath: "/x"}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(s.snapshotPath); err != nil {
		t.Fatal(err)
	}

	// 清除
	if err := s.Clear(); err != nil {
		t.Errorf("Clear: %v", err)
	}
	if _, err := os.Stat(s.snapshotPath); !os.IsNotExist(err) {
		t.Errorf("Clear 后文件应不存在")
	}

	// 第二次 Clear 应幂等
	if err := s.Clear(); err != nil {
		t.Errorf("第二次 Clear 不应报错（幂等）: %v", err)
	}
}

// 原子写：tmp 文件应在 rename 后消失
func TestStore_SaveAtomicNoLeftoverTmp(t *testing.T) {
	dir := t.TempDir()
	s := mustStore(t, dir)

	if err := s.Save(Snapshot{DrivePath: "/x"}); err != nil {
		t.Fatal(err)
	}

	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".tmp" {
			t.Errorf("Save 后不应有 .tmp 残留: %s", e.Name())
		}
	}
}

// Save → Load → Save → Load: 多轮覆盖 + SavedAt 应每次刷新
func TestStore_SaveOverwritesAndUpdatesSavedAt(t *testing.T) {
	dir := t.TempDir()
	s := mustStore(t, dir)

	if err := s.Save(Snapshot{DrivePath: "/v1"}); err != nil {
		t.Fatal(err)
	}
	loaded1, _ := s.Load()
	t1 := loaded1.SavedAt

	time.Sleep(20 * time.Millisecond) // 确保时间能 tick
	if err := s.Save(Snapshot{DrivePath: "/v2"}); err != nil {
		t.Fatal(err)
	}
	loaded2, _ := s.Load()
	if loaded2.DrivePath != "/v2" {
		t.Errorf("第 2 次 Save 应覆盖第 1 次")
	}
	if !loaded2.SavedAt.After(t1) {
		t.Errorf("SavedAt 应被第 2 次 Save 刷新: t1=%v t2=%v", t1, loaded2.SavedAt)
	}
}

// NewStore 在合法 OS 配置目录下能成功；path 非空
func TestNewStore_ProducesValidPath(t *testing.T) {
	s, err := NewStore()
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	if s.Path() == "" {
		t.Errorf("Store.Path 应非空")
	}
	if filepath.Base(s.Path()) != "session.json" {
		t.Errorf("路径应以 session.json 结尾, got %s", s.Path())
	}
}

// ============================================================
// v2.8.50 — append-log 增量持久化
// ============================================================

// AppendFiles → Load 应能 replay 出来
func TestStore_AppendFiles_LoadMerges(t *testing.T) {
	dir := t.TempDir()
	s := mustStore(t, dir)

	// 先写个 snapshot 含 1 个文件
	if err := s.Save(Snapshot{
		DrivePath: "/d",
		Files: []*types.RecoveredFile{
			{ID: "base1", FileName: "base.bin"},
		},
	}); err != nil {
		t.Fatal(err)
	}

	// Append 3 个新文件
	extra := []*types.RecoveredFile{
		{ID: "new1", FileName: "a.jpg"},
		{ID: "new2", FileName: "b.png"},
		{ID: "new3", FileName: "c.mp4"},
	}
	if err := s.AppendFiles(extra); err != nil {
		t.Fatalf("AppendFiles: %v", err)
	}

	// Load 应合并 snapshot + log
	loaded, err := s.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(loaded.Files) != 4 {
		t.Errorf("Load 应合并 1 base + 3 extra = 4, 得到 %d", len(loaded.Files))
	}
	names := map[string]bool{}
	for _, f := range loaded.Files {
		names[f.FileName] = true
	}
	for _, want := range []string{"base.bin", "a.jpg", "b.png", "c.mp4"} {
		if !names[want] {
			t.Errorf("Load 后缺文件 %s: 实际 %+v", want, names)
		}
	}
}

// AppendFiles 多次调用都应追加（不覆盖）
func TestStore_AppendFiles_MultipleCallsAppend(t *testing.T) {
	dir := t.TempDir()
	s := mustStore(t, dir)
	if err := s.Save(Snapshot{DrivePath: "/d"}); err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 5; i++ {
		batch := []*types.RecoveredFile{
			{ID: "f", FileName: "f.bin"},
		}
		if err := s.AppendFiles(batch); err != nil {
			t.Fatal(err)
		}
	}
	loaded, _ := s.Load()
	if len(loaded.Files) != 5 {
		t.Errorf("5 次 Append × 1 文件应得 5，得到 %d", len(loaded.Files))
	}
}

// Compact 后 log 应清空，所有文件并入 snapshot
func TestStore_Compact_MergesAndClearsLog(t *testing.T) {
	dir := t.TempDir()
	s := mustStore(t, dir)

	if err := s.Save(Snapshot{DrivePath: "/d"}); err != nil {
		t.Fatal(err)
	}
	if err := s.AppendFiles([]*types.RecoveredFile{
		{ID: "a", FileName: "a.bin"},
		{ID: "b", FileName: "b.bin"},
	}); err != nil {
		t.Fatal(err)
	}

	// Compact 前 log 文件应存在 + 非空
	if fi, err := os.Stat(s.LogPath()); err != nil || fi.Size() == 0 {
		t.Fatalf("Compact 前 log 应非空: err=%v size=%v", err, fi)
	}

	if err := s.Compact(); err != nil {
		t.Fatalf("Compact: %v", err)
	}

	// Compact 后 log 应已截断到 0
	fi, err := os.Stat(s.LogPath())
	if err != nil {
		t.Fatalf("Compact 后 log 应仍存在（已截断）: %v", err)
	}
	if fi.Size() != 0 {
		t.Errorf("Compact 后 log 应截断到 0 字节, 得到 %d", fi.Size())
	}

	// Load 仍能拿到全部文件（已经在 snapshot 里）
	loaded, _ := s.Load()
	if len(loaded.Files) != 2 {
		t.Errorf("Compact 后 Load 仍应得 2 文件，得到 %d", len(loaded.Files))
	}

	// Compact 是幂等：第二次 Compact 应 no-op
	if err := s.Compact(); err != nil {
		t.Errorf("第二次 Compact 应无错（幂等）: %v", err)
	}
}

// 崩溃模拟：log 最后一行截断 → Load 应跳过坏行保留前面的
func TestStore_Load_HandlesPartialLastLogLine(t *testing.T) {
	dir := t.TempDir()
	s := mustStore(t, dir)
	if err := s.Save(Snapshot{DrivePath: "/d"}); err != nil {
		t.Fatal(err)
	}
	// 写一个合法行 + 一个被截断的行
	good := `{"id":"good","fileName":"good.bin"}` + "\n"
	bad := `{"id":"bad","fileName":"bad.bi` // 截断
	if err := os.WriteFile(s.LogPath(), []byte(good+bad), 0o600); err != nil {
		t.Fatal(err)
	}

	loaded, err := s.Load()
	if err != nil {
		t.Fatalf("Load 不应因坏行报错: %v", err)
	}
	if len(loaded.Files) != 1 || loaded.Files[0].ID != "good" {
		t.Errorf("应只保留 good 行: %+v", loaded.Files)
	}
}

// AppendFiles + 老 session（无 log）也能 Load
func TestStore_Load_BackwardCompatNoLog(t *testing.T) {
	dir := t.TempDir()
	s := mustStore(t, dir)
	// 写老风格 snapshot，含 files；log 不存在
	if err := s.Save(Snapshot{
		DrivePath: "/old",
		Files:     []*types.RecoveredFile{{ID: "old1", FileName: "old.bin"}},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(s.LogPath()); !os.IsNotExist(err) {
		t.Fatalf("log 文件应不存在")
	}
	loaded, err := s.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.Files) != 1 || loaded.Files[0].ID != "old1" {
		t.Errorf("老 session 无 log 应正常 Load: %+v", loaded)
	}
}

// AppendFiles 空 slice 应是 no-op，不开文件
func TestStore_AppendFiles_EmptyIsNoOp(t *testing.T) {
	dir := t.TempDir()
	s := mustStore(t, dir)
	if err := s.AppendFiles(nil); err != nil {
		t.Errorf("nil append 应静默: %v", err)
	}
	if err := s.AppendFiles([]*types.RecoveredFile{}); err != nil {
		t.Errorf("空 slice append 应静默: %v", err)
	}
	if _, err := os.Stat(s.LogPath()); !os.IsNotExist(err) {
		t.Errorf("空 Append 不该建文件")
	}
}

// Clear 应同时删 snapshot + log
func TestStore_Clear_RemovesSnapshotAndLog(t *testing.T) {
	dir := t.TempDir()
	s := mustStore(t, dir)

	_ = s.Save(Snapshot{DrivePath: "/d"})
	_ = s.AppendFiles([]*types.RecoveredFile{{ID: "x", FileName: "x"}})

	if err := s.Clear(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(s.snapshotPath); !os.IsNotExist(err) {
		t.Errorf("snapshot 应删")
	}
	if _, err := os.Stat(s.logPath); !os.IsNotExist(err) {
		t.Errorf("log 应删")
	}
}
