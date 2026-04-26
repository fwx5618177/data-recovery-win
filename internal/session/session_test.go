package session

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"data-recovery/internal/types"
)

// 关键路径正向 round-trip：所有字段保留 + Version/SavedAt 自动填充
func TestStore_SaveLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	s := &Store{path: filepath.Join(dir, "session.json")}

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
	s := &Store{path: filepath.Join(dir, "missing.json")}
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
	path := filepath.Join(dir, "corrupt.json")
	if err := os.WriteFile(path, []byte("{not valid json"), 0o600); err != nil {
		t.Fatal(err)
	}
	s := &Store{path: path}
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
	path := filepath.Join(dir, "v999.json")
	// 构造 version=999 的合法 JSON
	if err := os.WriteFile(path, []byte(`{"version":999,"drivePath":"x"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	s := &Store{path: path}
	snap, _ := s.Load()
	if snap != nil {
		t.Errorf("Version=999 应被拒绝, got %+v", snap)
	}
}

// v1 向后兼容：v1 数据应被读为 v2（CarverResumeOffset 默认 0）
func TestStore_LoadV1BackwardCompatible(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "v1.json")
	if err := os.WriteFile(path, []byte(`{"version":1,"drivePath":"/dev/old","driveLabel":"v1 disk"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	s := &Store{path: path}
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
	s := &Store{path: filepath.Join(dir, "session.json")}

	// 先写一份
	if err := s.Save(Snapshot{DrivePath: "/x"}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(s.path); err != nil {
		t.Fatal(err)
	}

	// 清除
	if err := s.Clear(); err != nil {
		t.Errorf("Clear: %v", err)
	}
	if _, err := os.Stat(s.path); !os.IsNotExist(err) {
		t.Errorf("Clear 后文件应不存在")
	}

	// 第二次 Clear 应幂等
	if err := s.Clear(); err != nil {
		t.Errorf("第二次 Clear 不应报错（幂等）: %v", err)
	}
}

// 原子写：tmp 文件应在 rename 后消失（非常规：触发 rename 失败的 case 难造，
// 这里只验证 happy path 下 .tmp 文件不残留）
func TestStore_SaveAtomicNoLeftoverTmp(t *testing.T) {
	dir := t.TempDir()
	s := &Store{path: filepath.Join(dir, "session.json")}

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
	s := &Store{path: filepath.Join(dir, "session.json")}

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
