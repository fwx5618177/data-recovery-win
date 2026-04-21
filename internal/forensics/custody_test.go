package forensics

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCustody_BuildAndVerify(t *testing.T) {
	tmp := t.TempDir()
	// 写两个假文件
	os.WriteFile(filepath.Join(tmp, "a.txt"), []byte("hello"), 0o644)
	os.WriteFile(filepath.Join(tmp, "b.bin"), []byte{1, 2, 3, 4}, 0o644)

	c := Custody{
		ToolName:    "DataRecovery",
		ToolVersion: "1.0",
		StartedAt:   time.Now().UTC(),
		SourceDevice: "/dev/null",
	}
	manifestPath, err := BuildAndWrite(tmp, c)
	if err != nil {
		t.Fatalf("BuildAndWrite: %v", err)
	}
	if _, err := os.Stat(manifestPath); err != nil {
		t.Fatal("manifest 未生成")
	}

	// Verify 应通过
	problems, err := VerifyCustody(tmp)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if len(problems) != 0 {
		t.Errorf("不该有问题: %v", problems)
	}

	// 篡改一个文件 → Verify 应报错
	os.WriteFile(filepath.Join(tmp, "a.txt"), []byte("tampered"), 0o644)
	problems, _ = VerifyCustody(tmp)
	if len(problems) == 0 {
		t.Error("篡改后 Verify 应报错")
	}
}

func TestNSRLDB_LoadAndCheck(t *testing.T) {
	tmp := t.TempDir()
	hashFile := filepath.Join(tmp, "nsrl.txt")
	os.WriteFile(hashFile, []byte(
		"abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789\n"+
			"# comment line should skip\n"+
			"FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210\n"), 0o644)
	db, err := LoadNSRLFromFile(hashFile)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if db.Size() != 2 {
		t.Errorf("size=%d want 2", db.Size())
	}
	if !db.IsKnownBenign("ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789") {
		t.Error("应识别为 benign（大小写无关）")
	}
	if db.IsKnownBenign("0000000000000000000000000000000000000000000000000000000000000000") {
		t.Error("未知 hash 不该被识别")
	}
}
