package refs

import (
	"strings"
	"testing"
)

// buildFullPath 单测：给定 parent 映射构建 path
func TestBuildFullPath_Linear(t *testing.T) {
	parentOf := map[uint64]uint64{
		3: 2, // file3 under dir2
		2: 1, // dir2 under dir1
		1: 0x600, // dir1 under root
	}
	nameByID := map[uint64]string{
		1: "Users",
		2: "Alice",
		3: "report.docx",
	}
	path := buildFullPath(3, "report.docx", parentOf, nameByID, 32)
	want := "Users/Alice/report.docx"
	if path != want {
		t.Errorf("got %q want %q", path, want)
	}
}

// 缺 parent 链：应 fallback 到 "<obj_XX>"
func TestBuildFullPath_MissingParentName(t *testing.T) {
	parentOf := map[uint64]uint64{
		5: 4,
		4: 3, // 3 不在 nameByID
	}
	nameByID := map[uint64]string{
		5: "data.bin",
		// 4, 3 都没名字
	}
	path := buildFullPath(5, "data.bin", parentOf, nameByID, 32)
	// 最终 path = "<obj_3>/<obj_4>/data.bin"
	if !strings.Contains(path, "data.bin") || !strings.Contains(path, "<obj_") {
		t.Errorf("missing parent name fallback 不对: %q", path)
	}
}

// 循环检测：parent 链自引用或循环不能无限递归
func TestBuildFullPath_CycleDetection(t *testing.T) {
	parentOf := map[uint64]uint64{
		1: 2,
		2: 1, // 循环
	}
	nameByID := map[uint64]string{
		1: "a",
		2: "b",
	}
	// 不该死循环
	path := buildFullPath(1, "a", parentOf, nameByID, 32)
	// 至少含 "a" 自己
	if !strings.Contains(path, "a") {
		t.Errorf("循环检测后应保留 selfName: %q", path)
	}
}

// 根对象识别：遇 0x600 即停
func TestBuildFullPath_StopAtRoot(t *testing.T) {
	parentOf := map[uint64]uint64{
		5: 0x600, // 直接在 root 下
	}
	nameByID := map[uint64]string{
		5: "topfile.txt",
	}
	path := buildFullPath(5, "topfile.txt", parentOf, nameByID, 32)
	if path != "topfile.txt" {
		t.Errorf("root 下 file 应返回文件名本身: got %q", path)
	}
}

// looksLikeObjectID 启发
func TestLooksLikeObjectID(t *testing.T) {
	cases := map[uint64]bool{
		0:                  false,
		100:                true,
		1 << 40:            true,
		1 << 50:            false, // 超出 2^48
		0xFFFFFFFFFFFFFFFF: false,
	}
	for id, expect := range cases {
		if got := looksLikeObjectID(id); got != expect {
			t.Errorf("looksLikeObjectID(0x%X) = %v want %v", id, got, expect)
		}
	}
}
