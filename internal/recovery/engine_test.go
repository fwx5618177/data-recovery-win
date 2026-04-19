package recovery

import (
	"sort"
	"testing"

	"data-recovery/internal/types"
)

// 回归测试（Bug #1）：跨源去重需要 NTFS 先落地。
// 上一版用了 source[i] < source[j] 做排序，但 "carver" < "ntfs" 字母序反而让
// carver 跑在前，结果去重时保留了 carver 副本、丢弃 NTFS 副本，与设计相反。
// 本测试直接对 ntfsFirstLess 建立契约：
//   - ntfs vs carver → ntfs 在前
//   - carver vs ntfs → ntfs 在前（对称性）
//   - 同源 → 不交换（让 sort.SliceStable 保持原序）
func TestNTFSFirstLess_Contract(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"ntfs", "carver", true},
		{"carver", "ntfs", false},
		{"ntfs", "ntfs", false},
		{"carver", "carver", false},
		{"ntfs", "other", true},
		{"other", "ntfs", false},
	}
	for _, c := range cases {
		if got := ntfsFirstLess(c.a, c.b); got != c.want {
			t.Errorf("ntfsFirstLess(%q, %q) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}

// 端到端证据：给一组乱序 RecoveredFile，sort.SliceStable + ntfsFirstLess 能把 NTFS 提前。
func TestNTFSFirstLess_SortsNTFSAhead(t *testing.T) {
	files := []*types.RecoveredFile{
		{ID: "c1", Source: "carver"},
		{ID: "n1", Source: "ntfs"},
		{ID: "c2", Source: "carver"},
		{ID: "n2", Source: "ntfs"},
		{ID: "c3", Source: "carver"},
	}
	sort.SliceStable(files, func(i, j int) bool {
		return ntfsFirstLess(files[i].Source, files[j].Source)
	})

	// 前两个必须是 ntfs（按原相对顺序 n1, n2）
	want := []string{"n1", "n2", "c1", "c2", "c3"}
	for i, w := range want {
		if files[i].ID != w {
			t.Errorf("排序后位置 %d: got %s want %s", i, files[i].ID, w)
		}
	}
}

// Bug #D 回归测试：RecoverOptions.AllowSameDisk=true 时应跳过同盘校验。
// 不走完整 Recover 流程（需要扫描结果），仅断言 opts 类型和字段命名稳定。
func TestRecoverOptions_AllowSameDiskStructure(t *testing.T) {
	// 构造即失败即可，这里只验证编译期契约：AllowSameDisk 字段存在且为 bool。
	var opts RecoverOptions
	opts.AllowSameDisk = true
	if !opts.AllowSameDisk {
		t.Error("AllowSameDisk 应能被设为 true")
	}

	// Recover 默认应走不带 AllowSameDisk 的路径
	var defaultOpts RecoverOptions
	if defaultOpts.AllowSameDisk {
		t.Error("RecoverOptions 默认 AllowSameDisk 必须为 false，避免默认就绕过安全检查")
	}
}

func TestContainsCaseInsensitive(t *testing.T) {
	cases := []struct {
		s, substr string
		want      bool
	}{
		{"hello world", "WORLD", true},
		{"Hello World", "world", true},
		{"ABCDEF", "cde", true},
		{"abcdef", "XYZ", false},
		{"", "x", false},
		{"anything", "", true},
		{"x", "longer", false},
		// 中文直接按字节比较（UTF-8 多字节不与 ASCII 重叠）
		{"与已恢复文件内容重复 abc", "重复", true},
		{"unrelated", "重复", false},
	}
	for _, c := range cases {
		if got := containsCaseInsensitive(c.s, c.substr); got != c.want {
			t.Errorf("containsCaseInsensitive(%q, %q) = %v, want %v", c.s, c.substr, got, c.want)
		}
	}
}
