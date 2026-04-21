package netfs

import "testing"

func TestSuggestMount_SMB(t *testing.T) {
	got := SuggestMount("smb://server/share")
	if len(got) == 0 {
		t.Error("smb:// 应给挂载建议")
	}
}

func TestSuggestMount_NFS(t *testing.T) {
	got := SuggestMount("nfs://server/export")
	if len(got) == 0 {
		t.Error("nfs:// 应给挂载建议")
	}
}

func TestIsRemoteURL(t *testing.T) {
	for _, u := range []string{"smb://x", "nfs://x", "http://x"} {
		if !IsRemoteURL(u) {
			t.Errorf("%q 应识别为 remote", u)
		}
	}
	if IsRemoteURL("/local/path") {
		t.Error("本地路径不该识别为 remote")
	}
}
