package netfs

import "testing"

// 验证 NFS3 ACCESS bit mask 常量与 RFC 1813 §3.3.4 一致
func TestACCESS3Bits(t *testing.T) {
	cases := []struct {
		name string
		got  uint32
		want uint32
	}{
		{"READ", ACCESS3_READ, 0x0001},
		{"LOOKUP", ACCESS3_LOOKUP, 0x0002},
		{"MODIFY", ACCESS3_MODIFY, 0x0004},
		{"EXTEND", ACCESS3_EXTEND, 0x0008},
		{"DELETE", ACCESS3_DELETE, 0x0010},
		{"EXECUTE", ACCESS3_EXECUTE, 0x0020},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("%s: 0x%X != 0x%X", c.name, c.got, c.want)
		}
	}
}

// proc 编号必须与 RFC 1813 § Appendix I 一致
func TestNFSProcNumbers(t *testing.T) {
	if nfsProcAccess != 4 {
		t.Errorf("ACCESS proc = %d, RFC 1813 是 4", nfsProcAccess)
	}
	if nfsProcReadlink != 5 {
		t.Errorf("READLINK proc = %d, RFC 1813 是 5", nfsProcReadlink)
	}
	if nfsProcFsstat != 18 {
		t.Errorf("FSSTAT proc = %d, RFC 1813 是 18", nfsProcFsstat)
	}
	if nfsProcFsinfo != 19 {
		t.Errorf("FSINFO proc = %d, RFC 1813 是 19", nfsProcFsinfo)
	}
}

// NFSFSInfo / NFSFSStat 结构存在性 smoke
func TestFSInfoStructInit(t *testing.T) {
	info := NFSFSInfo{RTMax: 1048576, RTPref: 65536, MaxFileSz: 1 << 50}
	if info.RTMax != 1048576 || info.RTPref != 65536 {
		t.Error("FSInfo init")
	}
	stat := NFSFSStat{Tbytes: 1 << 40, Fbytes: 1 << 30}
	if stat.Tbytes == 0 {
		t.Error("FSStat init")
	}
}

// SetReadChunk 边界
func TestNFSFileReader_SetReadChunk(t *testing.T) {
	r := &NFSFileReader{}
	r.SetReadChunk(0)
	if r.chunk != 0 {
		t.Error("0 应被忽略")
	}
	r.SetReadChunk(1024 * 1024 * 2) // 超 1MB 上限
	if r.chunk != 0 {
		t.Error("超限应被忽略")
	}
	r.SetReadChunk(128 * 1024)
	if r.chunk != 128*1024 {
		t.Errorf("got %d", r.chunk)
	}
}
