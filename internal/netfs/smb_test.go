package netfs

import (
	"context"
	"testing"
	"time"
)

// OpenSMB 需要真实 SMB server；这里只验证"连不上时返回 error 而不是 panic"
// 真实 SMB 集成测试需要 docker-compose up samba-test，留给 integration.yml workflow。
func TestOpenSMB_UnreachableReturnsError(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err := OpenSMB(ctx, SMBConfig{
		Host: "127.0.0.1", Port: 1, // 非法端口
		User: "x", Password: "y", Share: "foo",
	}, "bar.img")
	if err == nil {
		t.Error("连不上应返回 error")
	}
}
