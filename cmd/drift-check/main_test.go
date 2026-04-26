package main

import (
	"os"
	"path/filepath"
	"testing"
)

// writeTempGo 在 t.TempDir 下创建带指定内容的 .go 文件，用于测试 scan
func writeTempGo(t *testing.T, name, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, name)
	// 写一个最小 package 头
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	return dir
}

// 场景 1：注释承诺超时，body 无任何 timeout 机制 → 必须报告
func TestScan_DriftDetected_Timeout(t *testing.T) {
	src := `package foo

import "io"

// DoIt 以 5s 超时执行工作
// 如果任务卡住会自动取消。
func DoIt(r io.Reader) error {
	_, err := r.Read(make([]byte, 16))
	return err
}
`
	dir := writeTempGo(t, "a.go", src)
	findings, _ := scan(dir)
	if len(findings) == 0 {
		t.Fatalf("期望发现漂移，实际 0 条")
	}
	hasTimeout := false
	for _, f := range findings {
		if f.Rule == "timeout" {
			hasTimeout = true
		}
	}
	if !hasTimeout {
		t.Errorf("期望发现 timeout 规则命中；findings=%+v", findings)
	}
}

// 场景 2：注释承诺超时，body 用了 context.WithTimeout → 不应报告
func TestScan_NoDrift_WhenResolverPresent(t *testing.T) {
	src := `package foo

import (
	"context"
	"time"
)

// DoIt 以 5s 超时执行；超时后自动取消。
func DoIt() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = ctx
	return nil
}
`
	dir := writeTempGo(t, "b.go", src)
	findings, _ := scan(dir)
	// 可能还会命中 cancel / cleanup，主要断言 timeout 规则不命中
	for _, f := range findings {
		if f.Rule == "timeout" {
			t.Errorf("不应命中 timeout drift；got %+v", f)
		}
	}
}

// 场景 3：注释提"取消"但 body 没 ctx.Done() → 命中 cancel 规则
func TestScan_DriftDetected_Cancel(t *testing.T) {
	src := `package foo

// Loop 循环处理消息，收到取消信号立即退出。
func Loop(ch chan int) {
	for v := range ch {
		_ = v
	}
}
`
	dir := writeTempGo(t, "c.go", src)
	findings, _ := scan(dir)
	hasCancel := false
	for _, f := range findings {
		if f.Rule == "cancel" {
			hasCancel = true
		}
	}
	if !hasCancel {
		t.Errorf("期望命中 cancel 规则；got %+v", findings)
	}
}

// 场景 4：非 .go 文件、测试文件应跳过
func TestScan_SkipsNonGoAndTestFiles(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "x.txt"), []byte(`// 超时注释`), 0o644); err != nil {
		t.Fatal(err)
	}
	testSrc := `package foo

// 超时执行
func Foo() {}
`
	if err := os.WriteFile(filepath.Join(dir, "foo_test.go"), []byte(testSrc), 0o644); err != nil {
		t.Fatal(err)
	}
	findings, _ := scan(dir)
	if len(findings) != 0 {
		t.Errorf("非 .go / _test.go 不应被扫描；got %+v", findings)
	}
}
