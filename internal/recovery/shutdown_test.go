package recovery

import (
	"bytes"
	"testing"
)

// Shutdown 应释放所有 fs source maps + apfsVEKs，防 Engine 复用 / 残留密钥。
func TestEngine_Shutdown_ReleasesAllSources(t *testing.T) {
	e := NewEngine()

	// 模拟一次扫描后的 source map 状态（不需要真扫，直接塞条目）
	e.ntfsSources = map[string]ntfsRecoverySource{"x": {}}
	e.exfatSources = map[string]exfatRecoverySource{"x": {}}
	e.fatSources = map[string]fatRecoverySource{"x": {}}
	e.extSources = map[string]extRecoverySource{"x": {}}
	e.apfsSources = map[string]apfsRecoverySource{"x": {}}
	e.hfsplusSources = map[string]hfsplusRecoverySource{"x": {}}
	e.btrfsSources = map[string]btrfsRecoverySource{"x": {}}
	// 假 VEK（用于验证字节归零 + map 清空）
	vek := bytes.Repeat([]byte{0xCC}, 32)
	e.apfsVEKs = map[[16]byte][]byte{
		{1, 2, 3}: vek,
	}

	e.Shutdown()

	// 所有 map 都应是 nil（显式 release）
	if e.ntfsSources != nil {
		t.Errorf("ntfsSources 未释放")
	}
	if e.exfatSources != nil {
		t.Errorf("exfatSources 未释放")
	}
	if e.fatSources != nil {
		t.Errorf("fatSources 未释放")
	}
	if e.extSources != nil {
		t.Errorf("extSources 未释放")
	}
	if e.apfsSources != nil {
		t.Errorf("apfsSources 未释放")
	}
	if e.hfsplusSources != nil {
		t.Errorf("hfsplusSources 未释放")
	}
	if e.btrfsSources != nil {
		t.Errorf("btrfsSources 未释放")
	}
	if e.apfsVEKs != nil {
		t.Errorf("apfsVEKs 未释放")
	}

	// VEK 字节应被归零（防 dump 泄密）
	zeros := make([]byte, 32)
	if !bytes.Equal(vek, zeros) {
		t.Errorf("VEK 字节未归零: %x", vek)
	}
}

// 多次 Shutdown 应幂等，不 panic
func TestEngine_Shutdown_Idempotent(t *testing.T) {
	e := NewEngine()
	e.Shutdown()
	e.Shutdown() // 第 2 次不应 panic
	e.Shutdown() // 第 3 次也不应 panic
}

// EncryptedReaderCacheStats：未设置 reader 时应返回 (空, false)
func TestEngine_EncryptedReaderCacheStats_Inactive(t *testing.T) {
	e := NewEngine()
	stats, ok := e.EncryptedReaderCacheStats()
	if ok {
		t.Errorf("无 reader 时应 inactive, got ok=true stats=%+v", stats)
	}
}
