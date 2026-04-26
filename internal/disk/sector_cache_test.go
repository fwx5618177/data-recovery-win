package disk

import (
	"sync"
	"testing"
)

func TestSectorCache_HitMissCounters(t *testing.T) {
	c := NewSectorCache(4)
	dst := make([]byte, 8)

	// 4 个 miss
	for i := uint64(0); i < 4; i++ {
		if c.Get(i, dst) {
			t.Errorf("空 cache get %d 应 miss", i)
		}
	}
	stats := c.Stats()
	if stats.Misses != 4 || stats.Hits != 0 {
		t.Errorf("4 misses 0 hits, got %+v", stats)
	}

	// 写 2 个
	c.Put(0, []byte("aaaaaaaa"))
	c.Put(1, []byte("bbbbbbbb"))

	// 各取 3 次 = 6 hits
	for i := 0; i < 3; i++ {
		c.Get(0, dst)
		c.Get(1, dst)
	}
	stats = c.Stats()
	if stats.Hits != 6 {
		t.Errorf("hits = %d want 6", stats.Hits)
	}
	if stats.Puts != 2 {
		t.Errorf("puts = %d want 2", stats.Puts)
	}
	// HitRatio = 6 / (6+4) = 0.6
	if stats.HitRatio < 0.59 || stats.HitRatio > 0.61 {
		t.Errorf("HitRatio = %f want ≈0.6", stats.HitRatio)
	}
	if stats.Size != 2 {
		t.Errorf("Size = %d want 2", stats.Size)
	}
	if stats.Capacity != 4 {
		t.Errorf("Capacity = %d want 4", stats.Capacity)
	}
}

func TestSectorCache_EvictionCounter(t *testing.T) {
	c := NewSectorCache(2)
	for i := uint64(0); i < 5; i++ {
		c.Put(i, []byte{byte(i)})
	}
	stats := c.Stats()
	if stats.Evictions != 3 { // 5 puts，cap 2，应淘汰 3 次
		t.Errorf("Evictions = %d want 3", stats.Evictions)
	}
	if stats.Size != 2 {
		t.Errorf("Size = %d want 2", stats.Size)
	}
}

// nil cache 上 Stats 应安全返回零值
func TestSectorCache_NilStats(t *testing.T) {
	var c *SectorCache // nil
	stats := c.Stats()
	if stats != (CacheStats{}) {
		t.Errorf("nil receiver Stats 应返回零值, got %+v", stats)
	}
}

// 0 capacity → 返回 nil
func TestNewSectorCache_ZeroCap(t *testing.T) {
	c := NewSectorCache(0)
	if c != nil {
		t.Errorf("capacity=0 应返回 nil")
	}
	// nil 上的所有方法都应安全
	if c.Get(0, nil) {
		t.Errorf("nil Get 应 false")
	}
	c.Put(0, nil) // 不应 panic
	if c.Len() != 0 {
		t.Errorf("nil Len 应 0")
	}
}

// 并发 put/get 不 race
func TestSectorCache_Concurrent(t *testing.T) {
	c := NewSectorCache(64)
	var wg sync.WaitGroup
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func(seed int) {
			defer wg.Done()
			dst := make([]byte, 8)
			for i := 0; i < 1000; i++ {
				idx := uint64((seed*i + i) % 100)
				if !c.Get(idx, dst) {
					c.Put(idx, []byte("filldata"))
				}
			}
		}(w)
	}
	wg.Wait()
	stats := c.Stats()
	if stats.Hits+stats.Misses != 8000 {
		t.Errorf("总访问 = %d want 8000", stats.Hits+stats.Misses)
	}
}
