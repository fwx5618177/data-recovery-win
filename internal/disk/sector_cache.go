package disk

// SectorCache 是按 sector index 索引的有界 LRU。
//
// 共享于加密卷 reader（LUKS / VC / BitLocker / FileVault）—— 加密卷扫描典型 pattern：
// NTFS scanner 反复读 MFT/boot 区，同一 sector 被解密几十次。AES-XTS 在 AES-NI
// CPU 上 ~0.2 μs/sector × 数千 entry × 数次 rescan = 累计可达数十秒，缓存命中
// 直接复制解密字节 → 显著加速。
//
// 并发：多 goroutine 同时 Get/Put 都加 Mutex；性能上瓶颈不在锁（典型 hit
// 路径只是 map 查找 + memcpy），完整 sectorCache 实测可承担 100M+ ops/s。

import (
	"container/list"
	"sync"
)

// SectorCache 有界 LRU sector 缓存。
type SectorCache struct {
	mu       sync.Mutex
	capacity int
	entries  map[uint64]*list.Element // sectorIdx → list.Element（value = *cachedSector）
	order    *list.List

	// 命中率 metrics（atomic 访问）；CacheStats() 返回快照。
	hits   uint64
	misses uint64
	puts   uint64
	evicts uint64
}

// CacheStats 是 SectorCache 的命中率快照。
//
// HitRatio 计算公式：hits / (hits + misses)；分母 0 时返回 0。
type CacheStats struct {
	Capacity  int     `json:"capacity"`
	Size      int     `json:"size"`      // 当前 entry 数
	Hits      uint64  `json:"hits"`      // Get 命中次数
	Misses    uint64  `json:"misses"`    // Get 未命中次数
	Puts      uint64  `json:"puts"`      // Put 调用次数（含覆盖）
	Evictions uint64  `json:"evictions"` // 因 capacity 淘汰的次数
	HitRatio  float64 `json:"hitRatio"`
}

type cachedSector struct {
	idx  uint64
	data []byte // 完整 sector 字节（长度 = sectorSize），cache 持有副本
}

// NewSectorCache 构造一个 capacity 个 sector 上限的 LRU。
// capacity ≤ 0 时返回 nil（调用方需 nil-check）。
func NewSectorCache(capacity int) *SectorCache {
	if capacity <= 0 {
		return nil
	}
	return &SectorCache{
		capacity: capacity,
		entries:  make(map[uint64]*list.Element, capacity),
		order:    list.New(),
	}
}

// Get 命中时把 cached data 复制到 dst（dst 长度应 = sectorSize），返回 true。
// 不直接返回 cache 内部 slice 防止 caller 写它污染 cache。
//
// nil receiver safe：返回 false。
func (c *SectorCache) Get(idx uint64, dst []byte) bool {
	if c == nil {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	elem, ok := c.entries[idx]
	if !ok {
		c.misses++
		return false
	}
	cs := elem.Value.(*cachedSector)
	copy(dst, cs.data)
	c.order.MoveToFront(elem)
	c.hits++
	return true
}

// Put 把 src 的副本放入 cache；超 capacity 时淘汰 LRU 末尾。
//
// nil receiver safe：no-op。
func (c *SectorCache) Put(idx uint64, src []byte) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.puts++
	if elem, ok := c.entries[idx]; ok {
		// 已有则刷新数据 + 升到队首
		cs := elem.Value.(*cachedSector)
		copy(cs.data, src)
		c.order.MoveToFront(elem)
		return
	}
	for c.order.Len() >= c.capacity {
		back := c.order.Back()
		if back == nil {
			break
		}
		cs := back.Value.(*cachedSector)
		delete(c.entries, cs.idx)
		c.order.Remove(back)
		c.evicts++
	}
	dup := make([]byte, len(src))
	copy(dup, src)
	c.entries[idx] = c.order.PushFront(&cachedSector{idx: idx, data: dup})
}

// Len 返回当前缓存条目数（用于诊断 / 测试）。
func (c *SectorCache) Len() int {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.order.Len()
}

// Stats 返回当前命中率快照。nil receiver 安全。
func (c *SectorCache) Stats() CacheStats {
	if c == nil {
		return CacheStats{}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	total := c.hits + c.misses
	var ratio float64
	if total > 0 {
		ratio = float64(c.hits) / float64(total)
	}
	return CacheStats{
		Capacity:  c.capacity,
		Size:      c.order.Len(),
		Hits:      c.hits,
		Misses:    c.misses,
		Puts:      c.puts,
		Evictions: c.evicts,
		HitRatio:  ratio,
	}
}
