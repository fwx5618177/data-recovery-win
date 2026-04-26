import { useEffect, useState } from "react";

// CacheStatsPanel —— 加密卷扫描的 sector 缓存命中率展示面板。
//
// 当扫描走加密卷链路（LUKS / VeraCrypt / BitLocker）时，DecryptedReader 内置 LRU
// 缓存会大幅减少重复 AES-XTS 解密。这个面板每 2s poll 后端，让用户直观看到缓存
// 在生效（"命中率 87%"）—— 不是噱头，是优化反馈。
//
// 非加密扫描（NTFS 直接物理盘）后端返回 active=false，本面板自动隐藏。

const POLL_INTERVAL_MS = 2000;

export default function CacheStatsPanel({ scanActive }) {
  const [stats, setStats] = useState(null);

  useEffect(() => {
    if (!scanActive || !window.go?.main?.App?.GetEncryptedReaderCacheStats) {
      setStats(null);
      return;
    }

    let cancelled = false;
    const tick = async () => {
      try {
        const resp = await window.go.main.App.GetEncryptedReaderCacheStats();
        if (cancelled) return;
        if (resp?.active) {
          setStats(resp.stats);
        } else {
          setStats(null);
        }
      } catch {
        // 忽略——非致命，下一轮再试
      }
    };

    tick(); // 立即跑一次拿基线
    const interval = setInterval(tick, POLL_INTERVAL_MS);

    return () => {
      cancelled = true;
      clearInterval(interval);
    };
  }, [scanActive]);

  if (!stats) return null;

  const hitRatioPct = Math.round((stats.hitRatio || 0) * 100);
  const hits = stats.hits || 0;
  const misses = stats.misses || 0;
  const totalAccesses = hits + misses;
  // capacity 单位 = sectors；按 512B 估算字节
  const capBytesMB = Math.round(((stats.capacity || 0) * 512) / 1024 / 1024);
  const sizeBytesMB = Math.round(((stats.size || 0) * 512) / 1024 / 1024);

  // 缓存命中颜色：绿 ≥80% / 黄 ≥50% / 灰 < 50%
  let bgColor = "var(--accent-soft)";
  let icon = "💾";
  if (hitRatioPct >= 80) {
    bgColor = "var(--success-soft, #d4edda)";
    icon = "🚀";
  } else if (hitRatioPct < 50 && totalAccesses > 100) {
    bgColor = "var(--warning-soft, #fff3cd)";
    icon = "⚠️";
  }

  return (
    <div
      style={{
        marginTop: 6,
        padding: "6px 10px",
        fontSize: 12,
        borderRadius: "var(--radius-md)",
        background: bgColor,
        border: "1px solid var(--border-strong)",
        display: "flex",
        gap: 12,
        flexWrap: "wrap",
        alignItems: "center",
      }}
      title={`LRU sector cache: ${stats.capacity} sectors capacity (≈ ${capBytesMB} MB).
Hits: ${hits.toLocaleString()}, Misses: ${misses.toLocaleString()}, Evictions: ${(stats.evictions || 0).toLocaleString()}, Puts: ${(stats.puts || 0).toLocaleString()}`}
    >
      <span>
        {icon} 加密卷扫描缓存命中率 <b>{hitRatioPct}%</b>
      </span>
      <span style={{ color: "var(--muted)" }}>
        {hits.toLocaleString()} hits / {misses.toLocaleString()} misses
      </span>
      <span style={{ color: "var(--muted)" }}>
        容量 <b>{sizeBytesMB}</b>/{capBytesMB} MB
      </span>
      {(stats.evictions || 0) > 1000 && (
        <span style={{ color: "var(--muted)" }}>
          淘汰 {(stats.evictions || 0).toLocaleString()}（容量可能偏小）
        </span>
      )}
    </div>
  );
}
