import { formatConfidence } from "./formatters";

export const DEFAULT_SCAN_MODE = "full";

/**
 * 分类元数据：只保留文字标签（图标由 icons.jsx 根据分类 key 返回）。
 * 新增一个分类时在这里加一行即可。
 */
const categoryMeta = {
  all: { key: "all", label: "全部文件" },
  image: { key: "image", label: "图片" },
  document: { key: "document", label: "文档" },
  video: { key: "video", label: "视频" },
  audio: { key: "audio", label: "音频" },
  archive: { key: "archive", label: "压缩包" },
  database: { key: "database", label: "数据库" },
  other: { key: "other", label: "其他" },
};

const sourceMeta = {
  all: { key: "all", label: "全部来源", shortLabel: "全部" },
  ntfs: { key: "ntfs", label: "NTFS MFT", shortLabel: "NTFS" },
  carver: { key: "carver", label: "深度扫描", shortLabel: "深度" },
  signature: { key: "signature", label: "签名匹配", shortLabel: "签名" },
  unknown: { key: "unknown", label: "未知来源", shortLabel: "未知" },
};

export function getCategoryMeta(key) {
  return categoryMeta[key] || categoryMeta.other;
}

export function getSourceMeta(key) {
  return sourceMeta[key] || sourceMeta.unknown;
}

export function getDriveLabel(drive) {
  return drive?.name || drive?.label || drive?.path || "未选择磁盘";
}

export function buildFallbackScanResult(files = [], progress = {}) {
  const stats = {};

  files.forEach((file) => {
    const category = file?.category || "other";
    stats[category] = (stats[category] || 0) + 1;
  });

  return {
    files,
    duration: 0,
    totalScanned: progress?.bytesScanned || 0,
    stats,
  };
}

export function isCancellationError(message) {
  const text = String(message || "").toLowerCase();
  return ["取消", "canceled", "cancelled", "stopped"].some((keyword) =>
    text.includes(keyword),
  );
}

/**
 * 把扫描事件 payload 合并到 fileIndex（Map<id, file>）里。
 * 使用 Map 让 O(n) 变成 O(1)，对 10 万级文件规模必需。
 */
export function mergeFileIntoIndex(index, file) {
  if (!file?.id) return;
  const prev = index.get(file.id);
  if (prev) {
    index.set(file.id, { ...prev, ...file });
  } else {
    index.set(file.id, file);
  }
}

export function normalizeRecoveryCompletion(
  payload,
  fallbackTotal = 0,
  fallbackBytesWritten = 0,
) {
  const success =
    payload?.success ??
    payload?.Success ??
    payload?.succeeded ??
    payload?.Succeeded ??
    0;

  const failed = payload?.failed ?? payload?.Failed ?? 0;
  const partial = payload?.partial ?? payload?.Partial ?? 0;

  const total =
    payload?.total ??
    payload?.Total ??
    fallbackTotal ??
    success + partial + failed;

  return {
    current: payload?.current ?? payload?.Current ?? total,
    total,
    currentFile: payload?.currentFile ?? payload?.CurrentFile ?? "",
    bytesWritten:
      payload?.bytesWritten ?? payload?.BytesWritten ?? fallbackBytesWritten,
    success,
    partial,
    failed,
    records: payload?.records ?? payload?.Records ?? null,
  };
}

export function recoveryScore(file) {
  const confidence = formatConfidence(file?.confidence);

  if (confidence > 0) {
    return confidence;
  }

  if (file?.isValid === true) {
    return 72;
  }

  if (file?.isValid === false) {
    return 30;
  }

  return 45;
}

/**
 * 把用户在 UI 里设定的过滤条件应用到文件列表上。
 * 为了扫描中也能高频调用，保持 O(n) 且无对象分配（除结果数组）。
 */
export function filterFiles(files, filter) {
  if (!files || files.length === 0) return [];
  const keyword = (filter.keyword || "").trim().toLowerCase();
  const categories = filter.categories instanceof Set ? filter.categories : null;
  const sources = filter.sources instanceof Set ? filter.sources : null;
  const validityMode = filter.validity || "all"; // all | valid | invalid

  const out = [];
  for (let i = 0; i < files.length; i++) {
    const f = files[i];
    if (!f) continue;
    if (categories && categories.size > 0 && !categories.has(f.category)) continue;
    if (sources && sources.size > 0 && !sources.has(f.source)) continue;
    if (validityMode === "valid" && !f.isValid) continue;
    if (validityMode === "invalid" && f.isValid) continue;
    if (keyword) {
      const name = (f.fileName || "").toLowerCase();
      const path = (f.originalPath || "").toLowerCase();
      if (!name.includes(keyword) && !path.includes(keyword)) continue;
    }
    out.push(f);
  }
  return out;
}

export function countByCategory(files) {
  const counts = {};
  for (let i = 0; i < files.length; i++) {
    const cat = files[i]?.category || "other";
    counts[cat] = (counts[cat] || 0) + 1;
  }
  return counts;
}

export function countBySource(files) {
  const counts = {};
  for (let i = 0; i < files.length; i++) {
    const src = files[i]?.source || "unknown";
    counts[src] = (counts[src] || 0) + 1;
  }
  return counts;
}

/**
 * 把一个字节数和另一个字节数比一下：返回 "富余 / 刚好 / 不够" 三态。
 * 30% 余量以上算 富余，保底 1GB。
 */
export function sufficiencyOf(needed, available) {
  if (!Number.isFinite(needed) || needed <= 0) return "unknown";
  if (!Number.isFinite(available) || available <= 0) return "unknown";
  if (available < needed) return "short";
  const margin = Math.max(needed * 0.3, 1 * 1024 * 1024 * 1024);
  if (available < needed + margin) return "tight";
  return "ample";
}
