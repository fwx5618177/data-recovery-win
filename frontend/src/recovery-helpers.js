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

/**
 * 系统文件"黑名单"：被重置的 Windows 盘里，MFT 里积累了大量旧操作系统 / 应用残留
 * （驱动、库、可执行、图标等），它们是真实存在的被删文件，但几乎不是用户想要的"我的数据"。
 * 默认把这些扩展名过滤掉，让照片/文档/视频浮上来。用户可在侧栏显式放开。
 *
 * 注意：只按扩展名看，并不禁止任何后端恢复能力。用户恢复某个 .exe 只要在 UI 里放开即可。
 */
const SYSTEM_FILE_EXTENSIONS = new Set([
  // Windows 可执行 / 动态库 / 驱动
  "exe", "dll", "sys", "drv", "ocx", "cpl", "efi", "scr",
  // Windows 资源 / 清单 / 配置残片
  "ico", "cur", "ani", "manifest", "mui", "nls",
  // 安装器 / 补丁 / 数字签名 / 安装脚本
  "msi", "msp", "mst", "cat", "inf", "reg",
  // Linux/Unix 可执行
  "elf", "so",
  // 通用"无结构"二进制，恢复后无法打开
  "bin", "dat", "pack", "idx",
]);

// 常见系统目录前缀（不区分大小写、正反斜杠）
const SYSTEM_PATH_PREFIXES = [
  "windows/", "winnt/", "program files", "programdata/",
  "$recycle.bin/", "system volume information/",
  "boot/", "perflogs/", "recovery/",
];

/**
 * isSystemFile 判断一条 RecoveredFile 是否属于"系统文件"（非用户内容）。
 * 命中条件（任意一条即判定）：
 *   - 扩展名在 SYSTEM_FILE_EXTENSIONS 中
 *   - 原路径（NTFS 来源才有）以系统目录前缀开头
 */
export function isSystemFile(file) {
  if (!file) return false;
  const ext = String(file.extension || "").toLowerCase();
  if (SYSTEM_FILE_EXTENSIONS.has(ext)) return true;

  const path = String(file.originalPath || "").toLowerCase().replace(/\\/g, "/");
  for (const prefix of SYSTEM_PATH_PREFIXES) {
    if (path.startsWith(prefix) || path.includes("/" + prefix)) return true;
  }
  return false;
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
 *
 * filter 支持的字段：
 *   - keyword          文件名/原路径模糊匹配
 *   - categories       Set<string> 分类白名单（空 Set 不过滤）
 *   - sources          Set<string> 来源白名单（空 Set 不过滤）
 *   - validity         "all" | "valid" | "invalid"
 *   - hideSystemFiles  true 时把 .exe/.dll/.ico/.sys 等系统文件藏起来，
 *                      NTFS 在 /Windows、/Program Files 下的文件也算
 */
export function filterFiles(files, filter) {
  if (!files || files.length === 0) return [];
  const keyword = (filter.keyword || "").trim().toLowerCase();
  const categories = filter.categories instanceof Set ? filter.categories : null;
  const sources = filter.sources instanceof Set ? filter.sources : null;
  const validityMode = filter.validity || "all"; // all | valid | invalid
  const hideSystemFiles = !!filter.hideSystemFiles;

  const out = [];
  for (let i = 0; i < files.length; i++) {
    const f = files[i];
    if (!f) continue;
    if (hideSystemFiles && isSystemFile(f)) continue;
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

/** countSystemFiles 统计文件列表里多少条会被系统文件过滤器命中。 */
export function countSystemFiles(files) {
  if (!files || files.length === 0) return 0;
  let n = 0;
  for (let i = 0; i < files.length; i++) {
    if (isSystemFile(files[i])) n++;
  }
  return n;
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
