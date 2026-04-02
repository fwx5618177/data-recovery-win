import { formatConfidence } from "./formatters";

export const DEFAULT_SCAN_MODE = "full";

export const DEFAULT_SCAN_PLAN = {
  value: DEFAULT_SCAN_MODE,
  label: "默认完整恢复扫描",
  duration: "约 1-5 小时",
  description:
    "自动执行分区发现、文件记录扫描、深度扫描和完整性验证，尽可能把可恢复内容都找回来。",
  bestFor: "系统被重置、磁盘被格式化、需要最大化恢复范围",
};

const categoryMeta = {
  all: { key: "all", icon: "全部", label: "全部文件" },
  image: { key: "image", icon: "图片", label: "图片" },
  document: { key: "document", icon: "文档", label: "文档" },
  video: { key: "video", icon: "视频", label: "视频" },
  audio: { key: "audio", icon: "音频", label: "音频" },
  archive: { key: "archive", icon: "压缩包", label: "压缩包" },
  database: { key: "database", icon: "数据库", label: "数据库" },
  other: { key: "other", icon: "其他", label: "其他" },
};

const sourceMeta = {
  all: { key: "all", label: "全部来源", shortLabel: "全部" },
  ntfs: { key: "ntfs", label: "NTFS MFT", shortLabel: "MFT" },
  carver: { key: "carver", label: "深度扫描", shortLabel: "深度" },
  signature: { key: "signature", label: "签名匹配", shortLabel: "签名" },
  fat: { key: "fat", label: "FAT 元数据", shortLabel: "FAT" },
  journal: { key: "journal", label: "日志恢复", shortLabel: "日志" },
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

export function mergeRecoveredFile(list, file) {
  if (!file?.id) {
    return list;
  }

  const index = list.findIndex((item) => item.id === file.id);

  if (index === -1) {
    return [...list, file];
  }

  const next = [...list];
  next[index] = { ...next[index], ...file };
  return next;
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
