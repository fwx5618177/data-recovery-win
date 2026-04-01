export function formatSize(bytes) {
  if (!Number.isFinite(bytes) || bytes <= 0) {
    return '0 B';
  }

  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let size = bytes;
  let unitIndex = 0;

  while (size >= 1024 && unitIndex < units.length - 1) {
    size /= 1024;
    unitIndex += 1;
  }

  return `${size.toFixed(unitIndex === 0 ? 0 : 1)} ${units[unitIndex]}`;
}

export function formatDuration(value) {
  if (value == null || value === '') {
    return '--';
  }

  if (typeof value === 'string') {
    return value;
  }

  if (!Number.isFinite(value) || value < 0) {
    return '--';
  }

  if (value < 60) {
    return `${value.toFixed(1)} 秒`;
  }

  if (value < 3600) {
    const minutes = Math.floor(value / 60);
    const seconds = Math.round(value % 60);
    return `${minutes} 分 ${seconds} 秒`;
  }

  const hours = Math.floor(value / 3600);
  const minutes = Math.round((value % 3600) / 60);
  return `${hours} 小时 ${minutes} 分`;
}

export function clampPercent(value) {
  if (!Number.isFinite(value)) {
    return 0;
  }

  return Math.max(0, Math.min(value, 100));
}

export function formatConfidence(value) {
  if (!Number.isFinite(value)) {
    return 0;
  }

  const percent = value > 1 ? value : value * 100;
  return Math.round(clampPercent(percent));
}

export function formatSpeed(bytesPerSecond) {
  if (!Number.isFinite(bytesPerSecond) || bytesPerSecond <= 0) {
    return '0 B/s';
  }

  return `${formatSize(bytesPerSecond)}/s`;
}

export function formatPath(file) {
  return file?.originalPath || file?.path || '原始路径不可用';
}
