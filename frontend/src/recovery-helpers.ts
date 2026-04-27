import { formatConfidence } from "./formatters";

export const DEFAULT_SCAN_MODE = "full";

/**
 * parseAdvancedQuery 高级搜索语法 → predicate(file)
 *   keyword          普通文本（match fileName 或 originalPath）
 *   size:>100MB      size 比较：>= > <= < =
 *   type:image       category 等于
 *   ext:jpg          extension 等于
 *   deleted:yes      isDeleted true/false
 *   source:ntfs      source 含
 *   path:/Users      originalPath 含
 */
export function parseAdvancedQuery(query) {
  if (!query || typeof query !== "string") return () => true;
  const tokens = query.match(/(\S*?:[^\s]+|\S+)/g) || [];
  const filters = [];
  const plain = [];
  for (const tok of tokens) {
    const c = tok.indexOf(":");
    if (c <= 0) { plain.push(tok.toLowerCase()); continue; }
    const key = tok.slice(0, c).toLowerCase();
    const val = tok.slice(c + 1).toLowerCase();
    switch (key) {
      case "size": filters.push(makeSizeFilter(val)); break;
      case "type":
      case "category": filters.push((f) => String(f.category || "").toLowerCase() === val); break;
      case "ext":
      case "extension": filters.push((f) => String(f.extension || "").toLowerCase() === val); break;
      case "deleted": {
        const want = val === "yes" || val === "true" || val === "1";
        filters.push((f) => Boolean(f.isDeleted) === want);
        break;
      }
      case "source": filters.push((f) => String(f.source || "").toLowerCase().includes(val)); break;
      case "path": filters.push((f) => String(f.originalPath || "").toLowerCase().includes(val)); break;
      default: plain.push(tok.toLowerCase());
    }
  }
  if (plain.length > 0) {
    filters.push((f) => {
      const hay = (String(f.fileName || "") + " " + String(f.originalPath || "")).toLowerCase();
      return plain.every((k) => hay.includes(k));
    });
  }
  return (f) => filters.every((fn) => fn(f));
}

function makeSizeFilter(spec) {
  const m = spec.match(/^([><=]=?|=)?\s*(\d+(?:\.\d+)?)\s*([kmgtKMGT]?b?)?$/);
  if (!m) return () => true;
  const op = m[1] || "=";
  const num = parseFloat(m[2]);
  const unit = (m[3] || "").toLowerCase();
  const mult = { "": 1, b: 1, k: 1024, kb: 1024, m: 1024 ** 2, mb: 1024 ** 2,
                 g: 1024 ** 3, gb: 1024 ** 3, t: 1024 ** 4, tb: 1024 ** 4 }[unit] || 1;
  const bytes = num * mult;
  return (f) => {
    const s = Number(f.size || 0);
    switch (op) {
      case ">":  return s > bytes;
      case ">=": return s >= bytes;
      case "<":  return s < bytes;
      case "<=": return s <= bytes;
      default:   return s === bytes;
    }
  };
}

/**
 * buildPathTree 把扁平 file 列表按 originalPath 组装成树（目录树视图用）
 */
export function buildPathTree(files) {
  const root = { name: "/", path: "", isDir: true, files: [], children: {} };
  for (const f of files) {
    if (!f) continue;
    const path = String(f.originalPath || f.fileName || "");
    const parts = path.split(/[/\\]+/).filter(Boolean);
    if (parts.length === 0) { root.files.push(f); continue; }
    let node = root;
    for (let i = 0; i < parts.length - 1; i++) {
      const seg = parts[i];
      if (!node.children[seg]) {
        node.children[seg] = {
          name: seg,
          path: node.path ? node.path + "/" + seg : seg,
          isDir: true, files: [], children: {},
        };
      }
      node = node.children[seg];
    }
    node.files.push(f);
  }
  return root;
}

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
 *
 * 例外：Windows.old 子树下的文件**不算**系统文件。
 * Windows 重装后，前一次系统 + 前一次的所有用户文件被整体搬到 Windows.old/，
 * 这是被盗电脑重装后最重要的数据来源之一，不能因为路径里包含 /Windows/ 就被误杀。
 */
export function isSystemFile(file) {
  if (!file) return false;
  const path = String(file.originalPath || "").toLowerCase().replace(/\\/g, "/");

  // Windows.old 是"旧系统备份"，里面的 Users/ 是原主人的数据，绝对不能当系统文件
  if (path.includes("windows.old/")) return false;

  const ext = String(file.extension || "").toLowerCase();
  if (SYSTEM_FILE_EXTENSIONS.has(ext)) return true;

  for (const prefix of SYSTEM_PATH_PREFIXES) {
    if (path.startsWith(prefix) || path.includes("/" + prefix)) return true;
  }
  return false;
}

/**
 * isHighPriorityRecovery 标记一条文件是否值得在 UI 里高亮 ——
 * 目前的判定：位于 Windows.old/Users/ 或 /Users/ 子树下的个人数据。
 * 这些文件是被盗电脑重装后最可能是用户真实数据的候选，优先推荐给用户挑选。
 */
export function isHighPriorityRecovery(file) {
  if (!file) return false;
  const path = String(file.originalPath || "").toLowerCase().replace(/\\/g, "/");
  if (path.includes("windows.old/")) return true;
  if (path.startsWith("users/") || path.includes("/users/")) return true;
  return false;
}

/** countHighPriority 统计值得优先关注的文件数量。 */
export function countHighPriority(files) {
  if (!files || files.length === 0) return 0;
  let n = 0;
  for (let i = 0; i < files.length; i++) {
    if (isHighPriorityRecovery(files[i])) n++;
  }
  return n;
}

/**
 * confidenceTier 把后端给的 0-1 浮点 confidence 映射成用户能读懂的 4 档徽章：
 *   high    高可靠 —— validator 打分 >= 0.85，基本可以直接开
 *   medium  可能可靠 —— >= 0.6，格式解析通过但边界不清
 *   partial 部分损坏 —— >= 0.3，能看出类型但不保证完整
 *   low     低可靠 —— 剩下的，很可能开不了
 *
 * 注意：这是 *扫描阶段* 的分档。恢复完成后 engine.go 有一个更精准的 5 档
 * （高可靠 / 低可靠 / 部分 / 拒绝 / 失败），那个看的是 validator 真解码
 * + DataRun 完整性结果。本函数是 UI 扫描态预览，只看 confidence 数字。
 */
export function confidenceTier(file) {
  const c = Number(file?.confidence || 0);
  if (file?.isValid === false) return { key: "low", label: "低可靠", color: "#9ca3af" };
  if (c >= 0.85) return { key: "high", label: "高可靠", color: "#16a34a" };
  if (c >= 0.6) return { key: "medium", label: "可能可靠", color: "#ca8a04" };
  if (c >= 0.3) return { key: "partial", label: "部分", color: "#ea580c" };
  return { key: "low", label: "低可靠", color: "#9ca3af" };
}

/**
 * bucketFiles 把扁平文件列表分到 6 个"用户视角"的桶里，每条文件只落进第一个
 * 命中的桶（按优先级），避免 UI 上一条文件出现两次让总数对不上。
 *
 * 优先级（自上而下，越往下越兜底）：
 *   1. windowsOld  —— Windows.old 子树（旧系统备份里的用户数据，最有价值）
 *   2. desktop     —— 桌面（用户"第一现场"数据）
 *   3. photos      —— Category=image（照片 / 壁纸 / 扫描件）
 *   4. documents   —— Category=document（论文、财务、合同）
 *   5. recent      —— 30 天内修改过（不在上面任何桶的新文件）
 *   6. other       —— 兜底（视频 / 音频 / 压缩包 / 数据库 / 其他）
 *
 * 系统文件按 isSystemFile 规则直接排除（不会进任何桶）—— 用户在高级模式
 * 勾选"显示系统文件"才看得到它们。
 */
const RECENT_MODIFIED_WINDOW_MS = 30 * 24 * 60 * 60 * 1000; // 30 天

export const BUCKETS = [
  { key: "windowsOld",  label: "Windows.old 里的文件", desc: "旧系统备份里保留的用户数据 —— 这里面最可能是你真正要找的东西",     priority: 1 },
  { key: "desktop",     label: "桌面上的文件",          desc: "扫描到的桌面路径文件，通常是你最近在用的东西",                      priority: 2 },
  { key: "photos",      label: "我的照片",              desc: "扫描到的图片文件，按置信度排序",                                     priority: 3 },
  { key: "documents",   label: "我的文档",              desc: "PDF / Word / Excel / PPT / 文本",                                   priority: 4 },
  { key: "recent",      label: "最近修改过的文件",      desc: "过去 30 天内改过的文件，排除了上面已经分好的类",                    priority: 5 },
  { key: "other",       label: "其他文件",              desc: "视频 / 音频 / 压缩包 / 数据库 / 其他杂项",                          priority: 6 },
];

function bucketOf(file, nowMs) {
  if (!file) return null;
  if (isSystemFile(file)) return null; // 系统文件不进任何桶

  const path = String(file.originalPath || "").toLowerCase().replace(/\\/g, "/");
  if (path.includes("windows.old/")) return "windowsOld";
  if (path.includes("/desktop/") || path.startsWith("desktop/")) return "desktop";

  const cat = String(file.category || "").toLowerCase();
  if (cat === "image") return "photos";
  if (cat === "document") return "documents";

  const mt = file.modifiedTime ? Date.parse(file.modifiedTime) : NaN;
  if (Number.isFinite(mt) && nowMs - mt <= RECENT_MODIFIED_WINDOW_MS) return "recent";

  return "other";
}

/**
 * bucketFiles 返回 { windowsOld: [...], desktop: [...], ... }，每个桶按
 * recoveryScore 降序排列（高可靠 + 高优先级靠前），便于卡片展示 Top N。
 */
export function bucketFiles(files) {
  const result = { windowsOld: [], desktop: [], photos: [], documents: [], recent: [], other: [] };
  if (!files || files.length === 0) return result;
  const now = Date.now();
  for (let i = 0; i < files.length; i++) {
    const b = bucketOf(files[i], now);
    if (b) result[b].push(files[i]);
  }
  // 每桶按 recoveryScore 降序（大致等同于置信度高的在前）
  for (const key of Object.keys(result)) {
    result[key].sort((a, b) => recoveryScore(b) - recoveryScore(a));
  }
  return result;
}

/** bucketCounts 数一下每个桶多大，避免每次渲染都遍历全量再 .length。 */
export function bucketCounts(bucketed) {
  const out = {};
  for (const key of Object.keys(bucketed || {})) {
    out[key] = (bucketed[key] || []).length;
  }
  return out;
}

export function buildFallbackScanResult(
  files: any[] = [],
  progress: { bytesScanned?: number } = {},
) {
  const stats: Record<string, number> = {};

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
      // 含 ":" 用高级语法（size:>100MB type:image deleted:yes path:/Users）
      if (keyword.indexOf(":") >= 0) {
        const pred = parseAdvancedQuery(keyword);
        if (!pred(f)) continue;
      } else {
        const name = (f.fileName || "").toLowerCase();
        const path = (f.originalPath || "").toLowerCase();
        if (!name.includes(keyword) && !path.includes(keyword)) continue;
      }
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
