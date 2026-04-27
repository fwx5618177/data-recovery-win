// 轻量 i18n：不拉第三方库（react-i18next / lingui 等），避免 200KB bundle 膨胀。
// 需求：支持中/英切换 + 插值 + 在 JSX 内直接调用。用不到的变更/复数/命名空间都不做。
//
// 使用：
//   import { t, setLocale } from "./i18n";
//   t("welcome.title")            // 读当前 locale 文案
//   t("found.count", { n: 42 })   // 插值：文案里写 "{{n}} 个文件"
//   setLocale("en")               // 切语言；触发订阅者重渲染

const dict = {
  zh: {
    "app.title": "数据恢复大师",
    "welcome.title": "先选择要恢复的源盘",
    "welcome.subtitle":
      "建议把被重置/格式化的磁盘通过硬盘盒外接过来。扫描过程只读，不写入源盘。",
    "welcome.startScan": "开始扫描",
    "welcome.refresh": "刷新",
    "welcome.needAdmin": "需要管理员 / root 权限",
    "welcome.selectImage": "选择镜像文件…",
    "scan.stop": "停止扫描",
    "scan.changeDrive": "换一块盘",
    "scan.phase.ntfs": "NTFS MFT 扫描中",
    "scan.phase.carving": "深度扫描中",
    "scan.phase.validating": "验证结果中",
    "scan.phase.default": "扫描中",
    "scan.phase.complete": "扫描完成",
    "bitlocker.unlockAndScan": "解锁并扫描",
    "bitlocker.deriving": "正在从 recovery key 派生卷主密钥（1M 次 SHA-256）",
    "bitlocker.unlocked": "BitLocker 已解锁",
    "recovery.start": "立即恢复",
    "recovery.stop": "停止恢复",
    "recovery.retry": "重试失败文件",
    "recovery.back": "返回工作台",
    "diag.export": "导出诊断包",
    "diag.done": "诊断包已保存到：{{path}}",
    "common.cancel": "取消",
    "common.confirm": "确认",
    "common.found": "已发现",
    "common.highPriority": "高优先级",
    // Workbench
    "wb.source": "源盘",
    "wb.elapsed": "已用",
    "wb.eta": "剩余",
    "wb.speed": "速度",
    "wb.discovered": "已发现",
    "wb.filter.placeholder": "按文件名 / 路径关键字过滤…",
    "wb.filter.category": "类型",
    "wb.filter.source": "来源",
    "wb.filter.validity": "有效性",
    "wb.filter.all": "全部",
    "wb.filter.valid": "有效",
    "wb.filter.invalid": "无效",
    "wb.filter.hideSystem": "隐藏系统文件 (.exe/.dll/.ico)",
    "wb.selected": "已选 {{n}} 个文件，约 {{size}}",
    "wb.outputDir": "输出目录",
    "wb.outputDir.pick": "选择…",
    "wb.outputDir.free": "剩余 {{free}}",
    "wb.preview": "预览",
    // Recovery
    "rec.completed": "恢复完成",
    "rec.success": "成功",
    "rec.partial": "部分成功",
    "rec.failed": "失败",
    "rec.duplicates": "去重",
    "rec.openFolder": "打开文件夹",
    "rec.exportReport": "导出 CSV 报告",
    "rec.newScan": "重新扫描",
  },
  en: {
    "app.title": "Data Recovery",
    "welcome.title": "Pick a source drive to recover from",
    "welcome.subtitle":
      "Recommended: connect the reset/formatted disk through an external enclosure. Scans are read-only.",
    "welcome.startScan": "Start scan",
    "welcome.refresh": "Refresh",
    "welcome.needAdmin": "Administrator / root privileges required",
    "welcome.selectImage": "Select image file…",
    "scan.stop": "Stop scan",
    "scan.changeDrive": "Change drive",
    "scan.phase.ntfs": "Scanning NTFS MFT",
    "scan.phase.carving": "Deep scan (carving)",
    "scan.phase.validating": "Validating results",
    "scan.phase.default": "Scanning",
    "scan.phase.complete": "Scan complete",
    "bitlocker.unlockAndScan": "Unlock & scan",
    "bitlocker.deriving":
      "Deriving the Volume Master Key from your recovery key (1M SHA-256 iterations)",
    "bitlocker.unlocked": "BitLocker unlocked",
    "recovery.start": "Recover now",
    "recovery.stop": "Stop recovery",
    "recovery.retry": "Retry failed files",
    "recovery.back": "Back to workbench",
    "diag.export": "Export diagnostic bundle",
    "diag.done": "Bundle saved to: {{path}}",
    "common.cancel": "Cancel",
    "common.confirm": "Confirm",
    "common.found": "Found",
    "common.highPriority": "High priority",
    // Workbench
    "wb.source": "Source",
    "wb.elapsed": "Elapsed",
    "wb.eta": "ETA",
    "wb.speed": "Speed",
    "wb.discovered": "discovered",
    "wb.filter.placeholder": "Filter by name / path keyword…",
    "wb.filter.category": "Category",
    "wb.filter.source": "Source",
    "wb.filter.validity": "Validity",
    "wb.filter.all": "All",
    "wb.filter.valid": "Valid",
    "wb.filter.invalid": "Invalid",
    "wb.filter.hideSystem": "Hide system files (.exe/.dll/.ico)",
    "wb.selected": "Selected {{n}} files, ~{{size}}",
    "wb.outputDir": "Output directory",
    "wb.outputDir.pick": "Pick…",
    "wb.outputDir.free": "Free: {{free}}",
    "wb.preview": "Preview",
    // Recovery
    "rec.completed": "Recovery complete",
    "rec.success": "Succeeded",
    "rec.partial": "Partial",
    "rec.failed": "Failed",
    "rec.duplicates": "Deduplicated",
    "rec.openFolder": "Open folder",
    "rec.exportReport": "Export CSV report",
    "rec.newScan": "Scan another drive",
  },
};

const STORAGE_KEY = "data-recovery.locale";

function detectDefault() {
  try {
    const saved = globalThis.localStorage?.getItem(STORAGE_KEY);
    if (saved && dict[saved]) return saved;
  } catch {/* no-op */}
  // 浏览器语言优先匹配
  const nav = globalThis.navigator?.language || "zh";
  if (nav.toLowerCase().startsWith("zh")) return "zh";
  return "en";
}

let locale = detectDefault();
type LocaleListener = (locale: string) => void;
const listeners = new Set<LocaleListener>();

export function getLocale() {
  return locale;
}

export function setLocale(next) {
  if (!dict[next] || next === locale) return;
  locale = next;
  try { globalThis.localStorage?.setItem(STORAGE_KEY, next); } catch {/* no-op */}
  listeners.forEach((fn) => {
    try { fn(locale); } catch {/* no-op */}
  });
}

export function onLocaleChange(fn: LocaleListener): () => void {
  listeners.add(fn);
  // 包成 () => void 让 React useEffect cleanup 兼容（listeners.delete 返回 boolean 会让 TS 报错）
  return () => {
    listeners.delete(fn);
  };
}

/**
 * t(key, vars?) — 取当前 locale 下的文案，再用 vars 插值。
 * 未命中 key 时返回 key 本身，便于开发期快速发现漏翻。
 */
export function t(key: string, vars?: Record<string, string | number>): string {
  const table = (dict as Record<string, Record<string, string>>)[locale] || dict.zh;
  let s = table[key];
  if (s === undefined) {
    // 回落到 zh
    s = (dict.zh as Record<string, string>)[key] ?? key;
  }
  if (vars) {
    for (const [k, v] of Object.entries(vars)) {
      s = s.replace(new RegExp(`\\{\\{${k}\\}\\}`, "g"), String(v));
    }
  }
  return s;
}

export const AVAILABLE_LOCALES = Object.keys(dict);
