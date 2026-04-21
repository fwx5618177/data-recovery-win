import React, { useEffect, useMemo, useState } from "react";
import FileTable from "./FileTable";
import {
  IconAlertTriangle,
  IconCheckCircle,
  IconDownload,
  IconFolderOpen,
  IconPlay,
  IconRefresh,
  IconStop,
} from "../icons";
import {
  filterFiles,
  countByCategory,
  countBySource,
  countSystemFiles,
  countHighPriority,
  isSystemFile,
  getCategoryMeta,
  getSourceMeta,
  getDriveLabel,
  sufficiencyOf,
} from "../recovery-helpers";
import { formatSize, formatDuration, formatSpeed, clampPercent } from "../formatters";
import { t, onLocaleChange } from "../i18n";

const CATEGORY_KEYS = ["image", "document", "video", "audio", "archive", "database", "other"];
const SOURCE_KEYS = ["ntfs", "carver"];

/**
 * Workbench —— 合并后的"扫描 + 筛选 + 选中 + 立即恢复"单页工作台。
 *
 * 左栏筛选器、中间文件表、下方输出目录 + 恢复按钮、顶栏实时进度。
 * 扫描期间所有筛选/选择都即时可用，不必等扫描结束。
 */
export default function Workbench({
  selectedDrive,
  scanActive,
  scanProgress,
  bitlockerState,
  files,
  outputDir,
  outputValidation,
  outputFreeSpace,
  onStopScan,
  onStartRecovery,
  onSelectOutputDir,
  onBackToWelcome,
  onRequestPreview,
}) {
  // 订阅 locale 变化让 t() 调用结果重新渲染
  const [, setLocaleVersion] = useState(0);
  useEffect(() => onLocaleChange(() => setLocaleVersion((v) => v + 1)), []);

  const [keyword, setKeyword] = useState("");
  const [categories, setCategories] = useState(() => new Set()); // 空集合表示"不过滤"
  const [sources, setSources] = useState(() => new Set());
  const [validity, setValidity] = useState("all");
  const [selectedIds, setSelectedIds] = useState(() => new Set());
  const [allowSameDisk, setAllowSameDisk] = useState(false);
  // 默认隐藏系统文件（.exe/.dll/.ico/.sys 等 + /Windows 子树），让真正的照片文档浮上来
  const [hideSystemFiles, setHideSystemFiles] = useState(true);

  // outputDir 或 outputValidation 变化时重置"我已了解风险"开关，避免旧盘留的勾延用到新盘
  useEffect(() => { setAllowSameDisk(false); }, [outputDir]);

  // 同盘错误信号：看 outputValidation 文案里是否命中"同一块…磁盘"关键字
  const isSameDiskBlock = /同一块.*磁盘|源盘所在/.test(outputValidation || "");

  // 当文件列表急剧变化时（大规模扫描），避免 selectedIds 里保留已经消失的 id
  useEffect(() => {
    if (selectedIds.size === 0) return;
    const present = new Set(files.map((f) => f.id));
    let dirty = false;
    const next = new Set();
    selectedIds.forEach((id) => {
      if (present.has(id)) next.add(id);
      else dirty = true;
    });
    if (dirty) setSelectedIds(next);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [files]);

  const filter = useMemo(
    () => ({ keyword, categories, sources, validity, hideSystemFiles }),
    [keyword, categories, sources, validity, hideSystemFiles],
  );
  const filtered = useMemo(() => filterFiles(files, filter), [files, filter]);

  // 分类/来源的计数跟随 hideSystemFiles 一起过滤——避免出现"侧栏说有 500 张图片，
  // 但表里只看到 20 张"的困惑（ICO 计入图片分类的常见误解）
  const baseForCounts = useMemo(
    () => (hideSystemFiles ? files.filter((f) => !isSystemFile(f)) : files),
    [files, hideSystemFiles],
  );
  const catCounts = useMemo(() => countByCategory(baseForCounts), [baseForCounts]);
  const srcCounts = useMemo(() => countBySource(baseForCounts), [baseForCounts]);
  const systemFileCount = useMemo(() => countSystemFiles(files), [files]);
  const highPriorityCount = useMemo(() => countHighPriority(files), [files]);

  const selectedFiles = useMemo(
    () => files.filter((f) => selectedIds.has(f.id)),
    [files, selectedIds],
  );
  const selectedSize = useMemo(
    () => selectedFiles.reduce((sum, f) => sum + (f.size || 0), 0),
    [selectedFiles],
  );

  const toggleCategory = (key) => {
    setCategories((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key); else next.add(key);
      return next;
    });
  };
  const toggleSource = (key) => {
    setSources((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key); else next.add(key);
      return next;
    });
  };
  const toggleFile = (file) => {
    setSelectedIds((prev) => {
      const next = new Set(prev);
      if (next.has(file.id)) next.delete(file.id); else next.add(file.id);
      return next;
    });
  };
  const toggleAllPage = (pageFiles, selectAll) => {
    setSelectedIds((prev) => {
      const next = new Set(prev);
      if (selectAll) {
        pageFiles.forEach((f) => next.add(f.id));
      } else {
        pageFiles.forEach((f) => next.delete(f.id));
      }
      return next;
    });
  };
  const selectAllValidVisible = () => {
    setSelectedIds((prev) => {
      const next = new Set(prev);
      filtered.forEach((f) => { if (f.isValid !== false) next.add(f.id); });
      return next;
    });
  };
  const clearSelection = () => setSelectedIds(new Set());

  // 能否恢复：要有选文件、要有输出目录；校验通过 OR（同盘警告 + 用户已知情勾选）
  const canRecover =
    selectedIds.size > 0 &&
    !!outputDir &&
    (!outputValidation || (isSameDiskBlock && allowSameDisk));

  const sufficiency = outputFreeSpace
    ? sufficiencyOf(selectedSize, outputFreeSpace.available)
    : "unknown";

  const percent = clampPercent(scanProgress?.percent || 0);
  const phaseLabel = phaseText(scanProgress?.phase, scanActive);

  return (
    <div className="workbench">
      {/* 顶部进度条 ---------------------------------------------------- */}
      <div className="workbench__progress">
        <div className="progress-strip">
          <div className="progress-strip__top">
            <div className="progress-strip__phase">
              {scanActive ? <IconPlay size={16} className="muted" /> : <IconCheckCircle size={16} style={{ color: "var(--success)" }} />}
              <span className="progress-strip__phase-label">{phaseLabel}</span>
              <span className="muted" style={{ fontSize: 12 }}>
                {t("wb.source")}：<span className="mono">{getDriveLabel(selectedDrive)}</span>
              </span>
            </div>
            <div className="progress-strip__stats">
              <span className="progress-strip__stat"><b>{files.length.toLocaleString()}</b> {t("common.found")}</span>
              {highPriorityCount > 0 && (
                <span
                  className="progress-strip__stat"
                  style={{ color: "var(--success)" }}
                  title="Windows.old / Users — likely the original owner's personal data"
                >
                  <b>{highPriorityCount.toLocaleString()}</b> {t("common.highPriority")}
                </span>
              )}
              <span className="progress-strip__stat"><b>{formatSize(scanProgress?.bytesScanned || 0)}</b> / {formatSize(scanProgress?.totalBytes || 0)}</span>
              <span className="progress-strip__stat">{t("wb.speed")}: <b>{formatSpeed(scanProgress?.speed || 0)}</b></span>
              {scanActive && <span className="progress-strip__stat">{t("wb.eta")} <b>{formatDuration(scanProgress?.eta)}</b></span>}
            </div>
            <div className="btn-group">
              {scanActive ? (
                <button className="btn btn--danger btn--sm" onClick={onStopScan}>
                  <IconStop size={14} /> {t("scan.stop")}
                </button>
              ) : (
                <button className="btn btn--ghost btn--sm" onClick={onBackToWelcome}>
                  <IconRefresh size={14} /> {t("scan.changeDrive")}
                </button>
              )}
            </div>
          </div>
          <div className={scanActive && percent === 0 ? "progress progress--indeterminate" : "progress"}>
            <div className="progress__fill" style={{ width: `${percent}%` }} />
          </div>
          {scanProgress?.currentFile && (
            <div className="muted mono" style={{ fontSize: 11, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>
              {scanProgress.currentFile}
            </div>
          )}
          {bitlockerState && bitlockerState.phase === "deriving" && (
            <div
              style={{
                marginTop: 6,
                padding: "6px 10px",
                fontSize: 12,
                borderRadius: "var(--radius-md)",
                background: "var(--accent-soft)",
                border: "1px solid var(--border-strong)",
              }}
            >
              🔑 BitLocker 正在从 recovery key 派生卷主密钥（1M 次 SHA-256）：
              {" "}
              <b>
                {Math.round((bitlockerState.done || 0) / Math.max(1, bitlockerState.total || 1048576) * 100)}%
              </b>
              {" — 派生完成后会自动进入 NTFS 扫描。"}
            </div>
          )}
          {bitlockerState && bitlockerState.phase === "unlocked" && (
            <div
              style={{
                marginTop: 6,
                padding: "6px 10px",
                fontSize: 12,
                borderRadius: "var(--radius-md)",
                background: "var(--success-soft, var(--accent-soft))",
                border: "1px solid var(--border-strong)",
              }}
            >
              ✅ BitLocker 已解锁
              {bitlockerState.info?.encryptionMethod ? ` · 加密方法 ${bitlockerState.info.encryptionMethod}` : ""}
              {" —— 解密在内存中透明完成，源盘和密钥均未落盘。"}
            </div>
          )}
          {systemFileCount > 0 && (
            <div
              className="system-file-banner"
              style={{
                marginTop: 6,
                padding: "6px 10px",
                fontSize: 12,
                borderRadius: "var(--radius-md)",
                background: hideSystemFiles ? "var(--accent-soft)" : "var(--warning-soft)",
                border: "1px solid " + (hideSystemFiles ? "var(--accent-border, var(--border-strong))" : "var(--warning-border)"),
                display: "flex",
                alignItems: "center",
                gap: 8,
                flexWrap: "wrap",
              }}
            >
              {hideSystemFiles ? (
                <>
                  <span>
                    已隐藏 <b>{systemFileCount.toLocaleString()}</b> 个系统文件
                    （<span className="mono">.exe / .dll / .ico / .sys</span> 以及
                    <span className="mono"> Windows/ / Program Files</span> 子目录下的内容）
                  </span>
                  <button className="btn btn--sm btn--ghost" onClick={() => setHideSystemFiles(false)}>
                    显示全部
                  </button>
                </>
              ) : (
                <>
                  <IconAlertTriangle size={14} />
                  <span>
                    当前显示全部文件，其中 <b>{systemFileCount.toLocaleString()}</b> 个是系统文件。
                    被重置的 Windows 盘 MFT 里积累了大量旧系统残留，通常不是你想要的个人数据。
                  </span>
                  <button className="btn btn--sm" onClick={() => setHideSystemFiles(true)}>
                    只看我的文件
                  </button>
                </>
              )}
            </div>
          )}
        </div>
      </div>

      {/* 左侧过滤器 -------------------------------------------------- */}
      <aside className="workbench__sidebar">
        <div className="filter-panel">
          <div className="filter-group">
            <div className="filter-group__title">分类</div>
            <div className="filter-row" onClick={() => setCategories(new Set())}>
              <span>全部</span>
              <span className="filter-row__count">{files.length.toLocaleString()}</span>
            </div>
            {CATEGORY_KEYS.map((key) => {
              const meta = getCategoryMeta(key);
              const count = catCounts[key] || 0;
              if (count === 0 && !categories.has(key)) return null;
              const active = categories.has(key);
              return (
                <label key={key} className="filter-row" style={active ? { background: "var(--accent-soft)" } : undefined}>
                  <span className="checkbox">
                    <input type="checkbox" checked={active} onChange={() => toggleCategory(key)} />
                    <span>{meta.label}</span>
                  </span>
                  <span className="filter-row__count">{count.toLocaleString()}</span>
                </label>
              );
            })}
          </div>

          <div className="filter-group">
            <div className="filter-group__title">来源</div>
            {SOURCE_KEYS.map((key) => {
              const count = srcCounts[key] || 0;
              if (count === 0 && !sources.has(key)) return null;
              const meta = getSourceMeta(key);
              const active = sources.has(key);
              return (
                <label key={key} className="filter-row" style={active ? { background: "var(--accent-soft)" } : undefined}>
                  <span className="checkbox">
                    <input type="checkbox" checked={active} onChange={() => toggleSource(key)} />
                    <span>{meta.label}</span>
                  </span>
                  <span className="filter-row__count">{count.toLocaleString()}</span>
                </label>
              );
            })}
          </div>

          <div className="filter-group">
            <div className="filter-group__title">完整性</div>
            {[
              { v: "all", label: "全部" },
              { v: "valid", label: "仅有效" },
              { v: "invalid", label: "仅可疑" },
            ].map((opt) => (
              <label key={opt.v} className="filter-row" style={validity === opt.v ? { background: "var(--accent-soft)" } : undefined}>
                <span className="checkbox">
                  <input type="radio" name="validity" checked={validity === opt.v} onChange={() => setValidity(opt.v)} />
                  <span>{opt.label}</span>
                </span>
              </label>
            ))}
          </div>

          <div className="filter-group">
            <div className="filter-group__title">系统文件</div>
            <label className="filter-row" title=".exe / .dll / .ico / .sys 以及 /Windows、/Program Files 子树下的文件">
              <span className="checkbox">
                <input
                  type="checkbox"
                  checked={hideSystemFiles}
                  onChange={() => setHideSystemFiles((v) => !v)}
                />
                <span>隐藏系统文件</span>
              </span>
              {systemFileCount > 0 && (
                <span className="filter-row__count">{systemFileCount.toLocaleString()}</span>
              )}
            </label>
            <div className="muted" style={{ fontSize: 11, padding: "0 8px 4px", lineHeight: 1.5 }}>
              重置前旧系统的 .exe / .dll 等会大量出现在 MFT 里，
              默认隐藏它们让真正的照片文档浮上来。需要恢复系统文件时取消勾选。
            </div>
          </div>

          <div className="filter-group">
            <div className="filter-group__title">批量选择</div>
            <button className="btn btn--sm" onClick={selectAllValidVisible}>
              选中当前筛选中的有效文件
            </button>
            <button className="btn btn--sm btn--ghost" onClick={clearSelection} disabled={selectedIds.size === 0}>
              清空选择
            </button>
          </div>
        </div>
      </aside>

      {/* 文件表 ------------------------------------------------------ */}
      <section className="workbench__files">
        <FileTable
          files={filtered}
          selectedIds={selectedIds}
          onToggle={toggleFile}
          onToggleAll={toggleAllPage}
          keyword={keyword}
          onKeywordChange={setKeyword}
          onRequestPreview={onRequestPreview}
          headerRight={
            <div className="btn-group">
              <button
                className="btn btn--sm"
                data-shortcut="select-all-visible"
                onClick={selectAllValidVisible}
                disabled={filtered.length === 0}
                title="Ctrl/Cmd+A"
              >
                全选有效
              </button>
              <button className="btn btn--sm btn--ghost" onClick={clearSelection} disabled={selectedIds.size === 0}>
                清空
              </button>
            </div>
          }
        />
      </section>

      {/* 底部操作条 -------------------------------------------------- */}
      <footer className="workbench__footer">
        <div className="selection-summary">
          <strong>{selectedIds.size.toLocaleString()} 个文件</strong>
          <span>约 {formatSize(selectedSize)}</span>
        </div>

        <div className="output-picker">
          <button className="btn" onClick={onSelectOutputDir}>
            <IconFolderOpen size={14} />
            {outputDir ? "更换输出目录" : "选择输出目录"}
          </button>
          <div
            className={
              outputDir
                ? outputValidation
                  ? "output-picker__value output-picker__value--err"
                  : "output-picker__value output-picker__value--ok"
                : "output-picker__value"
            }
            title={outputDir || "尚未选择"}
          >
            {outputDir || "尚未选择（必须选到 另一块 盘，避免覆盖源数据）"}
          </div>
        </div>

        <button
          className="btn btn--primary btn--lg"
          onClick={() => onStartRecovery?.(Array.from(selectedIds), { allowSameDisk: isSameDiskBlock && allowSameDisk })}
          disabled={!canRecover}
        >
          <IconDownload size={16} />
          开始恢复 {selectedIds.size > 0 ? `(${selectedIds.size})` : ""}
        </button>

        {outputValidation && !isSameDiskBlock && (
          <div className="banner banner--danger" style={{ flexBasis: "100%" }}>
            <IconAlertTriangle size={16} className="banner__icon" />
            <div className="banner__content">
              <div className="banner__title">输出目录不可用</div>
              <div className="banner__text">{outputValidation}</div>
            </div>
          </div>
        )}
        {scanActive && canRecover && (
          <div className="banner banner--info" style={{ flexBasis: "100%" }}>
            <IconCheckCircle size={16} className="banner__icon" />
            <div className="banner__content">
              <div className="banner__title">扫描进行中也可以先恢复已找到的文件</div>
              <div className="banner__text">
                深度扫描可能持续十几分钟。对已勾选的文件可以立即点"开始恢复"，
                不必等扫描跑完。后续新发现的文件随时再加进选择。
              </div>
            </div>
          </div>
        )}
        {outputValidation && isSameDiskBlock && (
          <div className="banner banner--warning" style={{ flexBasis: "100%" }}>
            <IconAlertTriangle size={16} className="banner__icon" />
            <div className="banner__content">
              <div className="banner__title">恢复目录与源盘位于同一块物理磁盘</div>
              <div className="banner__text">
                数据恢复行业标准做法是<b>强烈建议</b>把输出目录放到另一块盘（外接 U 盘 / 移动硬盘 / 另一块内置盘）。
                写入源盘可能覆盖尚未恢复的数据。
                <br />
                如确实没有另一块盘可用，可以勾选下方选项继续——但本工具将对此结果不做数据完整性保证。
              </div>
              <label className="checkbox" style={{ marginTop: 8 }}>
                <input
                  type="checkbox"
                  checked={allowSameDisk}
                  onChange={(e) => setAllowSameDisk(e.target.checked)}
                />
                <span>我已了解风险，仍希望恢复到此目录</span>
              </label>
            </div>
          </div>
        )}
        {!outputValidation && outputDir && sufficiency === "short" && (
          <div className="banner banner--danger" style={{ flexBasis: "100%" }}>
            <IconAlertTriangle size={16} className="banner__icon" />
            <div className="banner__content">
              <div className="banner__title">目标盘空间不足</div>
              <div className="banner__text">
                本次选中约 {formatSize(selectedSize)}，目标盘剩余 {formatSize(outputFreeSpace?.available || 0)}。请更换存储空间更大的盘。
              </div>
            </div>
          </div>
        )}
        {!outputValidation && outputDir && sufficiency === "tight" && (
          <div className="banner banner--warning" style={{ flexBasis: "100%" }}>
            <IconAlertTriangle size={16} className="banner__icon" />
            <div className="banner__content">
              <div className="banner__title">空间较紧张</div>
              <div className="banner__text">
                本次选中约 {formatSize(selectedSize)}，目标盘剩余 {formatSize(outputFreeSpace?.available || 0)}。建议留 30% 余量。
              </div>
            </div>
          </div>
        )}
      </footer>
    </div>
  );
}

function phaseText(phase, active) {
  if (!active && (phase === "complete" || phase === "validating")) return t("scan.phase.complete");
  switch (phase) {
    case "ntfs": return t("scan.phase.ntfs");
    case "carving": return t("scan.phase.carving");
    case "validating": return t("scan.phase.validating");
  }
  return phaseTextLegacy(phase, active);
}

function phaseTextLegacy(phase, active) {
  if (!active) return "扫描已完成";
  switch (phase) {
    case "ntfs": return "NTFS MFT 扫描中";
    case "carving": return "深度扫描中";
    case "validating": return "文件完整性验证中";
    case "ready": return "即将开始";
    default: return "扫描中";
  }
}
