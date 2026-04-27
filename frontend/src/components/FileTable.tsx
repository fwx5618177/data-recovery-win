import React, { useEffect, useMemo, useState } from "react";
import { formatSize, formatPath } from "../formatters";
import { getCategoryMeta, getSourceMeta, isHighPriorityRecovery } from "../recovery-helpers";
import { IconEye, IconForCategory, IconSearch, IconX } from "../icons";
import ConfidenceBadge from "./ConfidenceBadge";

/**
 * FileTable — 大列表展示 + 行选中。
 *
 * 为什么不用 react-window/虚拟滚动：
 * 当前用分页（默认 200 / 页 + 跳页输入）已经能覆盖 10 万级文件，
 * 切页延迟 < 50ms，心智负担明显低于虚拟滚动的边界 bug。
 *
 * 所有交互都向上冒泡：选中改变、跳页等都由父组件维护状态。
 */
// 文件列表 > 此阈值时切到虚拟滚动（不分页，只 mount 视口内 row）。
// 阈值是经验值：低于 1000 时分页 UI 更易用；高于时分页翻页心智成本高 + 性能也开始吃紧。
const VIRTUAL_SCROLL_THRESHOLD = 1000;

// 单 row 高度（必须与 CSS 保持一致；虚拟滚动需要预先知道）
const ROW_HEIGHT = 36;

// 虚拟视口高度（容器固定高，超出滚动）
const VIEWPORT_HEIGHT = 600;

// 视口外的 overscan：上下各多 mount 这么多 row，避免快速滚动时白屏
const OVERSCAN = 8;

export default function FileTable({
  files,
  selectedIds,
  onToggle,
  onToggleAll,
  keyword,
  onKeywordChange,
  showSearch = true,
  headerRight = null,
  pageSize = 200,
  onRequestPreview,   // 新增：(file) => Promise<string | null>  返回 data URL；父组件注入
}) {
  const [sortKey, setSortKey] = useState("size");
  const [sortDir, setSortDir] = useState("desc"); // asc | desc
  const [page, setPage] = useState(1);
  const [scrollTop, setScrollTop] = useState(0);
  const [previewFile, setPreviewFile] = useState(null);

  const sorted = useMemo(() => {
    const arr = files.slice();
    arr.sort((a, b) => {
      const av = valueOf(a, sortKey);
      const bv = valueOf(b, sortKey);
      if (av < bv) return sortDir === "asc" ? -1 : 1;
      if (av > bv) return sortDir === "asc" ? 1 : -1;
      return 0;
    });
    return arr;
  }, [files, sortKey, sortDir]);

  // 选择模式：≤阈值用经典分页；超过用虚拟滚动
  const useVirtual = sorted.length > VIRTUAL_SCROLL_THRESHOLD;

  const totalPages = Math.max(1, Math.ceil(sorted.length / pageSize));
  const safePage = Math.min(page, totalPages);

  // 当前可见 slice：虚拟滚动 vs 分页
  const pageSlice = useMemo(() => {
    if (useVirtual) {
      const visibleCount = Math.ceil(VIEWPORT_HEIGHT / ROW_HEIGHT) + OVERSCAN * 2;
      const startIdx = Math.max(0, Math.floor(scrollTop / ROW_HEIGHT) - OVERSCAN);
      const endIdx = Math.min(sorted.length, startIdx + visibleCount);
      const slice = sorted.slice(startIdx, endIdx);
      slice._startIdx = startIdx;
      slice._endIdx = endIdx;
      return slice;
    }
    return sorted.slice((safePage - 1) * pageSize, safePage * pageSize);
  }, [useVirtual, scrollTop, sorted, safePage, pageSize]);

  // 切换全选指的是 "当前页全部"，避免误勾上万文件
  const pageAllSelected = pageSlice.length > 0 && pageSlice.every((f) => selectedIds.has(f.id));
  const pagePartSelected =
    pageSlice.some((f) => selectedIds.has(f.id)) && !pageAllSelected;

  function handleHeaderClick(key) {
    if (sortKey === key) {
      setSortDir((d) => (d === "asc" ? "desc" : "asc"));
    } else {
      setSortKey(key);
      setSortDir(key === "fileName" ? "asc" : "desc");
    }
  }

  return (
    <div className="file-table-wrap">
      <div className="file-table-toolbar">
        <div className="file-table-toolbar__left">
          {showSearch && (
            <label className="file-table-search">
              <IconSearch size={14} />
              <input
                type="search"
                placeholder="搜索文件名或原路径…"
                value={keyword || ""}
                onChange={(e) => onKeywordChange?.(e.target.value)}
              />
            </label>
          )}
          <span className="muted" style={{ fontSize: 12 }}>
            {files.length.toLocaleString()} 个文件，已选 {selectedIds.size.toLocaleString()}
          </span>
        </div>
        {headerRight}
      </div>

      <div
        className="file-table-scroll"
        style={useVirtual ? { height: VIEWPORT_HEIGHT, overflow: "auto" } : undefined}
        onScroll={useVirtual ? (e) => setScrollTop(e.currentTarget.scrollTop) : undefined}
      >
        <table className="file-table">
          <thead>
            <tr>
              <th className="cell-check">
                <label className="checkbox" title="当前页全选 / 取消">
                  <input
                    type="checkbox"
                    checked={pageAllSelected}
                    ref={(el) => {
                      if (el) el.indeterminate = pagePartSelected;
                    }}
                    onChange={() => onToggleAll?.(pageSlice, !pageAllSelected)}
                  />
                </label>
              </th>
              <th>分类</th>
              <Th k="fileName" sk={sortKey} sd={sortDir} onClick={handleHeaderClick}>文件名</Th>
              <Th k="size" sk={sortKey} sd={sortDir} onClick={handleHeaderClick} align="right">大小</Th>
              <Th k="source" sk={sortKey} sd={sortDir} onClick={handleHeaderClick}>来源</Th>
              <Th k="confidence" sk={sortKey} sd={sortDir} onClick={handleHeaderClick}>置信度</Th>
              <th>原路径</th>
            </tr>
          </thead>
          <tbody>
            {/* 虚拟滚动：用空 row + 高度撑出滚动条总长度（startIdx * ROW_HEIGHT 像素） */}
            {useVirtual && pageSlice._startIdx > 0 && (
              <tr style={{ height: pageSlice._startIdx * ROW_HEIGHT }}><td colSpan={7} /></tr>
            )}
            {pageSlice.map((f) => (
              <Row
                key={f.id}
                file={f}
                selected={selectedIds.has(f.id)}
                onToggle={onToggle}
                onPreview={onRequestPreview ? () => setPreviewFile(f) : null}
              />
            ))}
            {useVirtual && pageSlice._endIdx < sorted.length && (
              <tr style={{ height: (sorted.length - pageSlice._endIdx) * ROW_HEIGHT }}><td colSpan={7} /></tr>
            )}
          </tbody>
        </table>

        {pageSlice.length === 0 && (
          <div className="empty-state" style={{ padding: "64px 24px" }}>
            <IconSearch size={44} className="empty-state__icon" />
            <div className="empty-state__title">没有匹配的文件</div>
            <div className="empty-state__text">
              调整左侧筛选条件或搜索关键字，也可以等扫描继续带来更多结果。
            </div>
          </div>
        )}
      </div>

      {previewFile && (
        <PreviewModal
          file={previewFile}
          onClose={() => setPreviewFile(null)}
          onRequestPreview={onRequestPreview}
        />
      )}

      {useVirtual && (
        <div className="muted" style={{ padding: "6px 12px", fontSize: 12 }}>
          {sorted.length.toLocaleString()} 项 · 虚拟滚动（10 万+ 文件不卡）·
          可见 {pageSlice._startIdx + 1}–{pageSlice._endIdx}
        </div>
      )}
      {!useVirtual && sorted.length > pageSize && (
        <div className="pagination">
          <span>
            第 {((safePage - 1) * pageSize + 1).toLocaleString()} –{" "}
            {Math.min(safePage * pageSize, sorted.length).toLocaleString()} 项 /
            共 {sorted.length.toLocaleString()} 项
          </span>
          <div className="pagination__nav">
            <button className="btn btn--sm btn--ghost" onClick={() => setPage(1)} disabled={safePage === 1}>首页</button>
            <button className="btn btn--sm btn--ghost" onClick={() => setPage((p) => Math.max(1, p - 1))} disabled={safePage === 1}>上一页</button>
            <span className="mono" style={{ fontSize: 12 }}>
              第&nbsp;
              <input
                type="number"
                min={1}
                max={totalPages}
                value={safePage}
                onChange={(e) => {
                  const v = Number(e.target.value);
                  if (Number.isFinite(v)) setPage(Math.max(1, Math.min(totalPages, v)));
                }}
              />
              &nbsp;/ {totalPages} 页
            </span>
            <button className="btn btn--sm btn--ghost" onClick={() => setPage((p) => Math.min(totalPages, p + 1))} disabled={safePage === totalPages}>下一页</button>
            <button className="btn btn--sm btn--ghost" onClick={() => setPage(totalPages)} disabled={safePage === totalPages}>末页</button>
          </div>
        </div>
      )}
    </div>
  );
}

function Row({ file, selected, onToggle, onPreview }) {
  const categoryMeta = getCategoryMeta(file.category);
  const sourceMeta = getSourceMeta(file.source);
  // 预览支持：image / document(pdf, txt) / video(前几秒) / archive(只列结构) — 多类型分发
  const canPreview = onPreview && previewableCategory(file);

  return (
    <tr
      className={selected ? "selected" : ""}
      onClick={(e) => {
        // 避免与 checkbox label 冲突
        if ((e.target instanceof HTMLElement) && e.target.closest(".cell-check")) return;
        if ((e.target instanceof HTMLElement) && e.target.closest(".cell-preview")) return;
        onToggle?.(file);
      }}
    >
      <td className="cell-check" onClick={(e) => e.stopPropagation()}>
        <label className="checkbox">
          <input type="checkbox" checked={selected} onChange={() => onToggle?.(file)} />
        </label>
      </td>
      <td>
        <span className="flex items-center gap-2 muted">
          <IconForCategory category={file.category} size={15} />
          <span style={{ fontSize: 12 }}>{categoryMeta.label}</span>
        </span>
      </td>
      <td className="file-name" title={file.fileName}>
        {isHighPriorityRecovery(file) && (
          <span
            className="badge badge--success"
            style={{ marginRight: 6, fontSize: 10, padding: "1px 6px" }}
            title="来自 Windows.old 或 Users/ 子树——最可能是原主人个人数据"
          >
            优先
          </span>
        )}
        {file.fileName}
        {canPreview && (
          <button
            type="button"
            className="btn btn--sm btn--ghost cell-preview"
            style={{ marginLeft: 8, padding: "2px 6px" }}
            title="预览图片（从源盘直接读取前若干字节）"
            onClick={(e) => { e.stopPropagation(); onPreview(); }}
          >
            <IconEye size={12} /> 预览
          </button>
        )}
      </td>
      <td className="cell-num">{formatSize(file.size)}</td>
      <td>
        <span className="badge">{sourceMeta.shortLabel}</span>
      </td>
      <td className="cell-confidence">
        <ConfidenceBadge file={file} />
      </td>
      <td className="file-path" title={formatPath(file)}>{formatPath(file)}</td>
    </tr>
  );
}

// PreviewModal 调用父组件注入的 onRequestPreview 拉取 data URL，成功后展示。
// 失败时展示明确提示而不是静默——源盘可能已被拔出/被写入覆盖，这些情况用户需要知道。
function PreviewModal({ file, onClose, onRequestPreview }) {
  const [state, setState] = useState({ loading: true, url: "", error: "" });

  useEffect(() => {
    let cancelled = false;
    setState({ loading: true, url: "", error: "" });
    (async () => {
      try {
        const url = await onRequestPreview(file);
        if (cancelled) return;
        if (!url) {
          setState({ loading: false, url: "", error: "无法获取预览数据" });
          return;
        }
        setState({ loading: false, url, error: "" });
      } catch (err) {
        if (cancelled) return;
        setState({ loading: false, url: "", error: String(err?.message || err) });
      }
    })();
    return () => { cancelled = true; };
  }, [file, onRequestPreview]);

  useEffect(() => {
    function onKey(e) { if (e.key === "Escape") onClose(); }
    globalThis.addEventListener("keydown", onKey);
    return () => globalThis.removeEventListener("keydown", onKey);
  }, [onClose]);

  return (
    <div
      className="preview-modal"
      onClick={onClose}
      role="dialog"
      aria-label={`预览 ${file.fileName}`}
    >
      <div className="preview-modal__inner" onClick={(e) => e.stopPropagation()}>
        <div className="preview-modal__header">
          <div className="preview-modal__title" title={file.fileName}>{file.fileName}</div>
          <button className="btn btn--sm btn--ghost" onClick={onClose} title="关闭 (Esc)">
            <IconX size={14} />
          </button>
        </div>
        <div className="preview-modal__body">
          {state.loading && <div className="muted">正在从源盘读取首批字节…</div>}
          {state.error && (
            <div className="banner banner--danger" style={{ margin: 0 }}>
              <div className="banner__content">
                <div className="banner__title">无法预览</div>
                <div className="banner__text">{state.error}</div>
              </div>
            </div>
          )}
          {state.url && renderPreviewByCategory(file, state.url)}
        </div>
        <div className="preview-modal__footer muted" style={{ fontSize: 11 }}>
          {formatSize(file.size)} · 偏移 0x{Number(file.offset || 0).toString(16)} ·
          {" "}只预览前若干字节，不代表完整解码；完整恢复后用系统图片程序打开更可靠。
        </div>
      </div>
    </div>
  );
}

interface ThProps {
  k: string;
  sk: string;
  sd: "asc" | "desc" | string;
  onClick: (key: string) => void;
  children: React.ReactNode;
  align?: "left" | "right" | "center";
}
function Th({ k, sk, sd, onClick, children, align }: ThProps) {
  const active = sk === k;
  return (
    <th
      className="sortable"
      onClick={() => onClick(k)}
      style={align === "right" ? { textAlign: "right" } : undefined}
      title="点击列头切换排序"
    >
      {children}
      {/* 激活列：明确 ↑/↓；其余列：默认浅色 ↕ 提示"可排序"（v2.7 加，之前没有任何指示） */}
      <span style={{ marginLeft: 4, fontSize: 9, opacity: active ? 1 : 0.35, color: active ? "var(--accent)" : "var(--text-subtle)" }}>
        {active ? (sd === "asc" ? "↑" : "↓") : "↕"}
      </span>
    </th>
  );
}

function valueOf(file, key) {
  switch (key) {
    case "fileName": return (file.fileName || "").toLowerCase();
    case "size": return Number(file.size || 0);
    case "source": return file.source || "";
    case "confidence": return Number(file.confidence || 0);
    default: return 0;
  }
}

/**
 * previewableCategory 判断文件是否可预览。
 * 之前只支持 image，现在扩展到 document(pdf/txt) / video / audio。
 */
function previewableCategory(file) {
  const cat = String(file.category || "").toLowerCase();
  if (cat === "image") return true;
  const ext = String(file.extension || "").toLowerCase();
  if (cat === "document" && (ext === "pdf" || ext === "txt" || ext === "md" || ext === "json" || ext === "log" || ext === "csv")) {
    return true;
  }
  if (cat === "video" && (ext === "mp4" || ext === "mov" || ext === "webm" || ext === "m4v")) {
    return true;
  }
  if (cat === "audio" && (ext === "mp3" || ext === "m4a" || ext === "wav" || ext === "ogg")) {
    return true;
  }
  return false;
}

/**
 * renderPreviewByCategory 按文件类型选择正确的 HTML5 元素。
 * 后端 ReadFilePreview 返回的是 data URL（前 N 字节 + 对应 mime）。
 *   - image → <img>
 *   - PDF / 视频 / 音频 → 浏览器原生 viewer
 *   - 文本 → 解码后 <pre>
 */
function renderPreviewByCategory(file, dataURL) {
  const cat = String(file.category || "").toLowerCase();
  const ext = String(file.extension || "").toLowerCase();

  if (cat === "image") {
    return <img src={dataURL} alt={file.fileName} className="preview-modal__image" />;
  }
  if (ext === "pdf") {
    // 浏览器内置 PDF.js（Chromium / Firefox / WebView2 都支持）
    return (
      <iframe
        src={dataURL}
        title={file.fileName}
        style={{ width: "100%", height: "70vh", border: 0 }}
      />
    );
  }
  if (cat === "video") {
    return (
      <video controls src={dataURL} style={{ maxWidth: "100%", maxHeight: "70vh" }}>
        浏览器不支持此视频格式
      </video>
    );
  }
  if (cat === "audio") {
    return <audio controls src={dataURL} style={{ width: "100%" }} />;
  }
  // 文本：从 data URL 抽出 base64 解码后展示
  if (cat === "document") {
    try {
      const m = String(dataURL).match(/^data:[^;]+;base64,(.*)$/);
      const b64 = m ? m[1] : "";
      const txt = b64ToText(b64);
      return (
        <pre style={{
          maxWidth: "100%", maxHeight: "70vh", overflow: "auto",
          fontSize: 12, lineHeight: 1.45,
          background: "var(--bg-2, #1d1d1d)", color: "var(--fg-1, #ddd)",
          padding: 12, margin: 0, borderRadius: 4,
        }}>{txt}</pre>
      );
    } catch (e) {
      return <div className="muted">无法解码为文本: {String(e?.message || e)}</div>;
    }
  }
  // 未知类型：兜底当图片试一次
  return <img src={dataURL} alt={file.fileName} className="preview-modal__image" />;
}

// b64ToText UTF-8 base64 → string
function b64ToText(b64) {
  const bin = globalThis.atob(b64);
  // 把字节用 TextDecoder 解 UTF-8（兼容中文）
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return new TextDecoder("utf-8", { fatal: false }).decode(bytes);
}
