import React, { useEffect, useMemo, useState } from "react";
import { formatSize, formatConfidence, formatPath } from "../formatters";
import { getCategoryMeta, getSourceMeta, isHighPriorityRecovery } from "../recovery-helpers";
import { IconEye, IconForCategory, IconSearch, IconX } from "../icons";

/**
 * FileTable — 大列表展示 + 行选中。
 *
 * 为什么不用 react-window/虚拟滚动：
 * 当前用分页（默认 200 / 页 + 跳页输入）已经能覆盖 10 万级文件，
 * 切页延迟 < 50ms，心智负担明显低于虚拟滚动的边界 bug。
 *
 * 所有交互都向上冒泡：选中改变、跳页等都由父组件维护状态。
 */
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

  const totalPages = Math.max(1, Math.ceil(sorted.length / pageSize));
  const safePage = Math.min(page, totalPages);
  const pageSlice = useMemo(
    () => sorted.slice((safePage - 1) * pageSize, safePage * pageSize),
    [sorted, safePage, pageSize],
  );

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

      <div className="file-table-scroll">
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
            {pageSlice.map((f) => (
              <Row
                key={f.id}
                file={f}
                selected={selectedIds.has(f.id)}
                onToggle={onToggle}
                onPreview={onRequestPreview ? () => setPreviewFile(f) : null}
              />
            ))}
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

      {sorted.length > pageSize && (
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
  const confidence = formatConfidence(file.confidence);
  const confClass =
    confidence >= 70 ? "confidence-bar--high" : confidence >= 40 ? "confidence-bar--mid" : "confidence-bar--low";
  const categoryMeta = getCategoryMeta(file.category);
  const sourceMeta = getSourceMeta(file.source);
  const canPreview = onPreview && file.category === "image";

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
        <span className={`confidence-bar ${confClass}`}>
          <span className="confidence-bar__track">
            <span className="confidence-bar__fill" style={{ width: `${confidence}%` }} />
          </span>
          {confidence}%
        </span>
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
          {state.url && (
            <img src={state.url} alt={file.fileName} className="preview-modal__image" />
          )}
        </div>
        <div className="preview-modal__footer muted" style={{ fontSize: 11 }}>
          {formatSize(file.size)} · 偏移 0x{Number(file.offset || 0).toString(16)} ·
          {" "}只预览前若干字节，不代表完整解码；完整恢复后用系统图片程序打开更可靠。
        </div>
      </div>
    </div>
  );
}

function Th({ k, sk, sd, onClick, children, align }) {
  const active = sk === k;
  return (
    <th
      className="sortable"
      onClick={() => onClick(k)}
      style={align === "right" ? { textAlign: "right" } : undefined}
      title="点击列头切换排序"
    >
      {children}
      {active && <span className="muted" style={{ marginLeft: 4 }}>{sd === "asc" ? "↑" : "↓"}</span>}
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
