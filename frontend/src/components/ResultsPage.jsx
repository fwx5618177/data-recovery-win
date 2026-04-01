import React, {
  startTransition,
  useDeferredValue,
  useEffect,
  useMemo,
  useState,
} from "react";
import { formatPath, formatSize } from "../formatters";
import {
  getCategoryMeta,
  getDriveLabel,
  getSourceMeta,
  recoveryScore,
} from "../recovery-helpers";
import "./ResultsPage.css";

const PAGE_SIZE = 80;
const CATEGORY_ORDER = [
  "all",
  "image",
  "document",
  "video",
  "audio",
  "archive",
  "database",
  "other",
];
const SORT_OPTIONS = [
  { value: "score-desc", label: "优先恢复重要文件" },
  { value: "size-desc", label: "先看大文件" },
  { value: "name-asc", label: "按文件名排序" },
  { value: "source-asc", label: "按来源排序" },
];
const HIGH_CONFIDENCE_THRESHOLD = 80;
const MEDIUM_CONFIDENCE_THRESHOLD = 60;

function getValidityLabel(file) {
  if (file?.isValid === true) {
    return "较可靠";
  }

  if (file?.isValid === false) {
    return file.validationMsg || "建议谨慎查看";
  }

  return "等待进一步判断";
}

function sumFileSizes(files) {
  return files.reduce((total, file) => total + (file?.size || 0), 0);
}

function getSuggestedFiles(files) {
  let next = files.filter(
    (file) =>
      file?.isValid === true || recoveryScore(file) >= HIGH_CONFIDENCE_THRESHOLD,
  );

  if (next.length === 0) {
    next = files.filter(
      (file) => recoveryScore(file) >= MEDIUM_CONFIDENCE_THRESHOLD,
    );
  }

  return next;
}

export default function ResultsPage({
  outputDir,
  result,
  selectedDrive,
  onBack,
  onSelectOutputDir,
  onStartRecovery,
}) {
  const [selectedIDs, setSelectedIDs] = useState(() => new Set());
  const [searchQuery, setSearchQuery] = useState("");
  const [categoryFilter, setCategoryFilter] = useState("all");
  const [sourceFilter, setSourceFilter] = useState("all");
  const [validFilter, setValidFilter] = useState("all");
  const [sortMode, setSortMode] = useState("score-desc");
  const [currentPage, setCurrentPage] = useState(1);
  const [showAdvanced, setShowAdvanced] = useState(false);

  const deferredSearchQuery = useDeferredValue(
    searchQuery.trim().toLowerCase(),
  );
  const files = result?.files || [];

  useEffect(() => {
    const validIDs = new Set(files.map((file) => file.id));

    setSelectedIDs((previous) => {
      const next = new Set();
      previous.forEach((id) => {
        if (validIDs.has(id)) {
          next.add(id);
        }
      });
      return next;
    });
  }, [files]);

  const suggestedFiles = useMemo(() => getSuggestedFiles(files), [files]);
  const suggestedIDs = useMemo(
    () => suggestedFiles.map((file) => file.id),
    [suggestedFiles],
  );
  const allRecoverableIDs = useMemo(
    () => files.map((file) => file.id),
    [files],
  );

  const categoryCounts = useMemo(() => {
    const counts = { all: files.length };
    files.forEach((file) => {
      const category = file?.category || "other";
      counts[category] = (counts[category] || 0) + 1;
    });
    return counts;
  }, [files]);

  const sourceCounts = useMemo(() => {
    const counts = { all: files.length };
    files.forEach((file) => {
      const source = file?.source || "unknown";
      counts[source] = (counts[source] || 0) + 1;
    });
    return counts;
  }, [files]);

  const summary = useMemo(() => {
    let validFiles = 0;
    let totalSize = 0;

    files.forEach((file) => {
      if (file?.isValid === true) {
        validFiles += 1;
      }
      totalSize += file?.size || 0;
    });

    return {
      totalFiles: files.length,
      validFiles,
      suggestedFiles: suggestedFiles.length,
      totalSize,
      suggestedSize: sumFileSizes(suggestedFiles),
    };
  }, [files, suggestedFiles]);

  const categoryOptions = useMemo(
    () =>
      CATEGORY_ORDER.map((key) => ({
        ...getCategoryMeta(key),
        count: categoryCounts[key] || 0,
      })),
    [categoryCounts],
  );

  const sourceOptions = useMemo(() => {
    const orderedKeys = [
      "all",
      ...Object.keys(sourceCounts)
        .filter((key) => key !== "all")
        .sort(),
    ];

    return orderedKeys.map((key) => ({
      ...getSourceMeta(key),
      count: sourceCounts[key] || 0,
    }));
  }, [sourceCounts]);

  const filteredFiles = useMemo(() => {
    let next = files;

    if (categoryFilter !== "all") {
      next = next.filter(
        (file) => (file?.category || "other") === categoryFilter,
      );
    }

    if (sourceFilter !== "all") {
      next = next.filter((file) => (file?.source || "unknown") === sourceFilter);
    }

    if (validFilter === "valid") {
      next = next.filter((file) => file?.isValid === true);
    } else if (validFilter === "invalid") {
      next = next.filter((file) => file?.isValid === false);
    }

    if (deferredSearchQuery) {
      next = next.filter((file) => {
        const target = [
          file?.fileName || "",
          file?.originalPath || file?.path || "",
          file?.extension || "",
        ]
          .join(" ")
          .toLowerCase();

        return target.includes(deferredSearchQuery);
      });
    }

    return next;
  }, [categoryFilter, deferredSearchQuery, files, sourceFilter, validFilter]);

  const sortedFiles = useMemo(() => {
    const next = [...filteredFiles];

    next.sort((left, right) => {
      switch (sortMode) {
        case "size-desc":
          return (right?.size || 0) - (left?.size || 0);
        case "name-asc":
          return (left?.fileName || "").localeCompare(right?.fileName || "");
        case "source-asc":
          return (left?.source || "").localeCompare(right?.source || "");
        case "score-desc":
        default:
          return recoveryScore(right) - recoveryScore(left);
      }
    });

    return next;
  }, [filteredFiles, sortMode]);

  const totalPages = Math.max(1, Math.ceil(sortedFiles.length / PAGE_SIZE));
  const safeCurrentPage = Math.min(currentPage, totalPages);

  const pageFiles = useMemo(() => {
    const start = (safeCurrentPage - 1) * PAGE_SIZE;
    return sortedFiles.slice(start, start + PAGE_SIZE);
  }, [safeCurrentPage, sortedFiles]);

  const selectedCount = selectedIDs.size;
  const selectedSize = useMemo(() => {
    const sizeMap = new Map(files.map((file) => [file.id, file.size || 0]));
    let total = 0;

    selectedIDs.forEach((id) => {
      total += sizeMap.get(id) || 0;
    });

    return total;
  }, [files, selectedIDs]);

  const allFilteredSelected =
    filteredFiles.length > 0 &&
    filteredFiles.every((file) => selectedIDs.has(file.id));

  const outputReady = Boolean(outputDir);
  const canRecoverSuggested = outputReady && suggestedIDs.length > 0;
  const canRecoverAll = outputReady && allRecoverableIDs.length > 0;
  const canRecoverManual = outputReady && selectedCount > 0;

  function resetToFirstPage() {
    startTransition(() => {
      setCurrentPage(1);
    });
  }

  function updateSelection(updater) {
    setSelectedIDs((previous) => updater(new Set(previous)));
  }

  function toggleFile(id) {
    updateSelection((next) => {
      if (next.has(id)) {
        next.delete(id);
      } else {
        next.add(id);
      }
      return next;
    });
  }

  function selectMatching(predicate) {
    updateSelection((next) => {
      filteredFiles.forEach((file) => {
        if (predicate(file)) {
          next.add(file.id);
        }
      });
      return next;
    });
  }

  function clearFilteredSelection() {
    updateSelection((next) => {
      filteredFiles.forEach((file) => next.delete(file.id));
      return next;
    });
  }

  function setCategory(value) {
    setCategoryFilter(value);
    resetToFirstPage();
  }

  function setSource(value) {
    setSourceFilter(value);
    resetToFirstPage();
  }

  function setValidity(value) {
    setValidFilter(value);
    resetToFirstPage();
  }

  if (files.length === 0) {
    return (
      <div className="results-page">
        <section className="results-hero surface">
          <div>
            <span className="results-hero__eyebrow">扫描完成</span>
            <h2>这次没有找到可直接展示的恢复文件。</h2>
            <p>
              源盘：<strong>{getDriveLabel(selectedDrive)}</strong>
            </p>
          </div>
        </section>

        <section className="results-guide surface">
          <div className="empty-state">
            <strong>没有拿到可恢复结果</strong>
            <span>可以重新选择源盘再扫一次，或检查磁盘是否仍然连接正常。</span>
          </div>
          <div className="output-status__actions">
            <button className="btn btn-secondary" onClick={onBack} type="button">
              重新选择源盘
            </button>
          </div>
        </section>
      </div>
    );
  }

  return (
    <div className="results-page">
      <section className="results-hero surface">
        <div className="results-hero__content">
          <span className="results-hero__eyebrow">扫描完成</span>
          <h2>已经找到可恢复文件，下一步先选恢复方式。</h2>
          <p>
            源盘：<strong>{getDriveLabel(selectedDrive)}</strong>。如果你不想自己判断文件，
            直接使用下面的“恢复推荐文件”即可。
          </p>
        </div>

        <div className="results-metrics">
          <div className="results-metric">
            <span>找到文件</span>
            <strong>{summary.totalFiles}</strong>
          </div>
          <div className="results-metric">
            <span>推荐恢复</span>
            <strong>{summary.suggestedFiles}</strong>
          </div>
          <div className="results-metric">
            <span>较可靠文件</span>
            <strong>{summary.validFiles}</strong>
          </div>
          <div className="results-metric">
            <span>全部大小</span>
            <strong>{formatSize(summary.totalSize)}</strong>
          </div>
        </div>
      </section>

      <section className="results-guide surface">
        <div className="results-guide__header">
          <div>
            <h3>普通用户按这 3 步就够了</h3>
            <p>如果你只是想尽快把数据找回来，不需要先看高级筛选。</p>
          </div>
        </div>

        <div className="results-guide__steps">
          <div className="guide-step">
            <span className="guide-step__index">1</span>
            <div>
              <strong>先选择恢复目录</strong>
              <p>必须选到另一块磁盘或 U 盘，不能和现在扫描的源盘相同。</p>
            </div>
          </div>
          <div className="guide-step">
            <span className="guide-step__index">2</span>
            <div>
              <strong>优先使用“恢复推荐文件”</strong>
              <p>它会先恢复验证通过或可信度高的文件，适合大多数人。</p>
            </div>
          </div>
          <div className="guide-step">
            <span className="guide-step__index">3</span>
            <div>
              <strong>只有在需要时再手动挑文件</strong>
              <p>如果推荐结果不够，再展开高级筛选自己勾选。</p>
            </div>
          </div>
        </div>

        <div
          className={`output-status${outputReady ? " output-status--ready" : ""}`}
        >
          <span className="output-status__label">当前恢复目录</span>
          <strong>{outputDir || "还没有选择恢复目录"}</strong>
          <p>
            {outputReady
              ? "恢复目录已经准备好，可以直接开始恢复。"
              : "还差一步：先把恢复目录选到另一块磁盘或 U 盘。"}
          </p>

          <div className="output-status__actions">
            <button
              className="btn btn-secondary"
              onClick={onSelectOutputDir}
              type="button"
            >
              选择恢复目录
            </button>
            <button className="btn btn-ghost" onClick={onBack} type="button">
              重新选择源盘
            </button>
          </div>
        </div>
      </section>

      <section className="results-primary surface">
        <div className="results-primary__header">
          <div>
            <h3>先用简单恢复方式</h3>
            <p>不知道怎么选时，先恢复推荐文件；想尽可能多找回内容，再恢复全部文件。</p>
          </div>
          <button
            className="btn btn-ghost"
            onClick={() => setShowAdvanced((value) => !value)}
            type="button"
          >
            {showAdvanced ? "收起手动筛选" : "手动挑文件（高级）"}
          </button>
        </div>

        <div className="recover-plan-grid">
          <article className="recover-plan recover-plan--primary">
            <span className="recover-plan__badge">推荐给多数人</span>
            <h4>恢复推荐文件</h4>
            <p>
              优先恢复验证通过或可信度高的文件，通常更适合先把最重要的数据找回来。
            </p>
            <div className="recover-plan__meta">
              <span>{summary.suggestedFiles} 个文件</span>
              <span>约 {formatSize(summary.suggestedSize)}</span>
            </div>
            <div className="recover-plan__hint">
              {outputReady
                ? "恢复目录已准备好，可以直接开始。"
                : "先选择恢复目录后才能开始恢复。"}
            </div>
            <button
              className="btn btn-primary btn-lg"
              disabled={!canRecoverSuggested}
              onClick={() => onStartRecovery(suggestedIDs)}
              type="button"
            >
              恢复推荐文件
            </button>
          </article>

          <article className="recover-plan">
            <span className="recover-plan__badge">范围最大</span>
            <h4>恢复全部可恢复文件</h4>
            <p>
              尽可能把这次扫描找到的内容都导出出来，更耗时，也会占用更多目标空间。
            </p>
            <div className="recover-plan__meta">
              <span>{summary.totalFiles} 个文件</span>
              <span>约 {formatSize(summary.totalSize)}</span>
            </div>
            <div className="recover-plan__hint">
              适合想先完整备份一份结果，后面再慢慢检查的人。
            </div>
            <button
              className="btn btn-secondary btn-lg"
              disabled={!canRecoverAll}
              onClick={() => onStartRecovery(allRecoverableIDs)}
              type="button"
            >
              恢复全部文件
            </button>
          </article>
        </div>
      </section>

      {showAdvanced && (
        <section className="results-advanced surface">
          <div className="results-advanced__header">
            <div>
              <span className="results-advanced__eyebrow">高级筛选</span>
              <h3>需要自己挑文件时，再用这一部分</h3>
              <p>
                可以按名称、类型和可靠程度手动勾选文件。只想尽快恢复时，不必处理这里。
              </p>
            </div>
          </div>

          <div className="results-filters">
            <div className="results-filters__top">
              <input
                className="input results-search"
                onChange={(event) => {
                  setSearchQuery(event.target.value);
                  resetToFirstPage();
                }}
                placeholder="按文件名、路径或扩展名搜索"
                type="text"
                value={searchQuery}
              />

              <select
                className="select results-sort"
                onChange={(event) => setSortMode(event.target.value)}
                value={sortMode}
              >
                {SORT_OPTIONS.map((option) => (
                  <option key={option.value} value={option.value}>
                    {option.label}
                  </option>
                ))}
              </select>
            </div>

            <div className="filter-group">
              <span className="filter-group__label">文件分类</span>
              <div className="filter-pills">
                {categoryOptions.map((option) => (
                  <button
                    key={option.key}
                    className={`pill${categoryFilter === option.key ? " pill--active" : ""}`}
                    onClick={() => setCategory(option.key)}
                    type="button"
                  >
                    {option.icon} {option.label} ({option.count})
                  </button>
                ))}
              </div>
            </div>

            <div className="filter-group">
              <span className="filter-group__label">来源</span>
              <div className="filter-pills">
                {sourceOptions.map((option) => (
                  <button
                    key={option.key}
                    className={`pill${sourceFilter === option.key ? " pill--active" : ""}`}
                    onClick={() => setSource(option.key)}
                    type="button"
                  >
                    {option.shortLabel} ({option.count})
                  </button>
                ))}
              </div>
            </div>

            <div className="filter-group filter-group--compact">
              <span className="filter-group__label">可靠程度</span>
              <div className="filter-pills">
                {[
                  ["all", "全部"],
                  ["valid", "优先看较可靠文件"],
                  ["invalid", "只看需谨慎文件"],
                ].map(([key, label]) => (
                  <button
                    key={key}
                    className={`pill${validFilter === key ? " pill--active" : ""}`}
                    onClick={() => setValidity(key)}
                    type="button"
                  >
                    {label}
                  </button>
                ))}
              </div>
            </div>

            <div className="results-actions">
              <button
                className="btn btn-secondary"
                onClick={() =>
                  selectMatching(
                    (file) => recoveryScore(file) >= HIGH_CONFIDENCE_THRESHOLD,
                  )
                }
                type="button"
              >
                选中较可靠文件
              </button>
              <button
                className="btn btn-secondary"
                onClick={() => selectMatching((file) => file?.isValid === true)}
                type="button"
              >
                选中验证通过
              </button>
              <button
                className="btn btn-secondary"
                onClick={() => {
                  if (allFilteredSelected) {
                    clearFilteredSelection();
                    return;
                  }
                  selectMatching(() => true);
                }}
                type="button"
              >
                {allFilteredSelected ? "取消当前筛选" : "选中当前筛选"}
              </button>
              <button
                className="btn btn-ghost"
                onClick={() => setSelectedIDs(new Set())}
                type="button"
              >
                清空手动勾选
              </button>
            </div>
          </div>

          <section className="results-list">
            <div className="results-list__header">
              <div>
                <h3>手动筛选文件</h3>
                <p>
                  当前匹配 <strong>{sortedFiles.length}</strong> 个文件，已手动勾选
                  <strong> {selectedCount}</strong> 个。
                </p>
              </div>
            </div>

            {pageFiles.length === 0 ? (
              <div className="empty-state">
                <strong>没有符合当前筛选条件的文件</strong>
                <span>放宽筛选条件后再试一次。</span>
              </div>
            ) : (
              <div className="result-file-list">
                {pageFiles.map((file) => {
                  const category = getCategoryMeta(file?.category || "other");
                  const source = getSourceMeta(file?.source);
                  const score = recoveryScore(file);
                  const scoreLevel =
                    score >= HIGH_CONFIDENCE_THRESHOLD
                      ? "high"
                      : score >= MEDIUM_CONFIDENCE_THRESHOLD
                        ? "medium"
                        : "low";
                  const isSelected = selectedIDs.has(file.id);

                  return (
                    <div
                      key={file.id}
                      className={`result-file${isSelected ? " result-file--selected" : ""}`}
                      onClick={() => toggleFile(file.id)}
                      onKeyDown={(event) => {
                        if (event.key === "Enter" || event.key === " ") {
                          event.preventDefault();
                          toggleFile(file.id);
                        }
                      }}
                      role="button"
                      tabIndex={0}
                    >
                      <div className="result-file__check">
                        <input
                          checked={isSelected}
                          onChange={() => toggleFile(file.id)}
                          onClick={(event) => event.stopPropagation()}
                          type="checkbox"
                        />
                      </div>

                      <div className="result-file__body">
                        <div className="result-file__headline">
                          <span className="result-file__icon">{category.icon}</span>
                          <div>
                            <strong>{file.fileName || "未命名文件"}</strong>
                            <span>{formatPath(file)}</span>
                          </div>
                        </div>

                        <div className="result-file__meta">
                          <span className="meta-chip">{category.label}</span>
                          <span className="meta-chip">{source.shortLabel}</span>
                          <span className="meta-chip">{formatSize(file.size)}</span>
                          <span className="meta-chip">
                            {file.extension ? `.${file.extension}` : "无扩展名"}
                          </span>
                          <span
                            className={`meta-chip${file?.isValid ? " meta-chip--success" : " meta-chip--warning"}`}
                          >
                            {getValidityLabel(file)}
                          </span>
                        </div>
                      </div>

                      <div className="result-file__score">
                        <span className={`score-pill score-pill--${scoreLevel}`}>
                          {score}%
                        </span>
                        <span>恢复优先级</span>
                      </div>
                    </div>
                  );
                })}
              </div>
            )}

            {sortedFiles.length > 0 && (
              <div className="results-pagination">
                <span>
                  第 {safeCurrentPage} / {totalPages} 页
                </span>
                <div className="results-pagination__controls">
                  <button
                    className="btn btn-ghost"
                    disabled={safeCurrentPage <= 1}
                    onClick={() => setCurrentPage(1)}
                    type="button"
                  >
                    首页
                  </button>
                  <button
                    className="btn btn-ghost"
                    disabled={safeCurrentPage <= 1}
                    onClick={() =>
                      setCurrentPage((page) => Math.max(1, page - 1))
                    }
                    type="button"
                  >
                    上一页
                  </button>
                  <button
                    className="btn btn-ghost"
                    disabled={safeCurrentPage >= totalPages}
                    onClick={() =>
                      setCurrentPage((page) => Math.min(totalPages, page + 1))
                    }
                    type="button"
                  >
                    下一页
                  </button>
                  <button
                    className="btn btn-ghost"
                    disabled={safeCurrentPage >= totalPages}
                    onClick={() => setCurrentPage(totalPages)}
                    type="button"
                  >
                    末页
                  </button>
                </div>
              </div>
            )}
          </section>

          <div className="recovery-dock">
            <div className="recovery-dock__summary">
              <div>
                <span className="recovery-dock__label">手动勾选文件</span>
                <strong>
                  {selectedCount > 0
                    ? `${selectedCount} 个，约 ${formatSize(selectedSize)}`
                    : "还没有手动勾选文件"}
                </strong>
                <span className="recovery-dock__hint">
                  {selectedCount > 0
                    ? "可以只恢复这些手动勾选的文件。"
                    : "不想自己筛选时，直接使用上面的推荐恢复即可。"}
                </span>
              </div>
              <div>
                <span className="recovery-dock__label">恢复目录</span>
                <strong>{outputDir || "还没有选择恢复目录"}</strong>
                <span className="recovery-dock__hint">
                  {outputReady
                    ? "恢复目录已准备好，可以恢复手动勾选的文件。"
                    : "先把恢复目录选到另一块磁盘，再恢复手动勾选的文件。"}
                </span>
              </div>
            </div>

            <div className="recovery-dock__actions">
              <button
                className="btn btn-secondary"
                onClick={onSelectOutputDir}
                type="button"
              >
                选择恢复目录
              </button>
              <button
                className="btn btn-primary btn-lg"
                disabled={!canRecoverManual}
                onClick={() => onStartRecovery(Array.from(selectedIDs))}
                type="button"
              >
                恢复手动勾选的文件
              </button>
            </div>
          </div>
        </section>
      )}
    </div>
  );
}
