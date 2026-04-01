import React from "react";
import {
  clampPercent,
  formatDuration,
  formatPath,
  formatSize,
  formatSpeed,
} from "../formatters";
import {
  DEFAULT_SCAN_PLAN,
  getCategoryMeta,
  getDriveLabel,
  recoveryScore,
} from "../recovery-helpers";
import "./ScanningPage.css";

function getPhaseLabel(phase) {
  const map = {
    ready: "准备开始扫描",
    ntfs: "先查找原来的文件记录",
    carving: "继续深度查找更多文件",
    validating: "正在检查文件是否可用",
    complete: "扫描完成",
  };

  return map[phase] || phase || "准备中";
}

function getConfidenceLabel(score, isValid, validationMsg) {
  if (isValid === true || score >= 80) {
    return "较可靠，建议优先恢复";
  }

  if (score >= 60) {
    return "可尝试恢复";
  }

  return validationMsg || "建议谨慎查看";
}

export default function ScanningPage({
  foundFiles,
  outputDir,
  progress,
  selectedDrive,
  onSelectOutputDir,
  onStartRecovery,
  onStopScan,
  onViewResults,
}) {
  const files = Array.isArray(foundFiles) ? foundFiles : [];
  const recentFiles = files.slice(-12).reverse();
  const percent = clampPercent(progress?.percent);

  async function handleQuickRecover(fileID) {
    if (!fileID) {
      return;
    }

    let nextOutputDir = outputDir;
    if (!nextOutputDir) {
      nextOutputDir = await onSelectOutputDir?.();
    }

    if (!nextOutputDir) {
      return;
    }

    onStartRecovery?.([fileID], "scanning", nextOutputDir);
  }

  return (
    <div className="scanning-page">
      <section className="scan-hero surface">
        <div className="scan-hero__content">
          <span className="scan-hero__eyebrow">扫描进行中</span>
          <h2>{getPhaseLabel(progress?.phase)}</h2>
          <p>
            正在扫描 <strong>{getDriveLabel(selectedDrive)}</strong>
            。这一步你只需要等待，
            扫描完成后再决定恢复哪些文件；如果已经看到重要文件，也可以提前先看当前结果。
          </p>
        </div>

        <div className="scan-hero__actions">
          <button
            className="btn btn-secondary"
            onClick={onViewResults}
            type="button"
          >
            查看当前结果
          </button>
          <button className="btn btn-danger" onClick={onStopScan} type="button">
            停止扫描
          </button>
        </div>
      </section>

      <div className="scan-layout">
        <section className="scan-progress surface">
          <div className="scan-progress__top">
            <div>
              <span className="scan-progress__label">整体进度</span>
              <div className="scan-progress__value">{percent.toFixed(1)}%</div>
            </div>
            <div className="scan-progress__summary">
              <span>{formatSize(progress?.bytesScanned)}</span>
              <span>/</span>
              <span>{formatSize(progress?.totalBytes)}</span>
            </div>
          </div>

          <div className="scan-progress__bar">
            <div
              className="scan-progress__bar-fill"
              style={{ width: `${percent}%` }}
            />
          </div>

          <div className="scan-progress__details">
            <div className="scan-progress__detail">
              <span>正在处理</span>
              <strong>{progress?.currentFile || "正在读取磁盘块…"}</strong>
            </div>
            <div className="scan-progress__detail">
              <span>预计还需</span>
              <strong>{formatDuration(progress?.eta)}</strong>
            </div>
            <div className="scan-progress__detail">
              <span>已经扫描</span>
              <strong>{formatDuration(progress?.elapsed)}</strong>
            </div>
          </div>
        </section>

        <aside className="scan-side">
          <div className="scan-stats surface">
            <div className="scan-stat">
              <span className="scan-stat__label">已找到文件</span>
              <strong>
                {Math.max(progress?.filesFound || 0, files.length)}
              </strong>
            </div>
            <div className="scan-stat">
              <span className="scan-stat__label">当前预览</span>
              <strong>{recentFiles.length}</strong>
            </div>
            <div className="scan-stat">
              <span className="scan-stat__label">扫描速度</span>
              <strong>{formatSpeed(progress?.speed)}</strong>
            </div>
            <div className="scan-stat">
              <span className="scan-stat__label">当前阶段</span>
              <strong>{getPhaseLabel(progress?.phase)}</strong>
            </div>
          </div>

          <div className="scan-tips surface">
            <h3>这一步只要注意两件事</h3>
            <ul>
              <li>不要把任何新文件写回源盘。</li>
              <li>如果是外接盘或移动硬盘，保持连接稳定。</li>
              <li>已经找到的重要文件，现在就可以单独恢复，不必等扫描结束。</li>
            </ul>
          </div>
        </aside>
      </div>

      <section className="scan-files surface">
        <div className="scan-files__header">
          <div>
            <h3>扫描过程中已经找到的文件</h3>
            <p>这里会持续更新。要恢复某一个文件，可以直接点右侧按钮。</p>
          </div>
          <span className="scan-files__count">{files.length} 个候选文件</span>
        </div>

        {recentFiles.length === 0 ? (
          <div className="empty-state">
            <strong>扫描已经开始</strong>
            <span>文件一旦被发现，会立即出现在这里。</span>
          </div>
        ) : (
          <div className="scan-file-list">
            {recentFiles.map((file) => {
              const category = getCategoryMeta(file.category || "other");
              const score = recoveryScore(file);
              const scoreLevel =
                score >= 80 ? "high" : score >= 60 ? "medium" : "low";

              return (
                <div key={file.id} className="scan-file-row">
                  <div className="scan-file-row__main">
                    <div className="scan-file-row__title">
                      <span className="scan-file-row__icon">
                        {category.icon}
                      </span>
                      <div>
                        <strong>{file.fileName || "未命名文件"}</strong>
                        <span>{formatPath(file)}</span>
                      </div>
                    </div>

                    <div className="scan-file-row__meta">
                      <span>{category.label}</span>
                      <span>{formatSize(file.size)}</span>
                      <span>
                        {file.extension ? `.${file.extension}` : "无扩展名"}
                      </span>
                    </div>
                  </div>

                  <div className="scan-file-row__score">
                    <span className={`score-pill score-pill--${scoreLevel}`}>
                      {score}%
                    </span>
                    <span>
                      {getConfidenceLabel(
                        score,
                        file.isValid,
                        file.validationMsg,
                      )}
                    </span>
                    <button
                      className="btn btn-secondary scan-file-row__recover"
                      onClick={() => handleQuickRecover(file.id)}
                      type="button"
                    >
                      恢复这个文件
                    </button>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </section>
    </div>
  );
}
