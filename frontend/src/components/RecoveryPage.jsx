import React from "react";
import { clampPercent, formatSize } from "../formatters";
import { getDriveLabel } from "../recovery-helpers";
import "./RecoveryPage.css";

export default function RecoveryPage({
  outputDir,
  progress,
  selectedDrive,
  onBack,
  onNewScan,
  onOpenFolder,
  onStopRecovery,
}) {
  const current = progress?.current || 0;
  const total = progress?.total || 0;
  const success = progress?.success || 0;
  const partial = progress?.partial || 0;
  const failed = progress?.failed || 0;
  const isCompleted = total > 0 && current >= total;
  const percent = total > 0 ? clampPercent((current / total) * 100) : 0;

  return (
    <div className="recovery-page">
      <section className="recovery-card surface">
        <span
          className={`recovery-state${isCompleted ? " recovery-state--done" : ""}`}
        >
          {isCompleted ? "恢复完成" : "正在恢复"}
        </span>

        <h2>
          {isCompleted
            ? "恢复完成，现在先检查找回的文件"
            : "正在把文件导出到安全目录"}
        </h2>

        <p className="recovery-subtitle">
          源盘：<strong>{getDriveLabel(selectedDrive)}</strong>
        </p>
        <p className="recovery-description">
          {isCompleted
            ? partial > 0
              ? "恢复已经结束，但有一部分文件只导出了部分内容。请先检查最重要的文件能否正常打开。"
              : "先打开恢复目录，优先检查最重要的文件能否正常打开。"
            : "这一步只需要等待，并保持源盘与恢复目录所在磁盘连接稳定。"}
        </p>

        <div className="recovery-progress">
          <div className="recovery-progress__header">
            <span>整体进度</span>
            <strong>{percent.toFixed(0)}%</strong>
          </div>
          <div className="recovery-progress__bar">
            <div
              className="recovery-progress__fill"
              style={{ width: `${percent}%` }}
            />
          </div>
          <div className="recovery-progress__meta">
            <span>
              {current} / {total} 个文件
            </span>
            <span>{progress?.currentFile || "等待下一个文件…"}</span>
          </div>
        </div>

        <div className="recovery-stats">
          <div className="recovery-stat">
            <span>已导出</span>
            <strong>{success}</strong>
          </div>
          <div className="recovery-stat">
            <span>部分导出</span>
            <strong>{partial}</strong>
          </div>
          <div className="recovery-stat">
            <span>未导出</span>
            <strong>{failed}</strong>
          </div>
          <div className="recovery-stat">
            <span>写入数据</span>
            <strong>{formatSize(progress?.bytesWritten)}</strong>
          </div>
          <div className="recovery-stat">
            <span>完成度</span>
            <strong>{percent.toFixed(0)}%</strong>
          </div>
        </div>

        <div className="recovery-output">
          <span>恢复目录</span>
          <strong>{outputDir || "未指定恢复目录"}</strong>
        </div>

        <div className="recovery-actions">
          {isCompleted ? (
            <>
              <button
                className="btn btn-primary btn-lg"
                onClick={() => onOpenFolder(outputDir)}
                type="button"
              >
                打开恢复目录
              </button>
              <button
                className="btn btn-secondary"
                onClick={onNewScan}
                type="button"
              >
                新建扫描
              </button>
              <button className="btn btn-ghost" onClick={onBack} type="button">
                返回首页
              </button>
            </>
          ) : (
            <>
              <button
                className="btn btn-danger"
                onClick={onStopRecovery}
                type="button"
              >
                停止恢复
              </button>
              <div className="recovery-tip">
                恢复过程中不要断开源盘，也不要把新文件写回源盘。
              </div>
            </>
          )}
        </div>
      </section>
    </div>
  );
}
