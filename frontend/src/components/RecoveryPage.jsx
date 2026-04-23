import React, { useMemo, useState } from "react";
import {
  IconAlertTriangle,
  IconArrowLeft,
  IconCheckCircle,
  IconDownload,
  IconFolderOpen,
  IconRefresh,
  IconStop,
  IconX,
} from "../icons";
import { formatSize, clampPercent } from "../formatters";

/**
 * RecoveryPage —— 既是"正在恢复"的进度页，也是"已结束"的结果报告。
 *
 * 在 isActive=true 期间，展示总体进度 + 当前文件；
 * 结束后，展示汇总 + 详细每文件记录（带筛选），并提供：
 *  - 打开目标文件夹
 *  - 导出 CSV 报告
 *  - 只重试失败的文件
 *  - 返回工作台继续挑文件恢复
 *  - 开始新扫描
 */
export default function RecoveryPage({
  isActive,
  progress,
  records,
  outputDir,
  onStopRecovery,
  onOpenFolder,
  onRetryFailed,
  onExportReport,
  onBackToWorkbench,
  onNewScan,
}) {
  const [filter, setFilter] = useState("failed"); // all | success | failed

  const counts = useMemo(() => {
    const c = { success: 0, lowConfidence: 0, partial: 0, failed: 0, skipped: 0 };
    (records || []).forEach((r) => {
      if (r.state === "success") {
        c.success++;
        // output path 含 _low_confidence → 统计到 low confidence（仍 success 但标警告）
        if (r.outputPath && r.outputPath.indexOf("_low_confidence") >= 0) {
          c.lowConfidence++;
        }
      } else if (r.state === "partial") c.partial++;
      else if (r.state === "failed") c.failed++;
      else if (r.state === "skipped") c.skipped++;
    });
    // 高可靠 = success 总数 - 走 low confidence 的数量
    c.highConfidence = c.success - c.lowConfidence;
    return c;
  }, [records]);

  const filteredRecords = useMemo(() => {
    if (!records) return [];
    if (filter === "all") return records;
    if (filter === "success") return records.filter((r) => r.state === "success");
    if (filter === "failed") return records.filter((r) => r.state !== "success");
    return records;
  }, [records, filter]);

  const percent = clampPercent(
    progress?.total > 0 ? (progress.current / progress.total) * 100 : 0,
  );
  const hasFailures = counts.failed + counts.partial + counts.skipped > 0;

  // 活动中：只显示实时进度
  if (isActive) {
    return (
      <div className="page">
        <div className="page__header">
          <div className="page__title">正在恢复文件…</div>
          <div className="page__subtitle">
            请勿拔出源盘或目标盘。单个文件写入完成后会做 SHA256 二次校验。
          </div>
        </div>

        <div className="page__body flex-col gap-4">
          <div className="card">
            <div className="flex items-center justify-between gap-4" style={{ marginBottom: 12 }}>
              <div>
                <div className="muted" style={{ fontSize: 12 }}>进度</div>
                <div style={{ fontSize: 22, fontWeight: 700, fontVariantNumeric: "tabular-nums" }}>
                  {(progress?.current ?? 0).toLocaleString()} / {(progress?.total ?? 0).toLocaleString()}
                </div>
              </div>
              <div className="btn-group">
                <button className="btn btn--danger" onClick={onStopRecovery}>
                  <IconStop size={14} /> 停止
                </button>
              </div>
            </div>
            <div className="progress"><div className="progress__fill" style={{ width: `${percent}%` }} /></div>
            <div className="flex items-center gap-3" style={{ marginTop: 12, fontSize: 12, color: "var(--text-muted)", flexWrap: "wrap" }}>
              <span>✓ 成功 <b style={{ color: "var(--success)" }}>{progress?.success ?? 0}</b></span>
              <span>⚠ 部分 <b style={{ color: "var(--warning)" }}>{progress?.partial ?? 0}</b></span>
              <span>✗ 失败 <b style={{ color: "var(--danger)" }}>{progress?.failed ?? 0}</b></span>
              <span>已写入 <b>{formatSize(progress?.bytesWritten || 0)}</b></span>
            </div>
            {progress?.currentFile && (
              <div className="mono muted" style={{ marginTop: 12, fontSize: 11, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>
                当前：{progress.currentFile}
              </div>
            )}
          </div>
        </div>
      </div>
    );
  }

  // 活动结束：展示报告
  return (
    <div className="page">
      <div className="page__header">
        <div className="page__title">
          {hasFailures ? "恢复完成（有失败项）" : "恢复完成"}
        </div>
        <div className="page__subtitle">
          输出目录：<span className="mono">{outputDir || "(未知)"}</span>
        </div>
      </div>

      <div className="page__body flex-col gap-3">
        <div className="report-summary">
          <div className="stat-card stat-card--success">
            <div className="stat-card__label">✓ 高可靠</div>
            <div className="stat-card__value">{counts.highConfidence.toLocaleString()}</div>
            <div className="stat-card__hint">能正常打开（真实解码验证通过）</div>
          </div>
          <div className={`stat-card ${counts.lowConfidence > 0 ? "stat-card--warning" : ""}`}>
            <div className="stat-card__label">⚠ 低可靠</div>
            <div className="stat-card__value">{counts.lowConfidence.toLocaleString()}</div>
            <div className="stat-card__hint">已归到 _low_confidence/，可能打不开</div>
          </div>
          <div className={`stat-card ${counts.partial > 0 ? "stat-card--warning" : ""}`}>
            <div className="stat-card__label">◑ 部分恢复</div>
            <div className="stat-card__value">{counts.partial.toLocaleString()}</div>
            <div className="stat-card__hint">大小不完整</div>
          </div>
          <div className={`stat-card ${counts.skipped > 0 ? "stat-card--muted" : ""}`}>
            <div className="stat-card__label">⊘ 已拒绝</div>
            <div className="stat-card__value">{counts.skipped.toLocaleString()}</div>
            <div className="stat-card__hint">validator 判废，未写盘</div>
          </div>
          <div className={`stat-card ${counts.failed > 0 ? "stat-card--danger" : ""}`}>
            <div className="stat-card__label">✗ 失败</div>
            <div className="stat-card__value">{counts.failed.toLocaleString()}</div>
            <div className="stat-card__hint">读/写错误</div>
          </div>
        </div>

        {hasFailures && (
          <div className="banner banner--warning">
            <IconAlertTriangle size={18} className="banner__icon" />
            <div className="banner__content">
              <div className="banner__title">有 {(counts.failed + counts.partial + counts.skipped).toLocaleString()} 个文件没能恢复成功</div>
              <div className="banner__text">
                常见原因：源盘扇区已被覆写、文件碎片跨越已用簇、权限不足。
                你可以只重试失败的文件，或者导出 CSV 报告后人工核对。
              </div>
            </div>
            <div className="banner__actions">
              <button className="btn btn--sm" onClick={onRetryFailed}>
                <IconRefresh size={14} /> 只重试失败
              </button>
            </div>
          </div>
        )}

        <div className="flex items-center gap-3" style={{ flexWrap: "wrap" }}>
          <button className="btn" onClick={() => outputDir && onOpenFolder?.(outputDir)} disabled={!outputDir}>
            <IconFolderOpen size={14} /> 打开输出目录
          </button>
          <button className="btn" onClick={onExportReport} disabled={!records?.length}>
            <IconDownload size={14} /> 导出恢复报告 (CSV)
          </button>
          <button className="btn" onClick={onBackToWorkbench}>
            <IconArrowLeft size={14} /> 回到工作台继续挑文件
          </button>
          <button className="btn btn--ghost" onClick={onNewScan}>
            换一块盘
          </button>
        </div>

        {records && records.length > 0 && (
          <div className="file-table-wrap" style={{ marginTop: 8 }}>
            <div className="file-table-toolbar">
              <div className="file-table-toolbar__left">
                <div className="btn-group">
                  {[
                    { v: "failed", label: `未成功 (${counts.failed + counts.partial + counts.skipped})` },
                    { v: "success", label: `成功 (${counts.success})` },
                    { v: "all", label: `全部 (${records.length})` },
                  ].map((opt) => (
                    <button
                      key={opt.v}
                      className={`btn btn--sm ${filter === opt.v ? "btn--primary" : "btn--ghost"}`}
                      onClick={() => setFilter(opt.v)}
                    >
                      {opt.label}
                    </button>
                  ))}
                </div>
              </div>
            </div>

            <div className="file-table-scroll">
              <table className="records-table">
                <thead>
                  <tr>
                    <th>状态</th>
                    <th>文件名</th>
                    <th>大小</th>
                    <th>输出 / 消息</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredRecords.map((r) => (
                    <tr key={r.fileId}>
                      <td><StateBadge state={r.state} /></td>
                      <td className="file-name" title={r.fileName} style={{ maxWidth: 260 }}>{r.fileName}</td>
                      <td style={{ textAlign: "right", fontVariantNumeric: "tabular-nums" }}>{r.sizeHuman}</td>
                      <td className="wrap mono" style={{ fontSize: 11.5 }}>
                        {r.state === "success" ? r.outputPath : r.message || "无错误消息"}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

function StateBadge({ state }) {
  switch (state) {
    case "success":
      return <span className="badge badge--success"><IconCheckCircle size={12} /> 成功</span>;
    case "partial":
      return <span className="badge badge--warning"><IconAlertTriangle size={12} /> 部分</span>;
    case "skipped":
      return <span className="badge"><IconX size={12} /> 跳过</span>;
    case "failed":
    default:
      return <span className="badge badge--danger"><IconX size={12} /> 失败</span>;
  }
}
