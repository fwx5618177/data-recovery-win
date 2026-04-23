import React, { useEffect, useMemo, useState } from "react";
import { bucketFiles, BUCKETS, confidenceTier } from "../recovery-helpers";
import { formatSize } from "../formatters";
import ConfidenceBadge from "./ConfidenceBadge";
import { IconDownload, IconEye, IconCheckCircle } from "../icons";

/**
 * BestChanceFirst —— 扫描完成后的"苹果级默认视图"。
 *
 * 设计动机：R-Studio 把"上万条文件按 offset 列成表格"丢给用户，用户心智负担
 * 大。本视图替代之，先按 6 个用户视角分桶：
 *   Windows.old / 桌面 / 照片 / 文档 / 最近修改 / 其他
 * 每桶一个卡片，有数量、置信度徽章样例、"恢复此类全部"按钮。用户通常能在
 * 其中一个桶里一键搞定，不用翻几万行表。
 *
 * 需要查全量文件时点"切换到高级模式" → 回到经典 FileTable 视图。
 */
export default function BestChanceFirst({
  files,
  scanActive,
  onBulkSelect,        // (fileIds: string[]) => void —— 把一批文件塞进 Workbench selectedIds
  onDrillBucket,       // (bucketKey: string) => void —— 用户想看某桶的完整列表
  onSwitchToAdvanced,  // () => void —— 切到 FileTable
  onRequestPreview,    // (file) => Promise<string|null>  —— 给照片桶做缩略图
}) {
  const bucketed = useMemo(() => bucketFiles(files), [files]);
  const total = files?.length || 0;

  return (
    <div className="best-chance">
      {/* Hero ------------------------------------------------- */}
      <div className="best-chance__hero">
        <div className="best-chance__hero-title">
          {scanActive ? (
            <>
              正在扫描 —— 已发现 <b>{total.toLocaleString()}</b> 个文件
            </>
          ) : (
            <>
              <IconCheckCircle size={20} style={{ color: "var(--success)", marginRight: 8, verticalAlign: "-3px" }} />
              扫描完成 —— 共 <b>{total.toLocaleString()}</b> 个文件，已按"最可能是你要的"排好
            </>
          )}
        </div>
        <div className="best-chance__hero-subtitle">
          我们把扫描到的所有文件分成了 6 类，从最可能是你个人数据的 <b>Windows.old</b> 开始。
          {" "}点击某个卡片里的"恢复此类全部"即可。不用翻上万行表格。
        </div>
      </div>

      {/* 6 桶网格 ------------------------------------------- */}
      <div className="best-chance__grid">
        {BUCKETS.map((bucket) => (
          <BucketCard
            key={bucket.key}
            bucket={bucket}
            files={bucketed[bucket.key] || []}
            onRecover={() => onBulkSelect?.((bucketed[bucket.key] || []).map((f) => f.id))}
            onDrillIn={() => onDrillBucket?.(bucket.key)}
            onRequestPreview={onRequestPreview}
          />
        ))}
      </div>

      {/* 进阶出口 ------------------------------------------- */}
      <div className="best-chance__advanced">
        <button className="btn btn--ghost" onClick={onSwitchToAdvanced}>
          查看全部 {total.toLocaleString()} 个文件（高级模式 / 手动筛选）
        </button>
        <div className="muted" style={{ fontSize: 11, marginTop: 6 }}>
          高级模式提供经典文件表、分类过滤器、搜索语法等。大多数场景不需要用到。
        </div>
      </div>
    </div>
  );
}

/**
 * BucketCard —— 单个桶的卡片。
 *
 * 空桶也渲染（dim 态），这样用户能明确知道"Windows.old 里什么都没找到"而
 * 不是以为我们漏扫了一类。
 */
function BucketCard({ bucket, files, onRecover, onDrillIn, onRequestPreview }) {
  const count = files.length;
  const empty = count === 0;
  const totalSize = useMemo(
    () => files.reduce((s, f) => s + Number(f.size || 0), 0),
    [files],
  );

  // 前 3 条作预览（照片桶会加载缩略图；其他桶只列文件名 + 徽章）
  const peek = useMemo(() => files.slice(0, bucket.key === "photos" ? 4 : 3), [files, bucket.key]);

  return (
    <div className={`bucket-card ${empty ? "bucket-card--empty" : ""}`}>
      <div className="bucket-card__head">
        <div className="bucket-card__title">
          <BucketIcon bucketKey={bucket.key} />
          <span>{bucket.label}</span>
        </div>
        <div className="bucket-card__count">
          {empty ? (
            <span className="muted">未发现</span>
          ) : (
            <>
              <b>{count.toLocaleString()}</b>
              <span className="muted"> · {formatSize(totalSize)}</span>
            </>
          )}
        </div>
      </div>

      <div className="bucket-card__desc muted">{bucket.desc}</div>

      {!empty && bucket.key === "photos" && (
        <PhotoThumbStrip files={peek} onRequestPreview={onRequestPreview} />
      )}
      {!empty && bucket.key !== "photos" && (
        <PeekList files={peek} />
      )}

      <div className="bucket-card__actions">
        <button
          className="btn btn--primary"
          onClick={onRecover}
          disabled={empty}
          title={empty ? "本桶为空" : `选中本桶全部 ${count} 个文件，进入恢复`}
        >
          <IconDownload size={14} /> 恢复此类全部 {empty ? "" : `(${count.toLocaleString()})`}
        </button>
        <button
          className="btn btn--ghost"
          onClick={onDrillIn}
          disabled={empty}
          title="查看本桶的文件列表，可逐个预览 / 选中"
        >
          <IconEye size={14} /> 查看列表
        </button>
      </div>
    </div>
  );
}

/**
 * PhotoThumbStrip —— 照片桶的缩略图条。
 * 懒加载最多 4 张 —— 直接从源盘读取前若干字节组 data URL；失败静默不影响卡片。
 */
function PhotoThumbStrip({ files, onRequestPreview }) {
  const [thumbs, setThumbs] = useState({}); // { [fileId]: dataURL }

  useEffect(() => {
    if (!onRequestPreview) return;
    let cancelled = false;
    (async () => {
      for (const f of files) {
        if (cancelled) return;
        if (thumbs[f.id]) continue;
        try {
          const url = await onRequestPreview(f);
          if (cancelled) return;
          if (url) setThumbs((prev) => ({ ...prev, [f.id]: url }));
        } catch {
          // 忽略预览失败（bad sector / 已解压覆盖等）—— 卡片仍能正常操作
        }
      }
    })();
    return () => { cancelled = true; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [files, onRequestPreview]);

  return (
    <div className="bucket-card__thumbs">
      {files.map((f) => (
        <div key={f.id} className="bucket-card__thumb" title={f.fileName}>
          {thumbs[f.id] ? (
            <img src={thumbs[f.id]} alt={f.fileName} />
          ) : (
            <div className="bucket-card__thumb-placeholder muted">加载中…</div>
          )}
          <div className="bucket-card__thumb-badge">
            <ConfidenceBadge file={f} size="sm" />
          </div>
        </div>
      ))}
    </div>
  );
}

/**
 * PeekList —— 非照片桶的前 3 条文件预览（只文件名 + 置信度徽章，无缩略图）。
 */
function PeekList({ files }) {
  return (
    <ul className="bucket-card__peek">
      {files.map((f) => (
        <li key={f.id} title={f.originalPath || f.fileName}>
          <span className="bucket-card__peek-name mono">{f.fileName}</span>
          <ConfidenceBadge file={f} size="sm" />
        </li>
      ))}
    </ul>
  );
}

/**
 * BucketIcon —— 每个桶一个 emoji 图标。故意不用 SVG 图标库统一风格，桶卡片
 * 视觉上比文件表格"更轻盈、更人话"，emoji 正好贴合这个调性。
 */
function BucketIcon({ bucketKey }) {
  const map = {
    windowsOld: "🗄️",
    desktop: "🖥️",
    photos: "🖼️",
    documents: "📄",
    recent: "🕒",
    other: "📦",
  };
  return <span className="bucket-card__icon" aria-hidden="true">{map[bucketKey] || "📁"}</span>;
}
