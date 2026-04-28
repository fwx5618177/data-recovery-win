/**
 * <MultiDiskScanModal> —— v2.8.5 多盘并行扫描真实现。
 *
 * 之前菜单点了只 toast 一句"功能就绪请用 CLI"——backend 真实现了但 GUI 没接。
 * 这个 Modal 把它接起来：
 *   - 选源盘（多选）
 *   - 选 mode（auto / quick / deep）
 *   - 选 maxParallel（1-N）
 *   - 启动 → backend StartParallelScanDrives
 *   - 流式进度：每盘一张卡片，实时显示 percent / 速度 / 已发现
 *   - allDone 后展示汇总（命中 / 错误）
 *   - 关 Modal 自动 CancelParallelScan
 *
 * 注意：多盘并行扫描不会写入主 scanProgress 状态（不替代单盘 Workbench），
 * 是个独立的辅助工具 —— 用户搞清楚后再各自打开 workbench 处理结果。
 */

import React, { useEffect, useRef, useState } from "react";
import {
  IconX,
  IconHardDrive,
  IconUsb,
  IconPlay,
  IconStop,
  IconCheck,
  IconAlertTriangle,
} from "../icons";
import { formatSize } from "../formatters";
import { toast } from "../toast";

interface DriveInfo {
  path: string;
  name: string;
  size: number;
  driveType?: string;
  isRemovable?: boolean;
  fileSystem?: string;
}

interface DiskJob {
  DrivePath: string;
  Mode: string;
}

interface ScanProgress {
  phase?: string;
  percent?: number;
  bytesScanned?: number;
  totalBytes?: number;
  filesFound?: number;
  speed?: number;
  elapsed?: string;
  currentFile?: string;
}

interface JobResultPayload {
  drivePath: string;
  result?: { files?: any[]; duration?: number };
  error?: string;
}

interface DriveState {
  status: "pending" | "running" | "done" | "error" | "cancelled";
  progress: ScanProgress;
  filesFound: number;
  error?: string;
}

declare global {
  interface Window {
    runtime?: {
      EventsOn: (event: string, cb: (...args: any[]) => void) => () => void;
    };
  }
}

interface Props {
  wailsApp: any;
  drives: DriveInfo[];
  onClose: () => void;
}

const MODES = [
  { value: "auto", label: "自动（推荐）" },
  { value: "quick", label: "快速（仅 MFT / 目录树）" },
  { value: "deep", label: "深度（雕刻 + 全签名）" },
];

export default function MultiDiskScanModal({ wailsApp, drives, onClose }: Props) {
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [mode, setMode] = useState<string>("auto");
  const [maxParallel, setMaxParallel] = useState<number>(2);
  const [running, setRunning] = useState(false);
  const [done, setDone] = useState(false);
  const [driveState, setDriveState] = useState<Record<string, DriveState>>({});
  const cleanupRef = useRef<(() => void) | null>(null);

  // 过滤可扫描盘：物理盘 + 逻辑盘（DEV 占位卡跳过）
  const scannableDrives = drives.filter((d) => d.driveType !== "dev-placeholder" && d.path);

  function toggleDrive(path: string) {
    if (running) return;
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(path)) next.delete(path);
      else next.add(path);
      return next;
    });
  }

  function selectAll() {
    if (running) return;
    setSelected(new Set(scannableDrives.map((d) => d.path)));
  }

  function selectNone() {
    if (running) return;
    setSelected(new Set());
  }

  // 订阅多盘扫描事件
  useEffect(() => {
    if (!running) return;
    const offStart = window.runtime?.EventsOn("parallel:diskStart", (j: DiskJob) => {
      setDriveState((s) => ({
        ...s,
        [j.DrivePath]: { status: "running", progress: {}, filesFound: 0 },
      }));
    });
    const offProgress = window.runtime?.EventsOn(
      "parallel:diskProgress",
      (p: { drive: string; progress: ScanProgress }) => {
        setDriveState((s) => ({
          ...s,
          [p.drive]: {
            ...(s[p.drive] || { status: "running", filesFound: 0 }),
            status: "running",
            progress: p.progress,
            filesFound: p.progress?.filesFound ?? s[p.drive]?.filesFound ?? 0,
          },
        }));
      },
    );
    const offFile = window.runtime?.EventsOn(
      "parallel:fileFound",
      (p: { drive: string }) => {
        setDriveState((s) => {
          const cur = s[p.drive];
          if (!cur) return s;
          return { ...s, [p.drive]: { ...cur, filesFound: cur.filesFound + 1 } };
        });
      },
    );
    const offDone = window.runtime?.EventsOn(
      "parallel:diskDone",
      (r: JobResultPayload) => {
        setDriveState((s) => ({
          ...s,
          [r.drivePath]: {
            ...(s[r.drivePath] || { progress: {}, filesFound: 0 }),
            status: r.error ? "error" : "done",
            error: r.error,
            filesFound: r.result?.files?.length ?? s[r.drivePath]?.filesFound ?? 0,
          },
        }));
      },
    );
    const offAll = window.runtime?.EventsOn("parallel:allDone", () => {
      setRunning(false);
      setDone(true);
      cleanupRef.current?.();
      cleanupRef.current = null;
    });
    cleanupRef.current = () => {
      offStart?.();
      offProgress?.();
      offFile?.();
      offDone?.();
      offAll?.();
    };
    return () => {
      cleanupRef.current?.();
      cleanupRef.current = null;
    };
  }, [running]);

  async function startScan() {
    if (selected.size === 0) {
      toast.warning("请至少选 1 块盘");
      return;
    }
    const jobs: DiskJob[] = Array.from(selected).map((path) => ({
      DrivePath: path,
      Mode: mode,
    }));
    // 重置每盘状态
    const init: Record<string, DriveState> = {};
    for (const p of selected) {
      init[p] = { status: "pending", progress: {}, filesFound: 0 };
    }
    setDriveState(init);
    setDone(false);
    setRunning(true);
    try {
      await wailsApp?.StartParallelScanDrives?.(jobs, maxParallel);
    } catch (err: any) {
      setRunning(false);
      toast.error("启动多盘扫描失败：" + (err?.message || err));
    }
  }

  function cancelScan() {
    wailsApp?.CancelParallelScan?.();
    setRunning(false);
    // 把还没完成的 drive 标 cancelled
    setDriveState((s) => {
      const next = { ...s };
      for (const k of Object.keys(next)) {
        if (next[k].status === "running" || next[k].status === "pending") {
          next[k] = { ...next[k], status: "cancelled" };
        }
      }
      return next;
    });
  }

  function tryClose() {
    if (running) {
      wailsApp?.CancelParallelScan?.();
    }
    onClose();
  }

  return (
    <div className="preview-modal" onClick={tryClose} role="dialog" aria-label="多盘并行扫描">
      <div
        className="preview-modal__inner"
        style={{ maxWidth: 820, width: "94%" }}
        onClick={(e) => e.stopPropagation()}
      >
        <div className="preview-modal__header">
          <div className="preview-modal__title" style={{ overflow: "visible" }}>
            ⚡ 多盘并行扫描
          </div>
          <button className="btn btn--ghost btn--sm" onClick={tryClose} aria-label="关闭" title="关闭">
            <IconX size={14} />
          </button>
        </div>

        <div className="preview-modal__body" style={{ display: "block", padding: "18px 20px" }}>
          {!running && !done && (
            <>
              {/* 盘列表 */}
              <div className="field" style={{ marginBottom: 12 }}>
                <label
                  className="field__label"
                  style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}
                >
                  <span>选择要扫描的盘（可多选）</span>
                  <span style={{ display: "flex", gap: 6 }}>
                    <button className="btn btn--ghost btn--sm" onClick={selectAll}>全选</button>
                    <button className="btn btn--ghost btn--sm" onClick={selectNone}>清空</button>
                  </span>
                </label>
                <div
                  style={{
                    display: "grid",
                    gridTemplateColumns: "repeat(auto-fill, minmax(220px, 1fr))",
                    gap: 8,
                    marginTop: 6,
                    maxHeight: 280,
                    overflowY: "auto",
                    padding: 4,
                  }}
                >
                  {scannableDrives.map((d) => {
                    const checked = selected.has(d.path);
                    const Icon = d.isRemovable ? IconUsb : IconHardDrive;
                    return (
                      <label
                        key={d.path}
                        className="checkbox"
                        style={{
                          padding: "10px 12px",
                          background: checked ? "var(--accent-soft)" : "var(--bg-surface-2)",
                          border: `1px solid ${checked ? "var(--accent-border)" : "var(--border)"}`,
                          borderRadius: "var(--radius-md)",
                          alignItems: "flex-start",
                          gap: 10,
                          cursor: "pointer",
                        }}
                      >
                        <input
                          type="checkbox"
                          checked={checked}
                          onChange={() => toggleDrive(d.path)}
                        />
                        <Icon size={16} style={{ color: checked ? "var(--accent)" : "var(--text-muted)", flex: "none", marginTop: 2 }} />
                        <div style={{ flex: 1, minWidth: 0 }}>
                          <div className="ellipsis" style={{ fontSize: "var(--text-sm)", fontWeight: "var(--weight-semibold)" }} title={d.name}>
                            {d.name || d.path}
                          </div>
                          <div className="muted ellipsis" style={{ fontSize: "var(--text-xs)" }} title={d.path}>
                            {d.path} · {formatSize(d.size)}
                          </div>
                        </div>
                      </label>
                    );
                  })}
                  {scannableDrives.length === 0 && (
                    <div className="muted" style={{ gridColumn: "1 / -1", padding: 16, textAlign: "center" }}>
                      没有可扫描的盘 —— 请在主界面刷新盘列表后再试。
                    </div>
                  )}
                </div>
              </div>

              {/* 扫描参数 */}
              <div style={{ display: "flex", gap: 12, marginBottom: 12 }}>
                <div className="field" style={{ flex: 1 }}>
                  <label className="field__label">扫描模式</label>
                  <select
                    className="select"
                    value={mode}
                    onChange={(e) => setMode(e.target.value)}
                  >
                    {MODES.map((m) => (
                      <option key={m.value} value={m.value}>{m.label}</option>
                    ))}
                  </select>
                </div>
                <div className="field" style={{ width: 160 }}>
                  <label className="field__label">同时最多扫</label>
                  <input
                    className="input"
                    type="number"
                    min={1}
                    max={8}
                    value={maxParallel}
                    onChange={(e) => setMaxParallel(Math.max(1, Math.min(8, Number(e.target.value) || 1)))}
                  />
                </div>
              </div>

              <div className="muted" style={{ fontSize: "var(--text-xs)", lineHeight: 1.6 }}>
                提示：并发数太大会让 IO 互相争抢反而变慢。SSD 建议 2-4，HDD 建议 1-2。
                每盘的扫描结果**不会**自动加到主 workbench —— 这是个独立的批量工具，
                适合「先粗扫所有盘看哪盘有想要的东西，再单独深扫那一盘」的场景。
              </div>
            </>
          )}

          {(running || done) && (
            <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
              {Object.entries(driveState).map(([path, st]) => {
                const drive = drives.find((d) => d.path === path);
                const percent = Math.max(0, Math.min(100, st.progress.percent || 0));
                const Icon = drive?.isRemovable ? IconUsb : IconHardDrive;
                const statusBadge =
                  st.status === "done" ? <IconCheck size={13} style={{ color: "var(--success)" }} /> :
                  st.status === "error" ? <IconAlertTriangle size={13} style={{ color: "var(--danger)" }} /> :
                  st.status === "cancelled" ? <IconStop size={13} style={{ color: "var(--text-muted)" }} /> :
                  st.status === "pending" ? <span className="muted" style={{ fontSize: 11 }}>等待</span> :
                  <IconPlay size={13} style={{ color: "var(--accent)" }} />;
                return (
                  <div key={path} className="card" style={{ padding: 10 }}>
                    <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 6 }}>
                      <Icon size={16} style={{ color: "var(--text-muted)", flex: "none" }} />
                      <div style={{ flex: 1, minWidth: 0 }}>
                        <div className="ellipsis" style={{ fontSize: "var(--text-sm)", fontWeight: "var(--weight-semibold)" }} title={drive?.name || path}>
                          {drive?.name || path}
                        </div>
                        <div className="muted ellipsis" style={{ fontSize: "var(--text-xs)" }} title={path}>{path}</div>
                      </div>
                      <span style={{ display: "inline-flex", alignItems: "center", gap: 4, fontSize: "var(--text-xs)" }}>
                        {statusBadge}
                        <b style={{ fontVariantNumeric: "tabular-nums" }}>{percent.toFixed(1)}%</b>
                      </span>
                    </div>
                    <div className="progress">
                      <div className="progress__fill" style={{ width: `${percent}%` }} />
                    </div>
                    <div className="muted" style={{ fontSize: "var(--text-xs)", marginTop: 4, display: "flex", gap: 12, flexWrap: "wrap" }}>
                      <span>已发现 <b>{st.filesFound.toLocaleString()}</b></span>
                      {st.progress.speed != null && st.progress.speed > 0 && (
                        <span>速度 <b>{formatSize(st.progress.speed)}/s</b></span>
                      )}
                      {st.progress.elapsed && (
                        <span>已用 <b>{st.progress.elapsed}</b></span>
                      )}
                      {st.error && (
                        <span style={{ color: "var(--danger)" }}>错误：{st.error}</span>
                      )}
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>

        <div className="preview-modal__footer" style={{ display: "flex", justifyContent: "flex-end", gap: 8 }}>
          {!running && !done && (
            <>
              <button className="btn btn--ghost btn--sm" onClick={tryClose}>取消</button>
              <button className="btn btn--primary btn--sm" onClick={startScan} disabled={selected.size === 0}>
                <IconPlay size={14} /> 开始扫描（{selected.size} 块盘）
              </button>
            </>
          )}
          {running && (
            <>
              <button className="btn btn--danger btn--sm" onClick={cancelScan}>
                <IconStop size={14} /> 停止全部
              </button>
            </>
          )}
          {done && (
            <button className="btn btn--primary btn--sm" onClick={onClose}>完成</button>
          )}
        </div>
      </div>
    </div>
  );
}
