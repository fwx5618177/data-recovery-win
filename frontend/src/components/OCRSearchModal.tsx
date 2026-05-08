/**
 * <OCRSearchModal> —— OCR 搜图 Modal（v2.8.4）。
 *
 * 功能：
 *   - 选目录 → 关键词 → 选语言 → 搜
 *   - 后端走 EventsOn 流式回 ocr:progress / ocr:hit / ocr:done / ocr:error
 *   - 内置 eng + chi_sim 默认勾上；其它语言 + 按需下载（点 "+" 走 OCRDownloadLanguage IPC）
 *   - 已下载非内置语言可删除
 *
 * 设计：
 *   - 不依赖外部 Modal 组件，复用 .preview-modal CSS（项目里已有）
 *   - 状态机：idle → searching（不可关）→ done（显示结果） → idle 关
 *   - cancel：用户关 modal 触发 OCRCancelSearch
 */

import React, { useEffect, useRef, useState } from "react";
import {
  IconX,
  IconSearch,
  IconFolderOpen,
  IconCheck,
  IconAlertTriangle,
  IconRefresh,
  IconDownload,
} from "../icons";
import { toast } from "../toast";

interface LanguageInfo {
  code: string;
  name: string;
  builtin?: boolean;
  installed?: boolean;
  sizeBytes?: number;
}

interface OCRStatus {
  binaryPath: string;
  binaryFound: boolean;
  binaryVersion: string;
  tessdataDir: string;
  installedLangs: string[];
  builtinLangs: string[];
  notFoundHint?: string;
}

interface SearchProgressPayload {
  current: number;
  total: number;
  currentFile: string;
  hitCount: number;
}

declare global {
  interface Window {
    runtime?: {
      EventsOn: (event: string, cb: (...args: any[]) => void) => () => void;
    };
    go?: any;
  }
}

interface Props {
  wailsApp: any;
  outputDir?: string;
  onClose: () => void;
}

export default function OCRSearchModal({ wailsApp, outputDir, onClose }: Props) {
  const [status, setStatus] = useState<OCRStatus | null>(null);
  const [langs, setLangs] = useState<LanguageInfo[]>([]);
  const [dir, setDir] = useState<string>(outputDir || "");
  const [keyword, setKeyword] = useState<string>("");
  const [selectedLangs, setSelectedLangs] = useState<string[]>(["eng", "chi_sim"]);
  const [showLangManager, setShowLangManager] = useState<boolean>(false);
  const [downloading, setDownloading] = useState<Record<string, boolean>>({});

  const [searching, setSearching] = useState(false);
  const [progress, setProgress] = useState<SearchProgressPayload | null>(null);
  const [hits, setHits] = useState<string[]>([]);
  const [doneMsg, setDoneMsg] = useState<string | null>(null);
  const cleanupRef = useRef<(() => void) | null>(null);

  // 加载 status / 语言列表
  const refreshStatus = async () => {
    try {
      const [st, ll] = await Promise.all([
        wailsApp?.OCRStatus?.(),
        wailsApp?.OCRListLanguages?.(),
      ]);
      setStatus(st);
      setLangs(ll || []);
    } catch (err: any) {
      toast.error("OCR 状态查询失败：" + (err?.message || err));
    }
  };

  useEffect(() => {
    refreshStatus();
  }, []);

  // 订阅事件
  useEffect(() => {
    if (!searching) return;
    const offProgress = window.runtime?.EventsOn("ocr:progress", (p: SearchProgressPayload) => {
      setProgress(p);
    });
    const offHit = window.runtime?.EventsOn("ocr:hit", (h: { path: string }) => {
      setHits((prev) => [...prev, h.path]);
    });
    const offDone = window.runtime?.EventsOn("ocr:done", (d: { hits: string[]; count: number }) => {
      setSearching(false);
      setDoneMsg(`扫描完成，命中 ${d.count} 张图片`);
      cleanupRef.current?.();
      cleanupRef.current = null;
    });
    const offError = window.runtime?.EventsOn("ocr:error", (e: { message: string }) => {
      setSearching(false);
      setDoneMsg("扫描失败：" + e.message);
      cleanupRef.current?.();
      cleanupRef.current = null;
    });
    cleanupRef.current = () => {
      offProgress?.();
      offHit?.();
      offDone?.();
      offError?.();
    };
    return () => {
      cleanupRef.current?.();
      cleanupRef.current = null;
    };
  }, [searching]);

  async function pickDir() {
    try {
      const p = await wailsApp?.SelectDirectory?.("选择要 OCR 搜索的目录");
      if (p) setDir(p);
    } catch (err: any) {
      toast.error("选目录失败：" + (err?.message || err));
    }
  }

  async function startSearch() {
    if (!dir) { toast.warning("请先选目录"); return; }
    if (!keyword.trim()) { toast.warning("请输入关键词"); return; }
    if (selectedLangs.length === 0) { toast.warning("请至少选一种语言"); return; }
    setHits([]);
    setProgress(null);
    setDoneMsg(null);
    setSearching(true);
    try {
      await wailsApp?.OCRSearchDirectory?.(dir, keyword.trim(), selectedLangs);
    } catch (err: any) {
      setSearching(false);
      toast.error("启动搜索失败：" + (err?.message || err));
    }
  }

  async function handleDownload(code: string) {
    setDownloading((d) => ({ ...d, [code]: true }));
    try {
      await wailsApp?.OCRDownloadLanguage?.(code);
      toast.success(`已下载语言包 ${code}`);
      await refreshStatus();
    } catch (err: any) {
      toast.error(`下载 ${code} 失败：` + (err?.message || err));
    } finally {
      setDownloading((d) => { const next = { ...d }; delete next[code]; return next; });
    }
  }

  async function handleDelete(code: string) {
    try {
      await wailsApp?.OCRDeleteLanguage?.(code);
      toast.success(`已删除语言包 ${code}`);
      setSelectedLangs((s) => s.filter((c) => c !== code));
      await refreshStatus();
    } catch (err: any) {
      toast.error(`删除失败：` + (err?.message || err));
    }
  }

  function tryClose() {
    if (searching) {
      wailsApp?.OCRCancelSearch?.();
      setSearching(false);
    }
    onClose();
  }

  const installedLangs = langs.filter((l) => l.installed);
  const downloadableLangs = langs.filter((l) => !l.installed);

  return (
    // 关键：v2.8.16 起背景层不再触发关闭 —— 关闭只走右上 X 或底部"关闭"按钮。
    // 之前的 onClick={tryClose} 容易误触（用户拖到 OCR 搜索运行中点旁边整个工具关掉）。
    <div className="preview-modal" role="dialog" aria-label="OCR 搜图">
      <div className="preview-modal__inner" style={{ maxWidth: 720, width: "92%" }}>
        <div className="preview-modal__header">
          <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <IconSearch size={18} style={{ color: "var(--accent)" }} />
            <div className="preview-modal__title" style={{ overflow: "visible" }}>
              OCR 搜图
              {status?.binaryVersion && (
                <span className="muted" style={{ fontSize: "var(--text-xs)", marginLeft: 8, fontWeight: "normal" }}>
                  · {status.binaryVersion}
                </span>
              )}
            </div>
          </div>
          <button className="btn btn--ghost btn--sm" onClick={tryClose} aria-label="关闭" title="关闭">
            <IconX size={14} />
          </button>
        </div>

        <div className="preview-modal__body" style={{ display: "block", padding: "18px 20px" }}>
          {/* 引擎不可用警告 */}
          {status && !status.binaryFound && (
            <div className="banner banner--warning" style={{ marginBottom: 14 }}>
              <IconAlertTriangle size={18} className="banner__icon" />
              <div className="banner__content">
                <div className="banner__title">OCR 引擎未找到</div>
                <div className="banner__text" style={{ whiteSpace: "pre-wrap" }}>{status.notFoundHint}</div>
                {/* v2.8.17 Issue 10：一键 winget 安装。GitHub releases 在国内访问不稳，
                    winget 内置在 Win10 21H1+ / Win11 命令一键。点击会打开 cmd 窗口
                    让用户看到下载进度 + UAC 提示。 */}
                {wailsApp?.Platform && (
                  <WingetInstallButton wailsApp={wailsApp} onInstalled={refreshStatus} />
                )}
              </div>
            </div>
          )}

          {/* 输入：目录 + 关键词 */}
          <div className="field" style={{ marginBottom: 12 }}>
            <label className="field__label">扫描目录（递归）</label>
            <div style={{ display: "flex", gap: 8 }}>
              <input
                className="input"
                style={{ flex: 1 }}
                value={dir}
                onChange={(e) => setDir(e.target.value)}
                placeholder="例：D:\\Recovery\\Pictures"
                disabled={searching}
              />
              <button className="btn btn--sm" onClick={pickDir} disabled={searching} title="选目录">
                <IconFolderOpen size={14} /> 选目录
              </button>
            </div>
          </div>

          <div className="field" style={{ marginBottom: 12 }}>
            <label className="field__label">关键词（不区分大小写）</label>
            <input
              className="input"
              value={keyword}
              onChange={(e) => setKeyword(e.target.value)}
              placeholder="例：会议纪要 / contract / 合同"
              disabled={searching}
              onKeyDown={(e) => { if (e.key === "Enter") startSearch(); }}
            />
          </div>

          {/* 语言选择 */}
          <div className="field" style={{ marginBottom: 12 }}>
            <label className="field__label" style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
              <span>识别语言（可多选）</span>
              <button
                className="btn btn--ghost btn--sm"
                onClick={() => setShowLangManager((v) => !v)}
                style={{ fontSize: "var(--text-xs)" }}
                disabled={searching}
              >
                {showLangManager ? "收起语言包管理" : "+ 添加 / 管理语言"}
              </button>
            </label>
            <div style={{ display: "flex", flexWrap: "wrap", gap: 6, marginTop: 6 }}>
              {installedLangs.map((l) => {
                const checked = selectedLangs.includes(l.code);
                return (
                  <label
                    key={l.code}
                    className="checkbox"
                    style={{
                      padding: "4px 10px",
                      border: `1px solid ${checked ? "var(--accent-border)" : "var(--border)"}`,
                      background: checked ? "var(--accent-soft)" : "var(--bg-surface-2)",
                      borderRadius: "var(--radius-pill)",
                      fontSize: "var(--text-sm)",
                    }}
                  >
                    <input
                      type="checkbox"
                      checked={checked}
                      onChange={(e) => {
                        if (e.target.checked) setSelectedLangs((s) => [...s, l.code]);
                        else setSelectedLangs((s) => s.filter((c) => c !== l.code));
                      }}
                      disabled={searching}
                    />
                    {l.name}
                    {l.builtin && (
                      <span className="muted" style={{ fontSize: "var(--text-xs)", marginLeft: 4 }}>· 内置</span>
                    )}
                  </label>
                );
              })}
            </div>
          </div>

          {/* 语言包管理面板（折叠） */}
          {showLangManager && (
            <div className="card" style={{ marginBottom: 14, padding: 12 }}>
              <div className="text-strong" style={{ fontSize: "var(--text-sm)", marginBottom: 6 }}>已下载</div>
              <div style={{ display: "flex", flexWrap: "wrap", gap: 6, marginBottom: 12 }}>
                {installedLangs.map((l) => (
                  <span
                    key={l.code}
                    className="badge"
                    style={{
                      display: "inline-flex",
                      alignItems: "center",
                      gap: 4,
                      padding: "3px 8px",
                    }}
                  >
                    <IconCheck size={11} /> {l.name}
                    {!l.builtin && (
                      <button
                        className="btn btn--ghost"
                        style={{ padding: 0, minHeight: 0, marginLeft: 4 }}
                        onClick={() => handleDelete(l.code)}
                        title="删除该语言包"
                      >
                        <IconX size={11} />
                      </button>
                    )}
                  </span>
                ))}
              </div>

              <div className="text-strong" style={{ fontSize: "var(--text-sm)", marginBottom: 6 }}>
                可下载 <span className="muted" style={{ fontWeight: "normal" }}>· 来自 tessdata_fast 官方仓库</span>
              </div>
              <div style={{
                display: "grid",
                gridTemplateColumns: "repeat(auto-fill, minmax(180px, 1fr))",
                gap: 6,
                maxHeight: 240,
                overflowY: "auto",
              }}>
                {downloadableLangs.map((l) => {
                  const isDownloading = !!downloading[l.code];
                  return (
                    <button
                      key={l.code}
                      className="btn btn--sm"
                      onClick={() => handleDownload(l.code)}
                      disabled={isDownloading}
                      style={{ justifyContent: "flex-start" }}
                    >
                      {isDownloading ? <IconRefresh size={12} className="muted" /> : <IconDownload size={12} />}
                      <span className="ellipsis" style={{ flex: 1, textAlign: "left" }}>{l.name}</span>
                      <span className="muted" style={{ fontSize: "var(--text-xs)" }}>{l.code}</span>
                    </button>
                  );
                })}
              </div>
            </div>
          )}

          {/* 进度 / 结果 */}
          {searching && progress && (
            <div className="card" style={{ marginBottom: 14, padding: 12 }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 6 }}>
                <span className="text-strong" style={{ fontSize: "var(--text-sm)" }}>
                  正在 OCR：{progress.current} / {progress.total} 张
                </span>
                <span className="muted" style={{ fontSize: "var(--text-xs)" }}>命中 {progress.hitCount}</span>
              </div>
              <div className="progress">
                <div className="progress__fill" style={{ width: `${(progress.current / Math.max(progress.total, 1)) * 100}%` }} />
              </div>
              {progress.currentFile && (
                <div className="muted mono ellipsis" style={{ fontSize: "var(--text-xs)", marginTop: 4 }} title={progress.currentFile}>
                  {progress.currentFile}
                </div>
              )}
            </div>
          )}

          {doneMsg && (
            <div className="banner banner--info" style={{ marginBottom: 14 }}>
              <IconCheck size={18} className="banner__icon" />
              <div className="banner__content">
                <div className="banner__title">{doneMsg}</div>
              </div>
            </div>
          )}

          {hits.length > 0 && (
            <div style={{ marginBottom: 14 }}>
              <div className="text-strong" style={{ fontSize: "var(--text-sm)", marginBottom: 6 }}>
                命中文件 <span className="muted" style={{ fontWeight: "normal" }}>· {hits.length}</span>
              </div>
              <div style={{
                maxHeight: 200,
                overflowY: "auto",
                border: "1px solid var(--border)",
                borderRadius: "var(--radius-md)",
                padding: 8,
                background: "var(--bg-inset)",
              }}>
                {hits.map((p, i) => (
                  <div key={i} className="mono ellipsis" style={{ fontSize: "var(--text-xs)", padding: "2px 0" }} title={p}>
                    {p}
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>

        <div className="preview-modal__footer" style={{ display: "flex", justifyContent: "space-between" }}>
          <span className="muted" style={{ fontSize: "var(--text-xs)" }}>
            内嵌 traineddata（fast 模型，eng + chi_sim 开箱）· 其它语言官方仓库按需下载
          </span>
          <div style={{ display: "flex", gap: 8 }}>
            <button className="btn btn--ghost btn--sm" onClick={tryClose}>关闭</button>
            <button
              className="btn btn--primary btn--sm"
              onClick={startSearch}
              disabled={searching || !status?.binaryFound}
            >
              <IconSearch size={14} /> {searching ? "搜索中…" : "开始搜索"}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

/**
 * WingetInstallButton — v2.8.17 加。
 *
 * 给"OCR 引擎未找到"banner 用：一键 winget install Tesseract。比让用户去 GitHub
 * releases 手动下载安装包好得多（特别是国内访问 GitHub 不稳）。
 *
 * 用户点击 → 后端 cmd /C start winget install ... → 打开新 cmd 窗口跑 winget →
 * UAC 提示 → 下载安装 → 装完用户回这里点"我已安装，重新检测"或重开 OCR modal。
 */
function WingetInstallButton({ wailsApp, onInstalled }: { wailsApp: any; onInstalled: () => void }) {
  const [platform, setPlatform] = useState<string>("");
  const [launching, setLaunching] = useState(false);
  const [launched, setLaunched] = useState(false);

  useEffect(() => {
    wailsApp?.Platform?.().then((p: string) => setPlatform(p)).catch(() => {});
  }, [wailsApp]);

  if (platform !== "windows") {
    return null; // 非 Windows 不显示（macOS/Linux 用 brew/apt）
  }

  const handleInstall = async () => {
    if (!wailsApp?.InstallTesseractViaWinget) return;
    setLaunching(true);
    try {
      await wailsApp.InstallTesseractViaWinget();
      setLaunched(true);
      // 不自动 refresh —— winget 异步下载，用户装完手动点重新检测
    } catch (err: any) {
      const msg = err?.message || String(err);
      // 简化错误：winget 不存在的话提示用户
      if (msg.includes("winget") || msg.includes("找不到") || msg.includes("not found")) {
        alert("找不到 winget 命令。请先在 Microsoft Store 搜索 'App Installer' 安装。");
      } else {
        alert("启动 winget 失败：" + msg);
      }
    } finally {
      setLaunching(false);
    }
  };

  if (launched) {
    return (
      <div style={{ marginTop: 10, display: "flex", gap: 8, alignItems: "center" }}>
        <span className="muted" style={{ fontSize: "var(--text-xs)" }}>
          ✓ 已启动 winget。装完后点击下方按钮重新检测：
        </span>
        <button className="btn btn--sm btn--primary" onClick={onInstalled}>
          重新检测
        </button>
      </div>
    );
  }

  return (
    <div style={{ marginTop: 10 }}>
      <button
        className="btn btn--sm btn--primary"
        onClick={handleInstall}
        disabled={launching}
        title="用 Windows 内置 winget 一键安装 Tesseract OCR（推荐）"
      >
        {launching ? "正在启动..." : "🚀 一键安装 (winget)"}
      </button>
      <span className="muted" style={{ marginLeft: 10, fontSize: "var(--text-xs)" }}>
        Win10 21H1+ / Win11 内置 winget；首次安装会弹 UAC 提示
      </span>
    </div>
  );
}
