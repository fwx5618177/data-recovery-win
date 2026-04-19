import React, {
  startTransition,
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import WelcomePage from "./components/WelcomePage";
import Workbench from "./components/Workbench";
import RecoveryPage from "./components/RecoveryPage";
import {
  DEFAULT_SCAN_MODE,
  getDriveLabel,
  isCancellationError,
  mergeFileIntoIndex,
  normalizeRecoveryCompletion,
} from "./recovery-helpers";
import { IconAlertTriangle, IconShield } from "./icons";
import "./style.css";
import "./App.css";

/* 三步工作流。旧版的 Scanning / Results 合并成 Workbench。 */
const FLOW_STEPS = [
  { key: "welcome", label: "选源盘" },
  { key: "workbench", label: "扫描 & 挑文件" },
  { key: "recovery", label: "恢复报告" },
];

const INITIAL_SCAN_PROGRESS = {
  phase: "ready",
  percent: 0,
  bytesScanned: 0,
  totalBytes: 0,
  filesFound: 0,
  currentFile: "",
  speed: 0,
  eta: "--",
  elapsed: "--",
};

const INITIAL_RECOVERY_PROGRESS = {
  current: 0,
  total: 0,
  currentFile: "",
  bytesWritten: 0,
  success: 0,
  partial: 0,
  failed: 0,
};

function getErrorText(error) {
  return String(error?.message || error || "").trim();
}

function getFriendlyActionError(action, error) {
  const text = getErrorText(error);
  if (!text) return `${action}失败，请重试一次。`;
  if (/管理员|权限|uac|access denied|sudo|permission/i.test(text))
    return `${action}失败。\n请允许管理员 / root 权限后再试。`;
  if (/同一块物理磁盘|同一块磁盘|源盘所在/i.test(text))
    return `${action}失败。\n恢复目录和源盘在同一块磁盘上，继续写入会覆盖待恢复数据。\n请改选另一块磁盘或 U 盘。`;
  if (/未选择任何文件|未找到要恢复的文件/i.test(text))
    return `${action}失败。\n请先选择要恢复的文件。`;
  if (/恢复引擎|bridge|wails/i.test(text))
    return `${action}失败。\n当前没有连接到本地恢复引擎，请从桌面版程序启动。`;
  return `${action}失败。\n${text}`;
}

function flowIndex(key) {
  return FLOW_STEPS.findIndex((s) => s.key === key);
}
function flowState(current, key) {
  const c = flowIndex(current);
  const k = flowIndex(key);
  if (k < c) return "done";
  if (k === c) return "active";
  return "idle";
}

export default function App() {
  // ------------------------- bridge / runtime -------------------------
  const [bridgeState, setBridgeState] = useState("loading"); // loading | ready | error
  const [bridgeError, setBridgeError] = useState("");
  const [wailsApp, setWailsApp] = useState(null);
  const [wailsRuntime, setWailsRuntime] = useState(null);

  // ------------------------- 权限 / 平台 -------------------------
  const [isAdmin, setIsAdmin] = useState(false);
  const [platform, setPlatform] = useState("");

  // ------------------------- 流程 / 页面 -------------------------
  const [currentPage, setCurrentPage] = useState("welcome");

  // ------------------------- 磁盘 -------------------------
  const [drives, setDrives] = useState([]);
  const [isLoadingDrives, setIsLoadingDrives] = useState(false);
  const [driveLoadError, setDriveLoadError] = useState("");
  const [selectedDrive, setSelectedDrive] = useState(null);

  // ------------------------- 会话 -------------------------
  const [pendingSession, setPendingSession] = useState(null);

  // ------------------------- VSS 卷影副本 -------------------------
  // 仅在 Windows 平台才有数据；非 Windows 一律空数组
  const [shadows, setShadows] = useState([]);

  // ------------------------- 扫描态 -------------------------
  const [scanActive, setScanActive] = useState(false);
  const [scanProgress, setScanProgress] = useState(INITIAL_SCAN_PROGRESS);
  const [files, setFiles] = useState([]);
  // 为了在 10k+ 文件规模下避免每次事件都重复 map.findIndex，用 Map 做索引
  const fileIndexRef = useRef(new Map());
  // 扫描事件来得很密，用节流 flush 降 React 重渲染压力
  const pendingFilesRef = useRef([]);
  const flushTimerRef = useRef(null);

  // ------------------------- 输出目录 -------------------------
  const [outputDir, setOutputDir] = useState("");
  const [outputValidation, setOutputValidation] = useState("");
  const [outputFreeSpace, setOutputFreeSpace] = useState(null);

  // ------------------------- 恢复态 -------------------------
  const [recoveryActive, setRecoveryActive] = useState(false);
  const [recoveryProgress, setRecoveryProgress] = useState(INITIAL_RECOVERY_PROGRESS);
  const [recoveryRecords, setRecoveryRecords] = useState([]);

  // ------------------------- 版本更新态 -------------------------
  // updateInfo:     null 代表没检查到更新；对象代表有新版可用
  // downloadState:  "idle" | "downloading" | "done" | "error"
  // pendingUpdate:  已下载好、等重启应用的 Pending；从后端拉或 update:downloaded 事件得
  const [updateInfo, setUpdateInfo] = useState(null);
  const [updateDismissed, setUpdateDismissed] = useState(false);
  const [downloadState, setDownloadState] = useState("idle");
  const [downloadProgress, setDownloadProgress] = useState(null);
  const [pendingUpdate, setPendingUpdate] = useState(null);

  /* =====================================================================
     1. 加载 Wails bridge
     ===================================================================== */
  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const appMod = await import("../wailsjs/go/main/App");
        const rtMod = await import("../wailsjs/runtime/runtime");
        if (cancelled) return;
        setWailsApp(appMod);
        setWailsRuntime(rtMod);
        setBridgeError("");
        setBridgeState("ready");
      } catch (err) {
        if (cancelled) return;
        setBridgeState("error");
        setBridgeError(
          `无法连接本地恢复引擎，请从桌面版程序启动（不要直接在浏览器里跑真实恢复）。\n\n技术信息：${
            getErrorText(err) || "未知错误"
          }`,
        );
      }
    })();
    return () => { cancelled = true; };
  }, []);

  /* =====================================================================
     2. Bridge 就绪后：读权限、平台、磁盘、会话
     ===================================================================== */
  const loadDrives = useCallback(async () => {
    if (bridgeState !== "ready" || !wailsApp?.GetDrives) {
      setDrives([]);
      return;
    }
    setIsLoadingDrives(true);
    setDriveLoadError("");
    try {
      const list = await wailsApp.GetDrives();
      setDrives(Array.isArray(list) ? list : []);
    } catch (err) {
      setDrives([]);
      setDriveLoadError(getFriendlyActionError("读取磁盘列表", err));
    } finally {
      setIsLoadingDrives(false);
    }
  }, [bridgeState, wailsApp]);

  useEffect(() => {
    if (bridgeState !== "ready" || !wailsApp) return;
    (async () => {
      try { setIsAdmin(Boolean(await wailsApp.IsAdmin())); } catch { /* noop */ }
      try { setPlatform(String(await wailsApp.Platform())); } catch { /* noop */ }
      try {
        if (wailsApp.LoadLastSession) {
          const snap = await wailsApp.LoadLastSession();
          if (snap && Array.isArray(snap.files)) setPendingSession(snap);
        }
      } catch { /* noop */ }
      // VSS 枚举：非 Windows 会返回 null；Windows 无快照返回空数组
      try {
        if (wailsApp.ListShadowCopies) {
          const list = await wailsApp.ListShadowCopies();
          if (Array.isArray(list)) setShadows(list);
        }
      } catch { /* noop */ }
    })();
    loadDrives();
  }, [bridgeState, wailsApp, loadDrives]);

  // 选中盘的外部同步：如果磁盘列表刷新后找不到之前选的盘，清除选择
  useEffect(() => {
    if (!selectedDrive) return;
    const match = drives.find((d) => d.path === selectedDrive.path);
    if (!match) setSelectedDrive(null);
    else if (match !== selectedDrive) setSelectedDrive(match);
  }, [drives, selectedDrive]);

  /* =====================================================================
     3. 扫描事件订阅（节流合并到 state）
     ===================================================================== */
  const flushPending = useCallback(() => {
    const pending = pendingFilesRef.current;
    if (pending.length === 0) return;
    pendingFilesRef.current = [];
    flushTimerRef.current = null;

    const idx = fileIndexRef.current;
    let anyNew = false;
    pending.forEach((f) => {
      if (!f?.id) return;
      if (!idx.has(f.id)) anyNew = true;
      mergeFileIntoIndex(idx, f);
    });
    if (!anyNew && pending.every((f) => idx.has(f?.id))) {
      // 全是更新也要重绘
    }
    startTransition(() => {
      setFiles(Array.from(idx.values()));
    });
  }, []);

  const queueFile = useCallback((file) => {
    if (!file?.id) return;
    pendingFilesRef.current.push(file);
    if (flushTimerRef.current) return;
    flushTimerRef.current = setTimeout(flushPending, 200);
  }, [flushPending]);

  useEffect(() => () => {
    if (flushTimerRef.current) clearTimeout(flushTimerRef.current);
  }, []);

  useEffect(() => {
    if (bridgeState !== "ready" || !wailsRuntime?.EventsOn) return;

    const offProg = wailsRuntime.EventsOn("scan:progress", (p) => {
      setScanProgress((prev) => {
        const merged = { ...prev, ...p };
        // 单调进度：阶段切换（ntfs → carving → validating）会引起百分比基线变动，
        // 兜底不让显示值倒退，避免用户觉得"扫着扫着倒退了"
        if (typeof prev.percent === "number" && typeof merged.percent === "number") {
          if (merged.percent < prev.percent && merged.percent < 100) {
            merged.percent = prev.percent;
          }
        }
        return merged;
      });
    });
    const offFound = wailsRuntime.EventsOn("scan:fileFound", (f) => queueFile(f));
    const offDone = wailsRuntime.EventsOn("scan:completed", (result) => {
      setScanActive(false);
      flushPending();
      if (Array.isArray(result?.files)) {
        // 全量覆盖（例如 completed 带回排序后结果）
        const idx = new Map();
        result.files.forEach((f) => { if (f?.id) idx.set(f.id, f); });
        fileIndexRef.current = idx;
        startTransition(() => setFiles(Array.from(idx.values())));
      }
    });
    const offErr = wailsRuntime.EventsOn("scan:error", async (payload) => {
      const msg = payload?.message || payload || "未知错误";
      setScanActive(false);
      flushPending();
      if (isCancellationError(msg)) return; // 用户主动停，静默
      alert(getFriendlyActionError("扫描", msg));
    });

    const offRecProg = wailsRuntime.EventsOn("recovery:progress", (p) => {
      setRecoveryProgress((prev) => normalizeRecoveryCompletion(p, prev.total, prev.bytesWritten));
    });
    const offRecDone = wailsRuntime.EventsOn("recovery:completed", (p) => {
      const norm = normalizeRecoveryCompletion(p, 0, 0);
      setRecoveryProgress(norm);
      setRecoveryActive(false);
      if (norm.records) setRecoveryRecords(norm.records);
      else if (wailsApp?.GetLastRecoveryRecords) {
        wailsApp.GetLastRecoveryRecords().then((list) => setRecoveryRecords(list || [])).catch(() => {});
      }
    });
    const offRecErr = wailsRuntime.EventsOn("recovery:error", (payload) => {
      const msg = payload?.message || payload || "未知错误";
      setRecoveryActive(false);
      alert(getFriendlyActionError("恢复", msg));
    });

    const offUpdate = wailsRuntime.EventsOn("update:available", (payload) => {
      if (payload?.hasUpdate) setUpdateInfo(payload);
    });
    const offDownloadProg = wailsRuntime.EventsOn("update:downloadProgress", (p) => {
      setDownloadProgress(p);
    });
    const offDownloaded = wailsRuntime.EventsOn("update:downloaded", (p) => {
      setDownloadState("done");
      setPendingUpdate(p);
    });
    const offDownloadErr = wailsRuntime.EventsOn("update:downloadError", (msg) => {
      setDownloadState("error");
      alert("下载更新失败：" + (msg?.message || msg || "未知错误"));
    });

    return () => {
      [offProg, offFound, offDone, offErr, offRecProg, offRecDone, offRecErr,
       offUpdate, offDownloadProg, offDownloaded, offDownloadErr]
        .filter((fn) => typeof fn === "function")
        .forEach((fn) => fn());
    };
  }, [bridgeState, wailsRuntime, wailsApp, queueFile, flushPending]);

  // 启动后拉一次 pending 状态；如果上一次会话下载好了，进入本次直接展示"重启以应用"
  useEffect(() => {
    if (bridgeState !== "ready" || !wailsApp?.GetPendingUpdate) return;
    wailsApp.GetPendingUpdate().then((p) => {
      if (p && p.version) {
        setPendingUpdate(p);
        setDownloadState("done");
      }
    }).catch(() => {});
  }, [bridgeState, wailsApp]);

  /* =====================================================================
     4. 操作：开始扫描 / 停止扫描
     ===================================================================== */
  const resetScanState = () => {
    fileIndexRef.current = new Map();
    pendingFilesRef.current = [];
    if (flushTimerRef.current) { clearTimeout(flushTimerRef.current); flushTimerRef.current = null; }
    setFiles([]);
    setScanProgress(INITIAL_SCAN_PROGRESS);
  };

  const startScan = useCallback(async () => {
    if (!selectedDrive || bridgeState !== "ready" || !wailsApp?.StartScan) return;
    resetScanState();
    setScanActive(true);
    setCurrentPage("workbench");
    try {
      await wailsApp.StartScan(selectedDrive.path, DEFAULT_SCAN_MODE);
    } catch (err) {
      setScanActive(false);
      alert(getFriendlyActionError("启动扫描", err));
      setCurrentPage("welcome");
    }
  }, [selectedDrive, bridgeState, wailsApp]);

  // 扫描一个 VSS 快照设备 —— 后端 NewReader 已识别 \\?\GLOBALROOT\... 路径
  const scanShadow = useCallback(async (shadow) => {
    if (!shadow?.DevicePath || !wailsApp?.StartScan) return;
    setSelectedDrive({
      path: shadow.DevicePath,
      name: `VSS 快照 (${shadow.CreatedAt ? new Date(shadow.CreatedAt).toLocaleString() : "未知时间"})`,
    });
    resetScanState();
    setScanActive(true);
    setCurrentPage("workbench");
    try {
      await wailsApp.StartScan(shadow.DevicePath, DEFAULT_SCAN_MODE);
    } catch (err) {
      setScanActive(false);
      alert(getFriendlyActionError("启动 VSS 扫描", err));
      setCurrentPage("welcome");
    }
  }, [wailsApp]);

  // 选一个磁盘镜像 (.img/.dd/.raw) 作为扫描源——无须管理员权限，也不占用设备句柄。
  const selectImageFileAndScan = useCallback(async () => {
    if (!wailsApp?.SelectImageFile || !wailsApp?.StartScan) return;
    let path = "";
    try {
      path = await wailsApp.SelectImageFile();
    } catch (err) {
      alert(getFriendlyActionError("选择镜像文件", err));
      return;
    }
    if (!path) return; // 用户取消

    const fakeDrive = { path, name: `镜像: ${path.split(/[\\/]/).pop()}` };
    setSelectedDrive(fakeDrive);
    resetScanState();
    setScanActive(true);
    setCurrentPage("workbench");
    try {
      await wailsApp.StartScan(path, DEFAULT_SCAN_MODE);
    } catch (err) {
      setScanActive(false);
      alert(getFriendlyActionError("启动镜像扫描", err));
      setCurrentPage("welcome");
    }
  }, [wailsApp]);

  const stopScan = useCallback(() => {
    if (!wailsApp?.StopScan) return;
    wailsApp.StopScan().catch(() => {});
    setScanActive(false);
  }, [wailsApp]);

  /* =====================================================================
     5. 操作：选输出目录 + 即时校验
     ===================================================================== */
  const selectOutputDir = useCallback(async () => {
    if (!wailsApp?.SelectOutputDir) return "";
    try {
      const dir = await wailsApp.SelectOutputDir();
      if (!dir) return "";
      setOutputDir(dir);

      // 同步 1: 校验是否与源盘同盘
      try {
        const errText = wailsApp.ValidateOutputDir
          ? await wailsApp.ValidateOutputDir(dir)
          : "";
        setOutputValidation(errText || "");
      } catch (err) {
        setOutputValidation(getErrorText(err));
      }

      // 同步 2: 查询剩余空间
      try {
        if (wailsApp.GetFreeSpace) {
          const fs = await wailsApp.GetFreeSpace(dir);
          setOutputFreeSpace(fs);
        }
      } catch { setOutputFreeSpace(null); }

      return dir;
    } catch (err) {
      alert(getFriendlyActionError("选择恢复目录", err));
      return "";
    }
  }, [wailsApp]);

  /* =====================================================================
     6. 操作：开始恢复 / 停止 / 重试 / 导出
     ===================================================================== */
  const startRecovery = useCallback(
    async (fileIDs, opts = {}) => {
      if (!Array.isArray(fileIDs) || fileIDs.length === 0 || !outputDir) return;
      if (!wailsApp?.StartRecovery) return;

      const allowSameDisk = !!opts.allowSameDisk;

      // 先尝试启动：StartRecovery 的同步错误路径（同盘校验、权限等）在这里会抛出。
      // 不要提前跳 recovery 页——否则失败时用户卡在"成功 0 / 失败 0"的空白报告上。
      try {
        if (allowSameDisk && wailsApp.StartRecoveryEx) {
          await wailsApp.StartRecoveryEx(fileIDs, outputDir, true);
        } else {
          await wailsApp.StartRecovery(fileIDs, outputDir);
        }
      } catch (err) {
        alert(getFriendlyActionError("启动恢复", err));
        return;
      }

      // 只有后台 goroutine 真正接管后才切换页面 + 打开实时进度
      setRecoveryActive(true);
      setRecoveryProgress({ ...INITIAL_RECOVERY_PROGRESS, total: fileIDs.length });
      setRecoveryRecords([]);
      setCurrentPage("recovery");
    },
    [outputDir, wailsApp],
  );

  const stopRecovery = useCallback(() => {
    wailsApp?.StopRecovery?.().catch(() => {});
    setRecoveryActive(false);
  }, [wailsApp]);

  const retryFailed = useCallback(async () => {
    if (!outputDir || !wailsApp?.RetryFailedRecovery) return;
    setRecoveryActive(true);
    setRecoveryProgress(INITIAL_RECOVERY_PROGRESS);
    setRecoveryRecords([]);
    try {
      await wailsApp.RetryFailedRecovery(outputDir);
    } catch (err) {
      setRecoveryActive(false);
      alert(getFriendlyActionError("重试失败项", err));
    }
  }, [outputDir, wailsApp]);

  const exportReport = useCallback(async () => {
    if (!outputDir || !wailsApp?.ExportRecoveryReport) return;
    try {
      const path = await wailsApp.ExportRecoveryReport(outputDir);
      if (path) alert(`报告已导出到：\n${path}`);
    } catch (err) {
      alert(getFriendlyActionError("导出恢复报告", err));
    }
  }, [outputDir, wailsApp]);

  const openFolder = useCallback(
    (p) => { if (p) wailsApp?.OpenFolder?.(p).catch(() => {}); },
    [wailsApp],
  );

  // 图片预览：从源盘直接读前若干字节，拼成 data URL 给 <img> 渲染。
  // Wails 在 JSON 层会把 Go []byte 自动编码成 base64 字符串。
  const requestPreview = useCallback(
    async (file) => {
      if (!file?.id || !wailsApp?.ReadFilePreview) return null;
      const ext = (file.extension || "").toLowerCase();
      const mime =
        ext === "jpg" || ext === "jpeg" ? "image/jpeg" :
        ext === "png" ? "image/png" :
        ext === "gif" ? "image/gif" :
        ext === "bmp" ? "image/bmp" :
        ext === "webp" ? "image/webp" :
        ext === "tiff" || ext === "tif" ? "image/tiff" :
        ext === "ico" ? "image/x-icon" :
        ext === "heic" || ext === "heif" ? "image/heic" :
        ext === "avif" ? "image/avif" :
        "application/octet-stream";
      const maxBytes = 2 * 1024 * 1024; // 2MB 够 99% 图片缩略
      const b64 = await wailsApp.ReadFilePreview(file.id, maxBytes);
      if (!b64) return null;
      return `data:${mime};base64,${b64}`;
    },
    [wailsApp],
  );

  /* =====================================================================
     7. 会话恢复
     ===================================================================== */
  const restoreSession = useCallback(() => {
    if (!pendingSession) return;
    // 把 snapshot 里的文件 + 进度灌回前端
    const idx = new Map();
    (pendingSession.files || []).forEach((f) => { if (f?.id) idx.set(f.id, f); });
    fileIndexRef.current = idx;
    setFiles(Array.from(idx.values()));
    setScanProgress({ ...INITIAL_SCAN_PROGRESS, ...(pendingSession.progress || {}) });
    setScanActive(false);

    // 同步选盘（便于显示"源盘"字样）
    if (pendingSession.drivePath) {
      const match = drives.find((d) => d.path === pendingSession.drivePath);
      if (match) setSelectedDrive(match);
      else setSelectedDrive({ path: pendingSession.drivePath, name: pendingSession.driveLabel });
    }

    setPendingSession(null);
    setCurrentPage("workbench");
    // 真正的数据在磁盘上，丢弃掉 session 文件（用户可以重新扫）
    wailsApp?.DiscardSession?.().catch(() => {});
  }, [pendingSession, drives, wailsApp]);

  const discardSession = useCallback(() => {
    wailsApp?.DiscardSession?.().catch(() => {});
    setPendingSession(null);
  }, [wailsApp]);

  /* =====================================================================
     8. 顶部标题文案
     ===================================================================== */
  const pageTitle = useMemo(() => {
    if (bridgeState === "loading") return "正在连接本地恢复引擎";
    if (bridgeState === "error") return "本地恢复引擎不可用";
    switch (currentPage) {
      case "workbench":
        return scanActive
          ? `正在扫描 ${getDriveLabel(selectedDrive)}`
          : `${getDriveLabel(selectedDrive)} · 共 ${files.length.toLocaleString()} 个候选`;
      case "recovery":
        return recoveryActive ? "恢复进行中" : "恢复完成";
      default:
        return "选定源盘，开始恢复";
    }
  }, [bridgeState, currentPage, scanActive, selectedDrive, files.length, recoveryActive]);

  /* =====================================================================
     渲染
     ===================================================================== */
  return (
    <div className="app-shell">
      <header className="app-topbar">
        <div className="app-brand">
          <div className="app-brand__mark no-drag">
            <IconShield size={18} />
          </div>
          <div>
            <div className="app-brand__title">数据恢复大师</div>
            <div className="app-brand__subtitle">{pageTitle}</div>
          </div>
        </div>
        <div className="flow-track no-drag">
          {FLOW_STEPS.map((step, i) => {
            const state = flowState(currentPage, step.key);
            return (
              <div key={step.key} className={`flow-step flow-step--${state}`}>
                <span className="flow-step__index">{state === "done" ? "✓" : i + 1}</span>
                <span>{step.label}</span>
              </div>
            );
          })}
        </div>
      </header>

      <UpdateBanner
        updateInfo={updateInfo}
        updateDismissed={updateDismissed}
        setUpdateDismissed={setUpdateDismissed}
        downloadState={downloadState}
        downloadProgress={downloadProgress}
        pendingUpdate={pendingUpdate}
        busy={scanActive || recoveryActive}
        onDownload={() => {
          if (!updateInfo) return;
          // 优先挑 Windows amd64 asset；桌面端实际跑什么平台 Wails 不直接告知，
          // 用名字启发（包含 "windows-amd64"、".exe" 等关键词）
          const plat = platform || "windows";
          const asset = pickAssetForPlatform(updateInfo.assets || [], plat);
          if (!asset) {
            alert("未找到适合当前平台的更新资源，请访问下载页手动下载");
            return;
          }
          setDownloadState("downloading");
          setDownloadProgress(null);
          // asset 字段对齐后端 JSON tag：name / size / downloadUrl
          wailsApp?.DownloadUpdate?.(
            updateInfo.latestVersion,
            asset.downloadUrl || "",
            asset.name || "",
            asset.size || 0,
          ).catch((err) => {
            setDownloadState("error");
            alert("启动下载失败：" + (err?.message || err));
          });
        }}
        onRestart={() => {
          if (!globalThis.confirm?.("应用即将关闭并以新版本重启，继续吗？")) return;
          wailsApp?.ApplyPendingUpdate?.().catch((err) => {
            alert("应用更新失败：" + (err?.message || err));
          });
        }}
        onCancelPending={() => {
          wailsApp?.CancelPendingUpdate?.().catch(() => {});
          setPendingUpdate(null);
          setDownloadState("idle");
        }}
        onOpenRelease={() => {
          if (!updateInfo?.downloadPage) return;
          wailsApp?.OpenFolder?.(updateInfo.downloadPage).catch(() => {
            globalThis.navigator?.clipboard?.writeText?.(updateInfo.downloadPage);
            alert(`下载页已复制到剪贴板：\n${updateInfo.downloadPage}`);
          });
        }}
      />

      <main className="app-stage">
        {bridgeState === "loading" && (
          <div className="blocker">
            <div className="app-brand__mark" style={{ width: 56, height: 56 }}>
              <IconShield size={28} />
            </div>
            <h2>正在连接本地恢复引擎…</h2>
            <p>首次启动需要加载 Wails 运行时，通常只要 1-2 秒。</p>
          </div>
        )}

        {bridgeState === "error" && (
          <div className="blocker">
            <IconAlertTriangle size={48} style={{ color: "var(--danger)" }} />
            <h2>无法连接本地恢复引擎</h2>
            <p>请从桌面应用程序启动本工具。浏览器里预览时只能看布局，没法做真实恢复。</p>
            <pre>{bridgeError}</pre>
            <button className="btn btn--primary" onClick={() => globalThis.location?.reload?.()}>
              重新连接
            </button>
          </div>
        )}

        {bridgeState === "ready" && currentPage === "welcome" && (
          <WelcomePage
            drives={drives}
            selectedDrive={selectedDrive}
            onSelectDrive={setSelectedDrive}
            onStartScan={startScan}
            onSelectImageFile={selectImageFileAndScan}
            onRefreshDrives={loadDrives}
            isLoadingDrives={isLoadingDrives}
            driveLoadError={driveLoadError}
            isAdmin={isAdmin}
            platform={platform}
            pendingSession={pendingSession}
            onRestoreSession={restoreSession}
            onDiscardSession={discardSession}
            shadows={shadows}
            onScanShadow={scanShadow}
          />
        )}

        {bridgeState === "ready" && currentPage === "workbench" && (
          <Workbench
            selectedDrive={selectedDrive}
            scanActive={scanActive}
            scanProgress={scanProgress}
            files={files}
            outputDir={outputDir}
            outputValidation={outputValidation}
            outputFreeSpace={outputFreeSpace}
            onStopScan={stopScan}
            onStartRecovery={startRecovery}
            onSelectOutputDir={selectOutputDir}
            onBackToWelcome={() => setCurrentPage("welcome")}
            onRequestPreview={requestPreview}
          />
        )}

        {bridgeState === "ready" && currentPage === "recovery" && (
          <RecoveryPage
            isActive={recoveryActive}
            progress={recoveryProgress}
            records={recoveryRecords}
            outputDir={outputDir}
            onStopRecovery={stopRecovery}
            onOpenFolder={openFolder}
            onRetryFailed={retryFailed}
            onExportReport={exportReport}
            onBackToWorkbench={() => setCurrentPage("workbench")}
            onNewScan={() => {
              resetScanState();
              setRecoveryRecords([]);
              setSelectedDrive(null);
              setOutputDir("");
              setOutputValidation("");
              setOutputFreeSpace(null);
              setCurrentPage("welcome");
            }}
          />
        )}
      </main>
    </div>
  );
}

/* ======================================================================
   UpdateBanner —— 三态顶栏：
     - 发现新版（点击"下载"）
     - 下载中（显示进度）
     - 已下载好（点击"立即重启应用"）
   在扫描 / 恢复期间自动隐藏，避免干扰长任务
   ====================================================================== */
function UpdateBanner({
  updateInfo, updateDismissed, setUpdateDismissed,
  downloadState, downloadProgress, pendingUpdate, busy,
  onDownload, onRestart, onCancelPending, onOpenRelease,
}) {
  if (busy) return null;

  // 最高优先级：已下载完成，等重启
  if (pendingUpdate && pendingUpdate.version) {
    return (
      <div className="update-banner update-banner--ready">
        <span>✅ 新版 <b>{pendingUpdate.version}</b> 已下载完成，重启后生效</span>
        <button className="btn btn--sm btn--primary" onClick={onRestart}>立即重启应用</button>
        <button className="btn btn--sm btn--ghost" onClick={onCancelPending}>放弃更新</button>
      </div>
    );
  }

  // 中等优先级：正在下载
  if (downloadState === "downloading") {
    const pct = downloadProgress && downloadProgress.bytesTotal > 0
      ? Math.round(downloadProgress.bytesDone / downloadProgress.bytesTotal * 100)
      : 0;
    const speed = downloadProgress?.speed || 0;
    const speedTxt = speed > 0 ? `${(speed / 1024 / 1024).toFixed(1)} MB/s` : "";
    return (
      <div className="update-banner update-banner--downloading">
        <span>⬇️ 正在下载新版 {updateInfo?.latestVersion}：<b>{pct}%</b> {speedTxt}</span>
      </div>
    );
  }

  // 最低优先级：发现新版
  if (updateInfo && updateInfo.hasUpdate && !updateDismissed) {
    return (
      <div className="update-banner update-banner--available">
        <span>
          🎉 新版 <b>{updateInfo.latestVersion}</b> 可用
          {updateInfo.currentVersion && (
            <span className="muted"> （当前 {updateInfo.currentVersion}）</span>
          )}
        </span>
        <button className="btn btn--sm btn--primary" onClick={onDownload}>
          后台下载，下次重启自动应用
        </button>
        <button className="btn btn--sm" onClick={onOpenRelease}>
          查看发布说明
        </button>
        <button className="btn btn--sm btn--ghost" onClick={() => setUpdateDismissed(true)}>
          稍后
        </button>
      </div>
    );
  }

  return null;
}

// pickAssetForPlatform 根据平台名从 release assets 里挑最匹配的那个。
// Wails 的 platform 字段是 Go GOOS 风格（"windows" / "darwin" / "linux"）。
// asset 字段按后端 JSON tag：`name`（camelCase）。
function pickAssetForPlatform(assets, platform) {
  if (!Array.isArray(assets) || assets.length === 0) return null;
  const plat = String(platform || "").toLowerCase();
  const priorityKeywords =
    plat === "windows" ? ["windows-amd64", "windows-arm64", "win-", ".exe"] :
    plat === "darwin" ? ["darwin", "macos", ".dmg", "mac-"] :
    plat === "linux" ? ["linux-amd64", "linux-arm64", ".tar.gz", ".AppImage"] :
    [];
  for (const kw of priorityKeywords) {
    const match = assets.find((a) => String(a.name || "").toLowerCase().includes(kw));
    if (match) return match;
  }
  return assets[0];
}
