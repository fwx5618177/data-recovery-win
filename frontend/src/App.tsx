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
import Select from "./components/Select";
import ToastViewport from "./components/ToastViewport";
import OCRSearchModal from "./components/OCRSearchModal";
import MultiDiskScanModal from "./components/MultiDiskScanModal";
import { DuplicateImagesModal } from "./components/DuplicateImagesModal";
import { ToolDialog, type ToolDialogProps } from "./components/ToolDialog";
import { toast } from "./toast";
import {
  CloudBackupsModal,
  NASScanModal,
  AndroidDumpModal,
  IOSBackupModal,
  PTPCameraModal,
  ADBPullModal,
  DiskDumpModal,
  AboutModal,
  TasksSidebar,
} from "./components/MobileToolsModals";
import {
  DEFAULT_SCAN_MODE,
  getDriveLabel,
  isCancellationError,
  mergeFileIntoIndex,
  normalizeRecoveryCompletion,
} from "./recovery-helpers";
import { IconAlertTriangle, IconShield, IconSunMoon, IconSun, IconMoon, IconClock, IconGlobe } from "./icons";
import { t, getLocale, setLocale, onLocaleChange, AVAILABLE_LOCALES } from "./i18n";
import { getTheme, setTheme, onThemeChange, AVAILABLE_THEMES } from "./theme";
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

  // ------------------------- 加密卷预警 -------------------------
  // BitLocker / FileVault / APFS 卷：本工具不解密，仅提示存在
  const [encryptedVolumes, setEncryptedVolumes] = useState([]);

  // ------------------------- 关闭确认对话框 (v2.8.16) -------------------------
  // 用户点窗口 X 时 Wails OnBeforeClose hook 拦截 → 后端发 app:closeRequested
  // 事件 → 这里弹模态框（退出 / 最小化 / 取消）。
  const [showCloseConfirm, setShowCloseConfirm] = useState(false);

  // ------------------------- 重复图片结果 (v2.8.17 Issue 8) -------------------------
  // FindDuplicateImages 返回 string[][]，每组一组相似图片的绝对路径。
  // 之前只 toast "找到 N 组"，现在弹模态框让用户看具体内容 + 删除/打开。
  const [duplicateGroups, setDuplicateGroups] = useState<string[][] | null>(null);

  // ------------------------- 通用工具弹窗 (v2.8.18) -------------------------
  // 替代 globalThis.prompt() 的丑 native 弹窗。
  // null = 关闭；非 null = 当前打开哪个工具的配置。
  const [toolDialog, setToolDialog] = useState<Omit<ToolDialogProps, "onClose" | "wailsApp"> | null>(null);

  // ------------------------- 扫描态 -------------------------
  const [scanActive, setScanActive] = useState(false);
  const [scanProgress, setScanProgress] = useState(INITIAL_SCAN_PROGRESS);
  // BitLocker 解锁态：派生 1M 次 SHA-256 的进度 + "已解锁"提示
  // null 表示没在解锁；对象含 { phase: "deriving"|"unlocked"|"error", done, total, info, volume }
  const [bitlockerState, setBitlockerState] = useState(null);
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

  // 移动端工具的 modal 显示开关
  // openModal: null | "cloud" | "nas-smb" | "nas-nfs" | "android-dump" | "ios-backup"
  //          | "ptp-camera" | "adb-pull" | "disk-dump" | "about"
  const [openMobileModal, setOpenMobileModal] = useState(null);

  // 多个移动端任务并行：Map<kind, task>
  // task = { kind, label, progress (number bytes 或 -1 不确定), error, done, startedAt }
  // 同 kind 只能有一个 in-flight task（系统约束：一次只一个 dump / 一次只一个 backup）
  const [mobileTasks, setMobileTasks] = useState(() => new Map());

  // 历史已完成任务（5 分钟内）：Array<task with id + completedAt>
  // 比 Map 更适合 history（同 kind 可以多次完成，每次独立记录）
  const [taskHistory, setTaskHistory] = useState([]);

  const upsertTask = useCallback((kind, patch) => {
    setMobileTasks((prev) => {
      const next = new Map(prev);
      const existing = next.get(kind) || { kind, startedAt: Date.now() };
      next.set(kind, { ...existing, ...patch });
      return next;
    });
  }, []);

  // 任务完成/出错 → 迁到 history（不立即删除 in-flight 卡片，让用户看到 5s 完成态）
  const completeTask = useCallback((kind) => {
    setMobileTasks((prev) => {
      const t = prev.get(kind);
      if (!t) return prev;
      // 加到历史
      setTaskHistory((hist) => [
        { ...t, id: `${kind}-${Date.now()}`, completedAt: Date.now() },
        ...hist,
      ]);
      return prev;
    });
    // 5 秒后从 in-flight 移除
    setTimeout(() => {
      setMobileTasks((prev) => {
        const next = new Map(prev);
        next.delete(kind);
        return next;
      });
    }, 5000);
  }, []);

  const dismissTask = useCallback((kind) => {
    setMobileTasks((prev) => {
      const next = new Map(prev);
      next.delete(kind);
      return next;
    });
  }, []);
  const dismissHistoryTask = useCallback((id) => {
    setTaskHistory((hist) => hist.filter((t) => t.id !== id));
  }, []);

  // history 自动清理：每 30 秒清掉 > 5 分钟的
  useEffect(() => {
    const id = setInterval(() => {
      const cutoff = Date.now() - 5 * 60 * 1000;
      setTaskHistory((hist) => hist.filter((t) => (t.completedAt || 0) > cutoff));
    }, 30000);
    return () => clearInterval(id);
  }, []);

  // 取消 in-flight 任务 — 调 backend Cancel<X> IPC
  const cancelTask = useCallback(async (kind) => {
    const ipcMap = {
      "android-dump": "CancelAndroidDump",
      "adb-pull":     "CancelMTPPull",
      "ios-backup":   "CancelIOSBackup",
      "ptp-pull":     "CancelPTPPull",
      "disk-dump":    "CancelDiskDump",
    };
    const method = ipcMap[kind];
    if (!method || !wailsApp?.[method]) return;
    try {
      await wailsApp[method]();
      // backend 取消后会触发对应 :Error 事件，自然走 completeTask 路径
    } catch (e) {
      // 取消本身报错（罕见）
      upsertTask(kind, { error: "取消失败: " + (e?.message || e), done: true });
      completeTask(kind);
    }
  }, [wailsApp, upsertTask, completeTask]);

  // sidebar 折叠状态
  const [tasksSidebarCollapsed, setTasksSidebarCollapsed] = useState(false);

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
      const drives = Array.isArray(list) ? list : [];
      setDrives(drives);
      // 注意：不再在启动时并发对每块盘跑 ScanEncryptedVolumes —— 那是真实 IO，
      // 一块 dirty U 盘（系统层 chkdsk 中）可能让 CreateFile hang，连带卡 wails IPC
      // 队列。改为：用户选中某块盘后才单盘触发（loadEncryptedVolumesForDrive）。
    } catch (err) {
      setDrives([]);
      setDriveLoadError(getFriendlyActionError("读取磁盘列表", err));
    } finally {
      setIsLoadingDrives(false);
    }
  }, [bridgeState, wailsApp]);

  // 用户选中一块盘后才扫这块盘的加密卷；后端已加 5s Open 超时
  const loadEncryptedVolumesForDrive = useCallback(async (drivePath) => {
    if (!wailsApp?.ScanEncryptedVolumes || !drivePath) return;
    try {
      const list = await wailsApp.ScanEncryptedVolumes(drivePath);
      if (Array.isArray(list)) {
        // 合并：保留其他盘已扫出的，替换/追加当前盘的
        setEncryptedVolumes((prev) => {
          const others = prev.filter((v) => v.drivePath !== drivePath);
          return [...others, ...list];
        });
      }
    } catch { /* 单盘失败静默：用户体验上等同"没加密卷" */ }
  }, [wailsApp]);

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

  // 用户选中真实盘后再扫该盘的加密卷预警（启动时不并发跑，避免 dirty U 盘 hang）
  useEffect(() => {
    if (!selectedDrive?.path) return;
    if (selectedDrive.path.startsWith("__")) return; // 跳过 image-file 之类伪 drive
    loadEncryptedVolumesForDrive(selectedDrive.path);
  }, [selectedDrive, loadEncryptedVolumesForDrive]);

  // U 盘拔插轻量轮询：在 welcome / 非扫描状态下每 30s 刷一次盘列表
  // 没做原生 WM_DEVICECHANGE 监听的简易替代；扫描中暂停以免打扰
  useEffect(() => {
    if (bridgeState !== "ready") return;
    if (scanActive || recoveryActive) return;
    if (currentPage !== "welcome") return;
    const id = setInterval(() => { loadDrives(); }, 30_000);
    return () => clearInterval(id);
  }, [bridgeState, scanActive, recoveryActive, currentPage, loadDrives]);

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
      toast.error(getFriendlyActionError("扫描", msg));
    });

    const offRecProg = wailsRuntime.EventsOn("recovery:progress", (p) => {
      setRecoveryProgress((prev) => normalizeRecoveryCompletion(p, prev.total, prev.bytesWritten));
    });
    const offRecDone = wailsRuntime.EventsOn("recovery:completed", (p) => {
      const norm = normalizeRecoveryCompletion(p, 0, 0);
      setRecoveryProgress(norm);
      setRecoveryActive(false);
      // v2.8.28: 修复"恢复完成后统计全 0、文件列表空"的 bug。
      // 之前 `if (norm.records)` 对空数组 `[]` 也是 truthy，于是不回退到
      // GetLastRecoveryRecords()。当事件 payload 因序列化原因带回空数组时，
      // 前端就拿不到记录，统计卡片（高可靠/低可靠/失败...）全显 0、文件列表也不渲染。
      // 改成显式检查长度 > 0 才用事件 payload；否则始终从后端拉一次。
      if (norm.records && norm.records.length > 0) {
        setRecoveryRecords(norm.records);
      } else if (wailsApp?.GetLastRecoveryRecords) {
        wailsApp.GetLastRecoveryRecords()
          .then((list) => setRecoveryRecords(list || []))
          .catch(() => setRecoveryRecords([]));
      } else {
        setRecoveryRecords([]);
      }
    });
    const offRecErr = wailsRuntime.EventsOn("recovery:error", (payload) => {
      const msg = payload?.message || payload || "未知错误";
      setRecoveryActive(false);
      toast.error(getFriendlyActionError("恢复", msg));
    });

    // OS 级文件拖拽：用户把磁盘镜像 / .img / .raw / .dd 拖到窗口任意位置
    // → 后端 OnFileDrop → "files:dropped" 事件
    const offFileDrop = wailsRuntime.EventsOn("files:dropped", (paths) => {
      if (!Array.isArray(paths) || paths.length === 0) return;
      const path = paths[0];
      const lower = String(path).toLowerCase();
      // 只接受常见镜像扩展，避免用户拖个 .docx 触发"扫描该文件"
      const looksLikeImage = /\.(img|raw|dd|iso|dmg|vhd|vhdx|vmdk|001|e01)$/i.test(lower);
      if (!looksLikeImage) {
        toast.warning({
          title: `不支持拖入 "${path.split(/[\\/]/).pop()}"`,
          description: "请拖入磁盘镜像文件 (.img / .raw / .dd / .iso / .dmg / .vhd / .vmdk / .001 / .e01)",
        });
        return;
      }
      const fakeDrive = { path, name: `镜像: ${path.split(/[\\/]/).pop()}` };
      setSelectedDrive(fakeDrive);
      resetScanState();
      setScanActive(true);
      setCurrentPage("workbench");
      wailsApp?.StartScan?.(path, DEFAULT_SCAN_MODE).catch((err) => {
        setScanActive(false);
        toast.error(getFriendlyActionError("启动镜像扫描", err));
        setCurrentPage("welcome");
      });
    });

    const offBLDerive = wailsRuntime.EventsOn("bitlocker:keyDeriving", (p) => {
      // p: { done, total } — 每 ~8k 次 iter 一条
      setBitlockerState((prev) => ({
        phase: "deriving",
        done: Number(p?.done || 0),
        total: Number(p?.total || 1048576),
        volume: prev?.volume,
      }));
    });
    const offBLUnlocked = wailsRuntime.EventsOn("bitlocker:unlocked", (info) => {
      setBitlockerState((prev) => ({
        phase: "unlocked",
        done: 1048576,
        total: 1048576,
        info,
        volume: prev?.volume,
      }));
    });

    // v2.8.16: 关闭按钮二次确认 —— 后端 OnBeforeClose 拦截 X，发这个事件让前端弹框
    const offCloseReq = wailsRuntime.EventsOn("app:closeRequested", () => {
      setShowCloseConfirm(true);
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
      toast.error("下载更新失败：" + (msg?.message || msg || "未知错误"));
    });

    // 移动端 / 备份 / NAS 全局进度事件 —— 推到 mobileTasks Map
    // 多个并行任务（如同时 Android dump + iOS backup + PTP pull）每个独立显示
    const offMobile = [
      // Android dump
      wailsRuntime.EventsOn("mtp:dumpStarted", (p) => {
        upsertTask("android-dump", {
          label: `Android dump: ${p?.block || "?"}`,
          progress: 0, totalBytes: 0,
        });
      }),
      wailsRuntime.EventsOn("mtp:dumpProgress", (b) => {
        const bytes = typeof b === "number" ? b : Number(b) || 0;
        upsertTask("android-dump", {
          progress: bytes,
          label: `Android dump: ${(bytes / 1024 / 1024).toFixed(1)} MB`,
        });
      }),
      wailsRuntime.EventsOn("mtp:dumpCompleted", () => {
        upsertTask("android-dump", { label: "Android dump 完成 ✓", done: true });
        completeTask("android-dump");
      }),
      wailsRuntime.EventsOn("mtp:dumpError", (e) => {
        upsertTask("android-dump", { label: "Android dump 失败", error: String(e), done: true });
        completeTask("android-dump");
      }),
      // ADB pull directory
      wailsRuntime.EventsOn("mtp:pullStarted", (p) => {
        upsertTask("adb-pull", {
          label: `ADB pull: ${typeof p === "object" ? p?.src || "" : p || ""}`,
          progress: -1,
        });
      }),
      wailsRuntime.EventsOn("mtp:pullCompleted", (dst) => {
        upsertTask("adb-pull", { label: `ADB pull 完成 → ${dst || ""}`, done: true });
        completeTask("adb-pull");
      }),
      wailsRuntime.EventsOn("mtp:pullError", (e) => {
        upsertTask("adb-pull", { label: "ADB pull 失败", error: String(e), done: true });
        completeTask("adb-pull");
      }),
      // iOS backup
      wailsRuntime.EventsOn("ios:backupStarted", (udid) => {
        upsertTask("ios-backup", {
          label: `iOS 备份 (${String(udid).slice(0, 12)}…)`,
          progress: -1,
        });
      }),
      wailsRuntime.EventsOn("ios:backupCompleted", () => {
        upsertTask("ios-backup", { label: "iOS 备份完成 ✓", done: true });
        completeTask("ios-backup");
      }),
      wailsRuntime.EventsOn("ios:backupError", (e) => {
        upsertTask("ios-backup", { label: "iOS 备份失败", error: String(e), done: true });
        completeTask("ios-backup");
      }),
      // PTP camera pull
      wailsRuntime.EventsOn("ptp:pullStarted", (port) => {
        upsertTask("ptp-pull", {
          label: `PTP 相机 (${port || "?"})`,
          progress: -1,
        });
      }),
      wailsRuntime.EventsOn("ptp:pullCompleted", (dst) => {
        upsertTask("ptp-pull", { label: `PTP pull 完成 → ${dst || ""}`, done: true });
        completeTask("ptp-pull");
      }),
      wailsRuntime.EventsOn("ptp:pullError", (e) => {
        upsertTask("ptp-pull", { label: "PTP pull 失败", error: String(e), done: true });
        completeTask("ptp-pull");
      }),
      // 镜像 dump
      wailsRuntime.EventsOn("image:dumpStarted", (p) => {
        upsertTask("disk-dump", {
          label: `镜像 dump: ${typeof p === "object" ? p?.src || "" : p || ""}`,
          progress: 0,
        });
      }),
      wailsRuntime.EventsOn("image:dumpProgress", (b) => {
        const bytes = typeof b === "number" ? b : Number(b) || 0;
        upsertTask("disk-dump", {
          progress: bytes,
          label: `镜像 dump: ${(bytes / 1024 / 1024).toFixed(1)} MB`,
        });
      }),
      wailsRuntime.EventsOn("image:dumpCompleted", () => {
        upsertTask("disk-dump", { label: "镜像 dump 完成 ✓", done: true });
        completeTask("disk-dump");
      }),
      wailsRuntime.EventsOn("image:dumpError", (e) => {
        upsertTask("disk-dump", { label: "镜像 dump 失败", error: String(e), done: true });
        completeTask("disk-dump");
      }),
    ];

    return () => {
      [offProg, offFound, offDone, offErr, offRecProg, offRecDone, offRecErr,
       offFileDrop, offBLDerive, offBLUnlocked,
       offCloseReq,
       offUpdate, offDownloadProg, offDownloaded, offDownloadErr,
       ...offMobile]
        .filter((fn) => typeof fn === "function")
        .forEach((fn) => fn());
    };
  }, [bridgeState, wailsRuntime, wailsApp, queueFile, flushPending, upsertTask, completeTask]);

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
    // v2.8.20 Issue 23: 系统盘扫描 IO 占满会让 OS 假死 —— 启动前警告
    try {
      const isSys = await wailsApp?.IsSystemDrive?.(selectedDrive.path);
      if (isSys) {
        const ok = confirm(
          "⚠️ 这是系统盘\n\n" +
          "扫描系统盘会占用大量磁盘 IO，可能导致系统响应变慢甚至假死。\n\n" +
          "强烈建议：\n" +
          "• 把要扫描的盘拆下来用硬盘盒外接到另一台机器\n" +
          "• 或者用 ddrescue / DMDE 先把盘 dump 成 .img 镜像再扫描镜像（更安全）\n\n" +
          "如果你确认要继续扫系统盘，请点「确定」。"
        );
        if (!ok) return; // 用户取消
      }
    } catch { /* 检测失败不阻塞，继续扫 */ }
    resetScanState();
    setScanActive(true);
    setCurrentPage("workbench");
    try {
      await wailsApp.StartScan(selectedDrive.path, DEFAULT_SCAN_MODE);
    } catch (err) {
      setScanActive(false);
      toast.error(getFriendlyActionError("启动扫描", err));
      setCurrentPage("welcome");
    }
  }, [selectedDrive, bridgeState, wailsApp]);

  // 扫描一个 VSS 快照设备 —— 后端 NewReader 已识别 \\?\GLOBALROOT\... 路径
  const scanShadow = useCallback(async (shadow) => {
    if (!shadow?.devicePath || !wailsApp?.StartScan) return;
    setSelectedDrive({
      path: shadow.devicePath,
      name: `VSS 快照 (${shadow.createdAt ? new Date(shadow.createdAt).toLocaleString() : "未知时间"})`,
    });
    resetScanState();
    setScanActive(true);
    setCurrentPage("workbench");
    try {
      await wailsApp.StartScan(shadow.devicePath, DEFAULT_SCAN_MODE);
    } catch (err) {
      setScanActive(false);
      toast.error(getFriendlyActionError("启动 VSS 扫描", err));
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
      toast.error(getFriendlyActionError("选择镜像文件", err));
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
      toast.error(getFriendlyActionError("启动镜像扫描", err));
      setCurrentPage("welcome");
    }
  }, [wailsApp]);

  // v2.8.20: stopScan 现在 await 后端 Stop() 完成（后端等所有 IO goroutine 真退出
  // 最多 10s）。修复致命 bug：之前用户点 stopScan 后任务管理器仍显示 100% IO 持续读盘。
  const stopScan = useCallback(async () => {
    if (!wailsApp?.StopScan) return;
    try {
      await wailsApp.StopScan(); // 后端同步等 goroutine 真退出
    } catch {
      // 忽略 —— scan:error 事件会更新 UI
    }
    setScanActive(false);
  }, [wailsApp]);

  // v2.8.20: 切换界面前确保扫描真停掉 —— 防止 "换一块盘" / 关闭后 IO 持续占用
  // （致命级 bug：用户停扫描后任务管理器仍 100% 占用磁盘 IO，可能导致系统假死）
  const safeBackToWelcome = useCallback(async () => {
    if (scanActive) {
      await stopScan();
    } else if (wailsApp?.StopScan) {
      // 即便前端 scanActive=false，后端可能 still alive（validate / saveSnapshot 等阶段）
      // 防御性也调一次 StopScan，确保彻底无 IO
      try { await wailsApp.StopScan(); } catch { /* no-op */ }
    }
    setCurrentPage("welcome");
  }, [scanActive, stopScan, wailsApp]);

  // 全局键盘快捷键（必须在 stopScan 声明之后，否则 TDZ 报错）
  // - Esc: 关弹窗 / 停扫描
  // - Ctrl+/Cmd+F: 聚焦"搜索文件名"输入框
  // - Ctrl+/Cmd+A: 全选当前可见文件（仅 workbench 页 + 目标不在 input/textarea 时）
  useEffect(() => {
    function handler(e) {
      const inEditable = e.target instanceof HTMLElement &&
        (e.target.tagName === "INPUT" || e.target.tagName === "TEXTAREA" || e.target.isContentEditable);

      if (e.key === "Escape" && !inEditable && scanActive) {
        e.preventDefault();
        if (globalThis.confirm?.("停止当前扫描？")) {
          stopScan();
        }
        return;
      }

      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "f" && currentPage === "workbench") {
        const input = globalThis.document?.querySelector(".file-table-search input") as HTMLInputElement | null;
        if (input) {
          e.preventDefault();
          input.focus();
          input.select?.();
        }
        return;
      }

      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "a" &&
          currentPage === "workbench" && !inEditable) {
        const allBtn = globalThis.document?.querySelector("[data-shortcut='select-all-visible']") as HTMLButtonElement | null;
        if (allBtn) {
          e.preventDefault();
          allBtn.click();
        }
      }
    }
    globalThis.addEventListener("keydown", handler);
    return () => globalThis.removeEventListener("keydown", handler);
  }, [scanActive, currentPage, stopScan]);

  // 用 TPM 卷的内存镜像（hiberfil.sys / dump）解锁并扫描
  const unlockBitLockerMemoryAndScan = useCallback(async (vol, memImagePath) => {
    if (!vol || !memImagePath || !wailsApp?.UnlockBitLockerWithMemoryImage) return;
    setSelectedDrive({
      path: vol.drivePath,
      name: `BitLocker (TPM via ${memImagePath.split(/[\\/]/).pop()})`,
    });
    setBitlockerState({ phase: "deriving", done: 0, total: 1, volume: vol });
    resetScanState();
    setScanActive(true);
    setCurrentPage("workbench");
    try {
      await wailsApp.UnlockBitLockerWithMemoryImage(
        vol.drivePath,
        Number(vol.offset || 0).toString(16),
        memImagePath,
        DEFAULT_SCAN_MODE,
      );
    } catch (err) {
      setScanActive(false);
      setBitlockerState({ phase: "error", error: getErrorText(err) || "解锁失败", volume: vol });
      toast.error(getFriendlyActionError("BitLocker 内存解锁", err));
      setCurrentPage("welcome");
    }
  }, [wailsApp]);

  // 解锁 BitLocker 卷并把解密 reader 喂给扫描引擎（recovery key → VMK → FVEK → NTFS）
  // 参数 vol 来自 ScanEncryptedVolumes 的结果；key 是用户从 48 位 recovery key 对话框输入的
  const unlockBitLockerAndScan = useCallback(async (vol, recoveryKey) => {
    if (!vol || !recoveryKey || !wailsApp?.UnlockBitLockerAndScan) return;
    const fakeDrive = {
      path: vol.drivePath,
      name: `BitLocker · ${vol.drivePath} @ 0x${Number(vol.offset || 0).toString(16)}`,
    };
    setSelectedDrive(fakeDrive);
    setBitlockerState({
      phase: "deriving",
      done: 0,
      total: 1048576,
      volume: vol,
    });
    resetScanState();
    setScanActive(true);
    setCurrentPage("workbench");
    try {
      await wailsApp.UnlockBitLockerAndScan(
        vol.drivePath,
        Number(vol.offset || 0).toString(16),
        recoveryKey,
        DEFAULT_SCAN_MODE,
      );
    } catch (err) {
      setScanActive(false);
      setBitlockerState({
        phase: "error",
        error: getErrorText(err) || "解锁失败",
        volume: vol,
      });
      toast.error(getFriendlyActionError("BitLocker 解锁 / 扫描", err));
      setCurrentPage("welcome");
    }
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
      toast.error(getFriendlyActionError("选择恢复目录", err));
      return "";
    }
  }, [wailsApp]);

  /* =====================================================================
     6. 操作：开始恢复 / 停止 / 重试 / 导出
     ===================================================================== */
  const startRecovery = useCallback(
    async (
      fileIDs: string[],
      opts: { allowSameDisk?: boolean; archiveByExifDate?: boolean } = {},
    ) => {
      if (!Array.isArray(fileIDs) || fileIDs.length === 0 || !outputDir) return;
      if (!wailsApp?.StartRecovery) return;

      const allowSameDisk = !!opts.allowSameDisk;
      const archiveByExifDate = !!opts.archiveByExifDate;

      // 先尝试启动：StartRecovery 的同步错误路径（同盘校验、权限等）在这里会抛出。
      // 不要提前跳 recovery 页——否则失败时用户卡在"成功 0 / 失败 0"的空白报告上。
      try {
        if (wailsApp.StartRecoveryWithOptions) {
          await wailsApp.StartRecoveryWithOptions(fileIDs, outputDir, allowSameDisk, archiveByExifDate);
        } else if (allowSameDisk && wailsApp.StartRecoveryEx) {
          await wailsApp.StartRecoveryEx(fileIDs, outputDir, true);
        } else {
          await wailsApp.StartRecovery(fileIDs, outputDir);
        }
      } catch (err) {
        toast.error(getFriendlyActionError("启动恢复", err));
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
      toast.error(getFriendlyActionError("重试失败项", err));
    }
  }, [outputDir, wailsApp]);

  const exportReport = useCallback(async () => {
    if (!outputDir || !wailsApp?.ExportRecoveryReport) return;
    try {
      const path = await wailsApp.ExportRecoveryReport(outputDir);
      if (path) toast.success({ title: "报告已导出", description: path });
    } catch (err) {
      toast.error(getFriendlyActionError("导出恢复报告", err));
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

  // 从断点继续扫描（跳过已扫的 carver 偏移）—— 只有 pendingSession 带 carverResumeOffset 才能用
  const resumeLastScan = useCallback(async () => {
    if (!pendingSession || !wailsApp?.ResumeLastScan) return;
    resetScanState();
    setScanActive(true);
    setCurrentPage("workbench");
    // 同步选盘显示
    if (pendingSession.drivePath) {
      const match = drives.find((d) => d.path === pendingSession.drivePath);
      setSelectedDrive(match || { path: pendingSession.drivePath, name: pendingSession.driveLabel });
    }
    try {
      await wailsApp.ResumeLastScan();
      setPendingSession(null);
    } catch (err) {
      setScanActive(false);
      toast.error(getFriendlyActionError("断点续扫", err));
      setCurrentPage("welcome");
    }
  }, [pendingSession, drives, wailsApp]);

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
        <div className="topbar-actions no-drag" style={{ display: "flex", gap: 6, alignItems: "center" }}>
          <ToolsMenu
            wailsApp={wailsApp}
            outputDir={outputDir}
            selectedDrive={selectedDrive}
            onOpenMobileModal={setOpenMobileModal}
            onDuplicateGroups={setDuplicateGroups}
            onToolDialog={setToolDialog}
          />
          <ThemeSwitcher />
          <LocaleSwitcher />
          {/* v2.8.17: 任务面板入口 —— 之前面板收起后无法再打开（Issue 3）。
              这个按钮永远可见，点击切换 tasksSidebarCollapsed，并强制展开（如果当前是折叠状态） */}
          <button
            className="btn btn--sm btn--ghost"
            title="任务面板"
            onClick={() => setTasksSidebarCollapsed((v) => !v)}
            style={{ position: "relative" }}
          >
            🗂 任务
            {mobileTasks.size > 0 && (
              <span style={{
                position: "absolute", top: -2, right: -2,
                background: "var(--accent)", color: "white",
                fontSize: 9, fontWeight: 700,
                borderRadius: 8, padding: "1px 5px",
                minWidth: 14, lineHeight: 1.2,
              }}>
                {mobileTasks.size}
              </span>
            )}
          </button>
          <button
            className="btn btn--sm btn--ghost"
            title={t("diag.export")}
            onClick={() => {
              // v2.8.19: 用 ToolDialog 替代 native prompt
              setToolDialog({
                title: "🛠 导出诊断包",
                description:
                  "把最近 N 天的日志 + 会话快照 + pending update 状态打成 zip，方便贴到 GitHub issue 排障。\n\n" +
                  "**不会**包含磁盘扇区 / 用户文件 / 加密密钥 —— 只是软件元数据。\n\n" +
                  "导出位置：自动写到桌面（Win 上走 SHGetKnownFolderPath 拿真桌面，OneDrive / 重定向都正确）。",
                fields: [
                  {
                    key: "notes",
                    label: "可选：简单描述遇到的问题",
                    type: "text",
                    placeholder: "例：扫描 NAS 时进度卡 9% 几小时不动",
                    hint: "会写入诊断包 metadata，不要含密码 / 个人信息。留空也可以。",
                    required: false,
                  },
                ],
                submitLabel: "导出",
                onSubmit: async (vals) => {
                  const path = await wailsApp?.ExportDiagnosticBundle?.("", vals.notes || "");
                  return `已导出：${path}`;
                },
              });
            }}
          >
            🛠 {t("diag.export")}
          </button>
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
            toast.warning("未找到适合当前平台的更新资源，请访问下载页手动下载");
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
            toast.error("启动下载失败：" + (err?.message || err));
          });
        }}
        onRestart={() => {
          if (!globalThis.confirm?.("应用即将关闭并以新版本重启，继续吗？")) return;
          wailsApp?.ApplyPendingUpdate?.().catch((err) => {
            toast.error("应用更新失败：" + (err?.message || err));
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
            toast.success({ title: "下载页已复制到剪贴板", description: updateInfo.downloadPage });
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
            onResumeScan={resumeLastScan}
            shadows={shadows}
            onScanShadow={scanShadow}
            encryptedVolumes={encryptedVolumes}
            onUnlockBitLocker={unlockBitLockerAndScan}
            onUnlockBitLockerMemory={unlockBitLockerMemoryAndScan}
            onOpenMobileModal={setOpenMobileModal}
          />
        )}

        {bridgeState === "ready" && currentPage === "workbench" && (
          <Workbench
            selectedDrive={selectedDrive}
            scanActive={scanActive}
            scanProgress={scanProgress}
            bitlockerState={bitlockerState}
            files={files}
            outputDir={outputDir}
            outputValidation={outputValidation}
            outputFreeSpace={outputFreeSpace}
            onStopScan={stopScan}
            onStartRecovery={startRecovery}
            onSelectOutputDir={selectOutputDir}
            onBackToWelcome={safeBackToWelcome}
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
            // v2.8.30 Issue 3 兜底：用户手动点"下一步"或倒计时归 0 自动调，
            // 强制切到结果页。如果后端 records 还没回，先去 GetLastRecoveryRecords 拉一次。
            onForceComplete={async () => {
              if (wailsApp?.GetLastRecoveryRecords) {
                try {
                  const list = await wailsApp.GetLastRecoveryRecords();
                  if (list && list.length > 0) setRecoveryRecords(list);
                } catch { /* 不阻塞切页 */ }
              }
              setRecoveryActive(false);
            }}
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

      {/* ============== 移动端 / 备份 / NAS 工具 modals ============== */}
      {openMobileModal === "cloud" && (
        <CloudBackupsModal
          wailsApp={wailsApp}
          onClose={() => setOpenMobileModal(null)}
          onStartedScan={() => setCurrentPage("workbench")}
        />
      )}
      {openMobileModal === "nas-smb" && (
        <NASScanModal
          kind="smb"
          wailsApp={wailsApp}
          onClose={() => setOpenMobileModal(null)}
          onStarted={() => setCurrentPage("workbench")}
        />
      )}
      {openMobileModal === "nas-nfs" && (
        <NASScanModal
          kind="nfs"
          wailsApp={wailsApp}
          onClose={() => setOpenMobileModal(null)}
          onStarted={() => setCurrentPage("workbench")}
        />
      )}
      {openMobileModal === "android-dump" && (
        <AndroidDumpModal
          wailsApp={wailsApp}
          outputDir={outputDir}
          onClose={() => setOpenMobileModal(null)}
          onStarted={() => setCurrentPage("workbench")}
        />
      )}
      {openMobileModal === "ios-backup" && (
        <IOSBackupModal
          wailsApp={wailsApp}
          outputDir={outputDir}
          onClose={() => setOpenMobileModal(null)}
          onStarted={() => setCurrentPage("workbench")}
        />
      )}
      {openMobileModal === "ptp-camera" && (
        <PTPCameraModal
          wailsApp={wailsApp}
          outputDir={outputDir}
          onClose={() => setOpenMobileModal(null)}
          onStarted={() => setCurrentPage("workbench")}
        />
      )}
      {openMobileModal === "adb-pull" && (
        <ADBPullModal
          wailsApp={wailsApp}
          outputDir={outputDir}
          onClose={() => setOpenMobileModal(null)}
          onStarted={() => setCurrentPage("workbench")}
        />
      )}
      {openMobileModal === "disk-dump" && (
        <DiskDumpModal
          wailsApp={wailsApp}
          selectedDrive={selectedDrive}
          onClose={() => setOpenMobileModal(null)}
        />
      )}
      {openMobileModal === "about" && (
        <AboutModal
          wailsApp={wailsApp}
          onClose={() => setOpenMobileModal(null)}
        />
      )}
      {openMobileModal === "ocr-search" && (
        <OCRSearchModal
          wailsApp={wailsApp}
          outputDir={outputDir}
          onClose={() => setOpenMobileModal(null)}
        />
      )}
      {openMobileModal === "multi-disk-scan" && (
        <MultiDiskScanModal
          wailsApp={wailsApp}
          drives={drives}
          onClose={() => setOpenMobileModal(null)}
        />
      )}

      {/* ============== 左侧 "今日任务" 侧栏（多任务并行 + 历史 tab + 取消） ============== */}
      <TasksSidebar
        tasks={mobileTasks}
        history={taskHistory}
        collapsed={tasksSidebarCollapsed}
        onToggleCollapsed={() => setTasksSidebarCollapsed((v) => !v)}
        onDismiss={dismissTask}
        onDismissHistory={dismissHistoryTask}
        onCancel={cancelTask}
      />
      <ToastViewport />
      {duplicateGroups && (
        <DuplicateImagesModal
          groups={duplicateGroups}
          wailsApp={wailsApp}
          onClose={() => setDuplicateGroups(null)}
        />
      )}
      {toolDialog && (
        <ToolDialog
          {...toolDialog}
          wailsApp={wailsApp}
          onClose={() => setToolDialog(null)}
        />
      )}
      {showCloseConfirm && (
        <CloseConfirmModal
          scanActive={scanActive}
          onMinimize={() => {
            setShowCloseConfirm(false);
            wailsApp?.MinimizeWindow?.();
          }}
          onExit={async () => {
            setShowCloseConfirm(false);
            // v2.8.20: 关闭应用前必须先 stopScan，否则后台 IO 在进程退出前继续占用磁盘
            // （Windows OS 可能还会清理一段时间）。让 backend Stop 同步等真退出再 Quit。
            if (scanActive && wailsApp?.StopScan) {
              try { await wailsApp.StopScan(); } catch { /* no-op */ }
            }
            wailsApp?.ConfirmExit?.();
          }}
          onCancel={() => setShowCloseConfirm(false)}
        />
      )}
    </div>
  );
}

/**
 * CloseConfirmModal v2.8.16: 关闭按钮二次确认
 * 防扫描跑到一半被误关。
 */
function CloseConfirmModal({ scanActive, onMinimize, onExit, onCancel }) {
  return (
    <div className="preview-modal" role="dialog" aria-label="关闭确认">
      <div className="preview-modal__inner" style={{ maxWidth: 460, width: "92%" }}>
        <div className="preview-modal__header">
          <div className="preview-modal__title">
            {scanActive ? "扫描进行中，确认要关闭吗？" : "关闭应用？"}
          </div>
        </div>
        <div className="preview-modal__body" style={{ padding: "18px 20px", display: "block" }}>
          <p className="muted" style={{ margin: 0, lineHeight: 1.6 }}>
            {scanActive ? (
              <>
                当前有扫描任务正在执行。<b>退出应用会丢失扫描进度</b>，下次需要从头重扫
                （或从断点续扫）。
                <br />
                你也可以选择"最小化"，扫描会在后台继续。
              </>
            ) : (
              "你想要退出应用，还是只把窗口最小化到任务栏？"
            )}
          </p>
        </div>
        <div className="preview-modal__footer" style={{ display: "flex", gap: 8, justifyContent: "flex-end", padding: "12px 20px" }}>
          <button className="btn btn--ghost" onClick={onCancel}>取消</button>
          <button className="btn btn--ghost" onClick={onMinimize}>最小化</button>
          <button className="btn btn--primary" onClick={onExit}>
            {scanActive ? "强制退出" : "退出应用"}
          </button>
        </div>
      </div>
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
        <button
          className="btn btn--sm btn--primary"
          onClick={onDownload}
          disabled={downloadState === "downloading"}
          title={downloadState === "downloading" ? "已在后台下载，无需重复点击" : ""}
        >
          {downloadState === "downloading" ? "已在下载..." : "后台下载，下次重启自动应用"}
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

/**
 * ThemeSwitcher —— 顶栏 system / auto-time / dark / light 切换（v2.8.1 换用 Material 风格 <Select>）。
 *
 * 选项：
 *   - 跟随系统  —— prefers-color-scheme，OS 设置说了算
 *   - 跟随时间  —— 06-18 浅色 / 18-06 深色，跨平台一致
 *   - 深色 / 浅色 —— 手动锁定
 */
function ThemeSwitcher() {
  const [th, setTh] = React.useState(() => getTheme());
  React.useEffect(() => onThemeChange((v) => setTh(v)), []);
  const META: Record<string, { label: string; Icon: React.ComponentType<any>; hint: string }> = {
    system:      { label: "跟随系统", Icon: IconSunMoon, hint: "由 macOS / Windows 当前主题决定" },
    "auto-time": { label: "跟随时间", Icon: IconClock,   hint: "白天浅色 (6–18)，夜里深色" },
    dark:        { label: "深色",     Icon: IconMoon,    hint: "始终保持暗色" },
    light:       { label: "浅色",     Icon: IconSun,     hint: "始终保持亮色" },
  };
  return (
    <Select
      value={th}
      onChange={(v) => setTheme(v as any)}
      variant="ghost"
      size="sm"
      title="主题 / Theme"
      ariaLabel="切换主题"
      options={AVAILABLE_THEMES.map((t) => {
        const Icon = META[t]?.Icon;
        return {
          value: t,
          icon: Icon ? <Icon size={15} /> : null,
          label: META[t]?.label ?? t,
          hint: META[t]?.hint,
        };
      })}
    />
  );
}

/**
 * LocaleSwitcher —— 顶栏右侧"中 / EN"切换。
 * 切换后所有用 t() 的文案立即更新；存进 localStorage 下次启动还原。
 */
function LocaleSwitcher() {
  const [loc, setLoc] = React.useState(() => getLocale());
  React.useEffect(() => onLocaleChange((l) => setLoc(l)), []);
  const META: Record<string, { label: string }> = {
    zh: { label: "中文" },
    en: { label: "English" },
  };
  return (
    <Select
      value={loc}
      onChange={(v) => setLocale(v)}
      variant="ghost"
      size="sm"
      title={loc === "zh" ? "切换语言" : "Switch language"}
      ariaLabel="Change language"
      options={AVAILABLE_LOCALES.map((l) => ({
        value: l,
        // 用 IconGlobe 替代国旗 emoji ——"语言"概念全球通用，不绑定单一国家
        icon: <IconGlobe size={15} />,
        label: META[l]?.label ?? l,
      }))}
    />
  );
}

// v2.8.19: exportDiagnosticBundle 函数已废弃 —— 改为 topbar 按钮 onClick 直接 setToolDialog
// （走统一的 ToolDialog 框架而不是 native prompt）

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

/**
 * ToolsMenu —— 顶栏"工具箱"下拉，把之前十几个 orphaned 功能都接到一个单点。
 *
 * 完整菜单（按分组）：
 *   🩺 磁盘健康：SMART / SED OPAL
 *   🗂 GPT：分区表恢复
 *   📸 恢复目录操作：查重复图 / EXIF 归档提示 / 计划备份
 *   🔍 OCR 搜图（需 tesseract）
 *   🕵️ 取证：时间线 / DFXML / 保管链 / VirusTotal / NSRL
 *   🌐 网络镜像：挂载建议
 *   ⚡ 多盘并行扫描
 */
function ToolsMenu({ wailsApp, outputDir, selectedDrive, onOpenMobileModal, onDuplicateGroups, onToolDialog }) {
  const [open, setOpen] = React.useState(false);
  const [filter, setFilter] = React.useState("");
  const ref = React.useRef(null);
  const searchRef = React.useRef(null);

  React.useEffect(() => {
    function onClick(e) {
      if (ref.current && !ref.current.contains(e.target)) setOpen(false);
    }
    globalThis.addEventListener("click", onClick);
    return () => globalThis.removeEventListener("click", onClick);
  }, []);

  // Cmd/Ctrl+K 全局快捷键打开工具菜单 + 自动 focus 搜索框
  React.useEffect(() => {
    function onKey(e) {
      const isMod = e.metaKey || e.ctrlKey;
      if (isMod && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setOpen(true);
        setTimeout(() => searchRef.current?.focus(), 0);
      } else if (e.key === "Escape" && open) {
        setOpen(false);
        setFilter("");
      }
    }
    globalThis.addEventListener("keydown", onKey);
    return () => globalThis.removeEventListener("keydown", onKey);
  }, [open]);

  // 打开时自动 focus 搜索框 + 清空 filter
  React.useEffect(() => {
    if (open) {
      setFilter("");
      setTimeout(() => searchRef.current?.focus(), 50);
    }
  }, [open]);

  const drivePath = selectedDrive?.path || "";

  // v2.8.39: 之前 `if (msg && r)` 在 r 是 null/undefined/空数组时跳过 toast ——
  // 用户点击如 "📸 APFS 时光快照" 等工具，在没有 APFS 的盘上 backend 返回 nil
  // (= JS null) → 整个调用静默无反应。用户报"点击无效果"。
  // 修：只要 msg 在就一定调用，让 msg 自己判定空数据 → 回退"未发现 X"提示。
  // 所有 msg callback 实测都已经做了 !list / list.length===0 检查，安全。
  async function runAsync(fn, msg) {
    setOpen(false);
    try {
      const r = await fn();
      if (msg) {
        const out = msg(r);
        if (out) toast.info(out);
      }
    } catch (err) {
      toast.error("失败: " + (err?.message || err));
    }
  }

  // filter 命中：拆掉 emoji + 大小写不敏感的子串匹配
  const matches = (label) => {
    if (!filter) return true;
    const s = String(label).toLowerCase().replace(/[\p{Emoji_Presentation}\p{Extended_Pictographic}]/gu, "").trim();
    return s.includes(filter.toLowerCase().trim());
  };

  // v2.8.20 Issue 21: item 加 needsDisk 形参标记"需要先选盘才能用的工具"。
  // 未选盘时按钮变灰 + 不可点 + tooltip 提示，避免点了报"deviceWebPath 为空"。
  const item = (label, handler, needsDisk = false) => {
    if (!matches(label)) return null;
    const disabled = needsDisk && !drivePath;
    return (
      <button
        key={label}
        onClick={disabled ? undefined : handler}
        disabled={disabled}
        title={disabled ? "请先在主界面选源盘 —— 这个工具需要针对具体磁盘操作" : undefined}
        style={{
          display: "block", width: "100%", textAlign: "left",
          padding: "var(--space-2) var(--space-3)",
          border: "none", background: "transparent",
          cursor: disabled ? "not-allowed" : "pointer",
          fontSize: "var(--text-sm)",
          color: disabled ? "var(--text-muted)" : "var(--text)",
          opacity: disabled ? 0.55 : 1,
        }}
        onMouseEnter={(e) => { if (!disabled) e.currentTarget.style.background = "var(--bg-surface-2)"; }}
        onMouseLeave={(e) => { e.currentTarget.style.background = "transparent"; }}
      >
        {label}
        {disabled && <span style={{ marginLeft: 6, fontSize: 10 }}>（需先选源盘）</span>}
      </button>
    );
  };

  return (
    <div ref={ref} style={{ position: "relative" }}>
      <button
        className="btn btn--sm btn--ghost"
        onClick={() => setOpen((v) => !v)}
        title="工具箱 (Cmd+K / Ctrl+K)"
      >
        🧰 工具 <kbd style={{
          marginLeft: 6, padding: "1px 5px", fontSize: 10,
          color: "var(--text-subtle)", border: "1px solid var(--border)",
          borderRadius: 3, fontFamily: "var(--font-mono)",
        }}>⌘K</kbd>
      </button>
      {open && (
        <div style={{
          position: "absolute", top: "100%", right: 0, marginTop: 4,
          background: "var(--bg-surface)", border: "1px solid var(--border)",
          borderRadius: "var(--radius-md)", width: 320,
          maxHeight: "70vh", overflowY: "auto",
          boxShadow: "var(--shadow-lg)",
          zIndex: 100, padding: 0,
        }}>
          {/* 搜索框：Cmd+K 打开后自动 focus，type 立刻 filter */}
          <div style={{
            position: "sticky", top: 0,
            padding: "var(--space-3)",
            background: "var(--bg-surface)",
            boxShadow: "inset 0 -1px 0 0 var(--border)",
            zIndex: 1,
          }}>
            <input
              ref={searchRef}
              type="text"
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
              placeholder="搜工具… (Esc 关闭)"
              style={{
                width: "100%",
                padding: "6px 10px",
                background: "var(--bg-inset)",
                border: "1px solid var(--border)",
                borderRadius: "var(--radius-sm)",
                color: "var(--text)",
                fontSize: "var(--text-sm)",
                outline: "none",
                boxSizing: "border-box",
              }}
              onKeyDown={(e) => {
                if (e.key === "Escape") {
                  if (filter) setFilter("");
                  else setOpen(false);
                }
              }}
            />
          </div>
          <div style={{ padding: "var(--space-1) 0" }}>
          {item("🩺 磁盘 S.M.A.R.T. 健康", async () => {
            setOpen(false);
            // v2.8.20 Issue 20: 未选盘时直接告诉用户去选盘（双重保险 —— item disabled 之外再判一次）
            if (!drivePath) {
              toast.warning({
                title: "请先选源盘",
                description: "S.M.A.R.T. 健康检查需要先在主界面选中一块物理盘 / 逻辑盘；" +
                  "本工具是针对具体磁盘读 SMART 寄存器的，没盘可查时无意义。",
                duration: 8000,
              });
              return;
            }
            try {
              const r = await wailsApp?.QueryDiskHealth?.(drivePath);
              if (!r) {
                toast.warning("S.M.A.R.T. 查询无返回");
                return;
              }
              if (!r.available) {
                // v2.8.17 Issue 6: SMART 不可用是 USB 桥接 / 虚拟盘等场景的物理限制
                // （USB-SATA 桥接芯片大多不透传 SMART 命令；这是硬件层限制不是 bug）。
                // 改善文案：明确说明原因 + 给出替代方案，而不只是冷冰冰一句"不可用"。
                const reason = r.notes || "未知原因";
                const desc = `${reason}\n\n常见原因：\n` +
                  `· U 盘 / SD 卡 / USB 移动硬盘（USB-SATA 桥不透传 SMART 命令，业界普遍限制）\n` +
                  `· 虚拟磁盘 / 镜像文件 / 网络盘（无物理 SMART 数据）\n` +
                  `· 部分 NVMe 走 nvme-cli 而非 SATA SMART\n\n` +
                  `不影响数据扫描和恢复 —— 直接选源盘开始扫描即可。\n` +
                  `如需健康检测：把硬盘装回主机直连 SATA / NVMe 后重试；` +
                  `或用 CrystalDiskInfo / smartctl --scan 等专业工具。`;
                // v2.8.20 Issue 20: toast 加 id 防止重复触发时叠加。
                // v2.8.28 Issue 5: duration 从 0（永不自动关闭）改为 15s。
                // 之前用户反馈"不会自动关闭很烦"——文字虽然多但 15s 够看完且能手动关。
                toast.warning({ title: "S.M.A.R.T. 不可用（硬件限制，非软件 bug）", description: desc, duration: 15000, dedupeKey: "smart-unavailable" });
                return;
              }
              // 拼装多行 description：型号 / 通电时长 / 温度 / 坏扇区
              const lines: string[] = [];
              if (r.model) lines.push(`型号：${r.model}`);
              if (r.serial) lines.push(`序列号：${r.serial}`);
              if (r.powerOnHours) {
                const years = (r.powerOnHours / 24 / 365).toFixed(1);
                lines.push(`通电：${r.powerOnHours.toLocaleString()} 小时（约 ${years} 年）`);
              }
              if (r.temperature) lines.push(`温度：${r.temperature} °C`);
              if (r.reallocated) lines.push(`已重映射坏扇区：${r.reallocated}`);
              if (r.pendingSectors) lines.push(`摇摆扇区：${r.pendingSectors}`);
              if (r.uncorrectableErrors) lines.push(`不可纠正错误：${r.uncorrectableErrors}`);
              const desc = [r.notes, lines.length ? lines.join("\n") : ""].filter(Boolean).join("\n\n");
              const title = `SMART：${r.healthy ? "健康" : "异常"}`;
              if (r.healthy) toast.success({ title, description: desc, duration: 10000 });
              else           toast.error({ title, description: desc, duration: 15000 });
            } catch (err: any) {
              toast.error("SMART 查询失败：" + (err?.message || err));
            }
          }, true /* needsDisk */)}
          {item("🔒 SED OPAL 锁定状态", async () => {
            setOpen(false);
            if (!drivePath) {
              toast.warning("请先选源盘再查 SED");
              return;
            }
            try {
              const r = await wailsApp?.QuerySEDStatus?.(drivePath);
              if (!r) {
                toast.warning("SED 查询无返回");
                return;
              }
              if (!r.available) {
                // v2.8.29: 详细说明 SED 是什么 + 怎么验证装好 sedutil 后能用
                toast.warning({
                  title: "SED 检测不可用",
                  description:
                    (r.note || "") + "\n\n" +
                    "什么是 SED：Self-Encrypting Drive，企业级 SSD 自带的 AES-XTS 全盘硬件加密\n" +
                    "（Samsung 850 EVO Pro / Intel SSD Pro / Micron 等）。普通家用盘 99% 不是 SED。\n\n" +
                    "如何验证：\n" +
                    "1. 装 sedutil-cli（开源工具）：https://github.com/Drive-Trust-Alliance/sedutil\n" +
                    "2. 命令行跑 sedutil-cli --scan，列出当前机器上所有 SED 盘\n" +
                    "3. 装好后重启本工具，本菜单就能查锁定状态了\n\n" +
                    "普通用户：跳过这一项即可，对扫描和恢复无影响",
                  duration: 15000,
                });
                return;
              }
              if (r.locked) {
                toast.error({
                  title: "SED 已锁定",
                  description: r.note + (r.opalVersion ? `\n\nOPAL 版本：${r.opalVersion}` : ""),
                  duration: 15000,
                });
              } else if (r.isSED) {
                toast.success({
                  title: r.lockingEnabled ? "SED 已启用 · 未锁定" : "SED 支持 · 未启用 locking",
                  description: r.note + (r.opalVersion ? `\n\nOPAL 版本：${r.opalVersion}` : ""),
                });
              } else {
                toast.info({ title: "盘不支持 TCG SED", description: r.note });
              }
            } catch (err: any) {
              toast.error("SED 查询失败：" + (err?.message || err));
            }
          }, true /* needsDisk */)}
          {item("🗂 GPT 备份表恢复", async () => {
            setOpen(false);
            if (!drivePath) {
              toast.warning("请先选源盘再恢复 GPT 备份表");
              return;
            }
            try {
              const parts = await wailsApp?.RecoverGPTPartitions?.(drivePath);
              if (!parts || parts.length === 0) {
                // v2.8.29: 加引导 —— "未找到"是正常的（多数盘是 MBR / 没坏 GPT）
                toast.info({
                  title: "未找到备份 GPT 分区表",
                  description:
                    "可能原因：\n" +
                    "  · 盘是 MBR 分区方式（老 BIOS 系统 / U 盘常见）\n" +
                    "  · GPT 主表健康，没必要恢复（只在主表损坏时才用备份表）\n" +
                    "  · 选的是逻辑卷（C: / D:）而不是物理盘 —— 必须在 PhysicalDrive* 上查\n" +
                    "  · 盘的备份表也已损坏（最后 33 个扇区被覆写）\n\n" +
                    "对扫描和恢复没影响，这个工具只是给「分区表挂掉了」的特殊场景用。",
                  duration: 12000,
                });
                return;
              }
              // v2.8.33: 用 GPTPartitionInfo DTO（含 typeName/sizeHuman 等已解码字段），
              // 不再读裸字段（之前没 JSON tag 全部 undefined）。
              const lines = parts.slice(0, 8).map((p: any) => {
                const name = (p.name && p.name.trim()) || p.typeName || "(未命名)";
                return `${p.index}. ${name} · ${p.sizeHuman || "?"} · LBA ${p.firstLBA}–${p.lastLBA}`;
              });
              const more = parts.length > 8 ? `\n…还有 ${parts.length - 8} 个` : "";
              toast.success({
                title: `✅ 从备份 GPT 读出 ${parts.length} 个分区`,
                description:
                  lines.join("\n") + more + "\n\n" +
                  "这是诊断信息 —— 证明备份表有效，分区元数据可读。\n" +
                  "如要真的把备份表写回主位置，业界标准做法是用专门工具：\n" +
                  "  · Linux: sgdisk --backup-from-backup\n" +
                  "  · Windows: TestDisk（开源）→ Advanced → Boot → Repair GPT\n" +
                  "本工具不直接改盘（设计原则：源盘只读），以免误操作。",
                duration: 25000,
              });
            } catch (err: any) {
              toast.error({
                title: "GPT 备份恢复失败",
                description: (err?.message || String(err)) +
                  "\n\n提示：GPT 备份表在物理盘的最后一个 LBA。在逻辑卷（C: / G: 等）上读不到，请选物理盘（PhysicalDrive*）后再试。",
                duration: 15000,
              });
            }
          }, true /* needsDisk */)}
          {item("🖼 查找重复图片", async () => {
            // v2.8.29 Issue 8: 加进度提示 toast。之前查重期间静默几十秒甚至几分钟，
            // 用户不知道有没有在跑，体验差。dedupeKey 保证不会叠多条 toast。
            // v2.8.39: toast.onDismiss → CancelFindDuplicateImages —— 用户关闭
            // toast 时让后台 Walk + hash 立刻退出，不再继续吃 IO。
            try {
              const dir = await wailsApp?.SelectDirectory?.("选择要查重的目录");
              if (!dir) return; // 用户取消

              toast.info({
                title: "🖼 正在扫描重复图片",
                description: `目录：${dir}\n\n每张图片算 perceptual hash 后两两比对，目录里图越多越慢。\n大目录（>1 万张）可能要 1-3 分钟，请等待...\n\n💡 提示：点 × 关闭此提示会同时停止后台扫描`,
                duration: 60000,
                dedupeKey: "dup-scan-running",
                onDismiss: () => {
                  // 自然结束时（结果到了主动调 dismissByKey）已 no-op；
                  // 用户主动关 toast 时真正取消 backend。
                  wailsApp?.CancelFindDuplicateImages?.();
                },
              });

              const groups = await wailsApp?.FindDuplicateImages?.(dir, 5);

              // 关掉进度 toast（结果出来了）
              toast.dismissByKey?.("dup-scan-running");

              if (!groups || groups.length === 0) {
                toast.info({ title: "✅ 扫描完成 · 未找到重复图片", description: "目录里没有相似度超过阈值的组（perceptual hash 距离 > 5）" });
                return;
              }
              // 弹出 DuplicateImagesModal 让用户看具体路径 + 删除/打开
              onDuplicateGroups?.(groups);
              toast.success({ title: `✅ 找到 ${groups.length} 组相似图片`, description: "点击查看并处理" });
            } catch (err: any) {
              toast.dismissByKey?.("dup-scan-running");
              toast.error("查重失败：" + (err?.message || err));
            }
          })}
          {item("🔎 OCR 搜图", () => {
            setOpen(false);
            onOpenMobileModal?.("ocr-search");
          })}
          {item("📅 计划定时备份", () => {
            // v2.8.31 Issue 0: 强化用户能看到的信息（说明做什么 / 装在哪 / 怎么卸载）
            // + Windows 隐藏 PowerShell 黑窗口（已在 internal/backup hideWindow 里做）
            // + 成功多行 toast 让用户看到任务名/时间/路径/验证方法
            setOpen(false);
            onToolDialog?.({
              title: "📅 计划定时备份",
              description:
                "在系统计划任务里装一个 daily 任务：每天指定时间用 robocopy（Windows）或 rsync（macOS/Linux）\n" +
                "把源目录镜像复制到目标目录。\n\n" +
                "用途：让恢复出来的数据自动备份到另一块盘，防止单盘故障再次丢数据。\n" +
                "前提：目标盘必须和源盘是**不同物理设备**（避免源盘故障同时丢备份）。\n\n" +
                "实现：\n" +
                "  · Windows: PowerShell Register-ScheduledTask，任务名 DataRecoveryBackup（v2.8.31 起隐藏黑窗口）\n" +
                "  · macOS / Linux: crontab 加一行 rsync 任务\n\n" +
                "卸载：Windows 开「任务计划程序」找 DataRecoveryBackup 右键删；或命令行\n" +
                "  schtasks /Delete /TN DataRecoveryBackup /F；Linux/macOS: crontab -e 删对应行。",
              fields: [
                {
                  key: "src",
                  label: "源目录（要备份的）",
                  type: "directory",
                  pickerTitle: "选择要备份的源目录",
                  defaultValue: outputDir || "",
                  placeholder: "例：C:\\Users\\xxx\\Documents 或 D:\\recovered",
                  hint: "通常是恢复输出目录或工作文件夹。Windows 路径含中文也支持。",
                  required: true,
                },
                {
                  key: "dst",
                  label: "目标目录（另一块盘上的位置）",
                  type: "directory",
                  pickerTitle: "选择备份目标目录",
                  placeholder: "例：E:\\backup\\daily",
                  hint: "⚠ 必须在不同物理盘上 —— 否则源盘坏的时候备份也一起丢",
                  required: true,
                },
                {
                  key: "hour",
                  label: "每天定时执行时间（小时，0-23）",
                  type: "number",
                  defaultValue: "2",
                  placeholder: "2",
                  hint: "默认凌晨 2 点（系统空闲时备份，不影响白天使用）",
                  required: true,
                },
              ],
              submitLabel: "安装定时任务",
              successPrefix: "✅",
              onSubmit: async (vals) => {
                const hour = parseInt(vals.hour, 10);
                if (isNaN(hour) || hour < 0 || hour > 23) throw new Error("小时必须是 0-23 之间的整数");
                await wailsApp?.ScheduleBackup?.(vals.src, vals.dst, hour);
                // v2.8.31: 多行 success message 给用户充分确认信息
                return `任务已装好 ✅\n\n` +
                  `任务名：DataRecoveryBackup\n` +
                  `触发时间：每天 ${String(hour).padStart(2, "0")}:00\n` +
                  `源：${vals.src}\n` +
                  `→ 目标：${vals.dst}\n\n` +
                  `验证：\n` +
                  `  · Windows: 开「任务计划程序」找 DataRecoveryBackup\n` +
                  `  · macOS / Linux: crontab -l 看到任务行即装好`;
              },
            });
          })}
          {item("📜 导出时间线 (mactime)", () => {
            // v2.8.29: 用 ToolDialog 引导用户选输出目录，并解释时间线是干什么的。
            // 之前直接传 outputDir || ""，输出目录为空时直接报错"outputDir 为空"，
            // 用户也不懂"时间线"是什么。
            setOpen(false);
            onToolDialog?.({
              title: "📜 导出时间线 (mactime / bodyfile 格式)",
              description:
                "把这次扫描发现的全部文件按时间顺序导出成 SleuthKit mactime body file，\n" +
                "再用 mactime 工具能生成「2024-03-15 14:30:21 文件 X 被修改」这种事件日志。\n\n" +
                "用途：取证场景查「被偷电脑里的攻击者操作时间线」；普通恢复场景可不导出。\n\n" +
                "输出文件：<目录>/timeline-YYYYMMDD-HHMMSS.body —— 用 SleuthKit 的 mactime\n" +
                "命令二次处理：mactime -b timeline-XXX.body -d > events.csv",
              fields: [
                {
                  key: "dir",
                  label: "输出目录",
                  type: "directory",
                  pickerTitle: "选择时间线导出目录",
                  defaultValue: outputDir || "",
                  hint: outputDir ? "默认是上次恢复输出目录；可改成其它目录" : "请选择把 timeline 文件保存到哪",
                  required: true,
                },
              ],
              submitLabel: "导出",
              onSubmit: async (vals) => {
                const p = await wailsApp?.ExportTimeline?.(vals.dir, "mactime");
                return `已导出：${p}`;
              },
            });
          })}
          {item("📄 导出 DFXML 取证报告", () => {
            // v2.8.29: 同 timeline，prompt outputDir + 解释用途
            setOpen(false);
            onToolDialog?.({
              title: "📄 导出 DFXML 取证报告",
              description:
                "DFXML (Digital Forensics XML) 是数字取证行业标准格式，记录扫描发现的所有文件的元数据：\n" +
                "  · 文件名 / 大小 / 偏移 / SHA-256\n" +
                "  · byte runs（碎片在磁盘上的物理位置）\n" +
                "  · 来源（carver / NTFS / exFAT...）\n\n" +
                "用途：交付给法务 / 第三方取证人员做证据；用 fiwalk / dfxml-python 等工具进一步分析。\n" +
                "普通家用恢复场景可以不导出。\n\n" +
                "输出文件：<目录>/dfxml-YYYYMMDD-HHMMSS.xml —— 可用浏览器或 fiwalk 工具打开。",
              fields: [
                {
                  key: "dir",
                  label: "输出目录",
                  type: "directory",
                  pickerTitle: "选择 DFXML 报告导出目录",
                  defaultValue: outputDir || "",
                  hint: outputDir ? "默认是上次恢复输出目录；可改成其它目录" : "请选择把 DFXML 文件保存到哪",
                  required: true,
                },
              ],
              submitLabel: "导出",
              onSubmit: async (vals) => {
                const p = await wailsApp?.ExportDFXML?.(vals.dir);
                return `已导出：${p}`;
              },
            });
          })}
          {item("🔐 生成保管链 (custody.json)", () => {
            // v2.8.29: 用户直接点这个工具时 outputDir 经常为空 → 后端报"outputDir 为空"。
            // 改成 ToolDialog 强制让用户选恢复输出目录（custody 是对那个目录里所有文件算 SHA256）。
            setOpen(false);
            onToolDialog?.({
              title: "🔐 生成保管链 (custody.json)",
              description:
                "保管链 (Chain of Custody) 是取证场景的标配文档：\n" +
                "  · 谁（操作员） / 何时 / 用什么工具 / 从哪个源盘恢复了哪些文件\n" +
                "  · 每个恢复文件的 SHA-256，证明从生成到提交未被篡改\n\n" +
                "用途：法庭 / 公司内审 / 跨团队交付时证明数据完整性。普通家用恢复场景可不生成。\n\n" +
                "操作：选已经做完恢复的输出目录 → 本工具递归算 SHA-256 + 写 custody.json。",
              fields: [
                {
                  key: "dir",
                  label: "恢复输出目录",
                  type: "directory",
                  pickerTitle: "选择已恢复完成的输出目录",
                  defaultValue: outputDir || "",
                  hint: "工具会递归扫描这个目录算每个文件的 SHA-256 —— 文件多/盘大时较慢",
                  required: true,
                },
                {
                  key: "operator",
                  label: "操作员（可选）",
                  type: "text",
                  placeholder: "你的姓名 / 工号，会写进 custody.json",
                  hint: "用于取证场景标识谁执行了恢复操作；私人使用可留空",
                  required: false,
                },
              ],
              submitLabel: "生成",
              onSubmit: async (vals) => {
                const p = await wailsApp?.BuildCustody?.(vals.dir, drivePath || "", vals.operator || "");
                return `已生成：${p}`;
              },
            });
          })}
          {item("✅ 校验保管链", () => {
            // v2.8.29: 同 BuildCustody，让用户选 custody.json 所在目录
            setOpen(false);
            onToolDialog?.({
              title: "✅ 校验保管链",
              description:
                "重算保管链 (custody.json) 里记录的每个文件的 SHA-256，与原值比对，发现：\n" +
                "  · 被删除的文件（manifest 里有但盘上没有）\n" +
                "  · 被修改的文件（manifest hash 与重算 hash 不一致）\n" +
                "  · 多出来的文件（盘上有但 manifest 没记）\n\n" +
                "用途：在交付证据后任何时间点重新验证文件没被改过。",
              fields: [
                {
                  key: "dir",
                  label: "含 custody.json 的目录",
                  type: "directory",
                  pickerTitle: "选择含 custody.json 的目录",
                  defaultValue: outputDir || "",
                  hint: "通常是之前「生成保管链」用的输出目录",
                  required: true,
                },
              ],
              submitLabel: "校验",
              onSubmit: async (vals) => {
                const probs = await wailsApp?.VerifyCustody?.(vals.dir);
                if (!probs || probs.length === 0) return "✅ 保管链完整 —— 所有文件 SHA-256 都与 custody.json 记录一致";
                return "⚠️ 发现 " + probs.length + " 处问题：\n" + probs.join("\n");
              },
            });
          })}
          {item("📥 载入 NSRL hash 库", () => {
            // v2.8.29: 支持系统文件选择器（之前要求手贴绝对路径）
            setOpen(false);
            onToolDialog?.({
              title: "📥 载入 NSRL hash 库",
              description:
                "NSRL（National Software Reference Library）是 NIST 发布的「已知良性软件」hash 库。\n\n" +
                "用途：恢复出 50 万个文件后，绝大多数是 Windows / macOS / 已装软件的系统文件" +
                "（用户根本不关心）。载入 NSRL 后扫描结果会自动隐藏这些已知系统文件，让真正的" +
                "用户数据浮上来 —— 数据恢复行业标准做法。\n\n" +
                "下载：https://www.nist.gov/itl/ssd/software-quality-group/national-software-reference-library-nsrl/" +
                "nsrl-download/current-rds —— 选「Modern」或「Legacy」库下载，解压后是 NSRLFile.txt。\n\n" +
                "文件格式：每行一个 SHA-1 / MD5 hash（NSRL 官方格式 / SleuthKit hashdb 格式都识别）。",
              fields: [
                {
                  key: "path",
                  label: "NSRL hash 文件",
                  type: "file",
                  pickerTitle: "选择 NSRL hash 库（NSRLFile.txt）",
                  fileFilterName: "NSRL hash 库",
                  fileFilterExt: "*.txt;*.csv;*.tsv",
                  placeholder: "点右边「选文件」打开系统文件选择器",
                  hint: "支持 NSRL 官方格式（SHA-1/MD5 每行一个）和 SleuthKit hashdb 格式",
                  required: true,
                },
              ],
              submitLabel: "载入",
              onSubmit: async (vals) => {
                const n = await wailsApp?.LoadNSRLDatabase?.(vals.path);
                return `已载入 ${n?.toLocaleString?.() || n} 个已知良性 hash —— 后续扫描会自动隐藏匹配的文件`;
              },
            });
          })}
          {item("🌐 网络镜像挂载建议", () => {
            // v2.8.18 Issue 1: ToolDialog
            setOpen(false);
            onToolDialog?.({
              title: "🌐 网络镜像挂载建议",
              description:
                "扫描 NAS / 远程共享上的镜像文件时，先要把它「挂载」成本地路径。\n\n" +
                "本工具不直接挂载（涉及凭据 + 平台命令），而是给你一份针对你目标 URL 的可复制" +
                "操作步骤（mount / net use / iscsiadm 等命令），你在终端 / 管理员 PowerShell 里" +
                "执行后就能在本地看到挂载点，然后用本工具的「选择镜像文件...」加载它。\n\n" +
                "支持协议：SMB（Windows 共享）/ NFS（Linux 共享）/ iSCSI（SAN 块设备）",
              fields: [
                {
                  key: "url",
                  label: "远程 URL",
                  type: "text",
                  defaultValue: "smb://",
                  placeholder: "smb://192.168.1.100/share / nfs://10.0.0.1:/export / iscsi://target.example",
                  hint: "包含完整协议 + 主机 + 路径；本工具只解析不发起连接",
                  required: true,
                },
              ],
              submitLabel: "生成挂载建议",
              onSubmit: async (vals) => {
                const adv = await wailsApp?.SuggestNetworkMount?.(vals.url);
                if (!adv || adv.length === 0) return "没有匹配的挂载方案（URL 协议可能不支持）";
                return adv.map((a: any) => a.method + ":\n" + a.steps.join("\n")).join("\n\n");
              },
            });
          })}
          {item("⚡ 多盘并行扫描", () => {
            setOpen(false);
            onOpenMobileModal?.("multi-disk-scan");
          })}
          {item("📸 APFS 时光快照", () => runAsync(
            () => wailsApp?.ListAPFSSnapshots?.(drivePath || ""),
            (list) => list.length === 0
              ? "✅ 已扫描，未发现 APFS 时光快照\n\n" +
                "这是正常的：APFS 是 macOS 的文件系统（HFS+ 的后继），只有 macOS 内置 Time\n" +
                "Machine 备份盘 / 用户手动 tmutil 创建 snapshot 才会有这些快照。\n" +
                "Windows / Linux 盘上不会有 APFS 快照。\n\n" +
                "对扫描和恢复无影响，本工具只是给 macOS 用户挖「删除前的 snapshot 时点」。"
              : list.map((c) => `容器 0x${c.containerOffset.toString(16)}: ${c.snapshots.length} 个 snapshot`).join("\n")
          ), true /* needsDisk */)}

          {/* ==================== 移动端 / 备份 / 云端 / NAS（v2.4 解锁）  ==================== */}

          <div style={{ boxShadow: "inset 0 1px 0 0 var(--border)", margin: "6px 0" }} />

          {item("☁️ 扫云端备份（iCloud/OneDrive/Drive...）", () => {
            setOpen(false);
            onOpenMobileModal?.("cloud");
          })}

          {item("📱 扫 iOS 备份（本机 MobileSync）", () => runAsync(
            () => wailsApp?.DiscoverIOSBackups?.(),
            (list) => {
              if (!list || list.length === 0) return "未发现 iOS 备份\n（路径：~/Library/Application Support/MobileSync/Backup/）";
              return `发现 ${list.length} 个 iOS 备份：\n` +
                list.map((b) => `  • ${b.deviceName || "未命名"} (${b.iosVersion || "?"}) ${b.encrypted ? "🔒加密" : "明文"} - ${b.path}`).join("\n");
            }
          ))}

          {item("🔍 启动 iOS 备份扫描", () => {
            // v2.8.18 Issue 1: ToolDialog 替代两个连续 prompt
            setOpen(false);
            onToolDialog?.({
              title: "🔍 启动 iOS 备份扫描",
              description:
                "扫描 iTunes / Finder 里的 iOS 设备本地备份，提取相册、消息、通讯录等数据。\n\n" +
                "iOS 备份默认目录：\n" +
                "  • Windows：C:\\Users\\<用户>\\Apple\\MobileSync\\Backup\\<UUID>\n" +
                "  • macOS：~/Library/Application Support/MobileSync/Backup/<UUID>\n\n" +
                "每个 UUID 子目录是一个 iPhone/iPad 的备份（多设备会有多个）。\n" +
                "扫云端备份功能可以列出本机所有备份及其设备名 —— 可以先点那个找路径。",
              fields: [
                {
                  key: "path",
                  label: "iOS 备份目录路径",
                  type: "directory",
                  pickerTitle: "选择 iOS 备份目录（含 Manifest.plist 那层）",
                  placeholder: "C:\\Users\\xxx\\Apple\\MobileSync\\Backup\\<UUID>",
                  hint: "选到含 Manifest.db / Manifest.plist 的那一级",
                  required: true,
                },
                {
                  key: "pwd",
                  label: "加密备份密码（如果有）",
                  type: "password",
                  placeholder: "明文备份请留空",
                  hint: "iOS 备份默认明文，若用户在 iTunes 勾了「加密本地备份」才需要密码",
                  required: false,
                },
              ],
              submitLabel: "启动扫描",
              onSubmit: async (vals) => {
                await wailsApp?.StartIOSBackupScan?.(vals.path, vals.pwd || "");
                return "iOS 备份扫描已启动；进度请见左侧任务面板";
              },
            });
          })}

          {item("🤖 选 Android .ab 备份扫描", async () => {
            // v2.8.19: 用 ToolDialog 替代 native prompt（只在文件加密时弹）
            try {
              const path = await wailsApp?.SelectAndroidBackup?.();
              if (!path) return; // 用户取消文件选择
              const info = await wailsApp?.InspectAndroidBackup?.(path);
              if (!info?.encrypted) {
                // 明文 .ab：直接启动扫描
                await wailsApp?.StartAndroidBackupScan?.(path, "");
                toast.success({ title: "Android .ab 扫描已启动", description: path });
                return;
              }
              // 加密 .ab：弹 ToolDialog 让用户输密码
              setOpen(false);
              onToolDialog?.({
                title: "🔒 Android .ab 加密备份扫描",
                description:
                  "选中的 .ab 备份是加密的（adb backup 时用户设了密码）。\n\n" +
                  "Android 4.0+ adb backup 用 PBKDF2-SHA1 + AES 加密；密码错了解密会失败但不会损坏文件。\n\n" +
                  "文件路径：" + path,
                fields: [
                  {
                    key: "pwd",
                    label: ".ab 加密备份密码",
                    type: "password",
                    placeholder: "用户在手机 adb backup 时设的密码",
                    hint: "这个密码不存任何地方，仅用于本次扫描",
                    required: true,
                  },
                ],
                submitLabel: "解密并启动扫描",
                onSubmit: async (vals) => {
                  await wailsApp?.StartAndroidBackupScan?.(path, vals.pwd);
                  return `已启动扫描：${path}`;
                },
              });
            } catch (err: any) {
              toast.error("Android .ab 扫描失败：" + (err?.message || err));
            }
          })}

          <div style={{ boxShadow: "inset 0 1px 0 0 var(--border)", margin: "6px 0" }} />

          {item("🔌 手机直连 ADB 设备列表", () => runAsync(
            () => wailsApp?.MTPListDevices?.(),
            (list) => {
              if (!list || list.length === 0) return "未发现 Android 设备\n请：\n  1. 手机开 USB 调试\n  2. 接 USB 线\n  3. 点手机弹出的 '允许 USB 调试'";
              return `发现 ${list.length} 个 Android 设备：\n` +
                list.map((d) => `  • ${d.model || d.serial} (${d.state}) ${d.product || ""}`).join("\n");
            }
          ))}

          {item("📂 ADB 拉手机目录扫描", () => {
            setOpen(false);
            onOpenMobileModal?.("adb-pull");
          })}

          {item("💽 Android root 块级 dump", () => {
            setOpen(false);
            onOpenMobileModal?.("android-dump");
          })}

          {item("📷 PTP 相机（gphoto2）拉照片扫描", () => {
            setOpen(false);
            onOpenMobileModal?.("ptp-camera");
          })}

          {item("🍎 iOS 直连备份触发（libimobiledevice）", () => {
            setOpen(false);
            onOpenMobileModal?.("ios-backup");
          })}

          <div style={{ boxShadow: "inset 0 1px 0 0 var(--border)", margin: "6px 0" }} />

          {item("📡 NAS SMB 扫描", () => {
            setOpen(false);
            onOpenMobileModal?.("nas-smb");
          })}

          {item("📡 NAS NFSv3 扫描", () => {
            setOpen(false);
            onOpenMobileModal?.("nas-nfs");
          })}

          {item("🎯 RAID 阵列检测", () => runAsync(
            () => wailsApp?.DetectRAIDArrays?.(),
            (arrays) => {
              if (!arrays || arrays.length === 0) {
                // v2.8.29: 之前文案"未检测到 RAID 阵列"让用户以为是"工具失败"。
                // 改成正面表达："已扫描，没发现 RAID 成员盘"（说明是单盘环境，不需要重组）
                return "✅ 已扫描所有盘，未发现 mdadm / LVM / Storage Spaces 等 RAID 成员标记。\n这是正常的（说明你的盘是单盘环境，不需要 RAID 重组）。";
              }
              // v2.8.33: 字段名对齐 v2.8.33 加的 JSON tag — DetectedArray.{level, raidDisks, members}
              return `检测到 ${arrays.length} 个 RAID 阵列：\n` +
                arrays.map((a: any) => {
                  const memberCount = a.members?.length || a.raidDisks || 0;
                  const label = a.level || "未知 level";
                  const name = a.name ? ` "${a.name}"` : "";
                  return `  • ${label}${name} · ${memberCount} 盘 · UUID ${(a.uuid || "").slice(0, 8)}…`;
                }).join("\n") +
                "\n\n下一步：用 mdadm --assemble（Linux）/ Storage Spaces 管理器（Windows）\n" +
                "把阵列组装起来后，再选拼好的 /dev/mdX 设备扫描即可。";
            }
          ))}

          {/* v2.8.31 Issue 23: 加 needsDisk gate —— 跟 SMART/SED/GPT 等"必须先选源盘"的工具
              统一行为：菜单上文案带「（需先选源盘）」+ 按钮变灰 + tooltip 提示。
              之前点开 modal 才提示"未选源盘"，体验割裂。 */}
          {item("💾 整盘镜像 dump (.img)", () => {
            setOpen(false);
            onOpenMobileModal?.("disk-dump");
          }, true /* needsDisk */)}

          <div style={{ boxShadow: "inset 0 1px 0 0 var(--border)", margin: "6px 0" }} />
          {item("📦 关于本工具", () => {
            setOpen(false);
            onOpenMobileModal?.("about");
          })}
          </div>

          {/* 空搜索结果时给提示 */}
          {filter && !document.querySelector(`[data-tools-menu-item="match"]`) && (
            <div style={{
              padding: "var(--space-4)", fontSize: "var(--text-xs)",
              color: "var(--text-muted)", textAlign: "center",
            }}>
              没有匹配的工具
            </div>
          )}
        </div>
      )}
    </div>
  );
}
