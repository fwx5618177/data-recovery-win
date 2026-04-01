import React, {
  startTransition,
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import WelcomePage from "./components/WelcomePage";
import ScanningPage from "./components/ScanningPage";
import ResultsPage from "./components/ResultsPage";
import RecoveryPage from "./components/RecoveryPage";
import {
  DEFAULT_SCAN_MODE,
  buildFallbackScanResult,
  getDriveLabel,
  isCancellationError,
  normalizeRecoveryCompletion,
} from "./recovery-helpers";
import "./App.css";

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

const FLOW_STEPS = [
  { key: "welcome", label: "选择磁盘" },
  { key: "scanning", label: "执行扫描" },
  { key: "results", label: "筛选文件" },
  { key: "recovery", label: "恢复导出" },
];
const SCAN_FILE_FLUSH_DELAY = 200;

function getFlowState(currentPage, stepKey) {
  const currentIndex = FLOW_STEPS.findIndex((step) => step.key === currentPage);
  const stepIndex = FLOW_STEPS.findIndex((step) => step.key === stepKey);

  if (stepIndex < currentIndex) {
    return "done";
  }

  if (stepIndex === currentIndex) {
    return "active";
  }

  return "idle";
}

function getErrorText(error) {
  return String(error?.message || error || "").trim();
}

function getFriendlyActionError(action, error) {
  const text = getErrorText(error);

  if (!text) {
    return `${action}失败，请重试一次。`;
  }

  if (/管理员|权限|uac|access denied/i.test(text)) {
    return `${action}失败。\n请允许管理员权限后再试。`;
  }

  if (/同一块物理磁盘|同一块磁盘|源盘所在/i.test(text)) {
    return `${action}失败。\n恢复目录和源盘在同一块磁盘上，继续写入会覆盖待恢复数据。\n请改选另一块磁盘或 U 盘。`;
  }

  if (/输出目录|恢复目录/i.test(text)) {
    return `${action}失败。\n请先把恢复目录选到另一块磁盘或 U 盘。`;
  }

  if (/未选择任何文件|未找到要恢复的文件/i.test(text)) {
    return `${action}失败。\n请先选择要恢复的文件，或直接使用“恢复推荐文件”。`;
  }

  if (/恢复引擎|bridge|wails/i.test(text)) {
    return `${action}失败。\n当前没有连接到本地恢复引擎，请从桌面版程序启动。`;
  }

  if (/打开磁盘|读取|device|reader/i.test(text)) {
    return `${action}失败。\n请确认源盘仍然连接，且没有被其他程序占用。\n\n技术信息：${text}`;
  }

  return `${action}失败。\n${text}`;
}

function App() {
  const [currentPage, setCurrentPage] = useState("welcome");
  const [bridgeState, setBridgeState] = useState("loading");
  const [bridgeError, setBridgeError] = useState("");
  const [wailsApp, setWailsApp] = useState(null);
  const [wailsRuntime, setWailsRuntime] = useState(null);

  const [drives, setDrives] = useState([]);
  const [driveLoadError, setDriveLoadError] = useState("");
  const [isLoadingDrives, setIsLoadingDrives] = useState(false);
  const [selectedDrive, setSelectedDrive] = useState(null);

  const [scanProgress, setScanProgress] = useState(INITIAL_SCAN_PROGRESS);
  const [foundFiles, setFoundFiles] = useState([]);
  const [scanResult, setScanResult] = useState(null);
  const [scanActive, setScanActive] = useState(false);

  const [recoveryProgress, setRecoveryProgress] = useState(
    INITIAL_RECOVERY_PROGRESS,
  );
  const [outputDir, setOutputDir] = useState("");
  const [recoveryReturnPage, setRecoveryReturnPage] = useState("results");

  const foundFilesRef = useRef(foundFiles);
  const foundFileIndexRef = useRef(new Map());
  const pendingFoundFilesRef = useRef([]);
  const pendingFoundFlushRef = useRef(null);
  const scanProgressRef = useRef(scanProgress);
  const stopScanRequestedRef = useRef(false);

  useEffect(() => {
    foundFilesRef.current = foundFiles;
  }, [foundFiles]);

  useEffect(() => {
    scanProgressRef.current = scanProgress;
  }, [scanProgress]);

  const replaceFoundFiles = useCallback((nextFiles) => {
    const normalizedFiles = Array.isArray(nextFiles) ? nextFiles : [];
    const nextIndex = new Map();

    normalizedFiles.forEach((file, index) => {
      if (file?.id) {
        nextIndex.set(file.id, index);
      }
    });

    foundFilesRef.current = normalizedFiles;
    foundFileIndexRef.current = nextIndex;
    pendingFoundFilesRef.current = [];

    if (pendingFoundFlushRef.current) {
      clearTimeout(pendingFoundFlushRef.current);
      pendingFoundFlushRef.current = null;
    }

    startTransition(() => {
      setFoundFiles(normalizedFiles);
    });
  }, []);

  const flushPendingFoundFiles = useCallback(() => {
    const pendingFiles = pendingFoundFilesRef.current;
    if (pendingFiles.length === 0) {
      return;
    }

    pendingFoundFilesRef.current = [];

    if (pendingFoundFlushRef.current) {
      clearTimeout(pendingFoundFlushRef.current);
      pendingFoundFlushRef.current = null;
    }

    const nextFiles = foundFilesRef.current.slice();
    const nextIndex = new Map(foundFileIndexRef.current);

    pendingFiles.forEach((file) => {
      if (!file?.id) {
        return;
      }

      const existingIndex = nextIndex.get(file.id);
      if (existingIndex == null) {
        nextIndex.set(file.id, nextFiles.length);
        nextFiles.push(file);
        return;
      }

      nextFiles[existingIndex] = {
        ...nextFiles[existingIndex],
        ...file,
      };
    });

    foundFilesRef.current = nextFiles;
    foundFileIndexRef.current = nextIndex;

    startTransition(() => {
      setFoundFiles(nextFiles);
    });
  }, []);

  const queueFoundFile = useCallback(
    (file) => {
      if (!file?.id) {
        return;
      }

      pendingFoundFilesRef.current.push(file);
      if (pendingFoundFlushRef.current) {
        return;
      }

      pendingFoundFlushRef.current = setTimeout(() => {
        pendingFoundFlushRef.current = null;
        flushPendingFoundFiles();
      }, SCAN_FILE_FLUSH_DELAY);
    },
    [flushPendingFoundFiles],
  );

  useEffect(
    () => () => {
      if (pendingFoundFlushRef.current) {
        clearTimeout(pendingFoundFlushRef.current);
        pendingFoundFlushRef.current = null;
      }
    },
    [],
  );

  useEffect(() => {
    let cancelled = false;

    async function loadBridge() {
      try {
        const appModule = await import("../wailsjs/go/main/App");
        const runtimeModule = await import("../wailsjs/runtime/runtime");

        if (cancelled) {
          return;
        }

        setWailsApp(appModule);
        setWailsRuntime(runtimeModule);
        setBridgeError("");
        setBridgeState("ready");
      } catch (error) {
        if (cancelled) {
          return;
        }

        setBridgeState("error");
        setBridgeError(
          `无法连接本地恢复引擎。请从桌面版程序启动，不要在浏览器预览页里执行真实恢复。\n\n技术信息：${getErrorText(error) || "未知错误"}`,
        );
      }
    }

    loadBridge();

    return () => {
      cancelled = true;
    };
  }, []);

  const loadDrives = useCallback(async () => {
    if (bridgeState !== "ready" || !wailsApp?.GetDrives) {
      setDrives([]);
      return;
    }

    setIsLoadingDrives(true);
    setDriveLoadError("");

    try {
      const result = await wailsApp.GetDrives();
      setDrives(Array.isArray(result) ? result : []);
    } catch (error) {
      setDrives([]);
      setDriveLoadError(getFriendlyActionError("读取磁盘列表", error));
    } finally {
      setIsLoadingDrives(false);
    }
  }, [bridgeState, wailsApp]);

  useEffect(() => {
    if (bridgeState === "loading") {
      return;
    }

    loadDrives();
  }, [bridgeState, loadDrives]);

  useEffect(() => {
    if (!selectedDrive) {
      return;
    }

    const updatedDrive = drives.find(
      (drive) => drive.path === selectedDrive.path,
    );

    if (!updatedDrive) {
      setSelectedDrive(null);
      return;
    }

    if (updatedDrive !== selectedDrive) {
      setSelectedDrive(updatedDrive);
    }
  }, [drives, selectedDrive]);

  const showPartialScanResults = useCallback(() => {
    flushPendingFoundFiles();
    const fallbackResult = buildFallbackScanResult(
      foundFilesRef.current,
      scanProgressRef.current,
    );

    setScanActive(false);
    setScanResult(fallbackResult.files.length > 0 ? fallbackResult : null);
    setCurrentPage(fallbackResult.files.length > 0 ? "results" : "welcome");
  }, [flushPendingFoundFiles]);

  const viewCurrentResults = useCallback(() => {
    flushPendingFoundFiles();
    setScanResult(
      buildFallbackScanResult(foundFilesRef.current, scanProgressRef.current),
    );
    setCurrentPage("results");
  }, [flushPendingFoundFiles]);

  useEffect(() => {
    if (bridgeState !== "ready" || !wailsRuntime?.EventsOn) {
      return undefined;
    }

    const offScanProgress = wailsRuntime.EventsOn(
      "scan:progress",
      (payload) => {
        setScanProgress((prev) => ({ ...prev, ...payload }));
      },
    );

    const offScanFileFound = wailsRuntime.EventsOn(
      "scan:fileFound",
      (payload) => {
        queueFoundFile(payload);
      },
    );

    const offScanCompleted = wailsRuntime.EventsOn(
      "scan:completed",
      (payload) => {
        stopScanRequestedRef.current = false;
        setScanActive(false);
        flushPendingFoundFiles();
        if (Array.isArray(payload?.files)) {
          replaceFoundFiles(payload.files);
        }
        setScanResult(payload);
        setCurrentPage((page) => (page === "recovery" ? page : "results"));
      },
    );

    const offScanError = wailsRuntime.EventsOn(
      "scan:error",
      async (payload) => {
        const message = payload?.message || payload || "未知错误";

        if (stopScanRequestedRef.current || isCancellationError(message)) {
          stopScanRequestedRef.current = false;
          setScanActive(false);

          if (wailsApp?.GetScanResults) {
            try {
              const latest = await wailsApp.GetScanResults();
              if (Array.isArray(latest?.files) && latest.files.length > 0) {
                replaceFoundFiles(latest.files);
                setScanResult(latest);
                setCurrentPage((page) =>
                  page === "recovery" ? page : "results",
                );
                return;
              }
            } catch (error) {
              // noop
            }
          }

          showPartialScanResults();
          return;
        }

        setScanActive(false);
        alert(getFriendlyActionError("扫描", message));
        setCurrentPage((page) => (page === "recovery" ? page : "welcome"));
      },
    );

    const offRecoveryProgress = wailsRuntime.EventsOn(
      "recovery:progress",
      (payload) => {
        setRecoveryProgress((prev) =>
          normalizeRecoveryCompletion(payload, prev.total, prev.bytesWritten),
        );
      },
    );

    const offRecoveryCompleted = wailsRuntime.EventsOn(
      "recovery:completed",
      (payload) => {
        setRecoveryProgress((prev) =>
          normalizeRecoveryCompletion(payload, prev.total, prev.bytesWritten),
        );
      },
    );

    const offRecoveryError = wailsRuntime.EventsOn(
      "recovery:error",
      (payload) => {
        const message = payload?.message || payload || "未知错误";
        alert(getFriendlyActionError("恢复", message));
      },
    );

    return () => {
      [
        offScanProgress,
        offScanFileFound,
        offScanCompleted,
        offScanError,
        offRecoveryProgress,
        offRecoveryCompleted,
        offRecoveryError,
      ]
        .filter((handler) => typeof handler === "function")
        .forEach((handler) => handler());
    };
  }, [
    bridgeState,
    flushPendingFoundFiles,
    queueFoundFile,
    replaceFoundFiles,
    showPartialScanResults,
    wailsApp,
    wailsRuntime,
  ]);

  const startScan = useCallback(() => {
    if (!selectedDrive) {
      return;
    }
    if (bridgeState !== "ready" || !wailsApp?.StartScan) {
      alert("当前没有连接到本地恢复引擎，请从桌面版程序启动。");
      return;
    }

    stopScanRequestedRef.current = false;
    setScanActive(true);
    setScanProgress(INITIAL_SCAN_PROGRESS);
    replaceFoundFiles([]);
    setScanResult(null);
    setCurrentPage("scanning");

    wailsApp.StartScan(selectedDrive.path, DEFAULT_SCAN_MODE).catch((error) => {
      setScanActive(false);
      alert(getFriendlyActionError("启动扫描", error));
      setCurrentPage("welcome");
    });
  }, [bridgeState, replaceFoundFiles, selectedDrive, wailsApp]);

  const stopScan = useCallback(() => {
    stopScanRequestedRef.current = true;
    setScanActive(false);
    if (bridgeState !== "ready" || !wailsApp?.StopScan) {
      showPartialScanResults();
      return;
    }

    wailsApp.StopScan().catch(() => {
      showPartialScanResults();
    });
    showPartialScanResults();
  }, [bridgeState, showPartialScanResults, wailsApp]);

  const selectOutputDir = useCallback(async () => {
    if (bridgeState !== "ready" || !wailsApp?.SelectOutputDir) {
      alert("当前没有连接到本地恢复引擎，请从桌面版程序启动。");
      return "";
    }

    try {
      const dir = await wailsApp.SelectOutputDir();
      if (dir) {
        setOutputDir(dir);
      }
      return dir || "";
    } catch (error) {
      alert(getFriendlyActionError("选择恢复目录", error));
      return "";
    }
  }, [bridgeState, wailsApp]);

  const startRecovery = useCallback(
    (fileIDs, sourcePage = currentPage, outputDirOverride = outputDir) => {
      const recoveryOutputDir = outputDirOverride || outputDir;

      if (
        !recoveryOutputDir ||
        !Array.isArray(fileIDs) ||
        fileIDs.length === 0
      ) {
        return;
      }
      if (bridgeState !== "ready" || !wailsApp?.StartRecovery) {
        alert("当前没有连接到本地恢复引擎，请从桌面版程序启动。");
        return;
      }

      setRecoveryReturnPage(sourcePage === "scanning" ? "scanning" : "results");
      setRecoveryProgress({
        ...INITIAL_RECOVERY_PROGRESS,
        total: fileIDs.length,
      });
      setCurrentPage("recovery");

      wailsApp.StartRecovery(fileIDs, recoveryOutputDir).catch((error) => {
        alert(getFriendlyActionError("启动恢复", error));
        setCurrentPage(sourcePage === "scanning" ? "scanning" : "results");
      });
    },
    [bridgeState, currentPage, outputDir, wailsApp],
  );

  const stopRecovery = useCallback(() => {
    if (bridgeState !== "ready" || !wailsApp?.StopRecovery) {
      setCurrentPage(recoveryReturnPage);
      return;
    }

    wailsApp.StopRecovery().catch(() => {
      setCurrentPage(recoveryReturnPage);
    });
    setCurrentPage(recoveryReturnPage);
  }, [bridgeState, recoveryReturnPage, wailsApp]);

  const openFolder = useCallback(
    (path) => {
      if (!path) {
        return;
      }

      if (bridgeState !== "ready" || !wailsApp?.OpenFolder) {
        return;
      }

      wailsApp.OpenFolder(path).catch(() => {});
    },
    [bridgeState, wailsApp],
  );

  const pageTitle = useMemo(() => {
    if (bridgeState === "loading") {
      return "正在连接本地恢复引擎";
    }

    if (bridgeState === "error") {
      return "本地恢复引擎不可用";
    }

    switch (currentPage) {
      case "scanning":
        return `正在扫描 ${getDriveLabel(selectedDrive)}`;
      case "results":
        return scanActive
          ? `扫描仍在继续，已找到 ${foundFiles.length} 个候选文件`
          : `已找到 ${scanResult?.files?.length ?? foundFiles.length} 个候选文件`;
      case "recovery":
        return "正在导出恢复文件";
      default:
        return "先锁定目标磁盘，再开始恢复";
    }
  }, [
    currentPage,
    bridgeState,
    scanActive,
    foundFiles.length,
    scanResult?.files?.length,
    selectedDrive,
  ]);

  return (
    <div className="app-shell">
      <header className="app-topbar drag-region">
        <div className="app-topbar__row">
          <div className="app-brand">
            <h1 className="app-brand__title">数据恢复大师</h1>
            <p className="app-brand__subtitle">{pageTitle}</p>
          </div>
        </div>

        <div className="flow-track no-drag">
          {FLOW_STEPS.map((step, index) => {
            const flowState = getFlowState(currentPage, step.key);

            return (
              <div
                key={step.key}
                className={`flow-step flow-step--${flowState}`}
              >
                <span className="flow-step__index">
                  {flowState === "done" ? "完成" : index + 1}
                </span>
                <span className="flow-step__label">{step.label}</span>
              </div>
            );
          })}
        </div>
      </header>

      <main className="app-stage">
        {bridgeState !== "ready" ? (
          <section className="app-blocker surface">
            <span className="app-blocker__eyebrow">
              {bridgeState === "loading"
                ? "正在准备恢复引擎"
                : "无法开始真实恢复"}
            </span>
            <h2>
              {bridgeState === "loading"
                ? "正在连接桌面恢复引擎，请稍候"
                : "当前没有连接到本地恢复引擎"}
            </h2>
            <p className="app-blocker__text">
              {bridgeState === "loading"
                ? "请等待桌面程序完成初始化。恢复真实数据时，不会使用浏览器模拟页面。"
                : bridgeError}
            </p>
            {bridgeState === "error" && (
              <div className="app-blocker__actions">
                <button
                  className="btn btn-primary"
                  onClick={() => globalThis.location?.reload?.()}
                  type="button"
                >
                  重新连接
                </button>
              </div>
            )}
          </section>
        ) : null}

        {bridgeState === "ready" && currentPage === "welcome" && (
          <WelcomePage
            drives={drives}
            driveLoadError={driveLoadError}
            isLoadingDrives={isLoadingDrives}
            selectedDrive={selectedDrive}
            onSelectDrive={setSelectedDrive}
            onStartScan={startScan}
            onRefreshDrives={loadDrives}
          />
        )}

        {bridgeState === "ready" && currentPage === "scanning" && (
          <ScanningPage
            foundFiles={foundFiles}
            outputDir={outputDir}
            progress={scanProgress}
            selectedDrive={selectedDrive}
            onSelectOutputDir={selectOutputDir}
            onStartRecovery={startRecovery}
            onStopScan={stopScan}
            onViewResults={viewCurrentResults}
          />
        )}

        {bridgeState === "ready" && currentPage === "results" && (
          <ResultsPage
            outputDir={outputDir}
            result={
              scanActive
                ? buildFallbackScanResult(foundFiles, scanProgress)
                : scanResult ||
                  buildFallbackScanResult(foundFiles, scanProgress)
            }
            scanActive={scanActive}
            selectedDrive={selectedDrive}
            onBack={() => setCurrentPage("welcome")}
            onBackToScan={() => setCurrentPage("scanning")}
            onSelectOutputDir={selectOutputDir}
            onStartRecovery={startRecovery}
            onStopScan={stopScan}
          />
        )}

        {bridgeState === "ready" && currentPage === "recovery" && (
          <RecoveryPage
            outputDir={outputDir}
            progress={recoveryProgress}
            returnPageLabel={
              recoveryReturnPage === "scanning"
                ? "回到扫描进度"
                : "回到当前结果"
            }
            scanActive={scanActive}
            selectedDrive={selectedDrive}
            onBack={() => setCurrentPage("welcome")}
            onNewScan={() => setCurrentPage("welcome")}
            onOpenFolder={openFolder}
            onReturnToPrevious={() => setCurrentPage(recoveryReturnPage)}
            onStopRecovery={stopRecovery}
          />
        )}
      </main>
    </div>
  );
}

export default App;
