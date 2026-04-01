import React, {
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
  mergeRecoveredFile,
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

  const [recoveryProgress, setRecoveryProgress] = useState(
    INITIAL_RECOVERY_PROGRESS,
  );
  const [outputDir, setOutputDir] = useState("");

  const foundFilesRef = useRef(foundFiles);
  const scanProgressRef = useRef(scanProgress);
  const stopScanRequestedRef = useRef(false);

  useEffect(() => {
    foundFilesRef.current = foundFiles;
  }, [foundFiles]);

  useEffect(() => {
    scanProgressRef.current = scanProgress;
  }, [scanProgress]);

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
    const fallbackResult = buildFallbackScanResult(
      foundFilesRef.current,
      scanProgressRef.current,
    );

    setScanResult(fallbackResult.files.length > 0 ? fallbackResult : null);
    setCurrentPage(fallbackResult.files.length > 0 ? "results" : "welcome");
  }, []);

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
        setFoundFiles((prev) => mergeRecoveredFile(prev, payload));
      },
    );

    const offScanCompleted = wailsRuntime.EventsOn(
      "scan:completed",
      (payload) => {
        stopScanRequestedRef.current = false;
        if (Array.isArray(payload?.files)) {
          setFoundFiles(payload.files);
        }
        setScanResult(payload);
        setCurrentPage("results");
      },
    );

    const offScanError = wailsRuntime.EventsOn(
      "scan:error",
      async (payload) => {
        const message = payload?.message || payload || "未知错误";

        if (stopScanRequestedRef.current || isCancellationError(message)) {
          stopScanRequestedRef.current = false;

          if (wailsApp?.GetScanResults) {
            try {
              const latest = await wailsApp.GetScanResults();
              if (Array.isArray(latest?.files) && latest.files.length > 0) {
                setFoundFiles(latest.files);
                setScanResult(latest);
                setCurrentPage("results");
                return;
              }
            } catch (error) {
              // noop
            }
          }

          showPartialScanResults();
          return;
        }

        alert(getFriendlyActionError("扫描", message));
        setCurrentPage("welcome");
      },
    );

    const offRecoveryProgress = wailsRuntime.EventsOn(
      "recovery:progress",
      (payload) => {
        setRecoveryProgress((prev) => ({ ...prev, ...payload }));
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
  }, [bridgeState, showPartialScanResults, wailsApp, wailsRuntime]);

  const startScan = useCallback(() => {
    if (!selectedDrive) {
      return;
    }
    if (bridgeState !== "ready" || !wailsApp?.StartScan) {
      alert("当前没有连接到本地恢复引擎，请从桌面版程序启动。");
      return;
    }

    stopScanRequestedRef.current = false;
    setScanProgress(INITIAL_SCAN_PROGRESS);
    setFoundFiles([]);
    setScanResult(null);
    setCurrentPage("scanning");

    wailsApp.StartScan(selectedDrive.path, DEFAULT_SCAN_MODE).catch((error) => {
      alert(getFriendlyActionError("启动扫描", error));
      setCurrentPage("welcome");
    });
  }, [bridgeState, selectedDrive, wailsApp]);

  const stopScan = useCallback(() => {
    stopScanRequestedRef.current = true;
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
      return;
    }

    try {
      const dir = await wailsApp.SelectOutputDir();
      if (dir) {
        setOutputDir(dir);
      }
    } catch (error) {
      alert(getFriendlyActionError("选择恢复目录", error));
    }
  }, [bridgeState, wailsApp]);

  const startRecovery = useCallback(
    (fileIDs) => {
      if (!outputDir || !Array.isArray(fileIDs) || fileIDs.length === 0) {
        return;
      }
      if (bridgeState !== "ready" || !wailsApp?.StartRecovery) {
        alert("当前没有连接到本地恢复引擎，请从桌面版程序启动。");
        return;
      }

      setRecoveryProgress({
        ...INITIAL_RECOVERY_PROGRESS,
        total: fileIDs.length,
      });
      setCurrentPage("recovery");

      wailsApp.StartRecovery(fileIDs, outputDir).catch((error) => {
        alert(getFriendlyActionError("启动恢复", error));
        setCurrentPage("results");
      });
    },
    [bridgeState, outputDir, wailsApp],
  );

  const stopRecovery = useCallback(() => {
    if (bridgeState !== "ready" || !wailsApp?.StopRecovery) {
      setCurrentPage("results");
      return;
    }

    wailsApp.StopRecovery().catch(() => {
      setCurrentPage("results");
    });
    setCurrentPage("results");
  }, [bridgeState, wailsApp]);

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
        return `已找到 ${scanResult?.files?.length ?? foundFiles.length} 个候选文件`;
      case "recovery":
        return "正在导出恢复文件";
      default:
        return "先锁定目标磁盘，再开始恢复";
    }
  }, [
    currentPage,
    bridgeState,
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
            progress={scanProgress}
            selectedDrive={selectedDrive}
            onStopScan={stopScan}
          />
        )}

        {bridgeState === "ready" && currentPage === "results" && (
          <ResultsPage
            outputDir={outputDir}
            result={
              scanResult || buildFallbackScanResult(foundFiles, scanProgress)
            }
            selectedDrive={selectedDrive}
            onBack={() => setCurrentPage("welcome")}
            onSelectOutputDir={selectOutputDir}
            onStartRecovery={startRecovery}
          />
        )}

        {bridgeState === "ready" && currentPage === "recovery" && (
          <RecoveryPage
            outputDir={outputDir}
            progress={recoveryProgress}
            selectedDrive={selectedDrive}
            onBack={() => setCurrentPage("welcome")}
            onNewScan={() => setCurrentPage("welcome")}
            onOpenFolder={openFolder}
            onStopRecovery={stopRecovery}
          />
        )}
      </main>
    </div>
  );
}

export default App;
