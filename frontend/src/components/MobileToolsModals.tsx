// 移动端 / 备份 / NAS / 云端 工具的完整 modal dialog 集合。
//
// 设计原则：
//   - 复用 .preview-modal CSS 变体（已有的暗色 backdrop + 居中 inner box 风格）
//   - 每个 modal 自管 state；父只传 onClose + wailsApp + 必要的 outputDir
//   - 所有耗时操作显示加载态（loading spinner / disabled 按钮 / 进度条）
//   - 错误友好：网络/工具缺失/权限问题分别给可执行的提示
//   - 进度可视化：监听 backend 事件（ios:backupProgress / mtp:dumpProgress 等）

import React, { useEffect, useRef, useState } from "react";
import { IconX } from "../icons";
import { toast } from "../toast";

// 所有 modal 的通用 prop shape —— wailsApp / outputDir / selectedDrive / 回调
// 故意宽松：让 modal 组件内部按需用，避免一次给 8 个 modal 都加严格 props 定义。
// 渐进迁移：未来逐个 modal 改严格 props 类型。
type ModalProps = {
  wailsApp?: any;
  outputDir?: string;
  selectedDrive?: any;
  onClose: () => void;
  onStarted?: () => void;
  onStartedScan?: (hit: any) => void;
  [k: string]: any;
};

// 通用 modal 壳：复用 preview-modal CSS，但内容可定制
// width 是 inner 的 max-width（默认 600）
export function GenericModal({ title, onClose, width = 600, children, footer }: { title: string; onClose: () => void; width?: number; children: React.ReactNode; footer?: React.ReactNode }) {
  const ref = useRef(null);
  useEffect(() => {
    function onKey(e) {
      if (e.key === "Escape") onClose();
    }
    globalThis.addEventListener("keydown", onKey);
    // 自动 focus 到第一个 input
    setTimeout(() => {
      const input = ref.current?.querySelector("input, button, textarea, select");
      input?.focus?.();
    }, 50);
    return () => globalThis.removeEventListener("keydown", onKey);
  }, [onClose]);

  return (
    <div className="preview-modal" onClick={onClose} role="dialog" aria-label={title}>
      <div
        className="preview-modal__inner"
        ref={ref}
        onClick={(e) => e.stopPropagation()}
        style={{ maxWidth: `min(${width}px, 92vw)` }}
      >
        <div className="preview-modal__header">
          <div className="preview-modal__title">{title}</div>
          <button
            className="btn btn--sm btn--ghost"
            onClick={onClose}
            title="关闭 (Esc)"
            aria-label="关闭对话框"
            style={{ minWidth: 32, minHeight: 32, padding: 0, display: "inline-flex", alignItems: "center", justifyContent: "center" }}
          >
            <IconX size={14} />
          </button>
        </div>
        <div className="preview-modal__body" style={{ display: "block", padding: 16, background: "var(--bg-surface)" }}>
          {children}
        </div>
        {footer && (
          <div className="preview-modal__footer" style={{ display: "flex", justifyContent: "flex-end", gap: 8 }}>
            {footer}
          </div>
        )}
      </div>
    </div>
  );
}

// 表单字段 helper —— 标签 + input 一体化
interface FieldProps {
  label: string;
  hint?: React.ReactNode;
  children: React.ReactNode;
}
export function Field({ label, hint, children }: FieldProps) {
  return (
    <div style={{ marginBottom: 14 }}>
      <label style={{ display: "block", fontSize: 12, fontWeight: 600, marginBottom: 4 }}>
        {label}
      </label>
      {children}
      {hint && (
        <div style={{ fontSize: 11, color: "var(--text-muted)", marginTop: 4 }}>{hint}</div>
      )}
    </div>
  );
}

interface TextInputProps {
  value: string;
  onChange: (v: string) => void;
  placeholder?: string;
  type?: string;
  disabled?: boolean;
}
export function TextInput({ value, onChange, placeholder, type = "text", disabled }: TextInputProps) {
  return (
    <input
      type={type}
      value={value}
      onChange={(e) => onChange(e.target.value)}
      placeholder={placeholder}
      disabled={disabled}
      style={{
        width: "100%",
        padding: "6px 10px",
        border: "1px solid var(--border)",
        borderRadius: 6,
        background: disabled ? "var(--bg-inset)" : "var(--bg-surface)",
        color: "var(--text)",
        fontSize: 13,
        boxSizing: "border-box",
      }}
    />
  );
}

// =============================================================================
// 1. CloudBackupsModal —— 云盘扫描结果可点击
// =============================================================================
//
// 旧路径：alert 一段长文本，用户要复制粘贴路径才能扫
// 新路径：list view，每条 hit 旁边一个 "🔍 扫描" 按钮直接调
//         StartIOSBackupScan / 触发 Android backup scan

export function CloudBackupsModal({ wailsApp, onClose, onStartedScan }: ModalProps) {
  const [loading, setLoading] = useState(true);
  const [roots, setRoots] = useState([]);
  const [hits, setHits] = useState([]);
  const [error, setError] = useState("");

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const r = await wailsApp?.DiscoverCloudSyncRoots?.();
        const h = await wailsApp?.ScanCloudForBackups?.();
        if (cancelled) return;
        setRoots(r || []);
        setHits(h || []);
      } catch (err) {
        if (!cancelled) setError(String(err?.message || err));
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => { cancelled = true; };
  }, [wailsApp]);

  async function startScanForHit(hit) {
    try {
      if (hit.kind === "iOS-MobileSync") {
        const pwd = globalThis.prompt?.("加密备份密码（明文备份留空）：", "") || "";
        await wailsApp?.StartIOSBackupScan?.(hit.path, pwd);
      } else if (hit.kind === "Android-AB") {
        const info = await wailsApp?.InspectAndroidBackup?.(hit.path);
        const pwd = info?.encrypted ? globalThis.prompt?.(".ab 加密备份密码：", "") || "" : "";
        await wailsApp?.StartAndroidBackupScan?.(hit.path, pwd);
      }
      onStartedScan?.(hit);
      onClose();
    } catch (err) {
      toast.error("启动扫描失败: " + (err?.message || err));
    }
  }

  return (
    <GenericModal
      title="☁️ 云盘备份发现"
      onClose={onClose}
      width={700}
      footer={
        <button className="btn btn--sm" onClick={onClose}>关闭</button>
      }
    >
      {loading && <div className="muted">正在扫云盘同步根…</div>}
      {error && (
        <div className="banner banner--danger" style={{ margin: 0 }}>
          <div className="banner__content">
            <div className="banner__title">扫描失败</div>
            <div className="banner__text">{error}</div>
          </div>
        </div>
      )}

      {!loading && !error && (
        <>
          <div style={{ fontSize: 12, marginBottom: 12 }}>
            <b>已发现的云同步根</b>（{roots.length}）：
          </div>
          {roots.length === 0 ? (
            <div className="muted" style={{ marginBottom: 16, fontSize: 12 }}>
              未找到任何云盘客户端的本地同步文件夹。
              <div style={{ marginTop: 6 }}>
                若你装了 iCloud Drive / OneDrive / Google Drive / Dropbox 桌面版，
                确保它们已同步过文件到本地（云端备份要先下载到本地我们才能扫到）。
              </div>
            </div>
          ) : (
            <ul style={{ margin: "0 0 16px 0", padding: 0, listStyle: "none", fontSize: 12 }}>
              {roots.map((r, i) => (
                <li key={i} style={{ padding: "4px 0", boxShadow: "inset 0 -1px 0 0 var(--border)" }}>
                  <span className="badge badge--success" style={{ marginRight: 8, fontSize: 10 }}>
                    {r.provider}
                  </span>
                  <span className="mono" style={{ fontSize: 11 }}>{r.path}</span>
                  <div className="muted" style={{ fontSize: 10, marginLeft: 60, marginTop: 2 }}>
                    {r.reason}
                  </div>
                </li>
              ))}
            </ul>
          )}

          <div style={{ fontSize: 12, marginBottom: 8 }}>
            <b>找到的 iOS / Android 备份</b>（{hits.length}）：
          </div>
          {hits.length === 0 ? (
            <div className="muted" style={{ fontSize: 12 }}>
              {roots.length > 0
                ? "云盘里没找到可识别的 iOS Manifest.plist 或 Android .ab 文件。"
                : "无云盘 → 无备份候选。"}
            </div>
          ) : (
            <table style={{ width: "100%", fontSize: 12, borderCollapse: "collapse" }}>
              <thead>
                <tr style={{ boxShadow: "inset 0 -1px 0 0 var(--border)" }}>
                  <th style={{ textAlign: "left", padding: "6px 4px" }}>类型</th>
                  <th style={{ textAlign: "left", padding: "6px 4px" }}>云端</th>
                  <th style={{ textAlign: "left", padding: "6px 4px" }}>路径</th>
                  <th style={{ textAlign: "right", padding: "6px 4px" }}>大小</th>
                  <th style={{ padding: "6px 4px" }}>操作</th>
                </tr>
              </thead>
              <tbody>
                {hits.map((h, i) => (
                  <tr key={i} style={{ boxShadow: "inset 0 -1px 0 0 var(--border)" }}>
                    <td style={{ padding: "6px 4px" }}>
                      {h.kind === "iOS-MobileSync" ? "📱 iOS" : "🤖 Android"}
                    </td>
                    <td style={{ padding: "6px 4px" }}>{h.provider}</td>
                    <td className="mono" style={{ padding: "6px 4px", fontSize: 11, maxWidth: 280, overflow: "hidden", textOverflow: "ellipsis" }} title={h.path}>
                      {h.path}
                    </td>
                    <td style={{ padding: "6px 4px", textAlign: "right", fontVariantNumeric: "tabular-nums" }}>
                      {(h.sizeBytes / 1024 / 1024).toFixed(1)} MB
                    </td>
                    <td style={{ padding: "6px 4px", textAlign: "center" }}>
                      <button
                        className="btn btn--sm btn--primary"
                        onClick={() => startScanForHit(h)}
                        title="启动扫描这个备份"
                      >
                        🔍 扫描
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </>
      )}
    </GenericModal>
  );
}

// =============================================================================
// 2. NASScanModal —— SMB / NFS 扫描表单
// =============================================================================

export function NASScanModal({ kind, wailsApp, onClose, onStarted }: ModalProps) {
  const isSMB = kind === "smb";
  const [host, setHost] = useState("");
  const [user, setUser] = useState(""); // SMB only
  const [pwd, setPwd] = useState("");   // SMB only
  const [share, setShare] = useState(""); // SMB share name 或 NFS export path
  const [submitting, setSubmitting] = useState(false);
  const [err, setErr] = useState("");

  async function submit() {
    setSubmitting(true);
    setErr("");
    try {
      if (isSMB) {
        await wailsApp?.StartSMBScan?.({
          host, port: 445, username: user, password: pwd,
          share, maxDepth: 50, maxFiles: 1000000,
        });
      } else {
        await wailsApp?.StartNFSScan?.({
          host, nfsPort: 0, mountPort: 0, // portmap 自动发现
          uid: 0, gid: 0,
          export: share,
          maxDepth: 50, maxFiles: 1000000,
        });
      }
      onStarted?.();
      onClose();
    } catch (e) {
      setErr(String(e?.message || e));
      setSubmitting(false);
    }
  }

  return (
    <GenericModal
      title={isSMB ? "📡 NAS SMB 扫描" : "📡 NAS NFSv3 扫描"}
      onClose={onClose}
      width={500}
      footer={
        <>
          <button className="btn btn--sm" onClick={onClose} disabled={submitting}>取消</button>
          <button
            className="btn btn--sm btn--primary"
            onClick={submit}
            disabled={!host || submitting}
          >
            {submitting ? "启动中…" : "开始扫描"}
          </button>
        </>
      }
    >
      <Field label="NAS 主机" hint="IP 或主机名（如 192.168.1.10 / nas.local）">
        <TextInput value={host} onChange={setHost} placeholder="192.168.1.10" disabled={submitting} />
      </Field>
      {isSMB && (
        <>
          <Field label="用户名" hint="匿名访问留空">
            <TextInput value={user} onChange={setUser} placeholder="（匿名留空）" disabled={submitting} />
          </Field>
          {user && (
            <Field label="密码">
              <TextInput value={pwd} onChange={setPwd} type="password" disabled={submitting} />
            </Field>
          )}
        </>
      )}
      <Field
        label={isSMB ? "Share 名" : "Export 路径"}
        hint={
          isSMB
            ? "如 'Public' / 'BackupPro'。留空会列出 server 上所有 share 让你挑（暂未实现，先填具体名）"
            : "如 '/volume1/backup'。留空走 portmap 自动发现 export"
        }
      >
        <TextInput
          value={share}
          onChange={setShare}
          placeholder={isSMB ? "Public" : "/volume1/backup"}
          disabled={submitting}
        />
      </Field>
      {err && (
        <div className="banner banner--danger" style={{ margin: "8px 0 0 0" }}>
          <div className="banner__content">
            <div className="banner__title">无法启动</div>
            <div className="banner__text">{err}</div>
          </div>
        </div>
      )}
      <div className="muted" style={{ fontSize: 11, marginTop: 12 }}>
        启动后扫描进度会出现在主面板。需要中止可去主面板点"停止扫描"。
      </div>
    </GenericModal>
  );
}

// =============================================================================
// 3. AndroidDumpModal —— Android root 块级 dump（含进度可视化）
// =============================================================================

export function AndroidDumpModal({ wailsApp, outputDir, onClose, onStarted }: ModalProps) {
  const [phase, setPhase] = useState("input"); // input → checking → ready → running → done
  const [serial, setSerial] = useState("");
  const [parts, setParts] = useState(null);
  const [selPart, setSelPart] = useState(null);
  const [outImg, setOutImg] = useState("");
  const [err, setErr] = useState("");
  const [dumpedBytes, setDumpedBytes] = useState(0);

  // dump 进度事件（mtp:dumpProgress）
  useEffect(() => {
    if (phase !== "running") return;
    if (!globalThis.runtime?.EventsOn) return;
    const un = globalThis.runtime.EventsOn("mtp:dumpProgress", (b) => {
      setDumpedBytes(typeof b === "number" ? b : Number(b) || 0);
    });
    const unDone = globalThis.runtime.EventsOn("mtp:dumpCompleted", () => {
      setPhase("done");
    });
    const unErr = globalThis.runtime.EventsOn("mtp:dumpError", (e) => {
      setErr(String(e?.message || e));
      setPhase("input");
    });
    return () => {
      un?.(); unDone?.(); unErr?.();
    };
  }, [phase]);

  async function checkAndList() {
    setErr("");
    setPhase("checking");
    try {
      const rooted = await wailsApp?.AndroidIsRooted?.(serial);
      if (!rooted) throw new Error("设备未 root（adb shell su -c id 没返回 uid=0）");
      const list = await wailsApp?.AndroidListPartitions?.(serial);
      if (!list || list.length === 0) throw new Error("没找到分区（设备可能不支持 /dev/block/by-name/）");
      setParts(list);
      // 默认选 userdata（多数情况这是用户最关心的）
      const userdata = list.find((p) => p.name === "userdata");
      setSelPart(userdata || list[0]);
      setOutImg(`${outputDir || ""}/${userdata?.name || list[0].name}.img`);
      setPhase("ready");
    } catch (e) {
      setErr(String(e?.message || e));
      setPhase("input");
    }
  }

  async function startDump() {
    if (!selPart || !outImg) return;
    setErr("");
    setDumpedBytes(0);
    setPhase("running");
    try {
      await wailsApp?.AndroidDumpPartitionAndScan?.(
        serial, selPart.blockNode, outImg, "full"
      );
      onStarted?.();
    } catch (e) {
      setErr(String(e?.message || e));
      setPhase("input");
    }
  }

  const pctDumped = selPart && selPart.sizeBytes > 0
    ? Math.min(100, (dumpedBytes / selPart.sizeBytes) * 100)
    : 0;

  return (
    <GenericModal
      title="💽 Android root 块级 dump"
      onClose={onClose}
      width={620}
      footer={
        <>
          <button className="btn btn--sm" onClick={onClose}>
            {phase === "running" ? "后台继续" : "关闭"}
          </button>
          {phase === "input" && (
            <button
              className="btn btn--sm btn--primary"
              onClick={checkAndList}
              disabled={!serial}
            >
              检测 + 列分区
            </button>
          )}
          {phase === "ready" && (
            <button
              className="btn btn--sm btn--primary"
              onClick={startDump}
              disabled={!selPart || !outImg}
            >
              开始 dump
            </button>
          )}
        </>
      }
    >
      {phase === "input" && (
        <>
          <div className="muted" style={{ fontSize: 11, marginBottom: 12 }}>
            前提：设备 root + 已 grant root（手机弹 'Allow Root Access' 时点允许）。
          </div>
          <Field
            label="Android 设备 serial"
            hint="adb devices 列出的（如 ABCDEF1234 或 192.168.1.5:5555）"
          >
            <TextInput value={serial} onChange={setSerial} placeholder="ABCDEF1234" />
          </Field>
        </>
      )}

      {phase === "checking" && (
        <div className="muted">检测 root + 列分区中…</div>
      )}

      {phase === "ready" && parts && (
        <>
          <Field label="选分区">
            <select
              value={selPart?.blockNode || ""}
              onChange={(e) => {
                const p = parts.find((x) => x.blockNode === e.target.value);
                setSelPart(p);
                if (p) setOutImg(`${outputDir || ""}/${p.name}.img`);
              }}
              style={{
                width: "100%", padding: "6px 10px",
                border: "1px solid var(--border)", borderRadius: 6,
                background: "var(--bg-surface)", color: "var(--text)", fontSize: 13,
              }}
            >
              {parts.map((p) => (
                <option key={p.blockNode} value={p.blockNode}>
                  {p.name} — {(p.sizeBytes / 1024 / 1024 / 1024).toFixed(2)} GB ({p.blockNode})
                </option>
              ))}
            </select>
          </Field>
          <Field
            label="输出镜像路径 (.img)"
            hint="必须**不同**物理盘（若手机 /sdcard 在外置盘，本路径必须是另一块盘）"
          >
            <TextInput value={outImg} onChange={setOutImg} placeholder="~/userdata.img" />
          </Field>
          <div className="muted" style={{ fontSize: 11 }}>
            预计 {selPart && selPart.sizeBytes > 0
              ? `${(selPart.sizeBytes / 1024 / 1024 / 1024).toFixed(1)} GB / ~${
                  Math.ceil(selPart.sizeBytes / (35 * 1024 * 1024))
                } 秒（USB 3 估算 35 MB/s）`
              : "未知"}。dump 完成后会自动启动镜像扫描。
          </div>
        </>
      )}

      {(phase === "running" || phase === "done") && (
        <>
          <div style={{ fontSize: 13, marginBottom: 8 }}>
            <b>{selPart?.name}</b> → <span className="mono" style={{ fontSize: 11 }}>{outImg}</span>
          </div>
          <div className="progress" style={{ position: "relative", height: 16 }}>
            <div className="progress__fill" style={{ width: `${pctDumped}%` }} />
            <div style={{
              position: "absolute", inset: 0, display: "flex",
              alignItems: "center", justifyContent: "center",
              fontSize: 11, fontWeight: 600,
              color: pctDumped > 50 ? "white" : "var(--text)",
            }}>
              {pctDumped.toFixed(1)}% · {(dumpedBytes / 1024 / 1024).toFixed(1)} MB
            </div>
          </div>
          {phase === "done" && (
            <div className="banner banner--success" style={{ margin: "12px 0 0 0" }}>
              <div className="banner__content">
                <div className="banner__title">✅ dump 完成</div>
                <div className="banner__text">已自动启动镜像扫描；详见主面板进度</div>
              </div>
            </div>
          )}
        </>
      )}

      {err && (
        <div className="banner banner--danger" style={{ margin: "12px 0 0 0" }}>
          <div className="banner__content">
            <div className="banner__title">失败</div>
            <div className="banner__text">{err}</div>
          </div>
        </div>
      )}
    </GenericModal>
  );
}

// =============================================================================
// 4. IOSBackupModal —— iOS libimobiledevice 直连备份触发（含 pair 状态 + 进度）
// =============================================================================

export function IOSBackupModal({ wailsApp, outputDir, onClose, onStarted }: ModalProps) {
  const [phase, setPhase] = useState("checking"); // checking → input → pairing → backup → done
  const [tools, setTools] = useState(null);
  const [devices, setDevices] = useState([]);
  const [selUDID, setSelUDID] = useState("");
  const [outDir, setOutDir] = useState(outputDir || "");
  const [pwd, setPwd] = useState("");
  const [err, setErr] = useState("");
  const [progressMsg, setProgressMsg] = useState("");

  // 工具检测 + 设备列表
  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const status = await wailsApp?.IOSDirectCheck?.();
        if (cancelled) return;
        setTools(status);
        if (!status?.available) {
          setErr("libimobiledevice 未安装\nmacOS: brew install libimobiledevice\nLinux: apt install libimobiledevice-utils");
          setPhase("input");
          return;
        }
        const devs = await wailsApp?.IOSListDevices?.();
        if (cancelled) return;
        setDevices(devs || []);
        if (devs?.[0]) setSelUDID(devs[0].udid);
        setPhase("input");
      } catch (e) {
        if (!cancelled) {
          setErr(String(e?.message || e));
          setPhase("input");
        }
      }
    })();
    return () => { cancelled = true; };
  }, [wailsApp]);

  // backup 进度事件
  useEffect(() => {
    if (phase !== "backup") return;
    if (!globalThis.runtime?.EventsOn) return;
    const un = globalThis.runtime.EventsOn("ios:backupCompleted", () => {
      setPhase("done");
    });
    const unErr = globalThis.runtime.EventsOn("ios:backupError", (e) => {
      setErr(String(e?.message || e));
      setPhase("input");
    });
    // libimobiledevice 不发细粒度进度；显示心跳
    const tickId = setInterval(() => {
      setProgressMsg("正在传输备份…（典型 30GB 数据 ~30 分钟）");
    }, 5000);
    return () => { un?.(); unErr?.(); clearInterval(tickId); };
  }, [phase]);

  const selDev = devices.find((d) => d.udid === selUDID);

  async function pair() {
    setErr("");
    setPhase("pairing");
    try {
      await wailsApp?.IOSPair?.(selUDID);
      // pair 成功后刷新设备状态
      const devs = await wailsApp?.IOSListDevices?.();
      setDevices(devs || []);
      setPhase("input");
    } catch (e) {
      setErr(String(e?.message || e) + "\n（请在 iPhone 屏幕上点 'Trust this Computer'）");
      setPhase("input");
    }
  }

  async function startBackup() {
    setErr("");
    setProgressMsg("");
    setPhase("backup");
    try {
      await wailsApp?.IOSTriggerBackupAndScan?.(selUDID, outDir, pwd);
      onStarted?.();
    } catch (e) {
      setErr(String(e?.message || e));
      setPhase("input");
    }
  }

  return (
    <GenericModal
      title="🍎 iOS 直连备份触发"
      onClose={onClose}
      width={580}
      footer={
        <>
          <button className="btn btn--sm" onClick={onClose}>
            {phase === "backup" ? "后台继续" : "关闭"}
          </button>
          {phase === "input" && tools?.available && selDev && !selDev.trusted && (
            <button className="btn btn--sm btn--primary" onClick={pair}>
              📱 配对设备
            </button>
          )}
          {phase === "input" && tools?.available && selDev?.trusted && (
            <button
              className="btn btn--sm btn--primary"
              onClick={startBackup}
              disabled={!outDir}
            >
              触发系统级备份
            </button>
          )}
        </>
      }
    >
      {phase === "checking" && <div className="muted">检测 libimobiledevice 工具链…</div>}

      {phase !== "checking" && tools && !tools.available && (
        <div className="banner banner--danger" style={{ margin: 0 }}>
          <div className="banner__content">
            <div className="banner__title">libimobiledevice 未安装</div>
            <div className="banner__text" style={{ whiteSpace: "pre-line" }}>{err}</div>
          </div>
        </div>
      )}

      {phase === "input" && tools?.available && (
        <>
          {devices.length === 0 ? (
            <div className="banner banner--info" style={{ margin: "0 0 12px 0" }}>
              <div className="banner__content">
                <div className="banner__title">未发现 iOS 设备</div>
                <div className="banner__text">用 USB 接 iPhone 并解锁屏幕，然后重新打开此对话框</div>
              </div>
            </div>
          ) : (
            <>
              <Field label="选 iPhone">
                <select
                  value={selUDID}
                  onChange={(e) => setSelUDID(e.target.value)}
                  style={{
                    width: "100%", padding: "6px 10px",
                    border: "1px solid var(--border)", borderRadius: 6,
                    background: "var(--bg-surface)", color: "var(--text)", fontSize: 13,
                  }}
                >
                  {devices.map((d) => (
                    <option key={d.udid} value={d.udid}>
                      {d.name || "未命名"} ({d.model || "?"}, iOS {d.iosVer || "?"}) {d.trusted ? "✓ 已配对" : "⚠ 未配对"}
                    </option>
                  ))}
                </select>
              </Field>
              {selDev && !selDev.trusted && (
                <div className="banner banner--warning" style={{ margin: "0 0 12px 0" }}>
                  <div className="banner__content">
                    <div className="banner__title">设备未配对</div>
                    <div className="banner__text">
                      点下方"配对设备"按钮 → iPhone 屏幕会弹"信任此电脑" → 在手机上点信任。
                    </div>
                  </div>
                </div>
              )}
              {selDev?.trusted && (
                <>
                  <Field
                    label="备份输出目录"
                    hint="iOS 完整备份可能 30GB+，确保有足够空间"
                  >
                    <TextInput value={outDir} onChange={setOutDir} placeholder="/path/to/backup" />
                  </Field>
                  <Field
                    label="备份加密密码"
                    hint="如果 iPhone 启用了备份加密（设置→通用→iTunes），输入密码；否则留空"
                  >
                    <TextInput value={pwd} onChange={setPwd} type="password" placeholder="（无加密留空）" />
                  </Field>
                </>
              )}
            </>
          )}
        </>
      )}

      {phase === "pairing" && (
        <div>
          <div className="muted">触发 idevicepair pair…</div>
          <div style={{ marginTop: 8, padding: 12, background: "var(--accent-soft)", borderRadius: 6 }}>
            👀 现在看 iPhone 屏幕，点 <b>"Trust this Computer"</b>，输入设备解锁码
          </div>
        </div>
      )}

      {phase === "backup" && (
        <>
          <div className="muted" style={{ marginBottom: 8 }}>
            备份运行中（idevicebackup2）…
          </div>
          <div className="progress" style={{ position: "relative", height: 16 }}>
            <div className="progress__fill" style={{ width: "100%", animation: "progressPulse 2s ease-in-out infinite" }} />
            <div style={{
              position: "absolute", inset: 0, display: "flex",
              alignItems: "center", justifyContent: "center",
              fontSize: 11, fontWeight: 600, color: "white",
            }}>
              {progressMsg || "等待 iOS 响应…"}
            </div>
          </div>
        </>
      )}

      {phase === "done" && (
        <div className="banner banner--success" style={{ margin: 0 }}>
          <div className="banner__content">
            <div className="banner__title">✅ 备份完成</div>
            <div className="banner__text">已自动启动 iOS 备份扫描；详见主面板进度</div>
          </div>
        </div>
      )}

      {err && phase !== "checking" && (
        <div className="banner banner--danger" style={{ margin: "12px 0 0 0" }}>
          <div className="banner__content">
            <div className="banner__title">失败</div>
            <div className="banner__text" style={{ whiteSpace: "pre-line" }}>{err}</div>
          </div>
        </div>
      )}
    </GenericModal>
  );
}

// =============================================================================
// 5. PTPCameraModal —— gphoto2 数码相机/老 Android 拉照片
// =============================================================================

export function PTPCameraModal({ wailsApp, outputDir, onClose, onStarted }: ModalProps) {
  const [phase, setPhase] = useState("checking"); // checking → input → starting
  const [tools, setTools] = useState(null);
  const [devs, setDevs] = useState([]);
  const [port, setPort] = useState("");
  const [outDir, setOutDir] = useState(outputDir || "");
  const [err, setErr] = useState("");

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const status = await wailsApp?.PTPCheck?.();
        if (cancelled) return;
        setTools(status);
        if (!status?.available) {
          setPhase("input");
          return;
        }
        const list = await wailsApp?.PTPListDevices?.();
        if (cancelled) return;
        setDevs(list || []);
        if (list?.[0]) setPort(list[0].port);
        setPhase("input");
      } catch (e) {
        if (!cancelled) {
          setErr(String(e?.message || e));
          setPhase("input");
        }
      }
    })();
    return () => { cancelled = true; };
  }, [wailsApp]);

  async function start() {
    setErr("");
    setPhase("starting");
    try {
      await wailsApp?.PTPPullAllAndScan?.(port, outDir, "full");
      onStarted?.();
      onClose();
    } catch (e) {
      setErr(String(e?.message || e));
      setPhase("input");
    }
  }

  return (
    <GenericModal
      title="📷 PTP 数码相机拉照片"
      onClose={onClose}
      width={560}
      footer={
        <>
          <button className="btn btn--sm" onClick={onClose}>取消</button>
          {tools?.available && (
            <button
              className="btn btn--sm btn--primary"
              onClick={start}
              disabled={!port || !outDir || phase === "starting"}
            >
              {phase === "starting" ? "启动中…" : "开始拉取并扫描"}
            </button>
          )}
        </>
      }
    >
      {phase === "checking" && <div className="muted">检测 gphoto2…</div>}

      {phase !== "checking" && tools && !tools.available && (
        <div className="banner banner--danger" style={{ margin: 0 }}>
          <div className="banner__content">
            <div className="banner__title">gphoto2 未安装</div>
            <div className="banner__text" style={{ whiteSpace: "pre-line" }}>
              macOS: brew install gphoto2{"\n"}Linux: apt install gphoto2{"\n"}Windows: 装 libgphoto2 + WinGphoto2 (zadig USB driver)
            </div>
          </div>
        </div>
      )}

      {phase !== "checking" && tools?.available && (
        <>
          {tools.version && (
            <div className="muted" style={{ fontSize: 11, marginBottom: 8 }}>{tools.version}</div>
          )}
          {devs.length === 0 ? (
            <div className="banner banner--info" style={{ margin: "0 0 12px 0" }}>
              <div className="banner__content">
                <div className="banner__title">未发现 PTP 相机</div>
                <div className="banner__text">用 USB 接相机并开机，然后重新打开此对话框</div>
              </div>
            </div>
          ) : (
            <>
              <Field label="选相机">
                <select
                  value={port}
                  onChange={(e) => setPort(e.target.value)}
                  style={{
                    width: "100%", padding: "6px 10px",
                    border: "1px solid var(--border)", borderRadius: 6,
                    background: "var(--bg-surface)", color: "var(--text)", fontSize: 13,
                  }}
                >
                  {devs.map((d) => (
                    <option key={d.port} value={d.port}>
                      {d.model} → {d.port}
                    </option>
                  ))}
                </select>
              </Field>
              <Field
                label="拉到本地目录"
                hint="拉所有照片（含 raw / video）到这个目录，然后启动扫描"
              >
                <TextInput value={outDir} onChange={setOutDir} placeholder="/path/to/photos" />
              </Field>
            </>
          )}
        </>
      )}

      {err && (
        <div className="banner banner--danger" style={{ margin: "12px 0 0 0" }}>
          <div className="banner__content">
            <div className="banner__title">失败</div>
            <div className="banner__text">{err}</div>
          </div>
        </div>
      )}
    </GenericModal>
  );
}

// =============================================================================
// 6. ADBPullModal —— Android adb pull 目录到本地后扫描
// =============================================================================

export function ADBPullModal({ wailsApp, outputDir, onClose, onStarted }: ModalProps) {
  const [phase, setPhase] = useState("loading"); // loading → input → starting
  const [devs, setDevs] = useState([]);
  const [serial, setSerial] = useState("");
  const [src, setSrc] = useState("/sdcard/DCIM");
  const [dst, setDst] = useState(outputDir || "");
  const [err, setErr] = useState("");

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const status = await wailsApp?.MTPCheck?.();
        if (cancelled) return;
        if (!status?.available) {
          setErr("adb 未安装\n请装 Android Platform Tools:\nhttps://developer.android.com/tools/releases/platform-tools");
          setPhase("input");
          return;
        }
        const list = await wailsApp?.MTPListDevices?.();
        if (cancelled) return;
        setDevs(list || []);
        if (list?.[0]) setSerial(list[0].serial);
        setPhase("input");
      } catch (e) {
        if (!cancelled) {
          setErr(String(e?.message || e));
          setPhase("input");
        }
      }
    })();
    return () => { cancelled = true; };
  }, [wailsApp]);

  async function start() {
    setErr("");
    setPhase("starting");
    try {
      await wailsApp?.MTPPullDirectoryAndScan?.(serial, src, dst, "full");
      onStarted?.();
      onClose();
    } catch (e) {
      setErr(String(e?.message || e));
      setPhase("input");
    }
  }

  const COMMON_PATHS = [
    "/sdcard/DCIM",
    "/sdcard/Pictures",
    "/sdcard/Download",
    "/sdcard/WhatsApp",
    "/sdcard/Documents",
    "/sdcard",
  ];

  return (
    <GenericModal
      title="📂 ADB 拉手机目录"
      onClose={onClose}
      width={560}
      footer={
        <>
          <button className="btn btn--sm" onClick={onClose}>取消</button>
          <button
            className="btn btn--sm btn--primary"
            onClick={start}
            disabled={!serial || !src || !dst || phase === "starting"}
          >
            {phase === "starting" ? "启动中…" : "开始 pull + 扫描"}
          </button>
        </>
      }
    >
      {phase === "loading" && <div className="muted">检测 adb + 列设备…</div>}
      {phase !== "loading" && (
        <>
          {devs.length === 0 ? (
            <div className="banner banner--info" style={{ margin: "0 0 12px 0" }}>
              <div className="banner__content">
                <div className="banner__title">未发现 Android 设备</div>
                <div className="banner__text">手机开 USB 调试 → 接 USB → 点手机弹出的"允许 USB 调试"</div>
              </div>
            </div>
          ) : (
            <>
              <Field label="选 Android 设备">
                <select
                  value={serial}
                  onChange={(e) => setSerial(e.target.value)}
                  style={{
                    width: "100%", padding: "6px 10px",
                    border: "1px solid var(--border)", borderRadius: 6,
                    background: "var(--bg-surface)", color: "var(--text)", fontSize: 13,
                  }}
                >
                  {devs.map((d) => (
                    <option key={d.serial} value={d.serial}>
                      {d.model || d.serial} ({d.state}) {d.product || ""}
                    </option>
                  ))}
                </select>
              </Field>
              <Field
                label="手机端目录"
                hint="不要选 /sdcard/ 根（含 100GB+ 媒体文件，全拉慢）"
              >
                <TextInput value={src} onChange={setSrc} placeholder="/sdcard/DCIM" />
                <div style={{ marginTop: 6, display: "flex", gap: 4, flexWrap: "wrap" }}>
                  {COMMON_PATHS.map((p) => (
                    <button
                      key={p}
                      className="btn btn--sm btn--ghost"
                      style={{ fontSize: 10, padding: "2px 8px" }}
                      onClick={() => setSrc(p)}
                    >
                      {p}
                    </button>
                  ))}
                </div>
              </Field>
              <Field label="本地目标目录">
                <TextInput value={dst} onChange={setDst} placeholder="/path/to/local" />
              </Field>
            </>
          )}
        </>
      )}
      {err && (
        <div className="banner banner--danger" style={{ margin: "12px 0 0 0" }}>
          <div className="banner__content">
            <div className="banner__title">失败</div>
            <div className="banner__text" style={{ whiteSpace: "pre-line" }}>{err}</div>
          </div>
        </div>
      )}
    </GenericModal>
  );
}

// =============================================================================
// 7. DiskDumpModal —— 整盘镜像 dump (.img)
// =============================================================================

export function DiskDumpModal({ wailsApp, selectedDrive, onClose, onStarted }: ModalProps) {
  const [outImg, setOutImg] = useState("");
  const [phase, setPhase] = useState("input"); // input → starting
  const [err, setErr] = useState("");

  const drivePath = selectedDrive?.path || "";
  const driveSize = selectedDrive?.size || 0;

  useEffect(() => {
    if (selectedDrive?.label && !outImg) {
      const safeName = selectedDrive.label.replace(/[^a-zA-Z0-9_-]/g, "_") || "disk";
      setOutImg(`~/Desktop/${safeName}.img`);
    }
  }, [selectedDrive, outImg]);

  async function start() {
    setErr("");
    setPhase("starting");
    try {
      await wailsApp?.DumpDisk?.(drivePath, outImg);
      onStarted?.();
      onClose();
    } catch (e) {
      setErr(String(e?.message || e));
      setPhase("input");
    }
  }

  return (
    <GenericModal
      title="💾 整盘镜像 dump (.img)"
      onClose={onClose}
      width={560}
      footer={
        <>
          <button className="btn btn--sm" onClick={onClose}>取消</button>
          <button
            className="btn btn--sm btn--primary"
            onClick={start}
            disabled={!drivePath || !outImg || phase === "starting"}
          >
            {phase === "starting" ? "启动中…" : "开始 dump"}
          </button>
        </>
      }
    >
      {!drivePath ? (
        <div className="banner banner--info" style={{ margin: 0 }}>
          <div className="banner__content">
            <div className="banner__title">未选源盘</div>
            <div className="banner__text">先回主面板选要 dump 的源盘，再打开本对话框</div>
          </div>
        </div>
      ) : (
        <>
          <Field label="源盘">
            <div className="mono" style={{
              padding: "6px 10px", border: "1px solid var(--border)",
              borderRadius: 6, background: "var(--bg-inset)", fontSize: 12,
            }}>
              {drivePath}
              {driveSize > 0 && (
                <span className="muted" style={{ marginLeft: 8 }}>
                  ({(driveSize / 1024 / 1024 / 1024).toFixed(1)} GB)
                </span>
              )}
            </div>
          </Field>
          <Field
            label="输出 .img 路径"
            hint="⚠️ 必须在**不同**物理盘上（避免覆盖源盘扇区）"
          >
            <TextInput value={outImg} onChange={setOutImg} placeholder="~/Desktop/disk.img" />
          </Field>
          {driveSize > 0 && (
            <div className="muted" style={{ fontSize: 11 }}>
              预计耗时：{Math.ceil(driveSize / (200 * 1024 * 1024) / 60)} - {Math.ceil(driveSize / (50 * 1024 * 1024) / 60)} 分钟
              （SATA SSD ~200 MB/s / SATA HDD ~50 MB/s 估算）
            </div>
          )}
        </>
      )}
      {err && (
        <div className="banner banner--danger" style={{ margin: "12px 0 0 0" }}>
          <div className="banner__content">
            <div className="banner__title">失败</div>
            <div className="banner__text">{err}</div>
          </div>
        </div>
      )}
    </GenericModal>
  );
}

// =============================================================================
// 8. AboutModal —— 版本 / 能力 / 依赖 / 鸣谢
// =============================================================================

export function AboutModal({ wailsApp, onClose }: ModalProps) {
  const [version, setVersion] = useState("");
  useEffect(() => {
    const v = wailsApp?.GetAppVersion?.();
    if (v && typeof v.then === "function") {
      v.then((s) => setVersion(s || "dev")).catch(() => setVersion("dev"));
    } else if (typeof v === "string") {
      setVersion(v);
    } else {
      setVersion("dev");
    }
  }, [wailsApp]);

  const features = [
    { icon: "💾", label: "文件系统", items: "NTFS / APFS / ext4 / FAT / exFAT / Btrfs / ZFS / HFS+ / F2FS / XFS / ReFS" },
    { icon: "🔐", label: "加密卷", items: "BitLocker / VeraCrypt / LUKS1+2 / FileVault" },
    { icon: "🧊", label: "VC cipher", items: "AES / Twofish / Serpent / Kuznyechik (GOST 国标) + 全 cascade 组合" },
    { icon: "🪞", label: "RAID", items: "0/1/5/6/10 + mdadm / LVM / Storage Spaces" },
    { icon: "📱", label: "移动端", items: "iOS 备份解密 / Android .ab / ADB 直连 / 块级 dump / PTP 相机 / iOS libimobiledevice" },
    { icon: "☁️", label: "云盘", items: "iCloud / OneDrive / Google Drive / Dropbox / Box / MEGA / pCloud / Nextcloud（本地同步根扫描）" },
    { icon: "🌐", label: "NAS", items: "SMB (go-smb2) / NFSv3 (自实现 RPC + portmap)" },
    { icon: "🎨", label: "JPEG 修复", items: "Annex K Huffman 注入 / RST 截尾 / 合成 RST stitching / in-tree partial decoder（71% 中段损坏可救）" },
    { icon: "🍎", label: "APFS LZFSE v2", items: "纯 Go bvx2 decoder（Apple compression_tool round-trip 通过）" },
    { icon: "🔍", label: "取证", items: "Ed25519 + RFC 3161 timestamp / DFXML / Custody chain / NSRL hash / VirusTotal" },
  ];

  return (
    <GenericModal
      title="📦 关于数据恢复大师"
      onClose={onClose}
      width={680}
      footer={<button className="btn btn--sm btn--primary" onClick={onClose}>关闭</button>}
    >
      <div style={{ display: "flex", alignItems: "center", gap: 16, marginBottom: 20 }}>
        <div style={{
          width: 64, height: 64, borderRadius: 12, background: "var(--accent-soft)",
          display: "flex", alignItems: "center", justifyContent: "center", fontSize: 32,
        }}>
          🛡
        </div>
        <div>
          <div style={{ fontSize: 18, fontWeight: 700 }}>数据恢复大师</div>
          <div className="mono muted" style={{ fontSize: 12 }}>{version}</div>
          <div className="muted" style={{ fontSize: 11, marginTop: 4 }}>
            离线 / 零网络 / 单二进制 / Go + Wails + React
          </div>
        </div>
      </div>

      <div style={{ fontSize: 12, marginBottom: 8 }}><b>支持的能力</b></div>
      <div style={{ display: "grid", gridTemplateColumns: "auto 1fr", rowGap: 6, columnGap: 12, fontSize: 12, marginBottom: 16 }}>
        {features.map((f) => (
          <React.Fragment key={f.label}>
            <div style={{ whiteSpace: "nowrap" }}>{f.icon} <b>{f.label}</b></div>
            <div className="muted">{f.items}</div>
          </React.Fragment>
        ))}
      </div>

      <div className="muted" style={{ fontSize: 11, boxShadow: "inset 0 1px 0 0 var(--border)", paddingTop: 12 }}>
        <div>所有解锁/扫描在本机完成；除显式"检查更新"外不连任何外网。</div>
        <div>第三方依赖：go-smb2 (BSD-3) · aead/serpent (BSD-2) · klauspost/compress (BSD-3) · wails v2 (MIT) · React (MIT)</div>
      </div>
    </GenericModal>
  );
}

// =============================================================================
// 9. TasksSidebar —— 左侧"今日任务"侧栏，跟踪所有 in-flight 移动端任务
// =============================================================================

const TASK_KIND_META = {
  "android-dump": { icon: "💽", color: "#3b82f6", title: "Android 块级 dump" },
  "adb-pull":     { icon: "📂", color: "#8b5cf6", title: "ADB 拉手机目录" },
  "ios-backup":   { icon: "🍎", color: "#10b981", title: "iOS 系统级备份" },
  "ptp-pull":     { icon: "📷", color: "#f59e0b", title: "PTP 数码相机" },
  "disk-dump":    { icon: "💾", color: "#ef4444", title: "整盘镜像 dump" },
};

// kind → backend Cancel<X> IPC method 名（v2.5.1 加）
const TASK_KIND_CANCEL_IPC: Record<string, string> = {
  "android-dump": "CancelAndroidDump",
  "adb-pull":     "CancelMTPPull",
  "ios-backup":   "CancelIOSBackup",
  "ptp-pull":     "CancelPTPPull",
  "disk-dump":    "CancelDiskDump",
};

// 任务对象 shape（in-flight 和 history 共用）
export interface MobileTask {
  kind: string;
  label: string;
  startedAt: number;
  completedAt?: number;
  progress?: number;       // bytes 已完成；-1 = 不确定
  totalBytes?: number;     // 已知总字节
  done?: boolean;
  error?: string;
  id?: string;             // 历史 task 用唯一 id
}

interface TasksSidebarProps {
  tasks: Map<string, MobileTask>;
  history?: MobileTask[];
  collapsed: boolean;
  onToggleCollapsed: () => void;
  onDismiss: (kind: string) => void;
  onDismissHistory?: (id: string) => void;
  onCancel?: (kind: string) => Promise<void> | void;
}

export function TasksSidebar({
  tasks,
  history,
  collapsed,
  onToggleCollapsed,
  onDismiss,
  onDismissHistory,
  onCancel,
}: TasksSidebarProps) {
  // **Hooks 必须全部在条件 return 之前调用** —— React Rules of Hooks。
  // 历史 bug (v2.7.0)：在 `if (... && collapsed) return null` 后再调
  // useReducer / useEffect → 用户点折叠按钮时 hook 数量从 3 变 1 → 白屏：
  //   "Rendered fewer hooks than expected"
  // 修复：所有 hooks 顶到函数最前；早返回之前不能再调任何 hook。
  const [tab, setTab] = React.useState<"active" | "history">("active");
  const [, force] = React.useReducer((x: number) => x + 1, 0);

  const inflight = Array.from(tasks.values()).sort((a, b) => (a.startedAt || 0) - (b.startedAt || 0));
  const histList = history || [];
  // v2.8.17 Issue 3 修复：之前 collapsed=true 且空列表时面板完全消失，用户无法重新打开。
  // 现在用户可以从顶栏 🗂 任务 按钮切换 collapsed 状态。这里逻辑保持原样：
  //   - collapsed=false（展开）→ 永远显示（即使空，给用户"无进行中任务"的反馈）
  //   - collapsed=true（折叠）+ 空列表 → 隐藏（节省屏幕空间，反正没东西展示）
  // 用户从顶栏按钮 setTasksSidebarCollapsed(false) 即可重新唤起面板。
  const shouldHide = inflight.length === 0 && histList.length === 0 && collapsed;

  // 本地时钟刷新（让 elapsed 显示走起来；每秒 tick 一次）
  // 关键：useEffect 也必须在 early return 之前；折叠或隐藏时直接 return（cleanup OK）
  React.useEffect(() => {
    if (shouldHide || collapsed || inflight.length === 0) return;
    const id = setInterval(force, 1000);
    return () => clearInterval(id);
  }, [shouldHide, collapsed, inflight.length]);

  // 所有 hooks 调过了，现在可以条件渲染
  if (shouldHide) return null;

  const list = tab === "active" ? inflight : histList;

  return (
    <div
      style={{
        position: "fixed",
        left: 0,
        top: 64,
        bottom: 0,
        width: collapsed ? 36 : 300,
        background: "var(--bg-surface)",
        boxShadow: collapsed
          ? "inset -1px 0 0 0 var(--border)"
          : "inset -1px 0 0 0 var(--border), 2px 0 12px rgba(0,0,0,0.08)",
        transition: "width 0.2s ease-out",
        zIndex: 80,
        display: "flex",
        flexDirection: "column",
        overflow: "hidden",
      }}
    >
      <div style={{
        display: "flex", alignItems: "center", justifyContent: "space-between",
        padding: collapsed ? "8px 4px" : "10px 12px",
        boxShadow: "inset 0 -1px 0 0 var(--border)",
      }}>
        {!collapsed && (
          <div style={{ fontSize: 12, fontWeight: 600 }}>
            🗂 任务
          </div>
        )}
        <button
          className="btn btn--sm btn--ghost"
          onClick={onToggleCollapsed}
          title={collapsed ? "展开" : "折叠"}
          style={{ padding: "0 6px", fontSize: 14 }}
        >
          {collapsed ? "›" : "‹"}
        </button>
      </div>

      {!collapsed && (
        <>
          {/* Tab 切换 */}
          <div style={{ display: "flex", boxShadow: "inset 0 -1px 0 0 var(--border)" }}>
            <button
              onClick={() => setTab("active")}
              style={{
                flex: 1, padding: "8px 0", fontSize: 11, fontWeight: 600,
                background: tab === "active" ? "var(--accent-soft)" : "transparent",
                color: tab === "active" ? "var(--accent)" : "var(--text-muted)",
                border: "none",
                boxShadow: tab === "active" ? "inset 0 -2px 0 0 var(--accent)" : "none",
                cursor: "pointer",
              }}
            >
              进行中 ({inflight.length})
            </button>
            <button
              onClick={() => setTab("history")}
              style={{
                flex: 1, padding: "8px 0", fontSize: 11, fontWeight: 600,
                background: tab === "history" ? "var(--accent-soft)" : "transparent",
                color: tab === "history" ? "var(--accent)" : "var(--text-muted)",
                border: "none",
                boxShadow: tab === "history" ? "inset 0 -2px 0 0 var(--accent)" : "none",
                cursor: "pointer",
              }}
            >
              历史 ({histList.length})
            </button>
          </div>

          <div style={{ overflowY: "auto", flex: 1, padding: "8px" }}>
            {list.length === 0 ? (
              <div className="muted" style={{ fontSize: 11, padding: 8, textAlign: "center" }}>
                {tab === "active" ? (
                  <>
                    无进行中任务
                    <div style={{ marginTop: 6, fontSize: 10, opacity: 0.7 }}>
                      启动 Android dump / iOS 备份 / PTP 拉取 / 镜像 dump 后出现在这里
                    </div>
                  </>
                ) : (
                  <>
                    最近 5 分钟无完成的任务
                    <div style={{ marginTop: 6, fontSize: 10, opacity: 0.7 }}>
                      完成 5 分钟以上的任务自动清理
                    </div>
                  </>
                )}
              </div>
            ) : (
              list.map((t) => (
                <TaskCard
                  key={t.id || t.kind}
                  task={t}
                  isHistory={tab === "history"}
                  onDismiss={() => tab === "history" ? onDismissHistory?.(t.id) : onDismiss?.(t.kind)}
                  onCancel={() => onCancel?.(t.kind)}
                />
              ))
            )}
          </div>
        </>
      )}
    </div>
  );
}

// 单任务卡片（in-flight 或 history）
function TaskCard({ task, isHistory, onDismiss, onCancel }) {
  const meta = TASK_KIND_META[task.kind] || { icon: "🔄", color: "#6b7280", title: task.kind };
  const elapsed = task.startedAt ? Math.floor(((task.completedAt || Date.now()) - task.startedAt) / 1000) : 0;
  const fmtElapsed = elapsed >= 60
    ? `${Math.floor(elapsed / 60)}m ${elapsed % 60}s`
    : `${elapsed}s`;
  const canCancel = !isHistory && !task.done && TASK_KIND_CANCEL_IPC[task.kind];
  const isError = !!task.error;

  return (
    <div
      style={{
        background: isError ? "var(--bg-danger-soft, #fee2e2)" : (task.done ? "var(--bg-inset)" : "var(--bg-inset)"),
        border: `1px solid ${isError ? "var(--danger)" : "var(--border)"}`,
        boxShadow: `inset 3px 0 0 0 ${isError ? "var(--danger)" : (task.done && !isError ? "var(--success, #16a34a)" : meta.color)}`,
        borderRadius: 6,
        padding: "8px 10px",
        marginBottom: 8,
        fontSize: 11,
        opacity: isHistory ? 0.85 : 1,
      }}
    >
      <div style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 4 }}>
        <span style={{ fontSize: 13 }}>{meta.icon}</span>
        <span style={{ flex: 1, fontWeight: 600, fontSize: 11 }}>{meta.title}</span>
        {canCancel && (
          <button
            onClick={() => {
              if (globalThis.confirm?.(`确定取消 ${meta.title}?\n（已传输的部分会保留）`)) {
                onCancel?.();
              }
            }}
            style={{
              border: "1px solid var(--danger)", background: "transparent",
              color: "var(--danger)", cursor: "pointer", fontSize: 10,
              padding: "1px 6px", borderRadius: 3, marginRight: 2,
            }}
            title="取消任务（停止 backend 子进程）"
          >
            🛑 取消
          </button>
        )}
        <button
          onClick={onDismiss}
          style={{
            border: "none", background: "transparent", cursor: "pointer",
            fontSize: 12, color: "var(--text-muted)", padding: "0 4px",
          }}
          title="关闭卡片"
        >
          ✕
        </button>
      </div>
      <div style={{ fontSize: 11, marginBottom: 6, color: "var(--text)" }}>{task.label}</div>
      {!task.done && !isHistory && (
        <>
          {typeof task.progress === "number" && task.progress > 0 && task.totalBytes > 0 ? (
            <div className="progress" style={{ height: 4 }}>
              <div className="progress__fill" style={{ width: `${Math.min(100, (task.progress / task.totalBytes) * 100)}%` }} />
            </div>
          ) : (
            <div className="progress" style={{ height: 4 }}>
              <div
                className="progress__fill"
                style={{ width: "100%", animation: "progressPulse 2s ease-in-out infinite" }}
              />
            </div>
          )}
        </>
      )}
      {elapsed > 0 && (
        <div className="muted" style={{ fontSize: 10, marginTop: 4 }}>
          {isHistory ? "用时" : "已用"} {fmtElapsed}
          {isHistory && task.completedAt && (
            <span style={{ marginLeft: 8 }}>
              · {Math.floor((Date.now() - task.completedAt) / 1000 / 60)} 分钟前
            </span>
          )}
        </div>
      )}
      {task.error && (
        <div style={{ fontSize: 10, color: "var(--danger)", marginTop: 4 }}>
          {task.error}
        </div>
      )}
    </div>
  );
}
