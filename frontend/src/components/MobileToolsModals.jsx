// 移动端 / 备份 / NAS / 云端 工具的完整 modal dialog 集合。
//
// 设计原则：
//   - 复用 .preview-modal CSS 变体（已有的暗色 backdrop + 居中 inner box 风格）
//   - 每个 modal 自管 state；父只传 onClose + wailsApp + 必要的 outputDir
//   - 所有耗时操作显示加载态（loading spinner / disabled 按钮 / 进度条）
//   - 错误友好：网络/工具缺失/权限问题分别给可执行的提示
//   - 进度可视化：监听 backend 事件（ios:backupProgress / mtp:dumpProgress 等）

import React, { useEffect, useRef, useState } from "react";

// 通用 modal 壳：复用 preview-modal CSS，但内容可定制
// width 是 inner 的 max-width（默认 600）
export function GenericModal({ title, onClose, width = 600, children, footer }) {
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
          <button className="btn btn--sm btn--ghost" onClick={onClose} title="关闭 (Esc)">
            ✕
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
export function Field({ label, hint, children }) {
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

export function TextInput({ value, onChange, placeholder, type = "text", disabled }) {
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

export function CloudBackupsModal({ wailsApp, onClose, onStartedScan }) {
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
      globalThis.alert?.("启动扫描失败: " + (err?.message || err));
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
                <li key={i} style={{ padding: "4px 0", borderBottom: "1px solid var(--border)" }}>
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
                <tr style={{ borderBottom: "1px solid var(--border)" }}>
                  <th style={{ textAlign: "left", padding: "6px 4px" }}>类型</th>
                  <th style={{ textAlign: "left", padding: "6px 4px" }}>云端</th>
                  <th style={{ textAlign: "left", padding: "6px 4px" }}>路径</th>
                  <th style={{ textAlign: "right", padding: "6px 4px" }}>大小</th>
                  <th style={{ padding: "6px 4px" }}>操作</th>
                </tr>
              </thead>
              <tbody>
                {hits.map((h, i) => (
                  <tr key={i} style={{ borderBottom: "1px solid var(--border)" }}>
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

export function NASScanModal({ kind, wailsApp, onClose, onStarted }) {
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

export function AndroidDumpModal({ wailsApp, outputDir, onClose, onStarted }) {
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

export function IOSBackupModal({ wailsApp, outputDir, onClose, onStarted }) {
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
