import React, { useEffect, useState } from "react";
import {
  IconAlertTriangle,
  IconArrowRight,
  IconHardDrive,
  IconInfo,
  IconRefresh,
  IconShield,
  IconUsb,
  IconCloud,
  IconPhone,
  IconCamera,
  IconServer,
  IconGripVertical,
  IconLock,
  IconLightbulb,
  IconApple,
  IconWindows,
  IconBox,
  IconCheck,
} from "../icons";
import { formatSize } from "../formatters";
import { t, onLocaleChange } from "../i18n";

/**
 * QuickCard —— WelcomePage 顶部快速入口卡片（云端 / 手机直连 / 相机 / NAS）。
 * 支持 HTML5 拖拽重排 + localStorage 持久化（v2.5.1）。
 */
function QuickCard({ Icon, title, desc, onClick, draggable, onDragStart, onDragOver, onDrop, isDragging, isDragOver }) {
  return (
    <div
      draggable={draggable}
      onDragStart={onDragStart}
      onDragOver={onDragOver}
      onDrop={onDrop}
      onClick={onClick}
      role="button"
      tabIndex={0}
      onKeyDown={(e) => { if (e.key === "Enter" || e.key === " ") onClick?.(); }}
      style={{
        textAlign: "left",
        padding: "var(--space-3) var(--space-4)",
        border: `1px solid ${isDragOver ? "var(--accent)" : "var(--border)"}`,
        borderRadius: "var(--radius-md)",
        background: isDragOver ? "var(--accent-soft)" : "var(--bg-surface)",
        cursor: draggable ? "grab" : "pointer",
        display: "flex",
        alignItems: "center",
        gap: "var(--space-3)",
        transition: "all 180ms cubic-bezier(.4,0,.2,1)",
        opacity: isDragging ? 0.4 : 1,
        userSelect: "none",
        boxShadow: "var(--shadow-sm)",
      }}
      onMouseEnter={(e) => {
        if (isDragging) return;
        e.currentTarget.style.borderColor = "var(--accent-border)";
        e.currentTarget.style.transform = "translateY(-2px)";
        e.currentTarget.style.boxShadow = "var(--shadow-md)";
      }}
      onMouseLeave={(e) => {
        if (isDragging) return;
        e.currentTarget.style.borderColor = isDragOver ? "var(--accent)" : "var(--border)";
        e.currentTarget.style.transform = "translateY(0)";
        e.currentTarget.style.boxShadow = "var(--shadow-sm)";
      }}
    >
      {/* 拖拽手柄默认就显示（不再 hover 才出），让用户一眼就知道可拖 */}
      {draggable && (
        <span
          className="drag-handle"
          style={{
            color: "var(--text-subtle)",
            cursor: "grab",
            display: "flex",
            alignItems: "center",
            flex: "none",
          }}
          title="拖拽重排"
        >
          <IconGripVertical size={14} />
        </span>
      )}
      {/* SVG icon 在 accent 圆角方块里 — 替代 emoji，统一笔画风格 */}
      <div style={{
        width: 38,
        height: 38,
        borderRadius: "var(--radius-md)",
        background: "var(--accent-soft)",
        color: "var(--accent)",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        flex: "none",
        border: "1px solid var(--accent-border)",
      }}>
        {Icon ? <Icon size={20} /> : null}
      </div>
      <div style={{ flex: 1, minWidth: 0 }}>
        <div
          className="ellipsis"
          style={{ fontWeight: "var(--weight-semibold)", fontSize: "var(--text-base)", marginBottom: 2, letterSpacing: "-0.005em" }}
          title={title}
        >
          {title}
        </div>
        <div className="muted ellipsis" style={{ fontSize: "var(--text-xs)" }} title={desc}>
          {desc}
        </div>
      </div>
    </div>
  );
}

// QuickCardsGrid —— 包装器，处理拖拽顺序 + localStorage 持久化
function QuickCardsGrid({ cards, onOpenMobileModal }) {
  const STORAGE_KEY = "welcome_quick_cards_order";
  // 读 localStorage 里保存的顺序；解析失败 fallback 到默认
  const [order, setOrder] = useState(() => {
    try {
      const saved = globalThis.localStorage?.getItem?.(STORAGE_KEY);
      if (saved) {
        const arr = JSON.parse(saved);
        if (Array.isArray(arr) && arr.every((k) => cards.find((c) => c.key === k))) {
          // 已保存的顺序里所有 key 都在当前 cards 里 → 用它
          // 同时把 cards 里没出现在 saved 的（新增功能）追加到末尾
          const missing = cards.filter((c) => !arr.includes(c.key)).map((c) => c.key);
          return [...arr, ...missing];
        }
      }
    } catch (_e) {}
    return cards.map((c) => c.key);
  });
  const [dragKey, setDragKey] = useState(null);
  const [dragOverKey, setDragOverKey] = useState(null);

  useEffect(() => {
    try {
      globalThis.localStorage?.setItem?.(STORAGE_KEY, JSON.stringify(order));
    } catch (_e) {}
  }, [order]);

  function handleDragStart(key) {
    return (e) => {
      setDragKey(key);
      e.dataTransfer.effectAllowed = "move";
      // Firefox 需要 setData 才肯触发 dragstart
      e.dataTransfer.setData("text/plain", key);
    };
  }

  function handleDragOver(key) {
    return (e) => {
      e.preventDefault();
      e.dataTransfer.dropEffect = "move";
      if (key !== dragOverKey) setDragOverKey(key);
    };
  }

  function handleDrop(key) {
    return (e) => {
      e.preventDefault();
      if (!dragKey || dragKey === key) {
        setDragKey(null);
        setDragOverKey(null);
        return;
      }
      setOrder((prev) => {
        const next = [...prev];
        const fromIdx = next.indexOf(dragKey);
        const toIdx = next.indexOf(key);
        if (fromIdx === -1 || toIdx === -1) return prev;
        next.splice(fromIdx, 1);
        next.splice(toIdx, 0, dragKey);
        return next;
      });
      setDragKey(null);
      setDragOverKey(null);
    };
  }

  // 按 order 排序后渲染
  const orderedCards = order
    .map((k) => cards.find((c) => c.key === k))
    .filter(Boolean);

  return (
    <div
      style={{
        display: "grid",
        gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))",
        gap: 10,
        marginBottom: 16,
      }}
      onDragLeave={() => setDragOverKey(null)}
    >
      {orderedCards.map((card) => (
        <QuickCard
          key={card.key}
          Icon={card.Icon}
          title={card.title}
          desc={card.desc}
          onClick={() => onOpenMobileModal(card.modal)}
          draggable
          onDragStart={handleDragStart(card.key)}
          onDragOver={handleDragOver(card.key)}
          onDrop={handleDrop(card.key)}
          isDragging={dragKey === card.key}
          isDragOver={dragOverKey === card.key && dragKey !== card.key}
        />
      ))}
    </div>
  );
}

/**
 * WelcomePage —— 选源盘 + 权限提示 + 会话恢复。
 * 移除了旧版本冗长的教学内容；关键信息都用 banner 一屏内呈现。
 */
export default function WelcomePage({
  drives,
  selectedDrive,
  onSelectDrive,
  onStartScan,
  onSelectImageFile,
  onRefreshDrives,
  isLoadingDrives,
  driveLoadError,
  isAdmin,
  platform,
  pendingSession,
  onRestoreSession,
  onDiscardSession,
  onResumeScan,
  shadows,
  onScanShadow,
  encryptedVolumes,
  onUnlockBitLocker,
  onUnlockBitLockerMemory,
  // 新：快速入口卡片回调（v2.5.0）
  // 调用 setOpenMobileModal("kind") 让 App 打开对应 modal
  onOpenMobileModal,
}) {
  const needsElevation = !isAdmin;
  // locale 变化触发重 render
  const [, setLocaleVer] = useState(0);
  React.useEffect(() => onLocaleChange(() => setLocaleVer((v) => v + 1)), []);
  // 哪个 BitLocker 卷当前在弹输入 recovery key 的对话框；null = 无对话框
  const [unlockingVolume, setUnlockingVolume] = useState(null);

  return (
    <div className="page">
      <div className="page__header">
        <div className="page__title">{t("welcome.title")}</div>
        <div className="page__subtitle">{t("welcome.subtitle")}</div>
      </div>

      <div className="page__body flex-col gap-3">
        {needsElevation && (
          <div className="banner banner--danger">
            <IconShield size={18} className="banner__icon" />
            <div className="banner__content">
              <div className="banner__title">当前没有磁盘原始读写权限</div>
              <div className="banner__text">
                {elevationHint(platform)}
              </div>
            </div>
          </div>
        )}

        {pendingSession && (
          <div className="banner banner--info">
            <IconInfo size={18} className="banner__icon" />
            <div className="banner__content">
              <div className="banner__title">发现未完成的扫描会话</div>
              <div className="banner__text">
                上次扫描 <b>{pendingSession.driveLabel || pendingSession.drivePath}</b>
                {pendingSession.completed ? " 已完成" : " 被中断"}，
                目前已收集 {(pendingSession.files?.length || 0).toLocaleString()} 个文件（
                {formatSize(pendingSession.progress?.bytesScanned || 0)} 已扫描）。
                <br />
                <span style={{ display: "inline-flex", alignItems: "flex-start", gap: 6, marginTop: 4, opacity: 0.85 }}>
                  <IconAlertTriangle size={13} style={{ color: "var(--warning)", flex: "none", marginTop: 3 }} />
                  <span>
                    如果上次因卡死被强关，请先 <b>丢弃</b> 旧会话后再重新扫描；
                    恢复旧会话只会加载旧文件列表，不会重新扫描。
                  </span>
                </span>
              </div>
            </div>
            <div className="banner__actions">
              <button className="btn btn--primary btn--sm" onClick={onDiscardSession}>
                丢弃旧会话
              </button>
              <button className="btn btn--sm" onClick={onRestoreSession}>
                恢复旧文件列表
              </button>
              {pendingSession.carverResumeOffset > 0 && onResumeScan && (
                <button className="btn btn--sm" onClick={onResumeScan} title="跳过已扫字节，从断点继续深度扫描">
                  从断点继续扫描（{formatSize(pendingSession.carverResumeOffset)} 处）
                </button>
              )}
            </div>
          </div>
        )}

        {driveLoadError && (
          <div className="banner banner--danger">
            <IconAlertTriangle size={18} className="banner__icon" />
            <div className="banner__content">
              <div className="banner__title">读取磁盘列表失败</div>
              <div className="banner__text" style={{ whiteSpace: "pre-wrap" }}>
                {driveLoadError}
              </div>
            </div>
            <div className="banner__actions">
              <button className="btn btn--sm" onClick={onRefreshDrives}>
                <IconRefresh size={14} /> 重试
              </button>
            </div>
          </div>
        )}

        {/* ============== 快速入口卡片（v2.5.0 新 / v2.5.1 加拖拽重排） ============== */}
        {onOpenMobileModal && (
          <div>
            <div
              style={{
                display: "flex",
                alignItems: "center",
                gap: "var(--space-2)",
                fontSize: "var(--text-sm)",
                fontWeight: "var(--weight-medium)",
                color: "var(--text)",
                marginBottom: 10,
                paddingLeft: 2,
              }}
            >
              <IconLightbulb size={14} style={{ color: "var(--accent)", flex: "none" }} />
              <span>也可以从其他来源恢复</span>
              <span className="muted" style={{ fontWeight: "var(--weight-normal)" }}>
                · 拖拽重排卡片顺序
              </span>
            </div>
            <QuickCardsGrid
              cards={[
                { key: "cloud", Icon: IconCloud, title: "iOS / Android 备份", desc: "本机或云盘里 iTunes / .ab 备份", modal: "cloud" },
                { key: "adb", Icon: IconPhone, title: "手机直连", desc: "ADB 拉目录 / 块级 dump / iOS 触发备份", modal: "adb-pull" },
                { key: "ptp", Icon: IconCamera, title: "数码相机 (PTP)", desc: "gphoto2 拉相机所有照片 + 扫描", modal: "ptp-camera" },
                { key: "nas", Icon: IconServer, title: "NAS (SMB / NFS)", desc: "扫局域网共享盘 + 直接恢复", modal: "nas-smb" },
              ]}
              onOpenMobileModal={onOpenMobileModal}
            />
          </div>
        )}

        <div className="flex items-center justify-between">
          <div className="muted" style={{ fontSize: 13 }}>
            共 {drives.length} 块磁盘{isLoadingDrives ? "（读取中…）" : ""}
          </div>
          <button className="btn btn--sm btn--ghost" onClick={onRefreshDrives} disabled={isLoadingDrives}>
            <IconRefresh size={14} /> 刷新列表
          </button>
        </div>

        {drives.length === 0 && !isLoadingDrives && !driveLoadError && (
          <div className="empty-state card">
            <IconHardDrive size={48} className="empty-state__icon" />
            <div className="empty-state__title">没有发现磁盘</div>
            <div className="empty-state__text">
              请确认源盘已连接到电脑，并以管理员/root 权限运行本程序后重试。
            </div>
          </div>
        )}

        <div className="drive-grid">
          {drives.map((d) => (
            <DriveCard
              key={d.path}
              drive={d}
              selected={selectedDrive?.path === d.path}
              onSelect={() => onSelectDrive?.(d)}
            />
          ))}
        </div>

        <div className="banner banner--info">
          <IconInfo size={18} className="banner__icon" />
          <div className="banner__content">
            <div className="banner__title">更安全：扫描磁盘镜像文件</div>
            <div className="banner__text">
              业界最佳实践：先用 <span className="mono">ddrescue</span>（Linux）、
              HDDSuperClone、或 DMDE 的 clone 功能把源盘整盘 dump 成 <span className="mono">.img</span> 文件，
              然后让本工具扫镜像而不是原盘 —— 源盘只读一次就放回保险箱，
              后续无论怎么试都不会再动它。
            </div>
          </div>
          <div className="banner__actions">
            <button className="btn btn--sm" onClick={onSelectImageFile}>
              选择镜像文件…
            </button>
          </div>
        </div>

        {Array.isArray(encryptedVolumes) && encryptedVolumes.length > 0 && (
          <div className="banner banner--warning" style={{ flexDirection: "column", alignItems: "stretch" }}>
            <div className="flex items-center gap-2">
              <IconAlertTriangle size={18} className="banner__icon" />
              <div className="banner__title">
                发现 {encryptedVolumes.length} 个加密 / 未支持卷
              </div>
            </div>
            <div className="banner__text" style={{ marginBottom: 8 }}>
              本工具<b>不解密</b>这些卷 —— BitLocker / FileVault / APFS 全卷加密都需要专门工具 + 用户密码 / 恢复密钥。
              下面列出来只是为了避免你以为"盘是空的"。专门工具：
              <span className="mono"> dislocker</span>（BitLocker，开源）/ R-Studio / 苹果 Recovery 工具（FileVault）。
            </div>
            <div className="flex-col gap-2">
              {encryptedVolumes.map((v, i) => {
                const KindIcon =
                  v.kind === "bitlocker" ? IconLock :
                  v.kind === "filevault" ? IconLock :
                  v.kind === "hfsplus"   ? IconApple :
                  v.kind === "refs"      ? IconWindows :
                                           IconBox;
                const kindLabel =
                  v.kind === "bitlocker" ? "BitLocker" :
                  v.kind === "filevault" ? "FileVault" :
                  v.kind === "hfsplus"   ? "HFS+" :
                  v.kind === "refs"      ? "ReFS" :
                                           "APFS 卷";
                const locationLine = `${v.drivePath} @ 0x${Number(v.offset || 0).toString(16)}${v.uuid ? ` · UUID ${v.uuid}` : ""}`;
                return (
                  <div
                    key={`${v.drivePath}-${v.offset}-${i}`}
                    className="card"
                    style={{ padding: "10px 14px", display: "flex", justifyContent: "space-between", alignItems: "flex-start", gap: 12 }}
                  >
                    <div style={{ flex: 1, minWidth: 0, display: "flex", gap: 10 }}>
                      <div style={{
                        flex: "none",
                        width: 28,
                        height: 28,
                        display: "grid",
                        placeItems: "center",
                        borderRadius: "var(--radius-sm)",
                        background: "var(--warning-soft)",
                        color: "var(--warning)",
                      }}>
                        <KindIcon size={16} />
                      </div>
                      <div style={{ flex: 1, minWidth: 0 }}>
                        <div className="ellipsis" style={{ fontSize: "var(--text-sm)", fontWeight: "var(--weight-semibold)" }} title={`${kindLabel}${v.name ? ` · ${v.name}` : ""}`}>
                          {kindLabel}{v.name ? <span className="muted" style={{ fontWeight: "var(--weight-normal)" }}> · {v.name}</span> : null}
                        </div>
                        <div className="muted ellipsis" style={{ fontSize: "var(--text-xs)" }} title={locationLine}>
                          {locationLine}
                        </div>
                        <div className="muted ellipsis" style={{ fontSize: "var(--text-xs)", marginTop: 2 }} title={v.note}>{v.note}</div>
                      </div>
                    </div>
                    {v.kind === "bitlocker" && typeof onUnlockBitLocker === "function" && (
                      <button
                        className="btn btn--sm btn--primary"
                        onClick={() => setUnlockingVolume(v)}
                        title="输入 48 位 recovery key，本工具将在内存中透明解密后直接扫描卷"
                      >
                        <IconLock size={14} /> 解锁并扫描
                      </button>
                    )}
                  </div>
                );
              })}
            </div>
          </div>
        )}

        {Array.isArray(shadows) && shadows.length > 0 && (
          <div className="banner banner--success" style={{ flexDirection: "column", alignItems: "stretch" }}>
            <div className="flex items-center gap-2">
              <IconInfo size={18} className="banner__icon" />
              <div className="banner__title">
                发现 {shadows.length} 个 Volume Shadow Copy 卷影副本
              </div>
            </div>
            <div className="banner__text" style={{ marginBottom: 8 }}>
              系统还原点 / VSS 自动快照里可能保留了**重装前**的用户数据。
              这是 R-Studio 式"时光机"能力，对被盗 Windows 找回数据价值最高。
              直接扫这里的快照设备，像扫原盘一样。
            </div>
            <div className="flex-col gap-2">
              {shadows.map((s) => (
                <div
                  key={s.id || s.devicePath}
                  className="card"
                  style={{ padding: "8px 12px", display: "flex", alignItems: "center", gap: 12 }}
                >
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div className="mono" style={{ fontSize: 12, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                      {s.devicePath}
                    </div>
                    <div className="muted" style={{ fontSize: 11 }}>
                      {s.createdAt ? new Date(s.createdAt).toLocaleString() : "创建时间未知"}
                      {s.originalVolume ? ` · 来源 ${s.originalVolume}` : ""}
                    </div>
                  </div>
                  <button
                    className="btn btn--sm btn--primary"
                    onClick={() => onScanShadow?.(s)}
                    disabled={!isAdmin}
                  >
                    扫描此快照
                  </button>
                </div>
              ))}
            </div>
          </div>
        )}

        <div className="flex justify-between items-center" style={{ marginTop: 8 }}>
          <div className="muted" style={{ fontSize: 12 }}>
            选好源盘后，下一步进入扫描工作台——扫描期间也能实时筛选、选中、立即恢复。
          </div>
          <button
            className="btn btn--primary btn--lg"
            onClick={onStartScan}
            disabled={!selectedDrive || !isAdmin}
          >
            {t("welcome.startScan")} <IconArrowRight size={16} />
          </button>
        </div>
      </div>

      {unlockingVolume && (
        <BitLockerUnlockModal
          volume={unlockingVolume}
          wailsApp={typeof window !== "undefined" ? window.go?.main?.App : null}
          onCancel={() => setUnlockingVolume(null)}
          onSubmit={(submitMode, value) => {
            const v = unlockingVolume;
            setUnlockingVolume(null);
            if (submitMode === "memory") {
              onUnlockBitLockerMemory?.(v, value);
            } else {
              onUnlockBitLocker?.(v, value);
            }
          }}
        />
      )}
    </div>
  );
}

/**
 * BitLockerUnlockModal —— 多模式 BitLocker 解锁对话框：
 *   recovery —— 48 位 recovery key
 *   memory   —— TPM-only / TPM+PIN 卷的"内存镜像 / hiberfil.sys"路径
 *
 * password / startup-key 模式预留接口（后端已就绪，UI 入口同 recovery 模式：
 * 用户在 textarea 里输入对应字符串即可），暂不做独立 tab 减少 UI 复杂度。
 *
 * onSubmit 收到三参数：(mode, value, extra) 由调用方分发：
 *   mode="recovery"  value=key
 *   mode="memory"    value=memImagePath
 */
function BitLockerUnlockModal({ volume, wailsApp, onCancel, onSubmit }) {
  const [mode, setMode] = React.useState("recovery");
  const [key, setKey] = React.useState("");
  const [memPath, setMemPath] = React.useState("");
  const [protectors, setProtectors] = React.useState(null); // null=loading, []=loaded
  const digits = key.replace(/\D/g, "");
  const recoveryValid = digits.length === 48;
  const memoryValid = memPath.trim() !== "";

  // open 时拉取 protector 清单让用户知道"这卷能不能解 / 该用哪种"
  React.useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        // v2.8.47 重构：App 从 package main 搬到 package appcore，wails 生成的
        // 全局命名空间也变；优先 appcore，向后兼容 main（旧版本未重新生成 bindings）。
        const ns: any = (window as any).go?.appcore?.App ?? (window as any).go?.main?.App;
        if (typeof window !== "undefined" && ns?.SummarizeBitLockerProtectors) {
          const list = await ns.SummarizeBitLockerProtectors(
            volume.drivePath,
            Number(volume.offset || 0).toString(16),
          );
          if (!cancelled) setProtectors(Array.isArray(list) ? list : []);
        } else {
          setProtectors([]);
        }
      } catch {
        if (!cancelled) setProtectors([]);
      }
    })();
    return () => { cancelled = true; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [volume.drivePath, volume.offset]);

  const tabBtn = (active) => ({
    padding: "6px 12px",
    border: active ? "1px solid var(--accent)" : "1px solid var(--border)",
    background: active ? "var(--accent-soft)" : "transparent",
    borderRadius: 4,
    cursor: "pointer",
    fontSize: 12,
  });

  return (
    <div
      className="modal-backdrop"
      onClick={onCancel}
      style={{
        position: "fixed", inset: 0, background: "rgba(0,0,0,0.55)",
        display: "flex", alignItems: "center", justifyContent: "center", zIndex: 50,
      }}
    >
      <div
        className="card"
        onClick={(e) => e.stopPropagation()}
        style={{ maxWidth: 600, width: "92%", padding: 20, display: "flex", flexDirection: "column", gap: 12 }}
      >
        <div style={{ fontSize: "var(--text-xl)", fontWeight: "var(--weight-semibold)", display: "flex", alignItems: "center", gap: 10, letterSpacing: "-0.01em" }}>
          <IconLock size={20} style={{ color: "var(--accent)" }} />
          解锁 BitLocker 卷
        </div>

        <div style={{ display: "flex", gap: 6 }}>
          <button style={tabBtn(mode === "recovery")} onClick={() => setMode("recovery")}>Recovery Key</button>
          <button style={tabBtn(mode === "memory")} onClick={() => setMode("memory")}>内存镜像 (TPM)</button>
        </div>

        <div className="muted" style={{ fontSize: 11, wordBreak: "break-all" }}>
          目标：<span className="mono">{volume.drivePath}</span>
          @ 0x{Number(volume.offset || 0).toString(16)}
          {volume.uuid ? ` · UUID ${volume.uuid}` : ""}
        </div>

        {protectors === null && (
          <div className="muted" style={{ fontSize: 11 }}>正在读保护器清单…</div>
        )}
        {Array.isArray(protectors) && protectors.length > 0 && (
          <div style={{
            padding: "8px 12px", background: "var(--bg-surface-2)",
            border: "1px solid var(--border)", borderRadius: 4, fontSize: 12,
          }}>
            <div style={{ fontWeight: 600, marginBottom: 4 }}>卷上配置的保护器：</div>
            {protectors.map((p, i) => (
              <div key={i} style={{ marginTop: 4, display: "flex", alignItems: "center", gap: 6 }}>
                {p.solvable
                  ? <IconCheck size={14} style={{ color: "var(--success)", flex: "none" }} />
                  : <IconAlertTriangle size={14} style={{ color: "var(--warning)", flex: "none" }} />}
                <b>{p.kind}</b>
                <span className="muted ellipsis" style={{ minWidth: 0 }} title={p.hint}>— {p.hint}</span>
              </div>
            ))}
          </div>
        )}

        {mode === "recovery" && (
          <>
            <div className="muted" style={{ fontSize: 12, lineHeight: 1.5 }}>
              输入 48 位 BitLocker recovery key（在微软账户 aka.ms/myrecoverykey / AD 域 / 管理员事先打印
              的 txt 文件里找得到）。本工具只在内存里派生 VMK → FVEK，<b>不</b>写盘、不联网。
            </div>
            <textarea
              autoFocus
              rows={3}
              value={key}
              onChange={(e) => setKey(e.target.value)}
              placeholder="例：123456-234567-345678-456789-567890-678901-789012-890123"
              className="mono"
              style={{
                fontSize: 13, padding: 10, borderRadius: 6,
                border: "1px solid var(--border)", resize: "vertical", width: "100%",
              }}
            />
            <div className="muted" style={{ fontSize: 11 }}>
              已输入 {digits.length}/48 位数字。连字符 / 空格 / 换行都会被忽略。
              <br />
              ⚠ 推导密钥会占用 CPU 约 1–2 秒（1M 次 SHA-256）。
            </div>
          </>
        )}

        {mode === "memory" && (
          <>
            <div className="muted" style={{ fontSize: 12, lineHeight: 1.5 }}>
              <b>TPM-only / TPM+PIN</b> 卷无法用 recovery key 解（TPM 在原机硬件里）。
              如果你能从原机抓到 <span className="mono">hiberfil.sys</span>（休眠文件）或内存 dump，
              本工具会在镜像里 <b>brute-force 搜出 VMK</b>（VMK 在 TPM 解出后会一直驻留在内存里）。
              这是 Passware / Elcomsoft 等专业取证工具用的同款方法。
              <br />
              典型扫描 4GB 内存镜像耗时约 2-3 分钟。
            </div>
            <input
              autoFocus
              type="text"
              value={memPath}
              onChange={(e) => setMemPath(e.target.value)}
              placeholder="C:\hiberfil.sys 或 /path/to/memory.dump"
              className="mono"
              style={{
                fontSize: 13, padding: 10, borderRadius: 6,
                border: "1px solid var(--border)", width: "100%",
              }}
            />
            <div className="muted" style={{ fontSize: 11 }}>
              支持的格式：raw 内存 dump（winpmem / DumpIt / FTK Imager） / Windows hiberfil.sys /
              VMware .vmem。
            </div>
          </>
        )}

        <div className="flex justify-end gap-2" style={{ marginTop: 4 }}>
          <button className="btn btn--ghost" onClick={onCancel}>取消</button>
          {mode === "recovery" ? (
            <button
              className="btn btn--primary"
              disabled={!recoveryValid}
              onClick={() => onSubmit("recovery", key)}
            >
              解锁并扫描
            </button>
          ) : (
            <button
              className="btn btn--primary"
              disabled={!memoryValid}
              onClick={() => onSubmit("memory", memPath)}
            >
              扫内存找 VMK 并扫描
            </button>
          )}
        </div>
      </div>
    </div>
  );
}

function DriveCard({ drive, selected, onSelect }) {
  // v2.7.2 起 macOS dev 模式会返回一个 driveType=dev-placeholder 的占位卡 ——
  // 不可点、特殊样式，让用户一眼看出"这是 dev 跳过的提示"，而不是把它当成 0 字节的真盘。
  if (drive.driveType === "dev-placeholder") {
    return (
      <div className="card drive-card drive-card--placeholder" aria-disabled="true">
        <div className="drive-card__head">
          <div className="drive-card__icon" style={{ background: "var(--warning-soft)", color: "var(--warning)" }}>
            <IconAlertTriangle size={20} />
          </div>
          <div style={{ flex: 1, minWidth: 0 }}>
            <div className="drive-card__name">DEV 模式：物理盘枚举已跳过</div>
            <div className="drive-card__path" style={{ fontFamily: "var(--font-sans)" }}>
              避免每次启动都触发 macOS 权限框
            </div>
          </div>
        </div>
        <div className="muted" style={{ fontSize: "var(--text-xs)", lineHeight: 1.6 }}>
          要测真物理盘扫描，请用 <span className="mono">make dev-elevated</span>（要 sudo 密码）。
          日常开发拖入 <span className="mono">.img</span> 镜像文件就够了。
        </div>
      </div>
    );
  }

  const Icon = drive.isRemovable ? IconUsb : IconHardDrive;
  return (
    <div
      className={`card drive-card card--hover ${selected ? "card--selected drive-card--selected" : ""}`}
      onClick={onSelect}
      role="button"
      tabIndex={0}
      onKeyDown={(e) => {
        if (e.key === "Enter" || e.key === " ") {
          e.preventDefault();
          onSelect();
        }
      }}
    >
      <div className="drive-card__head">
        <div className="drive-card__icon">
          <Icon size={20} />
        </div>
        <div style={{ flex: 1, minWidth: 0 }}>
          <div className="drive-card__name" title={drive.name || drive.path}>
            {drive.name || drive.path}
          </div>
          <div className="drive-card__path" title={drive.path}>{drive.path}</div>
        </div>
      </div>

      <dl className="drive-card__meta">
        <div>
          <dt>容量</dt>
          <dd>{formatSize(drive.size)}</dd>
        </div>
        {drive.fileSystem && (
          <div>
            <dt>文件系统</dt>
            <dd>{drive.fileSystem}</dd>
          </div>
        )}
      </dl>

      <div className="drive-card__tags">
        <span className="badge">{drive.driveType === "physical" ? "物理盘" : "逻辑盘"}</span>
        {drive.isRemovable && <span className="badge badge--warning">可移动</span>}
      </div>
    </div>
  );
}

function elevationHint(platform) {
  switch (platform) {
    case "darwin":
      return "请在终端中用 sudo 重新启动本程序：sudo /Applications/DataRecovery.app/Contents/MacOS/数据恢复大师";
    case "linux":
      return "请用 sudo 重启本程序，或把当前用户加入 disk 组后重新登录。";
    default:
      return "请退出后以管理员身份重新启动本程序（通过 UAC 确认）。读取磁盘原始数据必须拿到管理员 / root 权限。";
  }
}
