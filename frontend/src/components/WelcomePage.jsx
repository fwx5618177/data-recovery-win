import React from "react";
import {
  IconAlertTriangle,
  IconArrowRight,
  IconHardDrive,
  IconInfo,
  IconRefresh,
  IconShield,
  IconUsb,
} from "../icons";
import { formatSize } from "../formatters";

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
  shadows,
  onScanShadow,
}) {
  const needsElevation = !isAdmin;

  return (
    <div className="page">
      <div className="page__header">
        <div className="page__title">先选择要恢复的源盘</div>
        <div className="page__subtitle">
          建议把被重置/格式化的磁盘通过硬盘盒外接过来。扫描过程只读，不写入源盘。
        </div>
      </div>

      <div className="page__body flex-col gap-3">
        <div className="banner banner--warning">
          <IconAlertTriangle size={18} className="banner__icon" />
          <div className="banner__content">
            <div className="banner__title">重要数据请优先用成熟的行业工具</div>
            <div className="banner__text">
              这个工具目前支持 <b>NTFS</b> 的 MFT 解析 + 全盘签名雕刻，
              对 <span className="mono">exFAT/FAT32</span> / Volume Shadow Copy / 碎片重组 / BitLocker / RAID 等场景
              <b>不支持或刚起步</b>。
              <br />
              如果你是被盗电脑 / 重要数据恢复，建议先用 <b>PhotoRec</b>（免费）、
              <b>DMDE Free</b>（免费）、<b>R-Studio</b>（付费试用）跑一遍，
              再用本工具做交叉验证。这些工具经过 10+ 年真实案例打磨，可靠度是本工具没法比的。
            </div>
          </div>
        </div>

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
                直接恢复可以跳过重新扫描。
              </div>
            </div>
            <div className="banner__actions">
              <button className="btn btn--sm" onClick={onDiscardSession}>丢弃</button>
              <button className="btn btn--primary btn--sm" onClick={onRestoreSession}>
                继续上次扫描结果
              </button>
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
                  key={s.ID || s.DevicePath}
                  className="card"
                  style={{ padding: "8px 12px", display: "flex", alignItems: "center", gap: 12 }}
                >
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div className="mono" style={{ fontSize: 12, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                      {s.DevicePath}
                    </div>
                    <div className="muted" style={{ fontSize: 11 }}>
                      {s.CreatedAt ? new Date(s.CreatedAt).toLocaleString() : "创建时间未知"}
                      {s.OriginalVolume ? ` · 来源 ${s.OriginalVolume}` : ""}
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
            开始扫描 <IconArrowRight size={16} />
          </button>
        </div>
      </div>
    </div>
  );
}

function DriveCard({ drive, selected, onSelect }) {
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
          <div className="drive-card__path">{drive.path}</div>
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
