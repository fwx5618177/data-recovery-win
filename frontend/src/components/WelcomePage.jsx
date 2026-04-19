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
  onRefreshDrives,
  isLoadingDrives,
  driveLoadError,
  isAdmin,
  platform,
  pendingSession,
  onRestoreSession,
  onDiscardSession,
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
