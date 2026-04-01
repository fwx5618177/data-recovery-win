import React from "react";
import { formatSize } from "../formatters";
import { DEFAULT_SCAN_PLAN, getDriveLabel } from "../recovery-helpers";
import "./WelcomePage.css";

function getDriveTags(drive) {
  const tags = [];

  if (drive?.driveType === "physical") {
    tags.push("物理磁盘");
  }

  if (drive?.fileSystem) {
    tags.push(drive.fileSystem);
  }

  if (drive?.isRemovable) {
    tags.push("可移动");
  }

  return tags;
}

export default function WelcomePage({
  drives,
  driveLoadError,
  isLoadingDrives,
  selectedDrive,
  onSelectDrive,
  onStartScan,
  onRefreshDrives,
}) {
  const canStart = Boolean(selectedDrive);

  return (
    <div className="welcome-page">
      <section className="welcome-section surface">
        <div className="welcome-section__header">
          <div>
            <h3>1. 选择丢失数据原来所在的源盘</h3>
            <p>
              这里选的是原来存放数据的磁盘。恢复目录会在下一步单独选择到另一块磁盘或
              U 盘。
            </p>
          </div>
          <button
            className="btn btn-secondary"
            onClick={onRefreshDrives}
            type="button"
          >
            {isLoadingDrives ? "正在识别…" : "重新识别磁盘"}
          </button>
        </div>

        {driveLoadError ? (
          <div className="empty-state">
            <strong>读取磁盘列表失败</strong>
            <span>{driveLoadError}</span>
          </div>
        ) : drives.length === 0 ? (
          <div className="empty-state">
            <strong>未识别到可扫描磁盘</strong>
            <span>请确认设备已连接，并已经允许管理员权限后再重新识别。</span>
          </div>
        ) : (
          <div className="drive-grid">
            {drives.map((drive) => {
              const isSelected = selectedDrive?.path === drive.path;

              return (
                <button
                  key={drive.path}
                  className={`drive-card${isSelected ? " drive-card--selected" : ""}`}
                  onClick={() => onSelectDrive(drive)}
                  type="button"
                >
                  <div className="drive-card__top">
                    <div>
                      <div className="drive-card__title">
                        {getDriveLabel(drive)}
                      </div>
                      <div className="drive-card__path">{drive.path}</div>
                    </div>
                    <span className="drive-card__capacity">
                      {drive.sizeHuman || formatSize(drive.size)}
                    </span>
                  </div>

                  <div className="drive-card__tags">
                    {getDriveTags(drive).map((tag) => (
                      <span key={tag} className="drive-card__tag">
                        {tag}
                      </span>
                    ))}
                  </div>

                  <div className="drive-card__footer">
                    {isSelected ? "已选为源盘" : "点击设为源盘"}
                  </div>
                </button>
              );
            })}
          </div>
        )}
      </section>

      <section className="welcome-actions surface">
        <div className="welcome-actions__summary">
          <span className="welcome-actions__label">已选源盘</span>
          <div className="welcome-actions__value">
            {selectedDrive ? getDriveLabel(selectedDrive) : "请先选择磁盘"}
          </div>
          <span className="welcome-actions__hint">
            {selectedDrive
              ? `${selectedDrive.sizeHuman || formatSize(selectedDrive.size)} · 下一步会扫描这个源盘，恢复目录会单独选到其他磁盘`
              : "先找到丢失数据原来所在的源盘，再开始扫描"}
          </span>
        </div>

        <button
          className="btn btn-primary btn-lg"
          disabled={!canStart}
          onClick={onStartScan}
          type="button"
        >
          开始扫描源盘
        </button>
      </section>
    </div>
  );
}
