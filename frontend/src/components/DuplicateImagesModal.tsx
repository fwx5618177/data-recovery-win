/**
 * DuplicateImagesModal — v2.8.17
 *
 * 展示"图片查重"工具的结果：相似图片分组列表。每组显示文件路径，提供：
 *   - 删除：移除一个副本（保留其他）
 *   - 在文件管理器中打开：定位到该文件
 *
 * Issue 8 修复：之前查重只 toast "找到 N 组相似图片"，没有展示界面，用户无法处理。
 *
 * 注意：暂不显示缩略图（Wails webview 直接读 file:// 受 CSP 限制；缩略图功能留 v2.8.18）。
 */

import React, { useState } from "react";
import { IconX, IconTrash, IconFolderOpen } from "../icons";
import { toast } from "../toast";

interface DuplicateImagesModalProps {
  groups: string[][]; // 每组 = 一组相似图片的绝对路径
  wailsApp: any;
  onClose: () => void;
}

export function DuplicateImagesModal({ groups, wailsApp, onClose }: DuplicateImagesModalProps) {
  // 标记每个文件路径的状态：'live' / 'deleted'
  const [deletedSet, setDeletedSet] = useState<Set<string>>(new Set());

  if (!groups || groups.length === 0) {
    return (
      <div className="preview-modal" role="dialog" aria-label="重复图片">
        <div className="preview-modal__inner" style={{ maxWidth: 480, width: "92%" }}>
          <div className="preview-modal__header">
            <div className="preview-modal__title">查找重复图片</div>
            <button className="btn btn--ghost btn--sm" onClick={onClose} aria-label="关闭">
              <IconX size={14} />
            </button>
          </div>
          <div className="preview-modal__body" style={{ padding: 24, textAlign: "center" }}>
            <p className="muted">未找到相似图片组。</p>
          </div>
        </div>
      </div>
    );
  }

  const handleDelete = async (path: string) => {
    if (!confirm(`确定要删除这个文件吗？\n\n${path}\n\n此操作无法撤销。`)) return;
    try {
      await wailsApp?.DeleteFile?.(path);
      setDeletedSet((prev) => new Set(prev).add(path));
      toast.success({ title: "已删除", description: path });
    } catch (err: any) {
      toast.error("删除失败：" + (err?.message || err));
    }
  };

  const handleShow = async (path: string) => {
    try {
      await wailsApp?.ShowInFolder?.(path);
    } catch (err: any) {
      toast.error("打开文件管理器失败：" + (err?.message || err));
    }
  };

  const totalFiles = groups.reduce((sum, g) => sum + g.length, 0);
  const deletedCount = deletedSet.size;

  return (
    <div className="preview-modal" role="dialog" aria-label="重复图片">
      <div className="preview-modal__inner" style={{ maxWidth: 820, width: "92%", maxHeight: "85vh" }}>
        <div className="preview-modal__header">
          <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <div className="preview-modal__title">查找重复图片</div>
            <span className="muted" style={{ fontSize: "var(--text-xs)" }}>
              · {groups.length} 组 · 共 {totalFiles} 个文件 · 已删除 {deletedCount}
            </span>
          </div>
          <button className="btn btn--ghost btn--sm" onClick={onClose} aria-label="关闭" title="关闭">
            <IconX size={14} />
          </button>
        </div>

        <div className="preview-modal__body" style={{
          display: "block", padding: "12px 20px", overflowY: "auto",
          maxHeight: "calc(85vh - 120px)",
        }}>
          <p className="muted" style={{ fontSize: "var(--text-xs)", marginBottom: 14 }}>
            以下是基于 perceptual hash 找出的视觉相似图片。每组通常只需保留 1 张，其它可删除。
            <b>删除前请先确认</b> —— 此操作无法撤销，建议先在文件管理器里看实际内容。
          </p>

          {groups.map((group, gi) => (
            <DuplicateGroupCard
              key={gi}
              groupIndex={gi}
              paths={group}
              deletedSet={deletedSet}
              onDelete={handleDelete}
              onShow={handleShow}
            />
          ))}
        </div>

        <div className="preview-modal__footer" style={{
          display: "flex", justifyContent: "flex-end", gap: 8, padding: "12px 20px",
          borderTop: "1px solid var(--border)",
        }}>
          <button className="btn btn--ghost btn--sm" onClick={onClose}>关闭</button>
        </div>
      </div>
    </div>
  );
}

interface DuplicateGroupCardProps {
  groupIndex: number;
  paths: string[];
  deletedSet: Set<string>;
  onDelete: (path: string) => void;
  onShow: (path: string) => void;
}

function DuplicateGroupCard({ groupIndex, paths, deletedSet, onDelete, onShow }: DuplicateGroupCardProps) {
  const aliveCount = paths.filter((p) => !deletedSet.has(p)).length;

  return (
    <div style={{
      border: "1px solid var(--border)",
      borderRadius: 8,
      padding: 12,
      marginBottom: 12,
      background: "var(--bg-card)",
    }}>
      <div style={{
        display: "flex", justifyContent: "space-between", alignItems: "center",
        marginBottom: 8, fontWeight: 600, fontSize: "var(--text-sm)",
      }}>
        <span>第 {groupIndex + 1} 组（{paths.length} 张相似）</span>
        <span className="muted" style={{ fontSize: "var(--text-xs)", fontWeight: "normal" }}>
          {aliveCount} 张未删除
        </span>
      </div>
      <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
        {paths.map((p, i) => {
          const isDeleted = deletedSet.has(p);
          return (
            <div
              key={p}
              style={{
                display: "flex", alignItems: "center", gap: 8,
                padding: "6px 8px",
                background: isDeleted ? "rgba(220,38,38,0.05)" : "transparent",
                borderRadius: 4,
                opacity: isDeleted ? 0.5 : 1,
              }}
            >
              <span className="muted" style={{ fontSize: "var(--text-xs)", minWidth: 24 }}>
                {i + 1}.
              </span>
              <span
                style={{
                  flex: 1, fontFamily: "monospace", fontSize: "var(--text-xs)",
                  textDecoration: isDeleted ? "line-through" : "none",
                  overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap",
                }}
                title={p}
              >
                {p}
              </span>
              {!isDeleted && (
                <>
                  <button
                    className="btn btn--ghost btn--sm"
                    onClick={() => onShow(p)}
                    title="在文件管理器中显示"
                    style={{ padding: "2px 6px" }}
                  >
                    <IconFolderOpen size={12} />
                  </button>
                  <button
                    className="btn btn--ghost btn--sm"
                    onClick={() => onDelete(p)}
                    title="删除此文件"
                    style={{ padding: "2px 6px", color: "var(--danger)" }}
                  >
                    <IconTrash size={12} />
                  </button>
                </>
              )}
              {isDeleted && (
                <span className="muted" style={{ fontSize: "var(--text-xs)" }}>已删除</span>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
