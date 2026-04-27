/**
 * <ToastViewport> —— 渲染全局 toast 队列。
 * 必须在应用根（App.tsx）挂载一次，订阅 `toast.ts` 单例。
 */

import React, { useEffect, useState } from "react";
import { subscribeToasts, dismissToast, type ToastEntry } from "../toast";
import { IconCheck, IconAlertTriangle, IconInfo, IconXCircle, IconX } from "../icons";

const LEVEL_ICON = {
  info:    IconInfo,
  success: IconCheck,
  warning: IconAlertTriangle,
  error:   IconXCircle,
} as const;

export default function ToastViewport() {
  const [items, setItems] = useState<ToastEntry[]>([]);
  useEffect(() => subscribeToasts(setItems), []);

  if (items.length === 0) return null;

  return (
    <div className="toast-viewport" role="region" aria-label="通知">
      {items.map((t) => {
        const Icon = LEVEL_ICON[t.level];
        return (
          <div
            key={t.id}
            className={`toast toast--${t.level}`}
            role={t.level === "error" || t.level === "warning" ? "alert" : "status"}
            aria-live={t.level === "error" || t.level === "warning" ? "assertive" : "polite"}
          >
            <span className="toast__icon" aria-hidden="true">
              <Icon size={18} />
            </span>
            <div className="toast__body">
              {t.title && <div className="toast__title">{t.title}</div>}
              {t.description && (
                <div className="toast__desc" title={t.description.length > 120 ? t.description : undefined}>
                  {t.description}
                </div>
              )}
            </div>
            <div className="toast__actions">
              {t.action && (
                <button
                  type="button"
                  className="toast__action-btn"
                  onClick={() => {
                    try { t.action!.onClick(); } finally { dismissToast(t.id); }
                  }}
                >
                  {t.action.label}
                </button>
              )}
              <button
                type="button"
                className="toast__close"
                onClick={() => dismissToast(t.id)}
                aria-label="关闭通知"
                title="关闭"
              >
                <IconX size={14} />
              </button>
            </div>
          </div>
        );
      })}
    </div>
  );
}
