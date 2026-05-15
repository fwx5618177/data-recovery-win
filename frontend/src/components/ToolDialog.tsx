/**
 * ToolDialog — v2.8.18 通用工具操作弹窗。
 *
 * 替代 globalThis.prompt() 的丑陋"wails.localhost 显示"原生弹窗。
 *
 * 提供统一的工具操作界面：
 *   - 标题 + 描述（解释这个工具是干什么的）
 *   - 多种字段类型（文本 / 密码 / 目录选择 / 文件选择）
 *   - 字段提示（hint，给非技术用户解释字段含义）
 *   - 提交时显示 loading
 *   - 成功 / 失败的明确反馈
 *
 * 用一个组件覆盖所有"输入参数 → 调 IPC → 显示结果"工具。
 */

import React, { useState } from "react";
import { IconX, IconFolderOpen } from "../icons";
import { toast } from "../toast";

export type ToolDialogFieldType = "text" | "password" | "directory" | "file" | "number";

export interface ToolDialogField {
  key: string;
  label: string;
  type: ToolDialogFieldType;
  placeholder?: string;
  defaultValue?: string;
  hint?: string;          // 字段下方说明（解释字段含义）
  required?: boolean;
  // 用于 directory/file 类型：选择对话框标题
  pickerTitle?: string;
  // file 类型专用：过滤器显示名（如 "NSRL hash 库"）+ 扩展名模式（如 "*.txt;*.csv"）
  fileFilterName?: string;
  fileFilterExt?: string;
}

export interface ToolDialogProps {
  /** 弹窗标题 */
  title: string;
  /** 工具说明（顶部 banner，解释这个工具用途 + 适用场景） */
  description?: string;
  /** 字段定义 */
  fields: ToolDialogField[];
  /** 提交按钮文案；默认 "执行" */
  submitLabel?: string;
  /** 提交时的处理函数；返回成功消息或 throw 抛错 */
  onSubmit: (values: Record<string, string>) => Promise<string | void>;
  /** 关闭弹窗 */
  onClose: () => void;
  /** Wails app 实例（用于调 SelectDirectory） */
  wailsApp: any;
  /** 完成后的成功 toast 文案前缀（默认 "✅ 已执行"） */
  successPrefix?: string;
}

export function ToolDialog({
  title,
  description,
  fields,
  submitLabel = "执行",
  onSubmit,
  onClose,
  wailsApp,
  successPrefix = "✅",
}: ToolDialogProps) {
  // 初始化字段值
  const [values, setValues] = useState<Record<string, string>>(() => {
    const init: Record<string, string> = {};
    for (const f of fields) {
      init[f.key] = f.defaultValue || "";
    }
    return init;
  });
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const update = (key: string, value: string) => {
    setValues((v) => ({ ...v, [key]: value }));
    if (error) setError(null);
  };

  const pickDirectory = async (key: string, pickerTitle?: string) => {
    try {
      const dir = await wailsApp?.SelectDirectory?.(pickerTitle || "选择目录");
      if (dir) update(key, dir);
    } catch (err: any) {
      toast.error("选目录失败：" + (err?.message || err));
    }
  };

  // v2.8.29: 文件选择支持。之前 type:"file" 只渲染为文本框，用户得手贴绝对路径；
  // NSRL 库等场景文件名很长，复制粘贴出错率高。现在调后端 SelectFile IPC。
  const pickFile = async (
    key: string,
    pickerTitle?: string,
    filterName?: string,
    filterExt?: string,
  ) => {
    try {
      const path = await wailsApp?.SelectFile?.(pickerTitle || "选择文件", filterName || "", filterExt || "");
      if (path) update(key, path);
    } catch (err: any) {
      toast.error("选文件失败：" + (err?.message || err));
    }
  };

  const handleSubmit = async () => {
    // 必填校验
    for (const f of fields) {
      if (f.required !== false && !values[f.key]?.trim()) {
        setError(`请填写 "${f.label}"`);
        return;
      }
    }
    setSubmitting(true);
    setError(null);
    try {
      const result = await onSubmit(values);
      const message = typeof result === "string" && result ? result : `${successPrefix} 操作完成`;
      toast.success({ title: title, description: message, duration: 8000 });
      onClose();
    } catch (err: any) {
      const msg = err?.message || String(err);
      setError(msg);
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="preview-modal" role="dialog" aria-label={title}>
      <div className="preview-modal__inner" style={{ maxWidth: 540, width: "92%" }}>
        <div className="preview-modal__header">
          <div className="preview-modal__title">{title}</div>
          <button
            className="btn btn--ghost btn--sm"
            onClick={onClose}
            aria-label="关闭"
            title="关闭"
            disabled={submitting}
          >
            <IconX size={14} />
          </button>
        </div>

        <div className="preview-modal__body" style={{ display: "block", padding: "16px 20px" }}>
          {description && (
            <div
              className="banner banner--info"
              style={{
                marginBottom: 16,
                padding: "10px 12px",
                background: "var(--accent-soft)",
                borderRadius: 6,
                fontSize: "var(--text-xs)",
                lineHeight: 1.6,
                whiteSpace: "pre-wrap",
              }}
            >
              {description}
            </div>
          )}

          {fields.map((f) => (
            <div key={f.key} className="field" style={{ marginBottom: 14 }}>
              <label className="field__label" style={{ fontSize: "var(--text-xs)", fontWeight: 600 }}>
                {f.label}
                {f.required !== false && <span style={{ color: "var(--danger)", marginLeft: 4 }}>*</span>}
              </label>

              {f.type === "directory" ? (
                <div style={{ display: "flex", gap: 8, marginTop: 4 }}>
                  <input
                    className="input"
                    style={{ flex: 1 }}
                    type="text"
                    value={values[f.key] || ""}
                    onChange={(e) => update(f.key, e.target.value)}
                    placeholder={f.placeholder || "例：D:\\backup"}
                    disabled={submitting}
                  />
                  <button
                    className="btn btn--sm"
                    onClick={() => pickDirectory(f.key, f.pickerTitle || `选择"${f.label}"`)}
                    disabled={submitting}
                    title="选择目录"
                  >
                    <IconFolderOpen size={14} /> 选目录
                  </button>
                </div>
              ) : f.type === "file" ? (
                <div style={{ display: "flex", gap: 8, marginTop: 4 }}>
                  <input
                    className="input"
                    style={{ flex: 1 }}
                    type="text"
                    value={values[f.key] || ""}
                    onChange={(e) => update(f.key, e.target.value)}
                    placeholder={f.placeholder || "点右边「选文件」打开系统文件选择器"}
                    disabled={submitting}
                  />
                  <button
                    className="btn btn--sm"
                    onClick={() => pickFile(f.key, f.pickerTitle || `选择"${f.label}"`, f.fileFilterName, f.fileFilterExt)}
                    disabled={submitting}
                    title="选择文件"
                  >
                    <IconFolderOpen size={14} /> 选文件
                  </button>
                </div>
              ) : (
                <input
                  className="input"
                  style={{ marginTop: 4, width: "100%" }}
                  type={f.type === "password" ? "password" : f.type === "number" ? "number" : "text"}
                  value={values[f.key] || ""}
                  onChange={(e) => update(f.key, e.target.value)}
                  placeholder={f.placeholder || ""}
                  disabled={submitting}
                />
              )}

              {f.hint && (
                <div className="muted" style={{ marginTop: 4, fontSize: "var(--text-xs)", lineHeight: 1.5 }}>
                  {f.hint}
                </div>
              )}
            </div>
          ))}

          {error && (
            <div
              className="banner banner--danger"
              style={{
                marginTop: 8,
                padding: "8px 10px",
                background: "rgba(220,38,38,0.08)",
                color: "var(--danger)",
                borderRadius: 4,
                fontSize: "var(--text-xs)",
                whiteSpace: "pre-wrap",
              }}
            >
              {error}
            </div>
          )}
        </div>

        <div
          className="preview-modal__footer"
          style={{
            display: "flex",
            justifyContent: "flex-end",
            gap: 8,
            padding: "12px 20px",
            boxShadow: "inset 0 1px 0 0 var(--border)",
          }}
        >
          <button className="btn btn--ghost btn--sm" onClick={onClose} disabled={submitting}>
            取消
          </button>
          <button className="btn btn--primary btn--sm" onClick={handleSubmit} disabled={submitting}>
            {submitting ? "执行中..." : submitLabel}
          </button>
        </div>
      </div>
    </div>
  );
}
