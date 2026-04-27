/**
 * 全局 toast 通知系统（v2.8.1）—— 替代散落在代码里的 native `alert()` 调用。
 *
 * 为啥要：
 *   1. native alert() 在 Wails 里渲染成 "wails.localhost 显示" 这种丑爆框，
 *      跟应用的设计语言完全不搭
 *   2. alert 是阻塞的；用户被迫先点确定才能继续操作
 *   3. 多个 alert 排队弹出体验差
 *
 * 用法：
 *   import { toast } from "./toast";
 *   toast.success("操作成功");
 *   toast.error("失败：" + err);
 *   toast.info({ title: "SMART", description: "..." });
 *
 * 设计：单例 + 订阅。`<ToastViewport>` 监听变化渲染队列。
 * 这样模块函数（如 runAsync）也能调 toast，不需要 hook context。
 */

export type ToastLevel = "info" | "success" | "warning" | "error";

export interface ToastInput {
  title?: string;
  description?: string;
  level?: ToastLevel;
  /** 毫秒；0 = 不自动消失（用户手动关）。默认 5000；error 默认 8000 */
  duration?: number;
  /** 可选 action 按钮 */
  action?: { label: string; onClick: () => void };
}

export interface ToastEntry extends Required<Pick<ToastInput, "level">> {
  id: number;
  title?: string;
  description?: string;
  duration: number;
  action?: ToastInput["action"];
  createdAt: number;
}

type Listener = (toasts: ToastEntry[]) => void;
const listeners = new Set<Listener>();
let toasts: ToastEntry[] = [];
let nextId = 1;

function emit() {
  for (const l of listeners) l(toasts);
}

export function showToast(input: ToastInput | string): number {
  const obj: ToastInput = typeof input === "string" ? { description: input } : input;
  const level = obj.level ?? "info";
  const duration = obj.duration ?? (level === "error" ? 8000 : 5000);
  const id = nextId++;
  const entry: ToastEntry = {
    id,
    level,
    title: obj.title,
    description: obj.description,
    duration,
    action: obj.action,
    createdAt: Date.now(),
  };
  // 队列上限：超过 5 个时丢最早的（避免 toast 风暴塞屏）
  toasts = [...toasts, entry].slice(-5);
  emit();
  if (duration > 0) {
    setTimeout(() => dismissToast(id), duration);
  }
  return id;
}

export function dismissToast(id: number) {
  const before = toasts.length;
  toasts = toasts.filter((t) => t.id !== id);
  if (toasts.length !== before) emit();
}

export function dismissAllToasts() {
  if (!toasts.length) return;
  toasts = [];
  emit();
}

export function subscribeToasts(fn: Listener) {
  listeners.add(fn);
  fn(toasts);
  return () => {
    listeners.delete(fn);
  };
}

/**
 * 把 alert() 风格的「单一字符串、含 \n」消息拆成 title + description 显示得更好看。
 * 比如 "SMART: ⚠ 异常\nsmartctl 未安装" → title="SMART: ⚠ 异常", description="smartctl 未安装"。
 */
function splitMessage(msg: string): { title?: string; description?: string } {
  const trimmed = msg.trim();
  const newlineIdx = trimmed.indexOf("\n");
  if (newlineIdx === -1 || newlineIdx > 50) {
    return { description: trimmed };
  }
  return {
    title: trimmed.slice(0, newlineIdx).trim(),
    description: trimmed.slice(newlineIdx + 1).trim() || undefined,
  };
}

function makeShortcut(level: ToastLevel) {
  return (msg: string | ToastInput, opts?: Omit<ToastInput, "level" | "description" | "title">): number => {
    if (typeof msg === "string") {
      const parts = splitMessage(msg);
      return showToast({ level, ...parts, ...opts });
    }
    return showToast({ level, ...msg, ...opts });
  };
}

export const toast = {
  info: makeShortcut("info"),
  success: makeShortcut("success"),
  warning: makeShortcut("warning"),
  error: makeShortcut("error"),
  show: showToast,
  dismiss: dismissToast,
  dismissAll: dismissAllToasts,
};
