// 主题切换：system / dark / light / auto-time（v2.8 新增）。
//
// 写入 <html data-theme="..."> 让 style.css 里的 [data-theme="light|dark"] 选择器生效。
// 不带 data-theme 时跟随 prefers-color-scheme。
//
// **auto-time 模式**：根据本机时间在 light / dark 之间切换。
//   - 06:00–18:00 → light（白天用浅色，对比度高、视觉清醒）
//   - 18:00–06:00 → dark（夜里用深色，护眼）
// 实现策略：
//   1. setTheme("auto-time") 立刻按当前时间应用 light/dark
//   2. 每 60s 重新评估一次（粒度足够 —— 用户不会在意 17:59→18:00 慢 30s 切换）
//   3. tick 重置：切到非 auto-time 时清掉 timer

export type Theme = "system" | "dark" | "light" | "auto-time";

const STORAGE_KEY = "data-recovery.theme";
type ThemeListener = (theme: Theme) => void;
const listeners = new Set<ThemeListener>();
let current: Theme = loadInitial();
let autoTimer: ReturnType<typeof setInterval> | null = null;

applyToHTML(current);
if (current === "auto-time") startAutoTimer();

function loadInitial(): Theme {
  try {
    const saved = globalThis.localStorage?.getItem(STORAGE_KEY);
    if (saved === "dark" || saved === "light" || saved === "system" || saved === "auto-time") {
      return saved;
    }
  } catch {/* no-op */}
  return "system";
}

// 06:00–18:00 → light，其余时段 dark
function timeBasedResolution(): "light" | "dark" {
  const hour = new Date().getHours();
  return hour >= 6 && hour < 18 ? "light" : "dark";
}

function applyToHTML(theme: Theme) {
  const html = globalThis.document?.documentElement;
  if (!html) return;
  if (theme === "system") {
    html.removeAttribute("data-theme");
  } else if (theme === "auto-time") {
    html.setAttribute("data-theme", timeBasedResolution());
  } else {
    html.setAttribute("data-theme", theme);
  }
}

function startAutoTimer() {
  stopAutoTimer();
  autoTimer = setInterval(() => {
    if (current !== "auto-time") return;
    applyToHTML("auto-time");
  }, 60_000);
}

function stopAutoTimer() {
  if (autoTimer != null) {
    clearInterval(autoTimer);
    autoTimer = null;
  }
}

export function getTheme(): Theme {
  return current;
}

export function setTheme(next: Theme) {
  if (next !== "dark" && next !== "light" && next !== "system" && next !== "auto-time") return;
  current = next;
  applyToHTML(current);
  if (next === "auto-time") {
    startAutoTimer();
  } else {
    stopAutoTimer();
  }
  try { globalThis.localStorage?.setItem(STORAGE_KEY, next); } catch {/* no-op */}
  listeners.forEach((fn) => { try { fn(current); } catch {/* no-op */} });
}

export function onThemeChange(fn: ThemeListener): () => void {
  listeners.add(fn);
  return () => {
    listeners.delete(fn);
  };
}

export const AVAILABLE_THEMES: Theme[] = ["system", "auto-time", "dark", "light"];
