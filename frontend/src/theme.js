// 主题切换：dark / light / system（默认 system）。
// 写入 <html data-theme="..."> 让 style.css 里的 [data-theme="light"] 选择器生效。
// 不带 data-theme 时跟随 prefers-color-scheme。

const STORAGE_KEY = "data-recovery.theme";
const listeners = new Set();
let current = loadInitial();
applyToHTML(current);

function loadInitial() {
  try {
    const saved = globalThis.localStorage?.getItem(STORAGE_KEY);
    if (saved === "dark" || saved === "light" || saved === "system") return saved;
  } catch {/* no-op */}
  return "system";
}

function applyToHTML(theme) {
  const html = globalThis.document?.documentElement;
  if (!html) return;
  if (theme === "system") {
    html.removeAttribute("data-theme");
  } else {
    html.setAttribute("data-theme", theme);
  }
}

export function getTheme() {
  return current;
}

export function setTheme(next) {
  if (next !== "dark" && next !== "light" && next !== "system") return;
  current = next;
  applyToHTML(current);
  try { globalThis.localStorage?.setItem(STORAGE_KEY, next); } catch {/* no-op */}
  listeners.forEach((fn) => { try { fn(current); } catch {/* no-op */} });
}

export function onThemeChange(fn) {
  listeners.add(fn);
  return () => listeners.delete(fn);
}

export const AVAILABLE_THEMES = ["system", "dark", "light"];
