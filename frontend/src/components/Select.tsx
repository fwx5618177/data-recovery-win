/**
 * <Select> —— Material UI 风格的下拉选择器（v2.8.1）。
 *
 * 设计参考 MUI Filled / Outlined Select，但只用项目自己的 design tokens，
 * 无依赖。比原生 <select> 优势：
 *   - 跨平台外观一致（macOS 原生 select 灰扑扑、Windows 原生 select 也很丑）
 *   - 浮层（popover）可放图标 / 复杂内容（每个选项可有 icon + 副标题）
 *   - 选中态有明确视觉反馈（左侧 accent 条 + 右侧勾）
 *   - 键盘可达（Esc / 上下 / Enter）
 *
 * 不做的：
 *   - 不做异步搜索（这种场景才有必要上 Combobox）
 *   - 不做多选（项目里没场景）
 *   - 不做 Portal —— 当前用法都是顶栏 / 表单内，简单 absolute 够用
 */

import React, { useEffect, useRef, useState } from "react";
import { IconChevronDown, IconCheck } from "../icons";

export interface SelectOption {
  value: string;
  label: React.ReactNode;
  /** 可选：左侧 emoji / 小图标 */
  icon?: React.ReactNode;
  /** 可选：第二行副标题文字 */
  hint?: string;
  disabled?: boolean;
}

export interface SelectProps {
  value: string;
  options: SelectOption[];
  onChange: (value: string) => void;
  /** 触发器宽度。默认 auto；传数字按 px，传字符串原样 */
  width?: number | string;
  /** 触发器尺寸。sm = 28px / md = 36px（默认）/ lg = 44px */
  size?: "sm" | "md" | "lg";
  /** 触发器视觉变体。filled = 有底色（默认），ghost = 透明（用于顶栏） */
  variant?: "filled" | "ghost";
  title?: string;
  ariaLabel?: string;
  /** 浮层在触发器上方还是下方。默认 auto（看屏幕剩余空间） */
  placement?: "auto" | "top" | "bottom";
}

export default function Select({
  value,
  options,
  onChange,
  width,
  size = "md",
  variant = "filled",
  title,
  ariaLabel,
  placement = "auto",
}: SelectProps) {
  const [open, setOpen] = useState(false);
  const [highlightIdx, setHighlightIdx] = useState<number>(() =>
    Math.max(0, options.findIndex((o) => o.value === value)),
  );
  const [menuPlacement, setMenuPlacement] = useState<"top" | "bottom">("bottom");
  // 横向对齐：触发器靠近视口右侧时 menu 改右对齐，避免菜单（min-width 260px）越过右边界被裁
  const [hAlign, setHAlign] = useState<"left" | "right">("left");
  const triggerRef = useRef<HTMLButtonElement | null>(null);
  const menuRef = useRef<HTMLDivElement | null>(null);

  const selected = options.find((o) => o.value === value) ?? options[0];

  // 打开时：滚动到 highlight，并按 placement 计算上下 / 左右
  useEffect(() => {
    if (!open) return;
    if (placement !== "auto") {
      setMenuPlacement(placement);
    } else if (triggerRef.current) {
      const rect = triggerRef.current.getBoundingClientRect();
      const spaceBelow = window.innerHeight - rect.bottom;
      const spaceAbove = rect.top;
      // 估算菜单高度：每项 36 + padding 8
      const estHeight = Math.min(options.length * 36 + 8, 280);
      setMenuPlacement(spaceBelow < estHeight && spaceAbove > spaceBelow ? "top" : "bottom");
    }
    // 横向：触发器右侧距视口边 < 260px（菜单的 min-width）→ 改右对齐
    if (triggerRef.current) {
      const rect = triggerRef.current.getBoundingClientRect();
      const MENU_MIN_WIDTH = 260;
      const spaceRight = window.innerWidth - rect.left;
      setHAlign(spaceRight < MENU_MIN_WIDTH ? "right" : "left");
    }
    // 重置高亮到当前选中项
    const idx = options.findIndex((o) => o.value === value);
    setHighlightIdx(idx === -1 ? 0 : idx);
  }, [open, value, options, placement]);

  // 点击外部关闭
  useEffect(() => {
    if (!open) return;
    function onDocMouseDown(e: MouseEvent) {
      const t = e.target as Node;
      if (
        triggerRef.current && !triggerRef.current.contains(t) &&
        menuRef.current && !menuRef.current.contains(t)
      ) {
        setOpen(false);
      }
    }
    function onKey(e: KeyboardEvent) {
      if (e.key === "Escape") {
        setOpen(false);
        triggerRef.current?.focus();
      }
    }
    document.addEventListener("mousedown", onDocMouseDown);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onDocMouseDown);
      document.removeEventListener("keydown", onKey);
    };
  }, [open]);

  function commit(v: string) {
    onChange(v);
    setOpen(false);
    triggerRef.current?.focus();
  }

  function onTriggerKey(e: React.KeyboardEvent) {
    if (e.key === "ArrowDown" || e.key === "Enter" || e.key === " ") {
      e.preventDefault();
      setOpen(true);
    }
  }

  function onMenuKey(e: React.KeyboardEvent) {
    if (e.key === "ArrowDown") {
      e.preventDefault();
      setHighlightIdx((i) => {
        for (let n = 1; n <= options.length; n++) {
          const next = (i + n) % options.length;
          if (!options[next].disabled) return next;
        }
        return i;
      });
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      setHighlightIdx((i) => {
        for (let n = 1; n <= options.length; n++) {
          const next = (i - n + options.length) % options.length;
          if (!options[next].disabled) return next;
        }
        return i;
      });
    } else if (e.key === "Enter") {
      e.preventDefault();
      const opt = options[highlightIdx];
      if (opt && !opt.disabled) commit(opt.value);
    } else if (e.key === "Tab") {
      setOpen(false);
    }
  }

  return (
    <div className={`select-root select-root--${size}`} style={width != null ? { width } : undefined}>
      <button
        ref={triggerRef}
        type="button"
        className={`select-trigger select-trigger--${variant} select-trigger--${size} ${open ? "select-trigger--open" : ""}`}
        onClick={() => setOpen((o) => !o)}
        onKeyDown={onTriggerKey}
        title={title}
        aria-label={ariaLabel || title}
        aria-haspopup="listbox"
        aria-expanded={open}
      >
        {selected?.icon && <span className="select-trigger__icon">{selected.icon}</span>}
        <span className="select-trigger__label">{selected?.label}</span>
        <span className={`select-trigger__chevron ${open ? "is-open" : ""}`}>
          <IconChevronDown size={14} />
        </span>
      </button>

      {open && (
        <div
          ref={(el) => {
            menuRef.current = el;
            if (el) el.focus();
          }}
          className={`select-menu select-menu--${menuPlacement} ${hAlign === "right" ? "select-menu--align-right" : ""}`}
          role="listbox"
          tabIndex={-1}
          onKeyDown={onMenuKey}
        >
          {options.map((opt, i) => {
            const isSelected = opt.value === value;
            const isHighlighted = i === highlightIdx;
            // hint 单行 ellipsis；超长用 title 兜底
            const titleText = typeof opt.label === "string"
              ? (opt.hint ? `${opt.label} — ${opt.hint}` : opt.label)
              : opt.hint;
            return (
              <button
                key={opt.value}
                type="button"
                role="option"
                aria-selected={isSelected}
                disabled={opt.disabled}
                title={titleText}
                className={`select-item ${isSelected ? "is-selected" : ""} ${isHighlighted ? "is-highlighted" : ""}`}
                onMouseEnter={() => setHighlightIdx(i)}
                onClick={() => !opt.disabled && commit(opt.value)}
              >
                {opt.icon && <span className="select-item__icon">{opt.icon}</span>}
                <span className="select-item__body">
                  <span className="select-item__label">{opt.label}</span>
                  {opt.hint && <span className="select-item__hint">{opt.hint}</span>}
                </span>
                {isSelected && (
                  <span className="select-item__check">
                    <IconCheck size={14} />
                  </span>
                )}
              </button>
            );
          })}
        </div>
      )}
    </div>
  );
}
