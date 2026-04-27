import React from "react";
import { confidenceTier } from "../recovery-helpers";
import { IconCheck, IconAlertTriangle } from "../icons";

/**
 * ConfidenceBadge —— 4 档可视徽章，替代 FileTable 之前那条"87%"百分比条。
 *
 * 设计动机：R-Studio 给用户看的是 0-1 浮点数，用户读不懂。苹果级产品会给
 * "高可靠 ✓"这种一眼能做判断的标签。徽章色 / 文字由 confidenceTier 决定。
 *
 *   size "sm" → 表格行内紧凑显示
 *   size "md" → 卡片 / 预览面板显示
 */
export default function ConfidenceBadge({ file, size = "sm" }) {
  const tier = confidenceTier(file);
  const padding = size === "md" ? "3px 10px" : "1px 8px";
  const fontSize = size === "md" ? 12 : 11;
  return (
    <span
      className={`confidence-badge confidence-badge--${tier.key}`}
      style={{
        display: "inline-flex",
        alignItems: "center",
        gap: 4,
        padding,
        fontSize,
        fontWeight: 600,
        borderRadius: 999,
        color: "#fff",
        background: tier.color,
        whiteSpace: "nowrap",
        lineHeight: 1.4,
      }}
      title={`置信度 ${Math.round(Number(file?.confidence || 0) * 100)}% — ${tier.label}`}
    >
      {tier.key === "high" ? <IconCheck size={size === "md" ? 13 : 11} /> : null}
      {tier.key === "low"  ? <IconAlertTriangle size={size === "md" ? 13 : 11} /> : null}
      {tier.label}
    </span>
  );
}
