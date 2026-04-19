/**
 * 所有 UI 用到的图标统一放在这里，使用 inline SVG 避免引入 icon 依赖。
 * 接口：每个组件接收 size（默认 16）、className 与 其他 SVG 属性。
 * 颜色通过 currentColor 继承，方便在按钮/徽章里统一染色。
 */

function I(props, children) {
  const { size = 16, className = "", ...rest } = props;
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={1.75}
      strokeLinecap="round"
      strokeLinejoin="round"
      className={className}
      {...rest}
    >
      {children}
    </svg>
  );
}

export const IconShield = (p) =>
  I(
    p,
    <>
      <path d="M12 3l8 3v5c0 4.5-3.5 8.5-8 10-4.5-1.5-8-5.5-8-10V6l8-3z" />
      <path d="M9 12l2 2 4-4" />
    </>,
  );

export const IconHardDrive = (p) =>
  I(
    p,
    <>
      <rect x="3" y="5" width="18" height="14" rx="2" />
      <line x1="3" y1="12" x2="21" y2="12" />
      <circle cx="7" cy="16" r="1" />
      <circle cx="11" cy="16" r="1" />
    </>,
  );

export const IconUsb = (p) =>
  I(
    p,
    <>
      <circle cx="6" cy="19" r="2" />
      <path d="M6 17V9" />
      <path d="M6 9l4-5h8l-4 5" />
      <path d="M14 9v4l-4 4" />
    </>,
  );

export const IconArrowRight = (p) =>
  I(
    p,
    <>
      <line x1="5" y1="12" x2="19" y2="12" />
      <polyline points="13 6 19 12 13 18" />
    </>,
  );

export const IconArrowLeft = (p) =>
  I(
    p,
    <>
      <line x1="19" y1="12" x2="5" y2="12" />
      <polyline points="11 6 5 12 11 18" />
    </>,
  );

export const IconSearch = (p) =>
  I(
    p,
    <>
      <circle cx="11" cy="11" r="7" />
      <line x1="21" y1="21" x2="16.65" y2="16.65" />
    </>,
  );

export const IconCheck = (p) =>
  I(p, <polyline points="20 6 9 17 4 12" />);

export const IconX = (p) =>
  I(p, <><line x1="18" y1="6" x2="6" y2="18" /><line x1="6" y1="6" x2="18" y2="18" /></>);

export const IconAlertTriangle = (p) =>
  I(
    p,
    <>
      <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" />
      <line x1="12" y1="9" x2="12" y2="13" />
      <line x1="12" y1="17" x2="12.01" y2="17" />
    </>,
  );

export const IconInfo = (p) =>
  I(
    p,
    <>
      <circle cx="12" cy="12" r="9" />
      <line x1="12" y1="8" x2="12" y2="12" />
      <line x1="12" y1="16" x2="12.01" y2="16" />
    </>,
  );

export const IconCheckCircle = (p) =>
  I(
    p,
    <>
      <circle cx="12" cy="12" r="9" />
      <polyline points="8 12 11 15 16 9" />
    </>,
  );

export const IconRefresh = (p) =>
  I(
    p,
    <>
      <polyline points="21 3 21 9 15 9" />
      <polyline points="3 21 3 15 9 15" />
      <path d="M3 9a9 9 0 0 1 15-4l3 3" />
      <path d="M21 15a9 9 0 0 1-15 4l-3-3" />
    </>,
  );

export const IconStop = (p) =>
  I(
    p,
    <rect x="6" y="6" width="12" height="12" rx="2" />,
  );

export const IconPlay = (p) =>
  I(
    p,
    <polygon points="6 4 20 12 6 20 6 4" />,
  );

export const IconDownload = (p) =>
  I(
    p,
    <>
      <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
      <polyline points="7 10 12 15 17 10" />
      <line x1="12" y1="15" x2="12" y2="3" />
    </>,
  );

export const IconFolder = (p) =>
  I(
    p,
    <path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z" />,
  );

export const IconFolderOpen = (p) =>
  I(
    p,
    <>
      <path d="M4 20h15a2 2 0 0 0 1.94-1.5L23 10H6l-2 10z" />
      <path d="M2 19V6a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v3" />
    </>,
  );

export const IconImage = (p) =>
  I(
    p,
    <>
      <rect x="3" y="3" width="18" height="18" rx="2" />
      <circle cx="9" cy="9" r="2" />
      <polyline points="21 15 16 10 5 21" />
    </>,
  );

export const IconFileText = (p) =>
  I(
    p,
    <>
      <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
      <polyline points="14 2 14 8 20 8" />
      <line x1="8" y1="13" x2="16" y2="13" />
      <line x1="8" y1="17" x2="13" y2="17" />
    </>,
  );

export const IconFilm = (p) =>
  I(
    p,
    <>
      <rect x="3" y="4" width="18" height="16" rx="2" />
      <line x1="7" y1="4" x2="7" y2="20" />
      <line x1="17" y1="4" x2="17" y2="20" />
      <line x1="3" y1="12" x2="7" y2="12" />
      <line x1="17" y1="12" x2="21" y2="12" />
      <line x1="3" y1="8" x2="7" y2="8" />
      <line x1="17" y1="8" x2="21" y2="8" />
      <line x1="3" y1="16" x2="7" y2="16" />
      <line x1="17" y1="16" x2="21" y2="16" />
    </>,
  );

export const IconMusic = (p) =>
  I(
    p,
    <>
      <path d="M9 18V5l12-2v13" />
      <circle cx="6" cy="18" r="3" />
      <circle cx="18" cy="16" r="3" />
    </>,
  );

export const IconArchive = (p) =>
  I(
    p,
    <>
      <rect x="3" y="4" width="18" height="5" rx="1" />
      <path d="M5 9v10a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V9" />
      <line x1="10" y1="13" x2="14" y2="13" />
    </>,
  );

export const IconDatabase = (p) =>
  I(
    p,
    <>
      <ellipse cx="12" cy="5" rx="9" ry="3" />
      <path d="M3 5v14a9 3 0 0 0 18 0V5" />
      <path d="M3 12a9 3 0 0 0 18 0" />
    </>,
  );

export const IconFile = (p) =>
  I(
    p,
    <>
      <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
      <polyline points="14 2 14 8 20 8" />
    </>,
  );

const categoryIcons = {
  image: IconImage,
  document: IconFileText,
  video: IconFilm,
  audio: IconMusic,
  archive: IconArchive,
  database: IconDatabase,
};

export function IconForCategory({ category, size = 16, className = "" }) {
  const Cmp = categoryIcons[category] || IconFile;
  return <Cmp size={size} className={className} />;
}
