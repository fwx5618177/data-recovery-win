# OCR 内嵌资源（v2.8.4 起）

数据恢复大师"开箱即用 OCR" 的本地资源。

## 内容

```
internal/ocr/assets/
├── windows-amd64/
│   ├── tesseract.exe                 # UB Mannheim Windows 便携版
│   ├── leptonica-1.85.0.dll          # tesseract 依赖
│   └── ...                           # 其它 DLL（libpng / libjpeg / zlib 等）
├── darwin-arm64/
│   └── tesseract                     # Homebrew bottle (Apple Silicon)
├── darwin-amd64/
│   └── tesseract                     # Homebrew bottle (Intel)
├── linux-amd64/
│   └── tesseract                     # 静态构建（musl / Alpine）
└── tessdata/
    ├── eng.traineddata               # tessdata_fast/eng（~4 MB）
    └── chi_sim.traineddata           # tessdata_fast/chi_sim（~15 MB）
```

## 这些文件**不入 git**（见 `.gitignore`）

约 70 MB 二进制 + traineddata，git 仓库不放。开发者本地跑 `make tesseract-bundle`
后由脚本从官方源拉。CI release 流程也是先 `make tesseract-bundle && wails build`
保证发出的二进制完全自包含。

## 来源（v2.8.4，全部 Apache 2.0 许可，可重分发）

- **Windows 二进制**：<https://github.com/UB-Mannheim/tesseract/releases>（UB Mannheim 维护的官方 Windows 构建）
- **Linux 静态构建**：<https://github.com/tesseract-ocr/tesseract/releases> 官方 release，否则源码静态编译
- **macOS 二进制**：本地 Homebrew bottle 抽取 `brew --prefix tesseract`
- **traineddata（fast 模型）**：<https://github.com/tesseract-ocr/tessdata_fast>

## 不在仓库里的话怎么 build？

`go build` 不会因为缺这些文件而失败 —— `.placeholder` 占位文件让 `//go:embed` 能编译。
但运行时 `runtime.go` 检测到占位（文件大小 < 阈值）会拒绝跑 OCR，显示
"未打包 OCR 引擎，请运行 `make tesseract-bundle`"。

发布构建必须先 `make tesseract-bundle`。
