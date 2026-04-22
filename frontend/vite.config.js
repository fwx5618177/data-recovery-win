import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// base: "./"           相对路径，WebView2 / file:// 下都能解析
// inlineDynamicImports 把 dynamic import 全内联到主 bundle，
//                      避免 WebView2 加载多 chunk 时失败 → 白屏
export default defineConfig({
  plugins: [react()],
  base: "./",
  build: {
    outDir: "dist",
    rollupOptions: {
      output: {
        inlineDynamicImports: true,
      },
    },
  },
});
