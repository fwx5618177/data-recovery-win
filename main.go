// 主进程入口 —— 故意只做两件事：
//  1. 嵌入前端资源（//go:embed 路径必须相对源文件，且只能在 main 包用）
//  2. 把 assets 交给 appcore.Run，让 cmd/data-recovery 包做剩下的所有事
//
// 之前 main.go + app.go 加起来 ~4000 行全在 root。v2.8.47 重构：App 整个
// 搬到 cmd/data-recovery（package appcore），main 退化到这十几行。
package main

import (
	"embed"
	"os"

	appcore "data-recovery/cmd/data-recovery"
)

//go:embed all:frontend/dist
var assets embed.FS

func main() {
	os.Exit(appcore.Run(assets))
}
