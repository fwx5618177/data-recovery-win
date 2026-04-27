.PHONY: dev dev-elevated check-perms build build-windows build-windows-arm64 build-darwin build-darwin-universal \
        build-linux build-linux-arm64 build-all test lint clean deps install-wails check-wails \
        verify-platforms drift-check drift-check-strict

# Go 代理设置（解决国内/网络不稳定环境下载依赖超时问题）
# 可通过环境变量覆盖，例如: GOPROXY=https://proxy.golang.org,direct make deps
export GOPROXY ?= https://goproxy.cn,https://goproxy.io,direct
export GONOSUMDB ?= *
export GOFLAGS ?= -mod=mod

# 将 GOPATH/bin 加入 PATH，确保 wails 等 Go 安装的工具可被找到
GOPATH_BIN := $(shell go env GOPATH)/bin
WAILS := $(GOPATH_BIN)/wails

# 安装 Wails CLI
install-wails:
	@echo "📦 安装 Wails CLI..."
	go install github.com/wailsapp/wails/v2/cmd/wails@latest
	@echo "✅ Wails CLI 已安装到 $(WAILS)"

# 检查 wails 是否可用
check-wails:
	@test -x "$(WAILS)" || { \
		echo "❌ 未找到 wails 命令 ($(WAILS))"; \
		echo "   请先运行: make install-wails"; \
		exit 1; \
	}

# 开发模式（本地平台）
#
# **DEV 模式行为**（v2.7.2 起）：
#   - DATA_RECOVERY_DEV_MODE=1 → app 跳过物理盘枚举（不弹 macOS 权限框）
#   - 不弹 Touch ID / 密码框（admin_unix.go 走 dev 短路）
#   - 用户用 .img 镜像 + 拖文件 / 用户主目录测试足够
#   - 真要测物理盘扫描：跑 `make dev-elevated`（要 sudo）
dev: check-wails
	@DATA_RECOVERY_DEV_MODE=1 $(WAILS) dev

# 提权 dev 模式 —— 真需要测物理盘扫描时用（一次性 sudo 提权后跑）
dev-elevated: check-wails
	@echo "🔐 提权 dev 模式：会要 sudo 密码（仅这一次），用于测试物理磁盘读取"
	@echo "   日常开发请用 'make dev'（默认跳物理盘，免权限框）"
	@sudo -E $(WAILS) dev

# macOS 权限自检 —— 不申请权限（macOS 沙盒限制无法自动），只报告 + 给指引
check-perms:
	@bash scripts/check-macos-permissions.sh

# 本地构建（自动识别平台）
build: check-wails
	$(WAILS) build

# ===== 交叉编译目标 =====
# 原始系统被盗并被重置到 Windows 时，用户可能在 macOS 或 Linux 上构建并回挂源盘扫描。
# 以下提供三平台的交叉编译目标。

build-windows: check-wails
	$(WAILS) build -platform windows/amd64

build-windows-arm64: check-wails
	$(WAILS) build -platform windows/arm64

build-darwin: check-wails
	$(WAILS) build -platform darwin/arm64

build-darwin-universal: check-wails
	$(WAILS) build -platform darwin/universal

build-linux: check-wails
	$(WAILS) build -platform linux/amd64

build-linux-arm64: check-wails
	$(WAILS) build -platform linux/arm64

# 一键构建三平台（amd64）
build-all: build-darwin build-linux build-windows

# ===== 质量 =====
test:
	go test -race ./...

lint:
	go vet ./...

# 扫描"注释声称的保护层在代码里没实现"的漂移（CHANGELOG v2.0.1 里两起 bug 的同源防线）。
# drift-check: 只报告，exit 0。适合日常 check。
# drift-check-strict: 发现就 exit 1。CI 用。
drift-check:
	@go run ./cmd/drift-check

drift-check-strict:
	@go run ./cmd/drift-check -strict

# 只跑平台交叉编译冒烟，不依赖 wails CLI（CI 快速验证）
verify-platforms:
	@echo "🔧 交叉编译冒烟测试..."
	GOOS=darwin  GOARCH=arm64 go build ./...
	GOOS=darwin  GOARCH=amd64 go build ./...
	GOOS=linux   GOARCH=amd64 go build ./...
	GOOS=linux   GOARCH=arm64 go build ./...
	GOOS=windows GOARCH=amd64 go build ./...
	GOOS=windows GOARCH=arm64 go build ./...
	@echo "✅ 所有平台交叉编译均通过"

# 安装依赖
deps:
	@echo "📦 使用 GOPROXY=$(GOPROXY)"
	go mod tidy
	cd frontend && pnpm install

# 清理
clean:
	rm -rf build/bin
	rm -rf frontend/dist
	rm -rf frontend/node_modules
