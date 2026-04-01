.PHONY: dev build build-windows clean deps install-wails check-wails

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

# 开发模式（macOS 本地）
dev: check-wails
	$(WAILS) dev

# 构建 Windows 可执行文件（从 macOS 交叉编译）
build-windows: check-wails
	$(WAILS) build -platform windows/amd64

# 本地构建
build: check-wails
	$(WAILS) build

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
