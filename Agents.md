# AGENTS.md

## 项目概述
- 技术栈：Go + wails + TS
- 前端包管理器：pnpm

## 前端构建/开发命令
- 安装依赖：pnpm install
- 启动本地：pnpm dev
- 生产构建：pnpm build

## 代码风格
- 严格 TS、单引号、无分号
- 用函数式写法，少用 class

## 测试要求
- 运行测试：pnpm test、 go test -vvv
- 提交前必须全过

## 安全/边界
- 数据库操作必须写事务
