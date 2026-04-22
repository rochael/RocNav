# CLAUDE.md

本文档为 Claude Code（claude.ai/code）在此仓库中工作时提供指引。

## 项目概览

RocNav 是一个单二进制部署的链接导航应用：
- 后端：Go + Gin + GORM + SQLite
- 前端：React 19 + Vite + TypeScript + Tailwind
- 部署方式：先将前端构建到 `web/frontend/dist`，再通过 `web/web.go` 内嵌进 Go 二进制

## 常用命令

### 后端
- 构建本地二进制：`make build`（输出 `bin/rocnav`）
- 构建 Linux amd64 静态二进制：`make build-linux`
- 直接运行服务：`go run ./cmd/server --addr :8080`
- 查看版本：`go run ./cmd/server --version`
- 运行全部 Go 测试：`go test ./...`
- 运行单个 Go 包测试：`go test ./internal/app`
- 按名称运行单个 Go 测试：`go test ./internal/app -run TestName`

### 前端
- 安装依赖：`cd web/frontend && npm install`
- 启动 Vite 开发服务器：`cd web/frontend && npm run dev`
- 构建前端产物：`cd web/frontend && npm run build`
- 执行前端 lint：`cd web/frontend && npm run lint`
- 预览前端构建结果：`cd web/frontend && npm run preview`

### 本地开发流程
1. 如有需要，先将 `.env.example` 复制为 `.env`。
2. 在仓库根目录启动后端：`go run ./cmd/server --addr :8080`
3. 在另一个终端启动前端：`cd web/frontend && npm run dev`
4. Vite 会通过 `web/frontend/vite.config.ts` 将 `/api` 代理到 `http://localhost:8080`。

## 架构说明

### 运行时结构
- `cmd/server/main.go` 负责解析 CLI 参数、加载配置、构造 `app.App` 并启动 HTTP 服务。
- `internal/config/config.go` 负责加载 `.env` 和进程环境变量，并提供本地开发默认值。
- `internal/app/app.go` 负责组装配置、SQLite、数据库迁移、可选管理员种子、GitHub OAuth、Gin 以及路由注册。
- `internal/app/routes.go` 承载了几乎全部 HTTP 行为：认证、分类 CRUD、链接 CRUD、排序接口、点击统计以及 SPA/静态资源服务。

### 数据模型
`internal/models/models.go` 定义了四个持久化实体：
- `User`：邮箱/密码认证、可选 TOTP、可选 GitHub 绑定、管理员标记
- `Category`：链接分类容器，支持排序，可选归属到某个用户
- `Link`：书签链接，包含可见性、图标 URL、备注、点击计数和可选归属用户
- `Click`：点击分析记录，包含链接、可选用户、IP 和 User-Agent

权限规则主要直接写在 handler 中，而不是通过独立 service 层统一封装：
- 未登录用户只能看到公开链接和全局分类
- 普通用户能看到自己的私有数据以及公开/共享数据
- 管理员可以访问全部记录

### 认证流程
- 密码哈希逻辑位于 `internal/auth/auth.go`，使用 bcrypt。
- JWT 是主要会话机制，既支持 `nav_token` Cookie，也支持 `Authorization: Bearer ...`。
- 登录需要密码 + TOTP。
- 注册时会立即生成 TOTP secret，并返回 secret 和 otpauth URL。
- GitHub OAuth 是可选能力；`/api/auth/github/start` 发起授权，`/api/auth/github/callback` 完成登录或将 GitHub 账号绑定到当前用户。

### 持久化与启动行为
- SQLite 默认存放在 `data/nav.db`。
- `internal/database/database.go` 会创建数据库目录、打开 SQLite、执行 `AutoMigrate`，并按环境变量可选地种子一个管理员账号。
- 当前没有独立迁移框架，schema 变更依赖 GORM 自动迁移。

### 前端结构
- 当前前端几乎全部集中在 `web/frontend/src/App.tsx`，尚未拆成多个特性模块。
- `useAppData()` 是核心的数据加载和状态管理入口，负责用户、分类、链接和配置状态。
- 路由很简单：`/` 渲染公开首页，`/admin` 渲染登录和管理界面。
- 拖拽排序使用 `@hello-pangea/dnd`，并通过 `/api/categories/reorder` 和 `/api/links/reorder` 持久化顺序。
- 前端默认依赖 Cookie 会话，公共 `api()` helper 中固定使用 `credentials: 'include'`。

### 前端内嵌约定
- `web/web.go` 会把 `frontend/dist/*` 内嵌进 Go 二进制。
- `internal/app/routes.go` 会从内嵌产物中提供 `/assets`、`/vite.svg`、`/` 以及非 API 路径的 SPA fallback。
- 如果缺少 `web/frontend/dist/index.html`，服务启动时会直接 panic。构建或发布 Go 二进制前必须先构建前端。

## 配置

重要环境变量来自 `.env` 或进程环境：
- `ADDR`：后端监听地址，默认 `:8080`
- `SQLITE_PATH`：SQLite 文件路径，默认 `data/nav.db`
- `JWT_SECRET`、`JWT_ISSUER`、`JWT_TTL`：JWT 配置
- `COOKIE_DOMAIN`、`COOKIE_SECURE`：Cookie 行为
- `FRONTEND_ORIGIN`：本地前端开发时允许的 CORS 来源
- `GITHUB_CLIENT_ID`、`GITHUB_CLIENT_SECRET`、`GITHUB_REDIRECT`：可选 GitHub OAuth 配置
- `ADMIN_EMAIL`、`ADMIN_PASSWORD`：可选的首次启动管理员种子账号
- `ALLOW_REGISTER`：是否允许自助注册

## 仓库特定说明

- 当前仓库中没有提交任何 Go 测试文件，但默认验证命令仍然是 `go test ./...`。
- 根目录 `README.md` 是项目功能和部署方式的主说明；前端目录的 `README.md` 只是默认的 Vite 模板，并非项目专属文档。
- 修改前端行为时，通常需要直接编辑 `web/frontend/src/App.tsx`，除非你是在明确地做结构性重构。
