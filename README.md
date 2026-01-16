# RocNav

轻量级私人导航与链接管理应用，Go (Gin + GORM + SQLite) 后端，React + Tailwind 前端，前端资源内嵌生成单一可执行文件，支持 TOTP 密码登录与 GitHub OAuth、链接拖拽排序、搜索与点击统计。

## 特性
- 账号体系：邮箱+密码+TOTP，GitHub OAuth 可选。
- 链接管理：分类/排序/公开私有、图标自动猜测、备注、点击统计。
- 交互：拖拽排序（分类/链接）、搜索筛选、Admin 页编辑/删除/创建。
- 部署：前端打包并通过 Go `embed` 内嵌，单文件运行；`VERSION` 注入版本信息，支持 `-ldflags` 覆盖。

## 快速开始
```bash
# 安装前端依赖并打包（首次需要）
cd web/frontend && npm install && npm run build

# 回到项目根目录，构建本机二进制
cd ../.. && make build           # 输出 bin/server
# 或交叉编译 Linux amd64 静态版（需 musl 工具链）
make build-linux                 # 输出 bin/server-linux

# 运行（可选覆盖监听地址）
./bin/server --addr :8080
```

## 环境变量（可选）
- `ADDR`（默认`:8080`）：HTTP 监听地址。
- `SQLITE_PATH`（默认`data/nav.db`）：SQLite 数据文件路径。
- `JWT_SECRET` / `JWT_ISSUER` / `JWT_TTL`：JWT 配置。
- `COOKIE_DOMAIN` / `COOKIE_SECURE`：Cookie 域与安全标记。
- `FRONTEND_ORIGIN`（默认`http://localhost:5173`）：开发时 CORS 允许源。
- GitHub OAuth：`GITHUB_CLIENT_ID`、`GITHUB_CLIENT_SECRET`、`GITHUB_REDIRECT`。
- 管理员种子：`ADMIN_EMAIL`、`ADMIN_PASSWORD`。

## 版本号
- 根目录 `VERSION` 文件存储默认版本；构建时通过 `-ldflags "-X github.com/rochael/RocNav/internal/version.buildVersion=1.2.3"` 可覆盖。

## 开发提示
- 前端开发：`cd web/frontend && npm run dev`（默认走 Vite 代理 `/api`）。
- 后端仅需 Go 工具链；首次运行会自动迁移数据库并种子管理员（如提供）。
