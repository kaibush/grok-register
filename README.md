# Grok Register

基于 FastAPI、React 和 Playwright 浏览器适配层的 Web 注册管理工具。Camoufox 保持默认，同时可切换到 CloakBrowser，支持注册任务、账号管理，以及 CPA / Grok2API 授权文件生成。

[部署文档](DEPLOYMENT.md) · [Web 说明](WEB.md) · [GrokIQ 降智检测](https://github.com/kaibush/grok-iq)

> **重要：上游 grok.com 已不再下发 `bfs` 标记。**
> 注册机无法据此判断账号是否风控或降智。账号级降智检测和自动隔离必须使用 [GrokIQ](https://github.com/kaibush/grok-iq)：注册导入后由 GrokIQ 做质量探针、风险判定，并自动隔离异常账号。不要把本项目的 SSO / `botFlag` 检查当作风控结论。

## 界面预览

### 工作概览

![Grok Register 工作概览](docs/images/dashboard.png)

### 注册、监控与账号

| 新建注册 | 运行监控 | 账号列表 |
| --- | --- | --- |
| ![新建注册页面](docs/images/register.png) | ![运行监控页面](docs/images/runtime.png) | ![账号管理页面](docs/images/accounts.png) |

## 功能

- Web 控制台：任务进度、实时日志、账号管理和系统设置
- Camoufox（Firefox，默认）与 CloakBrowser（Chromium）双浏览器后端，共用注册流程、代理和异常进程清理
- 支持 Cloudflare、DuckMail / Mail.tm、YYDS、MailNest、OutlookEmail、CloudMail
- 注册完成后生成 CPA / Grok2API JSON
- 上游已不再下发 `bfs`，本项目不能判断账号是否风控；必须联动 [GrokIQ](https://github.com/kaibush/grok-iq) 做账号级降智检测和自动隔离
- Grok Build 导入成功后通过持久 Webhook 通知 GrokIQ，由 GrokIQ 自动探针并隔离异常账号
- JSON 查看、复制和下载
- 首次访问创建唯一管理员账号
- Docker Compose 部署，支持无桌面 Linux 服务器
- GitHub Actions 自动构建 GHCR 镜像

## Docker 快速启动

宿主机只需安装 Docker 和 Docker Compose。

```bash
git clone https://github.com/kaibush/grok-register.git
cd grok-register
cp .env.example .env
docker compose build
docker compose up -d
```

访问：`http://服务器IP:8787`

查看状态和日志：

```bash
docker compose ps
docker compose logs -f grok-register
curl http://127.0.0.1:8787/api/health
```

容器内使用 **Xvfb + 有头浏览器**，服务器不需要桌面环境。默认后端仍是 Camoufox，可在设置页切换 CloakBrowser；Docker 模式会强制关闭无头模式。

如果配置里的代理是 `127.0.0.1:7897`，Compose 会自动映射到宿主机代理。宿主机代理软件需要允许局域网连接（监听 `0.0.0.0` 或 Docker 网桥地址）。

完整说明见 [DEPLOYMENT.md](DEPLOYMENT.md)。

### 可选 OutlookEmail 邮箱池

Compose 已集成 [`ghcr.io/assast/outlookemail:latest`](https://github.com/assast/outlookEmail)，默认不随主服务启动。需要选择 OutlookEmail 邮箱、导入账号或读取邮件时，在 `.env` 修改登录密码和 `SECRET_KEY`，然后启动可选 profile：

```bash
docker compose --profile outlookemail up -d
```

访问地址：

```text
Grok Register: http://服务器IP:8787
OutlookEmail:  http://服务器IP:5000
```

`5000` 默认映射到宿主机所有网卡。主容器内的 API Base 使用：

```text
http://outlook-email:5000
```

Docker 首次生成 `data/config.json` 时会预填该内部地址；已有配置可在“系统设置 → Outlook 邮箱池”中填写。

OutlookEmail 数据保存在 `outlookemail-data/`，并已被 Git 和 Docker 构建上下文忽略。完整配置见 [DEPLOYMENT.md](DEPLOYMENT.md#可选-outlookemail-邮箱池)。

## 与 GrokIQ 联动（必须）

上游 grok.com 已经不下发 `bfs` 风控标记，**仅靠本注册机无法判断账号是否风控**。账号级降智检测和自动隔离必须交给 [GrokIQ](https://github.com/kaibush/grok-iq)。

Grok Register 只负责注册并导入 Grok2API；导入成功后通过持久 Webhook 通知 GrokIQ。GrokIQ 接收并去重账号事件，按设置自动执行质量探针，识别降智 / 异常账号并自动隔离。没有 GrokIQ 时，新注册账号只能当作“尚未检测”，不能当作“未风控”。

```text
Grok Register 注册并导入 Grok2API
              │
              └─ 持久 Webhook / 失败退避重试
                         │
                         ▼
              GrokIQ
              接收账号 → 自动探针 → 降智检测与自动隔离
```

复制环境变量模板，并至少为两端设置相同的联动 Token：

```bash
cp .env.example .env

# 编辑 .env
GROKIQ_WEBHOOK_TOKEN=替换为随机长字符串
```

随后使用两个 Compose 文件启动注册机、GrokIQ 后端和 GrokIQ 前端：

```bash
docker compose -f compose.yaml -f compose.grokiq.yaml pull
docker compose -f compose.yaml -f compose.grokiq.yaml up -d
```

默认访问地址：

```text
Grok Register: http://服务器IP:8787
GrokIQ:        http://服务器IP:8091
```

GrokIQ 前端通过容器内 Nginx 将 `/api` 请求转发至 `grokiq-backend:8090`，因此 GrokIQ 后端端口无需暴露到宿主机。`8091` 默认监听所有网卡；使用反向代理时可在 `.env` 设置 `GROKIQ_WEB_BIND=127.0.0.1`。

验证联动服务：

```bash
docker compose -f compose.yaml -f compose.grokiq.yaml ps
curl http://127.0.0.1:8091/api/health
docker compose -f compose.yaml -f compose.grokiq.yaml logs -f grokiq-backend grokiq-frontend
```

首次启动后，在 GrokIQ 的“系统设置 → 联动与启动项”中保存联动 Token、首次探针方案和出口目标；再到 Grok Register 的“系统设置 → Grok2API”中启用 GrokIQ 联动并填写相同 Token。完整说明见 [DEPLOYMENT.md](DEPLOYMENT.md#与-grokiq-统一编排)。

## 配置文件

### 本机运行

读取根目录：

```text
config.json
```

首次使用：

```bash
cp config.example.json config.json
```

### Docker 运行

读取宿主机：

```text
data/config.json
```

使用已有的本地配置：

```bash
mkdir -p data
cp config.json data/config.json
docker compose restart grok-register
```

也可以在 Web 的“系统设置”中修改配置。

Docker 配置中的授权目录建议保持：

```json
{
  "cpa_auth_dir": "data/cpa_auth",
  "grok2api_auth_dir": "data/grok2api_auth",
  "grok2api_remote_url": "https://grok2api.example.com",
  "grok2api_remote_username": "admin",
  "grok2api_remote_password": "change-me",
  "grok2api_auto_import": true,
  "grok2api_auto_import_build": true,
  "grok2api_auto_import_web": false,
  "grok2api_auto_import_console": false
}
```

## 本机运行

要求：Python 3.10+、Node.js 22+。

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python -m camoufox fetch

cd front
npm install
npm run build
cd ..

cp config.example.json config.json
./start-web.sh
```

访问：`http://127.0.0.1:8787`

Windows 启动：

```powershell
.venv\Scripts\python.exe -m backend.web.cli --host 127.0.0.1 --port 8787
```

## 主要配置

建议直接在 Web 设置页填写。

| 配置项 | 说明 |
| --- | --- |
| `email_provider` | 邮箱服务商 |
| `register_count` | 注册数量 |
| `register_workers` | 并发数量，默认 1 |
| `proxy` | 注册和 OAuth 请求使用的 HTTP(S) 代理；支持 `http://host:port` 和 `http://user:password@host:port`，凭据中的特殊字符需使用 URL 百分号编码。注册风控会记录浏览器识别到的出口 IP；下次若仍是该 IP，会重启浏览器换出口后再注册。风控名单在「账号中心 → 出口 IP 风控」查看，单账号出口 IP 在「账号中心 → 账号管理 → 查看」详情中。代理地址支持 `{session}` 占位符：每次启动浏览器（含风控换出口的重启）时替换为新的随机标识，例如 `http://register.{session}:token@resin:2260`，配合 resin 等按认证用户名分配粘性会话的代理池，可实现"每个浏览器会话一个固定出口 IP、会话结束即弃"，同时保证会话期间出口 IP 不变 |
| `browser_engine` | 浏览器后端：`camoufox`（默认）或 `cloakbrowser` |
| `browser_headless` | 本机无头模式；Docker 中强制关闭 |
| `browser_low_traffic_mode` | 低流量注册模式，默认开启；复用静态资源缓存并跳过非注册必需资源 |
| `browser_traffic_savings_level` | 低流量模式下的节省级别，默认 `more`（额外缓存 accounts.x.ai 哈希静态资源）；`standard` 仅缓存 grok.com CDN |
| `cpa_auto_add` | 注册后生成 CPA 授权 |
| `sso_detailed_risk_check` | 获取 SSO 后尝试读取账号页 `botFlagSource`。上游已不再稳定下发 `bfs` / `botFlag`，该检查不能作为风控结论；账号级降智检测请用 GrokIQ |
| `cpa_registration_risk_check` | 注册获取 SSO 后复查 grok.com `botFlag`；默认关闭。字段经常缺失，不能判断账号是否风控；必须使用 GrokIQ 做降智检测和自动隔离 |
| `cpa_auth_dir` | CPA JSON 保存目录 |
| `cpa_remote_url` | CPA Management API 地址 |
| `cpa_management_key` | CPA 管理密钥 |
| `grok2api_auth_dir` | Grok2API JSON 保存目录 |
| `grok2api_remote_url` | 远程 Grok2API 站点根地址 |
| `grok2api_remote_username` | 远程 Grok2API 管理员账号 |
| `grok2api_remote_password` | 远程 Grok2API 管理员密码 |
| `grok2api_auto_import` | JSON 生成后自动登录并导入远程 Grok2API |
| `grok2api_auto_import_build` | 自动导入 grok_build，默认开启 |
| `grok2api_auto_import_web` | 自动导入 grok_web，默认关闭 |
| `grok2api_auto_import_console` | 自动导入 grok_console，默认关闭 |
| `grokiq_webhook_enabled` | 导入 Grok Build 后发送账号已导入 Webhook |
| `grokiq_webhook_url` | GrokIQ `account-imported` 接口地址 |
| `grokiq_webhook_token` | Webhook 请求头 `x-grokiq-token` |
| `grokiq_webhook_timeout_seconds` | 单次投递超时；失败后由持久 Outbox 退避重试 |

GrokIQ 检测完成后会发送回调通知 `POST /api/integrations/grokiq/notify`（请求头 `x-grokiq-token`，类似支付异步通知）。账号详情会显示是否降智，注册机不会据此自动删除账号。

统一 Compose 中，`GROKIQ_REGISTER_PROBE_STABILIZATION_SECONDS` 控制 GrokIQ 收到新账号事件后等待多久再创建首次探针，默认 `15` 秒，设为 `0` 可关闭等待。

配置模板见 [`config.example.json`](config.example.json)。

## 数据目录

```text
data/
├── config.json                   # Docker 配置
├── web_auth.json                 # Web 管理员认证
├── accounts/                     # 账号和注册结果
├── cpa_auth/                     # CPA JSON
├── grok2api_auth/                # Grok2API JSON
└── cloakbrowser-cache/           # CloakBrowser 首次使用后下载的 Chromium

logs/                             # 运行日志
outlookemail-data/                # 可选 OutlookEmail 数据
```

`data/`、`logs/` 和本地 `config.json` 已被 Git 忽略。

## 常用命令

```bash
# 停止服务
docker compose down

# 更新本地构建
git pull
docker compose up -d --build

# 验证有头 Camoufox
docker compose run --rm grok-register python /app/docker/camoufox_smoke.py

# 验证有头 CloakBrowser（首次运行会下载并缓存 Chromium）
docker compose run --rm grok-register python /app/docker/cloakbrowser_smoke.py

# 后端测试
.venv/bin/python -m unittest discover -s backend/tests -v

# 前端构建
cd front && npm run build
```

## 新版本检测

服务启动后会读取根目录 `VERSION`，立即查询一次 GitHub Releases，之后每
1 小时复查。发现高于当前版本的正式 Release 时，管理控制台会自动弹出更新提示，
展示版本号、Markdown 更新说明和 Release 链接；关闭后同一版本不再重复弹出，更高版本
发布后会重新提示。Release 正文按 GitHub Markdown 渲染，标题、列表、链接和代码块会显示在弹窗里。

无需发布测试版本也可以预览弹窗：登录管理控制台后访问
`/overview?preview-update=1`。预览关闭状态不会写入正式版本的忽略记录，刷新页面
可以再次查看。

Docker 镜像更新仍使用：

```bash
docker compose pull
docker compose up -d --force-recreate
```

推送 `vX.Y.Z` 标签后，GitHub Actions 会构建对应多架构镜像并自动创建 GitHub
Release；标签版本同时注入镜像内的 `VERSION`。

## 常见问题

### 注册完成后如何判断账号是否风控？

不能靠本注册机判断。上游 grok.com 已不再下发 `bfs` 标记，SSO / `botFlag` 检查也无法给出可靠结论。必须接入 [GrokIQ](https://github.com/kaibush/grok-iq)，由它对账号做质量探针、降智检测和自动隔离。推荐使用 `compose.yaml` + `compose.grokiq.yaml` 一起启动。

### Docker 修改配置后未生效

Docker 读取 `data/config.json`，不是根目录 `config.json`。修改后执行：

```bash
docker compose restart grok-register
```

### Camoufox 未安装

```bash
.venv/bin/python -m camoufox fetch
.venv/bin/python -m camoufox version
```

### CloakBrowser 首次启动

安装依赖后可预先下载 Chromium；Docker 会把缓存保存在 `data/cloakbrowser-cache/`：

```bash
.venv/bin/python -m cloakbrowser install
```

### 公网 HTTPS 登录状态异常

在 `.env` 中设置：

```dotenv
GROK_WEB_COOKIE_SECURE=1
```

然后重建容器：

```bash
docker compose up -d --force-recreate
```

### CPA 没有出现新账号

检查 `cpa_auto_add`、`cpa_auth_dir`，或远程配置 `cpa_remote_url`、`cpa_management_key`，并查看日志中的 `[CPA]` 信息。

## 项目结构

```text
front/                  React 前端
backend/                Python 后端
  web/                  FastAPI、认证与任务调度
  registration/         注册编排、仓储和结果产物
  automation/           Camoufox / CloakBrowser 浏览器运行时与共用页面适配
  integrations/         代理、连通性和授权交换
  mailbox/              邮箱渠道适配
  shared/               公共路径等基础设施
backend/tests/          后端测试
docker/                 容器启动与浏览器验证
docs/images/            Web 界面截图
.github/workflows/      GitHub Actions
data/                   运行数据
  screenshots/          浏览器注册失败现场截图
logs/                   运行日志
outlookemail-data/      可选 OutlookEmail 数据
compose.yaml            Docker Compose 配置
compose.grokiq.yaml     GrokIQ 联动编排
```

## Stars 趋势

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/images/stars-trend-dark.svg">
  <source media="(prefers-color-scheme: light)" srcset="docs/images/stars-trend-light.svg">
  <img alt="Grok Register Stars 趋势" src="docs/images/stars-trend-light.svg">
</picture>

> 图表由 GitHub Actions 每 6 小时读取最新 Stars 总数并自动更新，浅色与深色主题会随 GitHub 页面设置切换。

## 友情链接

- [Linux.do 社区](https://linux.do)

## License

[MIT](LICENSE)
