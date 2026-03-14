# FRP 管理面板

一个面向中文用户的 FRP 可视化管理面板，用于统一管理 FRPS 服务器、端口映射，以及 FRPS/FRPC 一键部署。

## 核心能力

1. 首次访问强制初始化管理员账号与密码。
2. 登录鉴权与会话控制，未登录无法访问管理 API。
3. FRPS 服务器管理：新增、编辑、删除、状态检测。
4. 端口映射管理：支持 TCP/UDP/HTTP/HTTPS。
5. FRPS 一键部署改为“部署链接”模式，支持 `curl -fsSL ... | bash` 直接执行。
6. 部署链接带专属 `deploy_key` 鉴权，避免脚本被未授权调用。
7. FRPS 部署完成后自动回报服务器地址与状态到面板。
8. 支持多回调地址候选（服务器级回调地址 + 全局回调地址 + 当前请求地址）。
9. 状态页支持“最近回报在线”判定，弱网场景显示更稳定。

## 目录结构

```text
frp_manager/
├─ app.py
├─ control.sh
├─ install.sh
├─ uninstall.sh
├─ config.env.example
├─ requirements.txt
├─ static/
├─ templates/
├─ utils/
└─ frp_manager/config.json
```

## 快速部署（推荐）

在 Linux 服务器执行：

```bash
curl -fsSL https://raw.githubusercontent.com/HlONGlin/frp_manager/main/control.sh | sudo bash
```

控制器菜单支持：

1. 安装或更新
2. 卸载服务并删除文件
3. 重启服务
4. 停止服务
5. 查看服务状态与访问地址
6. 修改面板端口
7. 仅显示访问地址
8. 查看最近日志
9. 重置管理员账号（重新初始化）
10. Agent 编排控制
11. 备份配置（`config.env` + `frp_manager/config.json`）
12. 恢复配置（从备份包恢复）
13. 查看最新备份详情（时间、大小、包含文件）

更新策略说明：
- 每次在控制器执行“1) 安装或更新”时，会同步 GitHub 最新仓库内容。
- 默认会用 GitHub 最新 `frp_manager/config.json` 覆盖本地数据库。
- 如需保留本地数据库，可在运行前设置环境变量：`KEEP_LOCAL_DB_ON_UPDATE=1`。

## FRPS 一键部署（链接模式）

在面板中新增 FRPS 服务器后，会返回：

- 一键命令：`curl -fsSL <deploy_url> | bash`
- 部署链接：`/api/frps/server/<id>/deploy.sh?deploy_key=...`
- 候选部署链接（多地址容灾）

推荐直接复制面板提供的一键命令到目标 FRPS 服务器执行。执行后会自动：

1. 下载并安装 FRPS。
2. 写入与面板一致的 token 配置。
3. 启动 FRPS。
4. 回报 FRPS 实际地址到面板，并启动后台重试回报。

## FRPC 一键部署

在端口映射中可为 Linux/Windows 生成 FRPC 一键部署命令。

- Windows 脚本已兼容批处理回显问题（`(@echo off ... ) > frpc.ini`）。
- Token 与 FRPS 保持一致，避免手工复制错误导致的 token 不匹配。

### FRPC 链路加密方案（新）

当前支持 3 档加密方案，均可直接在面板选择：

- `balanced`（推荐）：`TLS + token`
  - 适合绝大多数生产场景
  - 兼顾安全和性能，配置最少

- `hybrid`（增强）：`TLS + token + use_encryption + use_compression`
  - 适合高敏感业务或弱网链路
  - 相比推荐档有更高 CPU 开销

- `mtls`（严格）：`mTLS + token`
  - 需要在客户端提前准备证书文件路径
  - 配置中已自动生成详细注解，便于直接替换路径

说明：
- 生成的 `frpc.ini` 会自动写入中文注解，标注当前安全档位与注意事项。
- API 也可显式指定：
  - `GET /api/frps/server/<id>/generate_frpc?security_profile=balanced|hybrid|mtls`
  - `GET /api/frps/server/<id>/port/<port_id>/deploy?system=linux|windows&security_profile=balanced|hybrid|mtls`

## 环境变量

`config.env`（安装时自动生成）支持以下关键项：

- `FRP_MANAGER_HOST`：监听地址，默认 `0.0.0.0`
- `FRP_MANAGER_PORT`：面板端口，默认 `5000`
- `FRP_MANAGER_SECRET_KEY`：会话密钥
- `FRP_SESSION_SECURE`：HTTPS 环境建议设为 `1`
- `FRP_TRUST_PROXY`：是否信任 `X-Forwarded-*`（仅在反代后设为 `1`）
- `FRP_SESSION_LIFETIME_HOURS`：登录会话有效时长（小时）
- `FRP_LOGIN_RATE_LIMIT` / `FRP_LOGIN_RATE_WINDOW_SEC`：登录限流阈值
- `FRP_SETUP_RATE_LIMIT` / `FRP_SETUP_RATE_WINDOW_SEC`：初始化提交限流阈值
- `FRP_DEPLOY_RATE_LIMIT` / `FRP_DEPLOY_RATE_WINDOW_SEC`：部署脚本下载限流阈值
- `FRP_AGENT_PULL_RATE_LIMIT` / `FRP_AGENT_PULL_RATE_WINDOW_SEC`：Agent 拉任务限流阈值
- `FRP_STATUS_TIMEOUT`：端口探测超时（秒）
- `FRP_STATUS_CACHE_TTL`：状态缓存时间（秒）
- `FRP_STATUS_WORKERS`：状态探测并发数
- `FRP_REPORT_ONLINE_TTL`：最近回报在线判定窗口（秒）
- `FRP_MANAGER_PUBLIC_URL`：全局面板公网地址（可多个，逗号或空格分隔）

## 首次使用建议

1. 优先填写可从 FRPS 服务器访问的“回调地址”（或设置 `FRP_MANAGER_PUBLIC_URL`）。
2. 新增 FRPS 后，直接使用面板生成的链接命令部署，不要手写配置。
3. FRPS 上线后再生成 FRPC 配置，保证 server 地址与 token 均最新。

## 常见问题

1. 页面打开了，但服务器状态更新慢
- 调低 `FRP_STATUS_TIMEOUT`，并检查网络与防火墙。

2. FRPS 部署后没有显示在线
- 确认 FRPS 服务器能访问面板 `deploy_url` 和 `/report` 回调地址。
- 可在面板中查看“回报地址候选”是否可达。

3. FRPC 报错 token 不匹配
- 说明 FRPS 侧配置与面板不一致。
- 重新执行面板提供的 FRPS 一键部署命令后，再重新生成 FRPC 命令。

4. 部署链接泄露怎么办
- 删除并重建该 FRPS 服务器可更换 `deploy_key`（后续可扩展为一键轮换）。

## 安全加固建议（强烈推荐）

1. 把面板放在 HTTPS 反向代理后，并设置 `FRP_SESSION_SECURE=1`。
2. 生产环境必须设置 `FRP_MANAGER_SECRET_KEY`，否则重启会导致会话失效。
3. 如使用反向代理，再设置 `FRP_TRUST_PROXY=1`；否则保持 `0`。
4. Agent 属于高权限运维能力，请仅在可信网络内启用并妥善保管 token。

## Agent 编排一期（已接入 API 底座）

为支持“批量部署 + 单实例开关”的傻瓜化目标，已新增一套管理端/Agent 端 API 底座：

- 管理端（需登录）：
  - `GET /api/agent/nodes`
  - `POST /api/agent/node`
  - `GET|PUT|DELETE /api/agent/node/<node_id>`
  - `POST /api/agent/node/<node_id>/rotate-token`
  - `POST /api/agent/node/<node_id>/bootstrap`（生成节点一键引导命令）
  - `GET /api/agent/jobs`
  - `POST /api/agent/job`
  - `POST /api/agent/job/<job_id>/retry`（失败任务重试）
  - `POST /api/agent/jobs/batch`
  - `GET /api/agent/runtimes`
  - `POST /api/agent/runtime/<runtime_id>/ensure-running`
  - `POST /api/agent/runtime/<runtime_id>/ensure-stopped`

- Agent 端（Bearer Token，无需会话）：
  - `POST /api/agent/v1/register`
  - `POST /api/agent/v1/pull`
  - `POST /api/agent/v1/jobs/<job_id>/start`
  - `POST /api/agent/v1/jobs/<job_id>/complete`
  - `POST /api/agent/v1/runtime/report`

说明：
- 当前阶段是后端编排底座，前端页面仍以现有 FRPS/FRPC 管理为主。
- Agent 任务采用租约领取（lease）和终态幂等回报，避免重复执行导致状态错乱。

### 快速引导 Agent（Linux）

1. 管理员先创建节点：`POST /api/agent/node`
2. 调用 `POST /api/agent/node/<node_id>/bootstrap` 获取 `command`
3. 在目标服务器直接执行该命令，Agent 会自动：
   - 注册节点（`/api/agent/v1/register`）
   - 轮询任务（`/api/agent/v1/pull`）
   - 回报执行结果与运行态（`/api/agent/v1/jobs/*`, `/api/agent/v1/runtime/report`）

应用命令建议：
- 推荐在“添加应用”时使用命令模板（`systemd` / `service`）+ 服务名。
- 模板会自动生成启动/停止/检查命令，减少手工错误并更安全。

`static/agent/frp_agent.py` 支持以下环境变量：
- `MANAGER_URL`：面板地址，例如 `https://panel.example.com`
- `NODE_ID`：节点 ID
- `NODE_TOKEN`：节点 Bearer Token
- `POLL_INTERVAL`：轮询间隔秒（默认 5）
- `REQUEST_TIMEOUT`：请求超时秒（默认 15）
- `COMMAND_TIMEOUT`：单条命令执行超时秒（默认 20）
- `MAX_COMMAND_LENGTH`：单条命令最大长度（默认 1024）
- `ALLOWED_COMMAND_PREFIXES`：命令前缀白名单（默认 `systemctl,service,pgrep,pkill,echo,nohup`）
- `ALLOW_UNSAFE_COMMANDS`：是否关闭前缀白名单（默认 `0`，仅紧急兼容时改为 `1`）

说明：
- Agent 现在会拒绝空命令、超长命令、含换行/空字符命令。
- 默认仅允许白名单前缀命令执行；建议保持默认并通过模板化命令管理。

任务审计：
- 新创建的任务会自动记录下发人、来源 IP、来源路径、客户端标识。
- 可通过 `GET /api/agent/jobs` 查看审计字段，便于追踪操作来源。
