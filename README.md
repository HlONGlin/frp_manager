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

## 环境变量

`config.env`（安装时自动生成）支持以下关键项：

- `FRP_MANAGER_HOST`：监听地址，默认 `0.0.0.0`
- `FRP_MANAGER_PORT`：面板端口，默认 `5000`
- `FRP_MANAGER_SECRET_KEY`：会话密钥
- `FRP_SESSION_SECURE`：HTTPS 环境建议设为 `1`
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
