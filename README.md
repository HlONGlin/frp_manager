# FRP 管理面板

一个面向中文用户的 FRP 可视化管理面板，用于统一管理 FRPS 服务器、端口映射与一键部署命令。

## 主要功能

1. 首次访问强制初始化管理员账号与密码。
2. 登录鉴权与会话控制，未登录无法访问管理接口。
3. FRPS 服务器管理：新增、编辑、删除、状态检测（新增时无需手填服务器地址）。
4. 端口映射管理：支持 TCP/UDP/HTTP/HTTPS。
5. 一键生成 FRPS/FRPC 部署命令。
6. 子服务器执行一键部署后，自动回报状态与服务器 IP 到面板。
7. 列表快速加载（状态异步刷新，页面先显示再探测）。

## 目录结构

```text
frp_manager/
├─ app.py
├─ config.env.example
├─ control.sh
├─ install.sh
├─ uninstall.sh
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

1. 部署/更新项目
2. 彻底卸载（删除服务、配置数据与项目目录）
3. 重启服务
4. 停止服务
5. 查看状态与访问地址
6. 修改面板端口
7. 仅显示访问地址
8. 查看最近日志
9. 重置管理员账号（重新初始化）

## 手动运行（开发模式）

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

默认地址：

- 面板首页：`http://127.0.0.1:5000/`
- 首次初始化：`http://127.0.0.1:5000/setup`
- 登录页：`http://127.0.0.1:5000/login`

## 环境变量说明

可在 `config.env` 中配置（首次安装会自动生成）：

- `FRP_MANAGER_HOST`：监听地址，默认 `0.0.0.0`
- `FRP_MANAGER_PORT`：面板端口，默认 `5000`
- `FLASK_DEBUG`：调试开关，默认 `0`
- `FRP_MANAGER_SECRET_KEY`：会话密钥（安装时自动生成）
- `FRP_SESSION_SECURE`：HTTPS 场景可设为 `1`
- `FRP_STATUS_TIMEOUT`：状态探测超时（秒）
- `FRP_STATUS_CACHE_TTL`：状态缓存时长（秒）
- `FRP_STATUS_WORKERS`：并发探测线程数

## 首次使用流程

1. 打开面板地址后会自动跳转到初始化页面。
2. 设置管理员账号和密码。
3. 新增 FRPS 服务器（无需输入服务器地址），复制一键部署命令到目标子服务器执行。
4. 子服务器回报成功后，面板自动显示该子服务器地址与在线状态。
5. 后续访问需先登录，未登录访问 API 会返回 401。

## 常见问题

1. 页面能打开但列表状态显示慢  
原因：正在探测服务器端口连通性。  
建议：适当下调 `FRP_STATUS_TIMEOUT`，并确认网络与防火墙配置。

2. 一键部署后未自动显示运行中  
原因：FRPS 机器无法回调面板 `/report` 接口。  
建议：确保部署命令中的 `MANAGER_URL` 可从 FRPS 服务器访问。

3. 忘记管理员密码  
处理：使用控制器菜单第 9 项重置管理员账号，重新初始化。
