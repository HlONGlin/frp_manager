# frp_manager
批量管理 FRP 穿透服务。

## Linux 快速控制器
参考 `subconvert-manager` 的控制器模式，已提供 `control.sh + install.sh + uninstall.sh`。

在线一键启动控制器:

```bash
curl -fsSL https://raw.githubusercontent.com/HlONGlin/frp_manager/main/control.sh | sudo bash
```

控制器能力:

1. 引导部署或更新代码
2. 安装并管理 `systemd` 服务（`frp-manager`）
3. 查看状态/日志/访问地址
4. 修改管理面板端口
5. 重置管理员账号（重新走首次初始化）
6. 卸载服务并清理项目目录

## 手动运行（开发）

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

默认地址:

- `http://127.0.0.1:5000/`
- 首次初始化页: `http://127.0.0.1:5000/setup`
