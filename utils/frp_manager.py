import os
import json
import subprocess
import psutil
import signal

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FRP_DIR = os.path.join(BASE_DIR, 'frp_files')

class FRPManager:
    def __init__(self):
        self.frps_process = None
        self.frpc_processes = {}
        
    def ensure_frp_dir(self):
        os.makedirs(FRP_DIR, exist_ok=True)
        
    def generate_frps_config(self, config):
        self.ensure_frp_dir()
        frps_ini = os.path.join(FRP_DIR, 'frps.ini')
        
        content = f"""[common]
bind_port = {config.get('bind_port', 7000)}
vhost_http_port = {config.get('vhost_http_port', 80)}
vhost_https_port = {config.get('vhost_https_port', 443)}
dashboard_port = {config.get('dashboard_port', 7500)}
dashboard_user = {config.get('dashboard_user', 'admin')}
dashboard_pwd = {config.get('dashboard_pwd', 'admin')}
token = {config.get('token', 'your_token_here')}
allow_ports = {config.get('allow_ports', '2000-30000')}
"""
        with open(frps_ini, 'w', encoding='utf-8') as f:
            f.write(content)
        return frps_ini
    
    def generate_frpc_config(self, config):
        self.ensure_frp_dir()
        frpc_ini = os.path.join(FRP_DIR, f'frpc_{config.get("id", "default")}.ini')
        
        custom = config.get('custom_config', '')
        
        content = f"""[common]
server_addr = {config.get('server_addr', '127.0.0.1')}
server_port = {config.get('server_port', 7000)}
token = {config.get('token', 'your_token_here')}

[{config.get('name', 'web')}]
type = {config.get('protocol', 'tcp')}
local_ip = {config.get('local_ip', '127.0.0.1')}
local_port = {config.get('local_port', 80)}
remote_port = {config.get('remote_port', 6000)}
"""
        if custom:
            content += "\n" + custom
            
        with open(frpc_ini, 'w', encoding='utf-8') as f:
            f.write(content)
        return frpc_ini
    
    def generate_frpc_template(self, frps_config, local_port=80, remote_port=6000):
        return f"""[common]
server_addr = 127.0.0.1
server_port = {frps_config.get('bind_port', 7000)}
token = {frps_config.get('token', 'your_token_here')}

[web]
type = tcp
local_ip = 127.0.0.1
local_port = {local_port}
remote_port = {remote_port}
"""
    
    def is_frps_running(self):
        for proc in psutil.process_iter(['name', 'cmdline']):
            try:
                cmdline = proc.info.get('cmdline', [])
                if cmdline and 'frps' in ' '.join(cmdline).lower():
                    return True
            except:
                pass
        return False
    
    def is_frpc_running(self, config_id):
        for proc in psutil.process_iter(['name', 'cmdline']):
            try:
                cmdline = proc.info.get('cmdline', [])
                if cmdline and f'frpc_{config_id}' in ' '.join(cmdline).lower():
                    return True
            except:
                pass
        return False
    
    def start_frps(self, config_path=None):
        if self.is_frps_running():
            return {"success": False, "message": "FRPS is already running"}
        
        if config_path is None:
            config_path = os.path.join(FRP_DIR, 'frps.ini')
        
        frps_binary = self._find_frp_binary('frps')
        if not frps_binary:
            return {"success": False, "message": "FRPS binary not found. Please place frps executable in frp_files directory"}
        
        try:
            self.frps_process = subprocess.Popen(
                [frps_binary, '-c', config_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=FRP_DIR
            )
            return {"success": True, "message": "FRPS started successfully"}
        except Exception as e:
            return {"success": False, "message": str(e)}
    
    def stop_frps(self):
        for proc in psutil.process_iter(['name', 'cmdline']):
            try:
                cmdline = proc.info.get('cmdline', [])
                if cmdline and 'frps' in ' '.join(cmdline).lower():
                    proc.terminate()
                    proc.wait(timeout=5)
            except:
                try:
                    proc.kill()
                except:
                    pass
        return {"success": True, "message": "FRPS stopped"}
    
    def start_frpc(self, config_path):
        frpc_binary = self._find_frp_binary('frpc')
        if not frpc_binary:
            return {"success": False, "message": "FRPC binary not found. Please place frpc executable in frp_files directory"}
        
        try:
            proc = subprocess.Popen(
                [frpc_binary, '-c', config_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=FRP_DIR
            )
            return {"success": True, "message": "FRPC started successfully", "pid": proc.pid}
        except Exception as e:
            return {"success": False, "message": str(e)}
    
    def stop_frpc(self, config_id):
        for proc in psutil.process_iter(['name', 'cmdline']):
            try:
                cmdline = proc.info.get('cmdline', [])
                if cmdline and f'frpc_{config_id}' in ' '.join(cmdline).lower():
                    proc.terminate()
                    proc.wait(timeout=5)
            except:
                try:
                    proc.kill()
                except:
                    pass
        return {"success": True, "message": "FRPC stopped"}
    
    def _find_frp_binary(self, name):
        ext = '.exe' if os.name == 'nt' else ''
        binary = name + ext
        
        paths = [
            os.path.join(FRP_DIR, binary),
            os.path.join(BASE_DIR, 'frp_files', binary),
            os.path.join(os.getcwd(), 'frp_files', binary),
            binary
        ]
        
        for path in paths:
            if os.path.isfile(path):
                return path
            if os.access(path, os.X_OK):
                return path
        
        import shutil
        result = shutil.which(binary)
        if result:
            return result
            
        return None
    
    def get_frps_status(self):
        return {
            "running": self.is_frps_running(),
            "pid": None
        }
    
    def get_frpc_status(self, config_id):
        return {
            "running": self.is_frpc_running(config_id),
            "pid": None
        }

frp_manager = FRPManager()
